#!/usr/bin/env sh
# Switchyard applier.
#
# Replaces the wireguard image's entrypoint and shares the wireguard
# container's network namespace (`network_mode: service:wireguard`). It never
# mounts the tunnel config and never brings the interface up: the wireguard
# container alone owns that and the account's private key. This script only
# calls `wg set` on the running interface to change which Mullvad server is
# the peer, following the panel's desired-state file.
#
# Privilege split (docs/architecture.md): the panel never calls wg or ip; it
# only writes the requested server name. This script re-validates that name
# against the panel's relay allowlist before acting, and stays fail-closed:
# on any failure it reports and stops. It never tries another server and
# never restores a non-tunnel route.
#
# The LinuxServer wireguard image ships sh, curl, wg and ip but not jq. jq is
# used when present; otherwise a small sed/awk parser reads the flat JSON
# fields needed. The parser normalizes `{`, `}` and `,` onto their own lines
# first, so it works for compact or pretty JSON as long as no string value
# contains those characters, which holds for every field read here
# (hostnames, base64 keys, dotted-quad IPs, city and country names).
#
# GATUS_TOKEN, when set, is used only in a curl Authorization header and is
# never printed.
set -u

STATE_DIR="${STATE_DIR:-/state}"
DESIRED_FILE="$STATE_DIR/panel/desired.json"
RELAYS_FILE="$STATE_DIR/panel/relays.json"
RESULT_DIR="$STATE_DIR/applier"
RESULT_FILE="$RESULT_DIR/result.json"
LAST_SERVER_FILE="$RESULT_DIR/.last-server"
IFACE="${EXIT_IF:-mullvad}"
TABLE="${EXIT_TABLE:-51821}"
POLL_INTERVAL_SEC="${POLL_INTERVAL_SEC:-5}"
REFRESH_INTERVAL_SEC="${REFRESH_INTERVAL_SEC:-60}"
HANDSHAKE_FRESH_SEC=180
SWITCH_TIMEOUT_SEC=60
# Optional health push to a Gatus external endpoint; unset GATUS_URL disables it.
GATUS_URL="${GATUS_URL:-}"
GATUS_ENDPOINT="${GATUS_ENDPOINT:-switchyard}"
GATUS_TOKEN="${GATUS_TOKEN:-}"

mkdir -p "$RESULT_DIR"

have_jq=0
if command -v jq >/dev/null 2>&1; then
    have_jq=1
fi

log() {
    printf '%s applier: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1"
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
json_str_or_null() { [ -z "$1" ] && printf 'null' || json_str "$1"; }
json_num_or_null() { [ -z "$1" ] && printf 'null' || printf '%s' "$1"; }

# ---- Result file (write-to-temp + rename) ----

write_result() {
    srv=$1; status=$2; message=$3; eip=$4; ecity=$5; ecountry=$6; mex=$7; hage=$8; ufb=$9
    tmp="$RESULT_FILE.tmp.$$"
    {
        printf '{\n'
        printf '  "server": %s,\n' "$(json_str_or_null "$srv")"
        printf '  "status": %s,\n' "$(json_str "$status")"
        printf '  "message": %s,\n' "$(json_str "$message")"
        printf '  "egress_ip": %s,\n' "$(json_str_or_null "$eip")"
        printf '  "egress_city": %s,\n' "$(json_str_or_null "$ecity")"
        printf '  "egress_country": %s,\n' "$(json_str_or_null "$ecountry")"
        printf '  "mullvad_exit_ip": %s,\n' "$mex"
        printf '  "handshake_age_s": %s,\n' "$(json_num_or_null "$hage")"
        printf '  "unreachable_fallback": %s,\n' "$ufb"
        printf '  "checked_at": %s\n' "$(json_str "$(now_iso)")"
        printf '}\n'
    } > "$tmp" && mv -f "$tmp" "$RESULT_FILE"
}

remember_last_server() {
    tmp="$LAST_SERVER_FILE.tmp.$$"
    printf '%s' "$1" > "$tmp" && mv -f "$tmp" "$LAST_SERVER_FILE"
}

last_server() {
    cat "$LAST_SERVER_FILE" 2>/dev/null || printf ''
}

# ---- JSON field readers ----

read_desired_server() {
    [ -f "$DESIRED_FILE" ] || { printf ''; return; }
    if [ "$have_jq" = 1 ]; then
        jq -r '.server // empty' "$DESIRED_FILE" 2>/dev/null
    else
        sed -e 's/{/{\n/g' -e 's/}/\n}\n/g' -e 's/,/,\n/g' "$DESIRED_FILE" \
            | sed -n 's/.*"server" *: *"\([^"]*\)".*/\1/p' | head -1
    fi
}

# Prints the named relay object's own lines (fallback path only). Robust to
# both compact and pretty JSON: normalizes brace/comma placement first, then
# tracks brace depth so it doesn't depend on indentation.
extract_relay_block() {
    host=$1
    sed -e 's/{/{\n/g' -e 's/}/\n}\n/g' -e 's/,/,\n/g' "$RELAYS_FILE" \
        | awk -v host="$host" '
            BEGIN { depth = 0; capturing = 0 }
            {
                if (!capturing) {
                    pat = "\"" host "\":"
                    if (index($0, pat) > 0 && index($0, "{") > 0) {
                        capturing = 1
                    } else {
                        next
                    }
                }
                print
                n = gsub(/{/, "{")
                c = gsub(/}/, "}")
                depth += n - c
                if (capturing && depth <= 0) exit
            }
        '
}

relay_field() {
    host=$1; field=$2
    if [ "$have_jq" = 1 ]; then
        jq -r --arg h "$host" --arg f "$field" '(.relays[$h][$f]) // empty' "$RELAYS_FILE" 2>/dev/null
    else
        extract_relay_block "$host" | sed -n "s/.*\"$field\" *: *\"\\([^\"]*\\)\".*/\\1/p" | head -1
    fi
}

relay_exists() {
    host=$1
    if [ "$have_jq" = 1 ]; then
        jq -e --arg h "$host" '(.relays[$h]) != null' "$RELAYS_FILE" >/dev/null 2>&1
    else
        [ -n "$(extract_relay_block "$host")" ]
    fi
}

valid_pubkey() {
    printf '%s' "$1" | grep -Eq '^[A-Za-z0-9+/]{43}=$'
}

valid_ipv4() {
    candidate=$1
    printf '%s' "$candidate" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || return 1
    old_ifs=$IFS
    IFS=.
    set -- $candidate
    IFS=$old_ifs
    for octet in "$1" "$2" "$3" "$4"; do
        [ "$octet" -le 255 ] || return 1
    done
    return 0
}

# ---- Interface / probe helpers ----

current_peer_pubkey() {
    wg show "$IFACE" peers 2>/dev/null | head -1
}

handshake_age() {
    line=$(wg show "$IFACE" latest-handshakes 2>/dev/null | head -1)
    ts=$(printf '%s' "$line" | awk '{print $2}')
    if [ -z "$ts" ] || [ "$ts" = "0" ]; then
        printf ''
        return
    fi
    now=$(date +%s)
    printf '%s' $((now - ts))
}

unreachable_fallback_present() {
    if ip route show table "$TABLE" 2>/dev/null | grep -q "unreachable default" \
        && ip -6 route show table "$TABLE" 2>/dev/null | grep -q "unreachable default"; then
        printf true
    else
        printf false
    fi
}

# Sets EGRESS_IP / EGRESS_CITY / EGRESS_COUNTRY / EGRESS_MULLVAD; returns
# non-zero if the probe itself failed (no response), independent of whether
# the response says mullvad_exit_ip is false.
egress_probe() {
    EGRESS_IP=""; EGRESS_CITY=""; EGRESS_COUNTRY=""; EGRESS_MULLVAD="false"
    resp=$(curl --interface "$IFACE" -fsS --max-time 10 https://am.i.mullvad.net/json 2>/dev/null) || return 1
    [ -n "$resp" ] || return 1
    if [ "$have_jq" = 1 ]; then
        EGRESS_IP=$(printf '%s' "$resp" | jq -r '.ip // empty')
        EGRESS_CITY=$(printf '%s' "$resp" | jq -r '.city // empty')
        EGRESS_COUNTRY=$(printf '%s' "$resp" | jq -r '.country // empty')
        EGRESS_MULLVAD=$(printf '%s' "$resp" | jq -r '.mullvad_exit_ip // false')
    else
        EGRESS_IP=$(printf '%s' "$resp" | sed -n 's/.*"ip" *: *"\([^"]*\)".*/\1/p' | head -1)
        EGRESS_CITY=$(printf '%s' "$resp" | sed -n 's/.*"city" *: *"\([^"]*\)".*/\1/p' | head -1)
        EGRESS_COUNTRY=$(printf '%s' "$resp" | sed -n 's/.*"country" *: *"\([^"]*\)".*/\1/p' | head -1)
        EGRESS_MULLVAD=$(printf '%s' "$resp" | sed -n 's/.*"mullvad_exit_ip" *: *\(true\|false\).*/\1/p' | head -1)
    fi
    [ -n "$EGRESS_MULLVAD" ] || EGRESS_MULLVAD="false"
    return 0
}

push_gatus() {
    success=$1; reason=$2
    if [ -z "$GATUS_URL" ] || [ -z "$GATUS_TOKEN" ]; then
        return
    fi
    # Gatus accepts external results only by POST (GET answers 405).
    curl -fsS --max-time 10 -X POST -G \
        --data-urlencode "success=$success" \
        --data-urlencode "error=$reason" \
        -H "Authorization: Bearer $GATUS_TOKEN" \
        "$GATUS_URL/api/v1/endpoints/$GATUS_ENDPOINT/external" >/dev/null 2>&1 \
        || log "Gatus push failed"
}

# ---- Switch flow ----

switch_peer() {
    host=$1; pubkey=$2; ip=$3

    write_result "$host" applying "switching to $host" "" "" "" false "" "$(unreachable_fallback_present)"

    old_peer=$(current_peer_pubkey)
    if [ -n "$old_peer" ]; then
        wg set "$IFACE" peer "$old_peer" remove 2>/dev/null || true
    fi

    if ! wg set "$IFACE" peer "$pubkey" endpoint "$ip:51820" allowed-ips 0.0.0.0/0,::/0 persistent-keepalive 25 2>/dev/null; then
        write_result "$host" failed "wg set failed while applying the new peer" "" "" "" false "" "$(unreachable_fallback_present)"
        push_gatus false wg-set-failed
        log "wg set failed for $host; staying fail-closed"
        return 1
    fi

    # The interface now runs this peer regardless of probe outcome below —
    # record it immediately so a failed switch is still reported honestly.
    remember_last_server "$host"

    deadline=$(( $(date +%s) + SWITCH_TIMEOUT_SEC ))
    ok=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if egress_probe; then
            age=$(handshake_age)
            if [ -n "$age" ] && [ "$age" -lt "$HANDSHAKE_FRESH_SEC" ] && [ "$EGRESS_MULLVAD" = "true" ]; then
                ok=1
                break
            fi
        fi
        sleep 3
    done

    ufb=$(unreachable_fallback_present)
    if [ "$ok" = 1 ]; then
        write_result "$host" ok "applied $host" "$EGRESS_IP" "$EGRESS_CITY" "$EGRESS_COUNTRY" "$EGRESS_MULLVAD" "$(handshake_age)" "$ufb"
        push_gatus true ok
        log "switched to $host"
        return 0
    fi

    write_result "$host" failed "no fresh Mullvad handshake/egress within ${SWITCH_TIMEOUT_SEC}s" \
        "$EGRESS_IP" "$EGRESS_CITY" "$EGRESS_COUNTRY" "$EGRESS_MULLVAD" "$(handshake_age)" "$ufb"
    push_gatus false switch-timeout
    log "switch to $host timed out; staying fail-closed (never trying another server, never restoring a non-tunnel route)"
    return 1
}

# ---- Periodic refresh / Gatus push (~60s) ----

refresh_and_push() {
    srv=$(last_server)
    age=$(handshake_age)
    ufb=$(unreachable_fallback_present)
    if egress_probe; then
        mex=$EGRESS_MULLVAD
        eip=$EGRESS_IP; ecity=$EGRESS_CITY; ecountry=$EGRESS_COUNTRY
    else
        mex="false"; eip=""; ecity=""; ecountry=""
    fi

    current=$(current_peer_pubkey)
    if [ -z "$current" ]; then
        write_result "$srv" failed "no peer configured on $IFACE" "" "" "" false "$age" "$ufb"
        push_gatus false no-peer
        return
    fi

    fresh=false
    if [ -n "$age" ] && [ "$age" -lt "$HANDSHAKE_FRESH_SEC" ]; then
        fresh=true
    fi

    if [ "$fresh" = "true" ] && [ "$mex" = "true" ] && [ "$ufb" = "true" ]; then
        write_result "$srv" ok healthy "$eip" "$ecity" "$ecountry" "$mex" "$age" "$ufb"
        push_gatus true ok
        return
    fi

    if [ "$mex" != "true" ] && [ "$fresh" != "true" ]; then
        reason="egress is not confirmed Mullvad and the handshake is stale; the Mullvad account may have expired"
    elif [ "$mex" != "true" ]; then
        reason="egress-not-mullvad"
    elif [ "$fresh" != "true" ]; then
        reason="handshake-stale"
    else
        reason="unreachable-fallback-missing"
    fi
    write_result "$srv" failed "$reason" "$eip" "$ecity" "$ecountry" "$mex" "$age" "$ufb"
    push_gatus false "$reason"
}

# ---- Main loop ----

log "starting; jq available: $have_jq"
last_refresh=0

while :; do
    server=$(read_desired_server)

    if [ -n "$server" ]; then
        if ! relay_exists "$server"; then
            log "desired server '$server' is not in the relay allowlist; ignoring"
        else
            pubkey=$(relay_field "$server" public_key)
            ip=$(relay_field "$server" ipv4_addr_in)
            if ! valid_pubkey "$pubkey"; then
                log "relay '$server' has an invalid public_key; ignoring"
            elif ! valid_ipv4 "$ip"; then
                log "relay '$server' has an invalid ipv4_addr_in; ignoring"
            else
                current=$(current_peer_pubkey)
                if [ "$current" != "$pubkey" ]; then
                    switch_peer "$server" "$pubkey" "$ip" || true
                elif [ "$(last_server)" != "$server" ]; then
                    # Already running this server (e.g. the rendered default
                    # after a wireguard restart); record it for the result file.
                    remember_last_server "$server"
                fi
            fi
        fi
    fi

    now=$(date +%s)
    if [ $(( now - last_refresh )) -ge "$REFRESH_INTERVAL_SEC" ]; then
        refresh_and_push
        last_refresh=$now
    fi

    sleep "$POLL_INTERVAL_SEC"
done

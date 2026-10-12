#!/usr/bin/env sh
# Checks the trust boundary and wiring of the three Compose forms as Compose
# resolves them (`docker compose config --format json`), against the example
# environment files: the exit and Switchyard services, capabilities, mounts,
# which service sees which secret, the settings each service passes on, and
# that the examples and the Compose files agree on what is a setting. It
# replaces the Compose-reading tests of the Python suite
# (tools/test_host_and_routing.py, test_gluetun.py, test_sidecar_tools.py,
# test_pia.py, test_nordvpn_applier.py, test_server_setting.py). Needs Docker
# Compose and jq, no daemon; starts no container, reads no secret and writes
# nothing in the checkout.
#   sh tools/check-compose.sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }
command -v jq >/dev/null 2>&1 || { echo "SKIP check-compose: jq not found"; exit 0; }
docker compose version >/dev/null 2>&1 || { echo "SKIP check-compose: docker compose not found"; exit 0; }

# resolve <name> <compose file> <env file> [VAR=value ...]: Compose's resolved
# model in $work/<name>.json.
resolve() {
    name=$1; file=$2; envfile=$3; shift 3
    env "$@" docker compose --env-file "$envfile" -f "$file" config --format json > "$work/$name.json" ||
        fail "$file does not resolve with $envfile"
}
# ok <name> <description> <jq expression that is true>
ok() { jq -e "$3" "$work/$1.json" >/dev/null || fail "$1: $2"; }

# Expressions shared by the forms. $svc is a service object.
defs='
def bind($t): [.volumes[]? | select(.target == $t)] | first;
def targets: [.volumes[]?.target];
def sources: [.volumes[]? | (.source // "")];
def hardened: .cap_drop == ["ALL"] and (.security_opt == ["no-new-privileges:true"]) and .read_only == true;
def exitcaps: (.cap_add | sort) == ["DAC_OVERRIDE","NET_ADMIN","NET_RAW"];
def jsonlog: .logging.driver == "json-file" and (.logging.options | keys) == ["max-size"];
def noSecretMounts: [sources[] | select(test("secrets|tunnel"))] == [];
def stateOnly: (targets | sort) == ["/state/applier","/state/panel"];
'

# --- the native form --------------------------------------------------------
resolve native compose.yaml .env.example
ok native "services are exit and switchyard" '.services | keys == ["exit","switchyard"]'
ok native "no old service, volume or owner record remains" '
  (.volumes | keys) == ["netbird-data"] and
  ([.services[] | .volumes[]? | .target] | map(select(test("/run/molebridge|routing|wait-for|contract-rules"))) == [])'
ok native "both services run the one image, the exit builds it from a checkout" '
  .services.exit.image == .services.switchyard.image and
  (.services.exit.image | startswith("ghcr.io/irashack/molebridge:")) and
  .services.exit.build.dockerfile == "Dockerfile" and (.services.switchyard.build == null)'
ok native "roles by argument" '.services.exit.command == ["exit"] and .services.switchyard.command == ["panel"]'
ok native "the exit is hardened with exactly NET_ADMIN, NET_RAW and DAC_OVERRIDE" '
  '"$defs"' .services.exit | hardened and exitcaps and jsonlog'
ok native "tmpfs on /run and /var/log/netbird, nothing else writable but the volumes" '
  (.services.exit.tmpfs | map(split(":")[0]) | sort) == ["/run","/var/log/netbird"]'
ok native "the exit stops within the grace period, forwards, and fixes path MTU discovery" '
  .services.exit.stop_grace_period == "15s" and
  .services.exit.sysctls["net.ipv4.ip_forward"] == "1" and
  .services.exit.sysctls["net.ipv6.conf.all.forwarding"] == "1" and
  .services.exit.sysctls["net.ipv4.icmp_errors_use_inbound_ifaddr"] == "1" and
  .services.exit.sysctls["net.ipv6.conf.all.disable_ipv6"] == "0" and
  .services.exit.sysctls["net.ipv6.conf.default.disable_ipv6"] == "0"'
ok native "the exit publishes nothing and shares no namespace" '
  .services.exit.ports == null and .services.exit.network_mode == null and
  (.services.exit.networks | keys) == ["default"]'
ok native "the exit mounts the tunnel config and the PIA login read-only, panel state read-only, applier state writable" '
  '"$defs"' .services.exit |
  (bind("/config/wg_confs") | .read_only == true and (.source | endswith("/tunnel/wg_confs"))) and
  (bind("/run/secrets/pia") | .read_only == true and (.bind.create_host_path // false) == false and (.source | endswith("/secrets/pia"))) and
  (bind("/state/panel") | .read_only == true) and
  (bind("/state/applier") | .read_only != true) and
  (bind("/var/lib/netbird") | .type == "volume" and .source == "netbird-data") and
  (targets | length) == 5'
# Resolved output drops env files that are absent, so read the optional pair from the source.
grep -A1 -- '- path: ./secrets/netbird.env' compose.yaml | grep -q 'required: false' &&
    grep -A1 -- '- path: ./secrets/applier.env' compose.yaml | grep -q 'required: false' ||
    fail "compose.yaml: netbird.env and applier.env must be optional env files"
ok native "NetBird settings: required ones set, forbidden ones absent, interface names agree" '
  .services.exit.environment as $e |
  $e.NB_DISABLE_USERSPACE_ROUTING == "true" and $e.NB_DISABLE_DNS == "true" and
  $e.NB_INTERFACE_NAME == $e.OVERLAY_IF and
  $e.NB_EXTRA_IFACE_BLACKLIST == $e.EXIT_IF and
  $e.TUNNEL_BACKEND == "native" and $e.EXIT_KIND == "overlay" and
  ([$e | keys[] | select(test("^(NB_FORCE_USERSPACE|NB_USE_NETSTACK|NB_WG_KERNEL|NB_ENABLE_ROSENPASS|WT_|NB_CONFIG|NB_PROFILE|NB_FOREGROUND|NB_FWMARK|NB_SKIP_SOCKET|NB_USE_LEGACY|NB_DISABLE_CUSTOM)"))] == [])'
ok native "the exit passes every override the binary reads, with the binary's default" '
  .services.exit.environment as $e |
  $e.ROUTING_RECONCILE_INTERVAL == "30" and $e.GUARD_GRACE == "30" and $e.EXIT_TABLE == "51821" and
  $e.OVERLAY_IF == "wt0" and $e.GATUS_ENDPOINT == "molebridge" and $e.STATE_DIR == "/state" and
  $e.PIA_PORT_FORWARD == "off" and $e.PIA_PORT_FORWARD_TARGET == "" and $e.SERVER == ""'
ok native "a healthcheck that asks the binary" '.services.exit.healthcheck.test == ["CMD","/usr/local/bin/molebridge","health"]'
ok native "the memory ceiling covers NordVPN's server list" '(.services.exit.deploy.resources.limits.memory | tonumber) >= 536870912'
ok native "Switchyard: no capabilities, a user, its own network, loopback port, its own mounts only" '
  '"$defs"' .services.switchyard |
  hardened and jsonlog and (has("cap_add") | not) and .user == "1000:1000" and
  (.networks | keys) == ["panel"] and .network_mode == null and
  .ports == [{"mode":"ingress","host_ip":"127.0.0.1","target":8080,"published":"8095","protocol":"tcp"}] and
  stateOnly and noSecretMounts and
  (bind("/state/panel") | .read_only != true) and (bind("/state/applier") | .read_only == true) and
  .healthcheck.test[0] == "CMD"'
ok native "SERVER goes only to the exit" '
  [.services | to_entries[] | select(.value.environment.SERVER != null) | .key] == ["exit"]'
ok native "Switchyard knows the provider, the root statement and the exits" '
  .services.switchyard.environment as $e |
  $e.PROVIDER == "mullvad" and $e.PANEL_ALLOW_ROOT == "" and $e.PANEL_EXITS == "" and $e.STATE_DIR == "/state"'
pass "native form: two services, hardened, secrets only where they belong"

# One file serves every provider.
for provider in mullvad pia nordvpn; do
    resolve "native-$provider" compose.yaml .env.example "PROVIDER=$provider" "EXIT_IF=$provider"
    ok "native-$provider" "PROVIDER=$provider reaches the exit and Switchyard" "
      .services.exit.environment.PROVIDER == \"$provider\" and .services.switchyard.environment.PROVIDER == \"$provider\" and
      .services.exit.environment.EXIT_IF == \"$provider\" and .services.exit.environment.NB_EXTRA_IFACE_BLACKLIST == \"$provider\""
done
resolve native-root compose.yaml .env.example PANEL_USER=0:0 PANEL_ALLOW_ROOT=1 PANEL_EXITS=a=mullvad,b=pia
ok native-root "PANEL_USER, PANEL_ALLOW_ROOT and PANEL_EXITS reach Switchyard" '
  .services.switchyard.user == "0:0" and .services.switchyard.environment.PANEL_ALLOW_ROOT == "1" and
  .services.switchyard.environment.PANEL_EXITS == "a=mullvad,b=pia"'
if env -u OVERLAY_CIDR docker compose --env-file /dev/null -f compose.yaml config --quiet >/dev/null 2>&1; then
    fail "compose.yaml resolved without OVERLAY_CIDR"
fi
pass "the provider, the root statement and the exits reach the right containers; OVERLAY_CIDR is required"

# --- the gluetun backend ----------------------------------------------------
resolve gluetun compose.gluetun.yaml .env.gluetun.example
ok gluetun "services are exit, gluetun and switchyard" '.services | keys == ["exit","gluetun","switchyard"]'
ok gluetun "gluetun is pinned by digest, has no published ports, and tells its preflight it is an overlay" '
  (.services.gluetun.image | test("^docker.io/qmcgaw/gluetun:v[0-9.]+@sha256:[0-9a-f]{64}$")) and
  .services.gluetun.ports == null and
  .services.gluetun.environment.MOLEBRIDGE_KIND == "overlay" and
  .services.gluetun.entrypoint == ["/bin/sh","/usr/local/bin/molebridge-gluetun-preflight","/gluetun-entrypoint"]'
ok gluetun "gluetun: kernelspace WireGuard, control server on loopback, server list in its own directory" '
  .services.gluetun.environment as $e |
  $e.VPN_TYPE == "wireguard" and $e.WIREGUARD_IMPLEMENTATION == "kernelspace" and
  $e.HTTP_CONTROL_SERVER_ADDRESS == "127.0.0.1:8000" and
  $e.WIREGUARD_PRIVATE_KEY_SECRETFILE == "/run/secrets/wireguard_private_key" and
  $e.STORAGE_FILEPATH == "/gluetun/servers/servers.json" and $e.VPN_INTERFACE == "wg0" and
  .services.gluetun.sysctls["net.ipv4.icmp_errors_use_inbound_ifaddr"] == "1"'
ok gluetun "gluetun mounts the preflight and its three files read-only, and Compose refuses to create them" '
  '"$defs"' .services.gluetun |
  (bind("/usr/local/bin/molebridge-gluetun-preflight") | .read_only == true and (.source | endswith("/routing/gluetun-preflight"))) and
  ([bind("/iptables/post-rules.txt"), bind("/gluetun/auth/config.toml"), bind("/run/secrets/wireguard_private_key")] |
     all(.read_only == true and ((.bind.create_host_path // false) == false))) and
  (bind("/gluetun/servers") | .type == "volume" and .source == "gluetun-servers")'
ok gluetun "the exit joins gluetun and is hardened with the same three capabilities" '
  '"$defs"' .services.exit |
  .network_mode == "service:gluetun" and hardened and exitcaps and jsonlog and .command == ["exit"] and
  .ports == null and .depends_on.gluetun.condition == "service_started" and .depends_on.gluetun.restart == true and
  (.tmpfs | map(split(":")[0]) | sort) == ["/run","/var/log/netbird"]'
ok gluetun "the exit sees the API key, never the role file or the provider key" '
  '"$defs"' .services.exit |
  (bind("/run/secrets/gluetun/api_key") | .read_only == true and (.bind.create_host_path // false) == false) and
  (bind("/gluetun-servers") | .read_only == true and .source == "gluetun-servers") and
  (bind("/state/panel") | .read_only == true) and (bind("/state/applier") | .read_only != true) and
  (bind("/var/lib/netbird") | .source == "netbird-data") and
  ([sources[] | select(test("auth.toml|wireguard_private_key|post-rules|tunnel"))] == [])'
ok gluetun "the exit is the gluetun kind of overlay exit, and its settings agree with gluetun and NetBird" '
  .services.exit.environment as $e | .services.gluetun.environment as $g |
  $e.TUNNEL_BACKEND == "gluetun" and $e.EXIT_KIND == "overlay" and
  ($e.PROVIDER | startswith("gluetun-")) and $e.PROVIDER == "gluetun-" + $g.VPN_SERVICE_PROVIDER and
  $e.GLUETUN_CONTROL_URL == "http://127.0.0.1:8000" and $e.GLUETUN_SERVERS_FILE == "/gluetun-servers/servers.json" and
  $e.GLUETUN_API_KEY_FILE == "/run/secrets/gluetun/api_key" and
  $e.NB_FWMARK_BASE == $e.CONTROL_MARK and $e.NB_EXTRA_IFACE_BLACKLIST == $e.EXIT_IF and $e.EXIT_IF == $g.VPN_INTERFACE and
  $e.NB_WIREGUARD_PORT == $g.FIREWALL_INPUT_PORTS and
  $e.FWMARK_GRACE == "30" and $e.GUARD_GRACE == "30" and $e.HOST_IF == "eth0" and $e.HOST_TABLE == "51822" and
  $e.NB_DISABLE_USERSPACE_ROUTING == "true" and
  ([$e | keys[] | select(test("^(NB_USE_LEGACY|NB_SKIP_SOCKET|NB_DISABLE_CUSTOM|NB_FORCE_USERSPACE)"))] == [])'
ok gluetun "SERVER goes only to the exit" '[.services | to_entries[] | select(.value.environment.SERVER != null) | .key] == ["exit"]'
ok gluetun "Switchyard is the same service as in compose.yaml, for this exit's provider, with no secrets" '
  '"$defs"' .services.switchyard |
  hardened and (has("cap_add") | not) and (.networks | keys) == ["panel"] and stateOnly and noSecretMounts and
  .environment.PROVIDER == "gluetun-nordvpn" and .command == ["panel"]'
ok gluetun "no old service remains" '.services | has("guard") or has("netbird") or has("applier") or has("control-panel") | not'
ok gluetun "volumes" '(.volumes | keys) == ["gluetun-data","gluetun-servers","netbird-data"]'
pass "gluetun form: three containers, the exit sees the API key only"

# --- the sidecar ------------------------------------------------------------
resolve sidecar compose.sidecar.yaml .env.sidecar.example
ok sidecar "services are exit, example-app, gluetun and switchyard" '.services | keys == ["example-app","exit","gluetun","switchyard"]'
ok sidecar "gluetun is the overlay form's image, tells its preflight it is a sidecar, and has no post-rules" '
  .services.gluetun.image == '"$(jq -c .services.gluetun.image "$work/gluetun.json")"' and
  .services.gluetun.environment.MOLEBRIDGE_KIND == "sidecar" and
  .services.gluetun.entrypoint == '"$(jq -c .services.gluetun.entrypoint "$work/gluetun.json")"' and
  .services.gluetun.ports == null and
  ([.services | .. | strings | select(test("post-rules"))] | length) == 0 and
  (([.services.gluetun.volumes[] | select(.type == "bind")] | map(.target) | sort) ==
     ["/gluetun/auth/config.toml","/run/secrets/wireguard_private_key","/usr/local/bin/molebridge-gluetun-preflight"]) and
  .services.gluetun.environment.HTTP_CONTROL_SERVER_ADDRESS == "127.0.0.1:8000" and
  .services.gluetun.environment.WIREGUARD_IMPLEMENTATION == "kernelspace"'
ok sidecar "the exit is a sidecar: no NetBird, no contract, only the API key, hardened" '
  '"$defs"' .services.exit |
  .network_mode == "service:gluetun" and hardened and exitcaps and jsonlog and .command == ["exit"] and
  .environment.EXIT_KIND == "sidecar" and .environment.TUNNEL_BACKEND == "gluetun" and
  (.environment.PROVIDER | startswith("gluetun-")) and
  ([.environment | keys[] | select(test("^(NB_|OVERLAY|CONTROL_MARK|HOST_|EXIT_TABLE|FWMARK)"))] == []) and
  ([.volumes[] | select(.type == "bind") | .target] | sort) == ["/run/secrets/gluetun/api_key","/state/applier","/state/panel"] and
  (bind("/run/secrets/gluetun/api_key") | .read_only == true and (.bind.create_host_path // false) == false) and
  (.tmpfs | map(split(":")[0])) == ["/run"] and
  .labels["io.molebridge.sidecar-apps"] == "example-app"'
ok sidecar "the example application shares the namespace, pinned, in its profile" '
  .services["example-app"].network_mode == "service:gluetun" and
  (.services["example-app"].image | test("@sha256:[0-9a-f]{64}$")) and
  .services["example-app"].profiles == ["example"]'
ok sidecar "Switchyard: sidecar kind, no capabilities, no secrets, loopback port" '
  '"$defs"' .services.switchyard |
  hardened and (has("cap_add") | not) and stateOnly and noSecretMounts and
  .environment.EXIT_KIND == "sidecar" and .environment.PROVIDER == "gluetun-nordvpn" and
  .ports[0].host_ip == "127.0.0.1" and .ports[0].target == 8080 and (.networks | keys) == ["panel"]'
ok sidecar "SERVER goes only to the exit" '[.services | to_entries[] | select(.value.environment.SERVER != null) | .key] == ["exit"]'
ok sidecar "no NetBird volume and no old service" '(.volumes | keys) == ["gluetun-data","gluetun-servers"] and (.services | has("applier") or has("control-panel") | not)'
pass "sidecar form: the exit holds the API key only, gluetun has no post-rules"

# --- the settings -----------------------------------------------------------
# .env.example lists at most 20 settings, once each, and every one is read by
# the Compose file; every ${NAME} the Compose files use that has no default
# is a documented requirement.
count=$(grep -cE '^[A-Z][A-Z0-9_]*=' .env.example)
[ "$count" -le 20 ] || fail ".env.example has $count settings, more than 20"
dups=$(grep -E '^[A-Z][A-Z0-9_]*=' .env.example | cut -d= -f1 | sort | uniq -d)
[ -z "$dups" ] || fail ".env.example sets $dups twice"
for envfile in .env.example .env.gluetun.example .env.sidecar.example; do
    case $envfile in
        .env.example) file=compose.yaml ;;
        .env.gluetun.example) file=compose.gluetun.yaml ;;
        *) file=compose.sidecar.yaml ;;
    esac
    for name in $(grep -E '^[A-Z][A-Z0-9_]*=' "$envfile" | cut -d= -f1); do
        # Compose itself reads these.
        case $name in COMPOSE_FILE|COMPOSE_PROFILES|COMPOSE_PROJECT_NAME) continue ;; esac
        # Used by this file, or by compose.yaml when this file extends it.
        grep -Eq "[$][{]${name}[:}?-]" "$file" compose.yaml || fail "$envfile sets $name, which $file does not read"
    done
    if grep -qE '(SECRET|PASSWORD|TOKEN|PRIVATE_KEY|API_KEY)[A-Z_]*=.' "$envfile"; then
        fail "$envfile sets something that looks like a secret"
    fi
done
pass ".env.example has $count settings, each read by its Compose file, none secret"
grep -qx 'COMPOSE_FILE=compose.gluetun.yaml' .env.gluetun.example || fail ".env.gluetun.example must select compose.gluetun.yaml"
grep -qx 'COMPOSE_FILE=compose.sidecar.yaml' .env.sidecar.example &&
    grep -qx 'COMPOSE_PROFILES=example' .env.sidecar.example &&
    grep -qx 'SIDECAR_APPS=example-app' .env.sidecar.example || fail ".env.sidecar.example must select the sidecar file, the example profile and its application"
! grep -q '^COMPOSE_FILE=' .env.example || fail ".env.example must not select a Compose file"

# The pinned image is the same in every Compose file, and none still names a
# service from 0.7.
refs=$(grep -hoE 'ghcr\.io/irashack/molebridge:[A-Za-z0-9._-]+' compose.yaml compose.gluetun.yaml compose.sidecar.yaml | sort -u)
[ "$(echo "$refs" | wc -l | tr -d ' ')" = 1 ] || fail "the Compose files name different Molebridge image tags: $refs"
if grep -nE 'exit-run|guard-run|wait-for-guards|contract-rules|routing/molebridge-exit|tools/molebridge\.py|applier/Dockerfile|routing/Dockerfile|python3? ' compose.yaml compose.gluetun.yaml compose.sidecar.yaml; then
    fail "a Compose file still names a 0.7 service, script or helper"
fi
[ ! -e compose.pia.yaml ] && [ ! -e compose.nordvpn.yaml ] || fail "compose.pia.yaml or compose.nordvpn.yaml is back"
pass "one image tag, no 0.7 leftovers"
echo "all Compose checks passed"

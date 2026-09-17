#!/usr/bin/env python3
"""Switchyard control panel.

Web UI for choosing which Mullvad WireGuard server the exit uses. It has no
login of its own: publish it only behind something that authenticates people,
such as an identity-aware reverse proxy or an overlay access policy. It:

- refreshes a validated allowlist of active Mullvad WireGuard relays from
  Mullvad's published API on start and every REFRESH_INTERVAL_S seconds,
  keeping the last good file on any failure or empty result;
- shows the current desired server, the applier's last result, and relay
  list freshness/errors;
- accepts a POSTed desired server, CSRF-protected, which is
  written to $STATE_DIR/panel/desired.json for the applier to pick up;
- measures relay latency lazily, only when a page asks for it: a TCP connect
  to each relay's port 443 from the exit host, cached for LATENCY_TTL_S;
- serves /embed, a compact view for a dashboard iframe widget, and a web
  manifest so phones can install the panel as a home-screen app.

Python standard library only. Never calls wg/ip/subprocess.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import http.client
import http.cookies
import http.server
import ipaddress
import json
import os
import re
import secrets
import sys
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# Configuration and file contract
# --------------------------------------------------------------------------

STATE_DIR = Path(os.environ.get('STATE_DIR', '/state'))
PANEL_DIR = STATE_DIR / 'panel'
RELAYS_PATH = PANEL_DIR / 'relays.json'
DESIRED_PATH = PANEL_DIR / 'desired.json'
APPLIER_RESULT_PATH = STATE_DIR / 'applier' / 'result.json'

MULLVAD_RELAYS_URL = 'https://api.mullvad.net/app/v1/relays'
FETCH_TIMEOUT_S = 20
MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB cap
REFRESH_INTERVAL_S = 6 * 60 * 60  # 6 hours

MAX_BODY_BYTES = 4096
CSRF_COOKIE_NAME = 'csrf_nonce'

# Latency probe: a TCP handshake round trip to the relay's port 443, which
# Mullvad relays accept. No ICMP, so no capabilities are needed.
PROBE_PORT = 443
PROBE_TIMEOUT_S = 1.5
PROBE_ATTEMPTS = 2
PROBE_WORKERS = 24
LATENCY_TTL_S = 15 * 60
MAX_PROBE_HOSTS = 64

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / 'static'
STATIC_FILES = {
    'panel.css': 'text/css; charset=utf-8',
    'panel.js': 'text/javascript; charset=utf-8',
    'JetBrainsMono-Regular.woff2': 'font/woff2',
    'apple-touch-icon.png': 'image/png',
    'icon-192.png': 'image/png',
    'icon-512.png': 'image/png',
}

# Presentation settings; none of these affect switching.
PANEL_TITLE = os.environ.get('PANEL_TITLE', 'Mullvad exit')
PANEL_SHORT_TITLE = os.environ.get('PANEL_SHORT_TITLE', 'Exit')
PANEL_HOST_LABEL = os.environ.get('PANEL_HOST_LABEL', 'this exit')
PANEL_HOME_URL = os.environ.get('PANEL_HOME_URL', '')
PANEL_HOME_LABEL = os.environ.get('PANEL_HOME_LABEL', 'Home')

THEME_COLOR = '#232638'
WEB_MANIFEST = {
    'name': PANEL_TITLE,
    'short_name': PANEL_SHORT_TITLE,
    'start_url': '/',
    'scope': '/',
    'display': 'standalone',
    'background_color': THEME_COLOR,
    'theme_color': THEME_COLOR,
    'icons': [
        {'src': '/static/icon-192.png', 'sizes': '192x192', 'type': 'image/png'},
        {'src': '/static/icon-512.png', 'sizes': '512x512', 'type': 'image/png'},
    ],
}

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 8080

# Tolerant hostname check: real Mullvad WireGuard hostnames look like
# "se-sto-wg-001" (^[a-z]{2}-[a-z]{3}-wg-[0-9]{3}$), but we accept the wider
# shape while still requiring the "-wg-<3 digits>" marker.
HOSTNAME_RE = re.compile(r'^[a-z0-9-]{1,40}-wg-[0-9]{3}$')

SECURITY_HEADERS = {
    # no-referrer makes browsers send `Origin: null` on form POSTs, which the
    # origin check must reject; same-origin keeps the real origin.
    'Referrer-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff',
}

CSP_BASE = (
    "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
    "font-src 'self'; img-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'"
)


def frame_ancestors() -> List[str]:
    """Origins allowed to frame the panel (for example a dashboard). Only
    https origins are accepted; anything else is ignored."""
    raw = os.environ.get('PANEL_FRAME_ANCESTORS', '')
    return [o.strip() for o in raw.split() if re.match(r'^https://[a-z0-9.-]+$', o.strip())]


def security_headers() -> Dict[str, str]:
    ancestors = frame_ancestors()
    headers = dict(SECURITY_HEADERS)
    if ancestors:
        headers['Content-Security-Policy'] = f"{CSP_BASE}; frame-ancestors {' '.join(ancestors)}"
    else:
        headers['Content-Security-Policy'] = f"{CSP_BASE}; frame-ancestors 'none'"
        headers['X-Frame-Options'] = 'DENY'
    return headers

# --------------------------------------------------------------------------
# Process-lifetime state
# --------------------------------------------------------------------------

_CSRF_SECRET = secrets.token_bytes(32)
_state_lock = threading.Lock()
_last_fetch_error: Optional[str] = None
_last_fetch_error_at: Optional[str] = None
# hostname -> (round-trip ms or None when unreachable, time.monotonic() measured)
_latency_cache: Dict[str, Tuple[Optional[float], float]] = {}
_probe_lock = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# --------------------------------------------------------------------------
# Atomic file helpers
# --------------------------------------------------------------------------

def write_json_atomic(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='.tmp-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(obj, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def read_json(path: Path) -> Optional[Any]:
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def load_allowlist() -> set:
    data = read_json(RELAYS_PATH)
    if not isinstance(data, dict) or not isinstance(data.get('relays'), dict):
        return set()
    return set(data['relays'].keys())


# --------------------------------------------------------------------------
# Relay list fetch, validation and refresh
# --------------------------------------------------------------------------

def _is_valid_wg_pubkey(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(decoded) == 32


def _is_valid_ipv4(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def validate_relay(relay: Dict[str, Any], locations: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Return the validated allowlist entry for one relay, or None to drop it."""
    if relay.get('active') is not True:
        return None
    hostname = relay.get('hostname')
    if not isinstance(hostname, str) or not HOSTNAME_RE.match(hostname):
        return None
    if not _is_valid_wg_pubkey(relay.get('public_key')):
        return None
    ipv4 = relay.get('ipv4_addr_in')
    if not _is_valid_ipv4(ipv4):
        return None
    loc_code = relay.get('location')
    if not isinstance(loc_code, str) or loc_code not in locations:
        return None
    loc = locations[loc_code]
    if not isinstance(loc, dict):
        return None
    country = loc.get('country')
    city = loc.get('city')
    if not isinstance(country, str) or not isinstance(city, str):
        return None
    return {
        'hostname': hostname,
        'country': country,
        'city': city,
        'location_code': loc_code,
        'public_key': relay['public_key'],
        'ipv4_addr_in': ipv4,
    }


def parse_relay_response(data: Any) -> Dict[str, Dict[str, str]]:
    """Return {hostname: entry} for every valid active relay. Raises ValueError
    on a response that does not match the expected top-level schema."""
    if not isinstance(data, dict):
        raise ValueError('top-level response is not a JSON object')
    locations = data.get('locations')
    wireguard = data.get('wireguard')
    if not isinstance(locations, dict):
        raise ValueError("missing or invalid 'locations' map")
    if not isinstance(wireguard, dict) or not isinstance(wireguard.get('relays'), list):
        raise ValueError("missing or invalid 'wireguard.relays' list")

    result: Dict[str, Dict[str, str]] = {}
    for relay in wireguard['relays']:
        if not isinstance(relay, dict):
            continue
        entry = validate_relay(relay, locations)
        if entry:
            result[entry['hostname']] = entry
    return result


def fetch_relays_raw(url: str = MULLVAD_RELAYS_URL, timeout: int = FETCH_TIMEOUT_S) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': 'switchyard-panel/0.1'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec: fixed https URL
        raw = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(f'relay response exceeded {MAX_RESPONSE_BYTES} byte cap')
    return raw


def _record_fetch_error(message: str) -> None:
    global _last_fetch_error, _last_fetch_error_at
    with _state_lock:
        _last_fetch_error = message
        _last_fetch_error_at = now_iso()


def _clear_fetch_error() -> None:
    global _last_fetch_error, _last_fetch_error_at
    with _state_lock:
        _last_fetch_error = None
        _last_fetch_error_at = None


def get_fetch_error() -> Tuple[Optional[str], Optional[str]]:
    with _state_lock:
        return _last_fetch_error, _last_fetch_error_at


def refresh_relays_once() -> bool:
    """Fetch, validate and persist the relay allowlist. On any failure or an
    empty result, the last good relays.json is left untouched and the error
    is recorded for display. Returns True on a successful write."""
    try:
        raw = fetch_relays_raw()
        data = json.loads(raw)
        relays = parse_relay_response(data)
        if not relays:
            raise ValueError('parsed relay list is empty')
    except Exception as exc:  # noqa: BLE001 - any failure keeps the last good file
        _record_fetch_error(f'{type(exc).__name__}: {exc}')
        return False

    write_json_atomic(RELAYS_PATH, {'fetched_at': now_iso(), 'relays': relays})
    _clear_fetch_error()
    return True


def relay_refresh_loop(stop_event: threading.Event) -> None:
    refresh_relays_once()
    while not stop_event.wait(REFRESH_INTERVAL_S):
        refresh_relays_once()


# --------------------------------------------------------------------------
# Lazy latency probing
# --------------------------------------------------------------------------

def probe_tcp_rtt_ms(ip: str, port: int = PROBE_PORT, timeout: float = PROBE_TIMEOUT_S,
                     attempts: int = PROBE_ATTEMPTS) -> Optional[float]:
    """Best TCP handshake time in ms, or None if every attempt failed. A
    refused connection still completes a round trip, so it counts."""
    best: Optional[float] = None
    for _ in range(attempts):
        start = time.monotonic()
        try:
            socket.create_connection((ip, port), timeout=timeout).close()
        except ConnectionRefusedError:
            pass
        except OSError:
            continue
        elapsed = (time.monotonic() - start) * 1000
        best = elapsed if best is None else min(best, elapsed)
    return round(best, 1) if best is not None else None


def measure_latency(relays: Dict[str, Dict[str, Any]], hostnames: Iterable[str],
                    fresh: bool = False) -> Dict[str, Optional[float]]:
    """Latency for each listed hostname present in the allowlist, probing
    only entries missing from or stale in the cache (or all, when fresh)."""
    wanted = [h for h in dict.fromkeys(hostnames) if h in relays]
    with _probe_lock:
        now = time.monotonic()
        stale = [h for h in wanted
                 if fresh or h not in _latency_cache or now - _latency_cache[h][1] > LATENCY_TTL_S]
        if stale:
            with ThreadPoolExecutor(max_workers=min(PROBE_WORKERS, len(stale))) as pool:
                results = pool.map(lambda h: probe_tcp_rtt_ms(str(relays[h]['ipv4_addr_in'])), stale)
                measured_at = time.monotonic()
                for hostname, ms in zip(stale, results):
                    _latency_cache[hostname] = (ms, measured_at)
        return {h: _latency_cache[h][0] for h in wanted}


def city_representatives(relays: Dict[str, Dict[str, Any]]) -> List[str]:
    """One relay per city (the lowest-numbered), for a whole-list sweep."""
    chosen: Dict[Tuple[str, str], str] = {}
    for hostname in sorted(relays):
        info = relays[hostname]
        chosen.setdefault((str(info.get('country', '')), str(info.get('city', ''))), hostname)
    return list(chosen.values())


def latency_targets(query: Dict[str, List[str]], relays: Dict[str, Dict[str, Any]]) -> List[str]:
    targets: List[str] = []
    if query.get('scope', [''])[0] == 'cities':
        targets.extend(city_representatives(relays))
    country = query.get('country', [''])[0]
    if country:
        targets.extend(sorted(h for h, info in relays.items() if info.get('country') == country))
    hosts = [h for h in query.get('hosts', [''])[0].split(',') if h][:MAX_PROBE_HOSTS]
    targets.extend(hosts)
    return targets


def load_relays() -> Dict[str, Dict[str, Any]]:
    data = read_json(RELAYS_PATH)
    if isinstance(data, dict) and isinstance(data.get('relays'), dict):
        return data['relays']
    return {}


# --------------------------------------------------------------------------
# CSRF and Origin checks
# --------------------------------------------------------------------------

def new_csrf_nonce() -> str:
    return secrets.token_urlsafe(24)


def csrf_token(nonce: str) -> str:
    return hmac.new(_CSRF_SECRET, nonce.encode('utf-8'), hashlib.sha256).hexdigest()


def verify_csrf(nonce: Optional[str], token: Optional[str]) -> bool:
    if not nonce or not token:
        return False
    expected = csrf_token(nonce)
    return hmac.compare_digest(expected, token)


def get_cookie(cookie_header: Optional[str], name: str) -> Optional[str]:
    if not cookie_header:
        return None
    jar = http.cookies.SimpleCookie()
    try:
        jar.load(cookie_header)
    except Exception:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel else None


def origin_matches_host(
    origin_header: Optional[str], host_header: Optional[str], forwarded_host: Optional[str] = None
) -> bool:
    """True unless an Origin header is present and disagrees with Host.

    Behind a reverse proxy the upstream Host may be the loopback target, so
    the proxy's X-Forwarded-Host is accepted too. The CSRF token remains the
    primary control."""
    if not origin_header:
        return True
    origin_netloc = urllib.parse.urlsplit(origin_header).netloc
    if not origin_netloc:
        return False
    origin_host = origin_netloc.rsplit(':', 1)[0].lower()
    # Some proxies forward neither the public Host nor X-Forwarded-Host, so the
    # published name can be configured explicitly.
    candidates = [h.strip().lower() for h in os.environ.get('PANEL_PUBLIC_HOSTS', '').split(',') if h.strip()]
    for header in (host_header, forwarded_host):
        if header:
            first = header.split(',', 1)[0].strip()
            candidates.append(first.rsplit(':', 1)[0].lower())
    return origin_host in candidates


def parse_select_form(body: bytes) -> Dict[str, str]:
    text = body.decode('utf-8', errors='replace')
    fields = urllib.parse.parse_qs(text, keep_blank_values=True)
    return {k: v[0] for k, v in fields.items() if v}


def process_select(*, server: Optional[str], allowlist: set, desired_path: Path) -> Tuple[int, str]:
    if not server or server not in allowlist:
        return 400, 'unknown or unlisted server'
    write_json_atomic(desired_path, {'server': server, 'requested_at': now_iso()})
    return 303, 'ok'


# --------------------------------------------------------------------------
# Page rendering
# --------------------------------------------------------------------------

def _static_versions() -> Dict[str, str]:
    versions = {}
    for name in STATIC_FILES:
        try:
            versions[name] = hashlib.sha256((STATIC_DIR / name).read_bytes()).hexdigest()[:10]
        except OSError:
            versions[name] = '0'
    return versions


_STATIC_VERSIONS = _static_versions()


def flag_emoji(location_code: Any) -> str:
    """Regional-indicator flag from a Mullvad location code like 'se-sto'."""
    code = str(location_code or '')[:2].upper()
    if len(code) != 2 or not code.isascii() or not code.isalpha():
        return ''
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code)


def relay_label(hostname: str) -> str:
    """Short chip label: 'se-sto-wg-001' -> 'wg-001'."""
    marker = hostname.rfind('-wg-')
    return hostname[marker + 1:] if marker >= 0 else hostname


def _field(container: Optional[Dict[str, Any]], key: str, default: str = '(unknown)') -> str:
    if not container:
        return default
    value = container.get(key)
    return html.escape(str(value)) if value is not None else default


def status_view(desired: Optional[Dict[str, Any]], result: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """(css state, label) for the current-exit pill. A desired server the
    applier hasn't reached yet reads as switching."""
    desired_server = (desired or {}).get('server')
    status = (result or {}).get('status')
    if desired_server and (result or {}).get('server') != desired_server:
        return 'applying', 'switching'
    if status == 'ok':
        return 'ok', 'connected'
    if status == 'applying':
        return 'applying', 'switching'
    if status == 'failed':
        return 'failed', 'failed'
    return 'unknown', 'unknown'


def render_index_html(
    desired: Optional[Dict[str, Any]],
    result: Optional[Dict[str, Any]],
    relays_data: Optional[Dict[str, Any]],
    fetch_error: Optional[str],
    fetch_error_at: Optional[str],
    csrf_token_value: str,
    *,
    embed: bool = False,
) -> str:
    esc = html.escape

    relays: Dict[str, Dict[str, Any]] = {}
    fetched_at = 'never'
    if isinstance(relays_data, dict):
        fetched_at = esc(str(relays_data.get('fetched_at', 'never')))
        maybe_relays = relays_data.get('relays')
        if isinstance(maybe_relays, dict):
            relays = maybe_relays

    desired_server = str((desired or {}).get('server') or '')
    result_server = str((result or {}).get('server') or '')
    current_info = relays.get(desired_server) or relays.get(result_server) or {}
    state, state_label = status_view(desired, result)

    if current_info:
        current_place = f"{esc(str(current_info.get('city', '')))}, {esc(str(current_info.get('country', '')))}"
        current_flag = flag_emoji(current_info.get('location_code'))
    elif desired_server:
        current_place, current_flag = esc(desired_server), ''
    else:
        current_place, current_flag = 'No server selected', ''

    switching_note = ''
    if state == 'applying' and result_server and result_server != desired_server:
        switching_note = f'<p class="note">Leaving {esc(result_server)}. Open connections through the exit will drop.</p>'
    message = (result or {}).get('message')
    failure_note = ''
    if state == 'failed' and message:
        failure_note = f'<p class="note note-negative">{esc(str(message))}</p>'

    grouped: Dict[str, Dict[str, List[str]]] = {}
    codes: Dict[str, str] = {}
    for hostname, info in relays.items():
        country = str(info.get('country', ''))
        city = str(info.get('city', ''))
        grouped.setdefault(country, {}).setdefault(city, []).append(hostname)
        codes.setdefault(country, str(info.get('location_code', '')))

    token = esc(csrf_token_value)
    country_html = []
    for country in sorted(grouped):
        cities = grouped[country]
        count = sum(len(v) for v in cities.values())
        is_current = any(desired_server in hosts for hosts in cities.values())
        search_terms = ' '.join([country, *cities.keys(), *(h for hosts in cities.values() for h in hosts)]).lower()
        city_html = []
        for city in sorted(cities):
            chips = []
            for hostname in sorted(cities[city]):
                hn = esc(hostname)
                current = ' is-current' if hostname == desired_server else ''
                chips.append(
                    f'<button type="submit" name="server" value="{hn}" class="relay{current}" '
                    f'data-host="{hn}" data-city="{esc(city)}" data-country="{esc(country)}" '
                    f'data-flag="{flag_emoji(relays[hostname].get("location_code"))}" title="{hn}">'
                    f'<span class="relay-name">{esc(relay_label(hostname))}</span>'
                    '<span class="ms" data-ms></span></button>'
                )
            city_html.append(
                f'<div class="city" data-search="{esc(" ".join([country, city, *cities[city]]).lower())}">'
                f'<div class="city-name">{esc(city)}<span class="ms" data-city-ms></span></div>'
                f'<div class="relays">{"".join(chips)}</div></div>'
            )
        cities_label = f'{len(cities)} {"city" if len(cities) == 1 else "cities"}'
        country_html.append(
            f'<details class="country{" is-current" if is_current else ""}" data-country="{esc(country)}" '
            f'data-search="{esc(search_terms)}"{" open" if is_current and not embed else ""}>'
            f'<summary><span class="flag">{flag_emoji(codes[country])}</span>'
            f'<span class="country-name">{esc(country)}</span>'
            f'<span class="subdue country-meta">{cities_label} · {count}</span>'
            f'<span class="ms" data-country-ms></span></summary>'
            f'<div class="cities">{"".join(city_html)}</div></details>'
        )
    locations_html = ''.join(country_html) if country_html else '<p class="subdue">No relays available.</p>'

    error_html = ''
    if fetch_error:
        error_html = (
            f'<p class="note note-negative">Relay refresh error: {esc(fetch_error)} '
            f'(at {esc(fetch_error_at or "unknown")})</p>'
        )

    v = _STATIC_VERSIONS
    return_to = 'embed' if embed else ''
    home_link = ''
    if PANEL_HOME_URL.startswith(('https://', 'http://')):
        home_link = (f'<a class="subdue back-link" href="{esc(PANEL_HOME_URL)}" target="_top">'
                     f'← {esc(PANEL_HOME_LABEL)}</a>')
    heading = '' if embed else (
        f'<header class="page-header"><h1>{esc(PANEL_TITLE)}</h1>{home_link}</header>'
    )
    open_link = (
        '<a class="subdue small" href="/" target="_blank" rel="noopener">Open panel ↗</a>' if embed else ''
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="{THEME_COLOR}">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="{esc(PANEL_SHORT_TITLE)}">
<title>{esc(PANEL_TITLE)}</title>
<!-- An authenticating proxy needs its session cookie, which manifest fetches omit by default. -->
<link rel="manifest" href="/manifest.webmanifest" crossorigin="use-credentials">
<link rel="apple-touch-icon" href="/static/apple-touch-icon.png?v={v['apple-touch-icon.png']}">
<link rel="stylesheet" href="/static/panel.css?v={v['panel.css']}">
<script src="/static/panel.js?v={v['panel.js']}" defer></script>
</head>
<body class="{'embed' if embed else 'full'}">
<main class="page" data-desired="{esc(desired_server)}" data-state="{state}">
{heading}
<section class="widget">
  <div class="widget-header"><h2>Current exit</h2>{open_link}</div>
  <div class="widget-content current">
    <div class="current-row">
      <span class="flag flag-lg" data-current-flag>{current_flag}</span>
      <div class="current-main">
        <div class="current-place" data-current-place>{current_place}</div>
        <div class="subdue small"><span data-current-host>{esc(desired_server or '—')}</span> · <span data-current-ip>{'—' if state == 'applying' else _field(result, 'egress_ip', '—')}</span></div>
      </div>
      <div class="current-side">
        <span class="pill pill-{state}" data-state-pill>{state_label}</span>
        <span class="ms" data-current-ms></span>
      </div>
    </div>
    <div data-notes>{switching_note}{failure_note}</div>
    <details class="diagnostics">
      <summary>Diagnostics</summary>
      <dl>
        <dt>Applier</dt><dd data-f="status">{_field(result, 'status')}</dd>
        <dt>Message</dt><dd data-f="message">{_field(result, 'message', '')}</dd>
        <dt>Egress</dt><dd data-f="egress">{_field(result, 'egress_city')}, {_field(result, 'egress_country')}</dd>
        <dt>Mullvad IP</dt><dd data-f="mullvad_exit_ip">{_field(result, 'mullvad_exit_ip')}</dd>
        <dt>Handshake</dt><dd data-f="handshake_age_s">{_field(result, 'handshake_age_s')}s ago</dd>
        <dt>Fail-closed</dt><dd data-f="unreachable_fallback">{_field(result, 'unreachable_fallback')}</dd>
        <dt>Checked</dt><dd data-f="checked_at">{_field(result, 'checked_at')}</dd>
        <dt>Requested</dt><dd>{_field(desired, 'requested_at', '')}</dd>
        <dt>Relay list</dt><dd>{len(relays)} relays, fetched {fetched_at}</dd>
      </dl>
    </details>
  </div>
</section>

<form method="post" action="/select" id="select-form">
<input type="hidden" name="csrf_token" value="{token}">
<input type="hidden" name="return" value="{return_to}">

<section class="widget" id="fastest" hidden>
  <div class="widget-header"><h2>Fastest from {esc(PANEL_HOST_LABEL)}</h2><button type="button" class="link-button small" data-retest>Retest</button></div>
  <div class="widget-content">
    <ol class="fastest-list" data-fastest><li class="subdue">Measuring…</li></ol>
  </div>
</section>

<section class="widget">
  <div class="widget-header"><h2>Locations</h2><span class="subdue small">{len(grouped)} countries</span></div>
  <div class="widget-content">
    <input type="search" class="search" placeholder="Filter country, city or relay…" aria-label="Filter locations" data-filter autocomplete="off">
    {error_html}
    <div class="countries">{locations_html}</div>
  </div>
</section>
</form>
</main>
</body>
</html>"""


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

class PanelHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'switchyard-panel/0.1'
    protocol_version = 'HTTP/1.1'

    # -- helpers -----------------------------------------------------------

    def _send_security_headers(self) -> None:
        for key, value in security_headers().items():
            self.send_header(key, value)

    def _send_body(self, code: int, content_type: str, body: bytes, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header('Connection', 'close')
        self._send_security_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def _send_plain(self, code: int, message: str) -> None:
        self._send_body(code, 'text/plain; charset=utf-8', message.encode('utf-8'))

    def _send_json(self, obj: Any) -> None:
        self._send_body(200, 'application/json', json.dumps(obj).encode('utf-8'),
                        {'Cache-Control': 'no-store'})

    # -- routes --------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == '/healthz':
            self._send_plain(200, 'ok')
        elif parsed.path == '/':
            self._handle_index(embed=False)
        elif parsed.path == '/embed':
            self._handle_index(embed=True)
        elif parsed.path == '/manifest.webmanifest':
            self._send_body(200, 'application/manifest+json', json.dumps(WEB_MANIFEST).encode('utf-8'),
                            {'Cache-Control': 'public, max-age=86400'})
        elif parsed.path == '/api/status':
            self._send_json({'desired': read_json(DESIRED_PATH), 'result': read_json(APPLIER_RESULT_PATH)})
        elif parsed.path == '/api/latency':
            query = urllib.parse.parse_qs(parsed.query)
            relays = load_relays()
            fresh = query.get('fresh', [''])[0] == '1'
            self._send_json({'latency': measure_latency(relays, latency_targets(query, relays), fresh)})
        elif parsed.path.startswith('/static/'):
            self._handle_static(parsed.path[len('/static/'):])
        else:
            self._send_plain(404, 'not found')

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != '/select':
            self._send_plain(404, 'not found')
            return

        length_header = self.headers.get('Content-Length')
        if length_header is None:
            self._send_plain(411, 'length required')
            return
        try:
            length = int(length_header)
        except ValueError:
            self._send_plain(400, 'bad content-length')
            return
        if length < 0:
            self._send_plain(400, 'bad content-length')
            return
        if length > MAX_BODY_BYTES:
            self._send_plain(413, 'request body too large')
            return

        body = self.rfile.read(length)

        if not origin_matches_host(
            self.headers.get('Origin'), self.headers.get('Host'), self.headers.get('X-Forwarded-Host')
        ):
            origin = urllib.parse.urlsplit(self.headers.get('Origin') or '').netloc or '(none)'
            sys.stderr.write(f'rejected POST origin={origin[:80]}\n')
            self._send_plain(403, 'origin does not match host')
            return

        fields = parse_select_form(body)
        cookie_nonce = get_cookie(self.headers.get('Cookie'), CSRF_COOKIE_NAME)
        if not verify_csrf(cookie_nonce, fields.get('csrf_token')):
            self._send_plain(403, 'invalid or missing csrf token')
            return

        status, message = process_select(
            server=fields.get('server'),
            allowlist=load_allowlist(),
            desired_path=DESIRED_PATH,
        )
        if status == 303:
            location = '/embed' if fields.get('return') == 'embed' else '/'
            self._send_body(303, 'text/plain; charset=utf-8', b'', {'Location': location})
            return
        self._send_plain(status, message)

    def _handle_index(self, *, embed: bool) -> None:
        nonce = new_csrf_nonce()
        token = csrf_token(nonce)
        fetch_error, fetch_error_at = get_fetch_error()
        body = render_index_html(
            read_json(DESIRED_PATH), read_json(APPLIER_RESULT_PATH), read_json(RELAYS_PATH),
            fetch_error, fetch_error_at, token, embed=embed,
        ).encode('utf-8')
        self._send_body(200, 'text/html; charset=utf-8', body, {
            'Set-Cookie': f'{CSRF_COOKIE_NAME}={nonce}; Path=/; HttpOnly; SameSite=Strict',
            'Cache-Control': 'no-store',
        })

    def _handle_static(self, name: str) -> None:
        content_type = STATIC_FILES.get(name)
        if content_type is None:
            self._send_plain(404, 'not found')
            return
        try:
            body = (STATIC_DIR / name).read_bytes()
        except OSError:
            self._send_plain(404, 'not found')
            return
        self._send_body(200, content_type, body, {'Cache-Control': 'public, max-age=86400'})

    # -- logging: no query strings or bodies ----------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        path = self.path.split('?', 1)[0]
        sys.stderr.write(
            f'{self.log_date_time_string()} {self.address_string()} {self.command} {path}\n'
        )


def main() -> None:
    stop_event = threading.Event()
    refresher = threading.Thread(target=relay_refresh_loop, args=(stop_event,), daemon=True)
    refresher.start()

    server = http.server.ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), PanelHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        # serve_forever has returned; shutdown() here would deadlock.
        stop_event.set()
        server.server_close()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Molebridge control panel.

Web UI for choosing which Mullvad WireGuard server the exit uses. It has no
login of its own: publish it only behind something that authenticates people,
such as an identity-aware reverse proxy or an overlay access policy. It:

- reads the applier-owned relay catalogue through a read-only mount;
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

import hashlib
import hmac
import html
import http.client
import http.cookies
import http.server
import json
import os
import re
import secrets
import signal
import sys
import socket
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from molebridge.state import (CATALOG_MAX_AGE, HOSTNAME_RE, now_iso, read_json,
                              recent, status_view, write_json_atomic)
from molebridge.relays import snapshot_relays

# --------------------------------------------------------------------------
# Configuration and file contract
# --------------------------------------------------------------------------

STATE_DIR = Path(os.environ.get('STATE_DIR', '/state'))
PANEL_DIR = STATE_DIR / 'panel'
RELAYS_PATH = STATE_DIR / 'applier' / 'relays.json'
RELAY_ERROR_PATH = STATE_DIR / 'applier' / 'relay-error.json'
DESIRED_PATH = PANEL_DIR / 'desired.json'
APPLIER_RESULT_PATH = STATE_DIR / 'applier' / 'result.json'

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
PANEL_TITLE = os.environ.get('PANEL_TITLE', 'Molebridge')
PANEL_SHORT_TITLE = os.environ.get('PANEL_SHORT_TITLE', 'Molebridge')
PANEL_HOST_LABEL = os.environ.get('PANEL_HOST_LABEL', 'this exit')
PANEL_HOME_URL = os.environ.get('PANEL_HOME_URL', '')
PANEL_HOME_LABEL = os.environ.get('PANEL_HOME_LABEL', 'Home')


def theme_setting(value: str) -> str:
    """auto follows the viewer's system setting; anything unrecognised is auto."""
    return value if value in ('auto', 'dark', 'light') else 'auto'


PANEL_THEME = theme_setting(os.environ.get('PANEL_THEME', 'auto'))

THEME_COLOR = '#232638'
THEME_COLOR_LIGHT = '#eff1f5'
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
# hostname -> (round-trip ms or None when unreachable, time.monotonic() measured)
_latency_cache: Dict[str, Tuple[Optional[float], float]] = {}
_probe_lock = threading.Lock()


def load_allowlist() -> set:
    snapshot = read_json(RELAYS_PATH)
    if not isinstance(snapshot, dict) or not recent(snapshot.get('fetched_at'), CATALOG_MAX_AGE):
        return set()
    return set(snapshot_relays(snapshot))


def get_fetch_error():
    data = read_json(RELAY_ERROR_PATH, 4096)
    snapshot = read_json(RELAYS_PATH)
    if not isinstance(snapshot, dict) or not recent(snapshot.get('fetched_at'), CATALOG_MAX_AGE):
        return 'No fresh trusted relay catalogue; selections are unavailable.', None
    return (data.get('message'), data.get('checked_at')) if isinstance(data, dict) else (None, None)


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
    return snapshot_relays(read_json(RELAYS_PATH))


# --------------------------------------------------------------------------
# CSRF and Origin checks
# --------------------------------------------------------------------------

def new_csrf_nonce() -> str:
    return secrets.token_urlsafe(24)


def csrf_token(nonce: str) -> str:
    return hmac.new(_CSRF_SECRET, nonce.encode('utf-8'), hashlib.sha256).hexdigest()


def verify_csrf(nonce: Optional[str], token: Optional[str]) -> bool:
    if not isinstance(nonce, str) or not isinstance(token, str) or not re.fullmatch(r'[0-9a-f]{64}', token):
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


LOOPBACK_HOSTS = {'localhost', '127.0.0.1', '::1'}


def _split_host(value: str) -> Optional[Tuple[str, Optional[int]]]:
    """(hostname, port or None) from a Host-style value; None when malformed."""
    try:
        parsed = urllib.parse.urlsplit('//' + value.strip())
        if not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            return None
        return parsed.hostname.lower(), parsed.port
    except ValueError:
        return None


def allowed_hosts() -> List[Tuple[str, Optional[int]]]:
    """Names the panel may be asked for: PANEL_PUBLIC_HOSTS plus loopback.

    A proxy that rewrites the upstream Host (for example to
    host.docker.internal:8095) needs that name listed too."""
    hosts = []
    for entry in os.environ.get('PANEL_PUBLIC_HOSTS', '').split(','):
        if entry.strip():
            parsed = _split_host(entry)
            if parsed:
                hosts.append(parsed)
    return hosts


def _host_allowed(hostname: str, port: Optional[int], default_port: Optional[int] = None) -> bool:
    if hostname in LOOPBACK_HOSTS:
        return True  # any port: SSH forwards and local proxies vary
    for allowed_name, allowed_port in allowed_hosts():
        if hostname != allowed_name:
            continue
        if allowed_port is None:
            if port is None or port == default_port or port in (80, 443):
                return True
        elif port == allowed_port:
            return True
    return False


def host_allowed(host_header: Optional[str]) -> bool:
    """Reject requests for names the panel is not published under. This keeps
    a DNS-rebinding page from reading status or a token-bearing page."""
    if not host_header:
        return False
    parsed = _split_host(host_header.split(',', 1)[0])
    return bool(parsed) and _host_allowed(parsed[0], parsed[1])


def origin_allowed(origin_header: Optional[str]) -> bool:
    """True unless an Origin header is present and names a host the panel is
    not published under. Browsers always send Origin on form and fetch POSTs;
    the request's own Host header is deliberately not trusted here, because a
    rebinding page controls it. The CSRF token remains the primary control."""
    if not origin_header:
        return True
    try:
        origin = urllib.parse.urlsplit(origin_header)
        if origin.scheme not in ('http', 'https') or not origin.hostname or origin.username or origin.password:
            return False
        if origin.path or origin.query or origin.fragment:
            return False
        default_port = 443 if origin.scheme == 'https' else 80
        return _host_allowed(origin.hostname.lower(), origin.port or default_port, default_port)
    except ValueError:
        return False


def parse_select_form(body: bytes) -> Dict[str, str]:
    text = body.decode('utf-8', errors='replace')
    fields = urllib.parse.parse_qs(text, keep_blank_values=True)
    return {k: v[0] for k, v in fields.items() if v}


def process_select(*, server: Optional[str], allowlist: set, desired_path: Path) -> Tuple[int, str]:
    if not isinstance(server, str) or not HOSTNAME_RE.fullmatch(server) or server not in allowlist:
        return 400, 'unknown or unlisted server'
    write_json_atomic(desired_path, {'server': server, 'requested_at': now_iso(), 'request_id': secrets.token_hex(16)})
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


# Catalogue attribute -> filter label. Shown only when some relay carries it.
ATTRIBUTE_FILTERS = {'owned': 'Mullvad-owned', 'stboot': 'RAM-only'}


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


def relay_attributes(info: Dict[str, Any]) -> str:
    """data-owned/data-stboot for the filters, only when the catalogue knows."""
    return ''.join(f' data-{key}="{"1" if info[key] else "0"}"'
                   for key in ATTRIBUTE_FILTERS if isinstance(info.get(key), bool))


def relay_title(hostname: str, info: Dict[str, Any]) -> str:
    details = relay_details(info)
    return f'{hostname} · {details}' if details else hostname


def relay_details(info: Dict[str, Any]) -> str:
    """Hosting summary such as 'Example Hosting · rented · RAM-only'."""
    parts = []
    if isinstance(info.get('provider'), str):
        parts.append(str(info['provider']))
    if isinstance(info.get('owned'), bool):
        parts.append('Mullvad-owned' if info['owned'] else 'rented')
    if info.get('stboot') is True:
        parts.append('RAM-only')
    return ' · '.join(parts)


def _field(container: Optional[Dict[str, Any]], key: str, default: str = '(unknown)') -> str:
    if not container:
        return default
    value = container.get(key)
    return html.escape(str(value)) if value is not None else default


def status_payload():
    desired = read_json(DESIRED_PATH, 4096)
    result = read_json(APPLIER_RESULT_PATH, 16384)
    desired = desired if isinstance(desired, dict) else None
    result = result if isinstance(result, dict) else None
    state, label = status_view(desired, result)
    return {'desired': desired, 'result': result, 'view': {'state': state, 'label': label}}


def theme_color_meta() -> str:
    if PANEL_THEME == 'auto':
        return (f'<meta name="theme-color" content="{THEME_COLOR}" media="(prefers-color-scheme: dark)">\n'
                f'<meta name="theme-color" content="{THEME_COLOR_LIGHT}" media="(prefers-color-scheme: light)">')
    return f'<meta name="theme-color" content="{THEME_COLOR_LIGHT if PANEL_THEME == "light" else THEME_COLOR}">'


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
    desired = desired if isinstance(desired, dict) else {}
    result = result if isinstance(result, dict) else {}

    relays: Dict[str, Dict[str, Any]] = {}
    fetched_at = 'never'
    if isinstance(relays_data, dict):
        fetched_at = esc(str(relays_data.get('fetched_at', 'never')))
        maybe_relays = relays_data.get('relays')
        if isinstance(maybe_relays, dict):
            relays = maybe_relays

    desired_server = str((desired or {}).get('server') or '')
    result_server = str((result or {}).get('server') or '')
    state, state_label = status_view(desired, result)
    display_server = desired_server if state == 'applying' else result_server
    current_info = relays.get(display_server) or {}

    if current_info:
        current_place = f"{esc(str(current_info.get('city', '')))}, {esc(str(current_info.get('country', '')))}"
        current_flag = flag_emoji(current_info.get('location_code'))
    elif display_server:
        current_place, current_flag = esc(display_server), ''
    else:
        current_place, current_flag = 'Awaiting verified server', ''

    switching_note = ''
    if state == 'applying' and result_server and result_server != desired_server:
        switching_note = f'<p class="note">Leaving {esc(result_server)}. Open connections through the exit will drop.</p>'
    message = (result or {}).get('message')
    failure_note = ''
    retry = ''
    if state == 'failed' and desired_server in relays:
        # Outside the form element but submitted with it, so it works without JS.
        retry = (f' <button type="submit" form="select-form" name="server" value="{esc(desired_server)}" '
                 f'class="relay-switch" data-retry>Retry</button>')
    if state == 'failed' and (message or retry):
        failure_note = f'<p class="note note-negative">{esc(str(message or "Switch failed."))}{retry}</p>'

    if state == 'unknown':
        failure_note = '<p class="note note-negative">Status is unavailable or stale. Details are from the last check.</p>'

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
                info = relays[hostname]
                chips.append(
                    f'<button type="submit" name="server" value="{hn}" class="relay{current}" '
                    f'data-host="{hn}" data-city="{esc(city)}" data-country="{esc(country)}" '
                    f'data-flag="{flag_emoji(info.get("location_code"))}"{relay_attributes(info)} '
                    f'title="{esc(relay_title(hostname, info))}">'
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

    filter_buttons = ''.join(
        f'<button type="button" class="filter-chip" data-attr-filter="{key}" aria-pressed="false">{label}</button>'
        for key, label in ATTRIBUTE_FILTERS.items()
        # Only where it would narrow the list: some relays have it, some do not.
        if any(info.get(key) is True for info in relays.values())
        and any(info.get(key) is not True for info in relays.values())
    )
    filters_toggle = filters_row = ''
    if filter_buttons:
        filters_toggle = ('<button type="button" class="link-button small" data-filters-toggle '
                          'aria-expanded="false" aria-controls="relay-filters" hidden>Filters</button>')
        filters_row = f'<div class="filter-row" id="relay-filters" hidden>{filter_buttons}</div>'
    current_details = relay_details(current_info) if current_info else ''

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
<html lang="en" data-theme="{PANEL_THEME}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="{'dark light' if PANEL_THEME == 'auto' else PANEL_THEME}">
{theme_color_meta()}
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="{esc(PANEL_SHORT_TITLE)}">
<title>{esc(PANEL_TITLE)}</title>
<!-- An authenticating proxy needs its session cookie, which manifest fetches omit by default. -->
<link rel="manifest" href="/manifest.webmanifest" crossorigin="use-credentials">
<link rel="icon" href="/static/icon-192.png?v={v['icon-192.png']}" type="image/png">
<link rel="apple-touch-icon" href="/static/apple-touch-icon.png?v={v['apple-touch-icon.png']}">
<link rel="stylesheet" href="/static/panel.css?v={v['panel.css']}">
<script src="/static/panel.js?v={v['panel.js']}" defer></script>
</head>
<body class="{'embed' if embed else 'full'}">
<main class="page" data-desired="{esc(desired_server)}" data-request="{esc(str(desired.get('request_id', '')))}" data-requested="{esc(str(desired.get('requested_at', '')))}" data-actual="{esc(result_server)}" data-state="{state}">
{heading}
<section class="widget">
  <div class="widget-header"><h2>Current exit</h2>{open_link}</div>
  <div class="widget-content current">
    <div class="current-row">
      <span class="flag flag-lg" data-current-flag>{current_flag}</span>
      <div class="current-main">
        <div class="current-place" data-current-place>{current_place}</div>
        <div class="subdue small"><span data-current-host>{esc(display_server or '—')}</span> <span class="nowrap">· <span data-current-ip>{'—' if state in ('applying', 'unknown') else _field(result, 'egress_ip', '—')}</span></span></div>
      </div>
      <button type="button" class="link-button pin" data-pin aria-pressed="false" aria-label="Pin this server" title="Pin this server" hidden>☆</button>
      <div class="current-side">
        <span class="pill pill-{state}" data-state-pill role="status" aria-live="polite">{state_label}</span>
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
        <dt>Handshake</dt><dd data-f="handshake_age_s">{_field(result, 'handshake_age_s')}s at last check</dd>
        <dt>Fallback routes</dt><dd data-f="unreachable_fallback">{_field(result, 'unreachable_fallback')}</dd>
        <dt>Routing protection</dt><dd data-f="routing_ok">{_field(result, 'routing_ok')}</dd>
        <dt>Server</dt><dd>{esc(current_details) or '(unknown)'}</dd>
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

<section class="widget" id="saved" hidden>
  <div class="widget-header"><h2>Saved</h2></div>
  <div class="widget-content">
    <ol class="fastest-list" data-saved></ol>
  </div>
</section>

<section class="widget" id="fastest" hidden>
  <div class="widget-header"><h2>Fastest from {esc(PANEL_HOST_LABEL)}</h2><button type="button" class="link-button small" data-retest>Retest</button></div>
  <div class="widget-content">
    <ol class="fastest-list" data-fastest><li class="subdue">Measuring…</li></ol>
  </div>
</section>

<section class="widget">
  <div class="widget-header"><h2>Locations</h2>{filters_toggle}<span class="subdue small">{len(grouped)} countries</span></div>
  <div class="widget-content">
    <input type="search" class="search" placeholder="Filter country, city or relay…" aria-label="Filter locations" data-filter autocomplete="off">
    {filters_row}
    {error_html}
    <div class="countries">{locations_html}</div>
  </div>
</section>
</form>
<div class="sr-only" aria-live="polite" data-announce></div>
</main>
</body>
</html>"""


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

class PanelHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'molebridge-panel/0.1'
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

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

    def _misdirected(self) -> bool:
        if host_allowed(self.headers.get('Host')):
            return False
        sys.stderr.write('rejected request: host is not in PANEL_PUBLIC_HOSTS or loopback\n')
        self._send_plain(421, 'unknown host; publish the panel under PANEL_PUBLIC_HOSTS')
        return True

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == '/healthz':
            self._send_plain(200, 'ok')
        elif self._misdirected():
            return
        elif parsed.path == '/readyz':
            ready = status_payload()['view']['state'] == 'ok'
            self._send_plain(200 if ready else 503, 'ready' if ready else 'not ready')
        elif parsed.path == '/':
            self._handle_index(embed=False)
        elif parsed.path == '/embed':
            self._handle_index(embed=True)
        elif parsed.path == '/manifest.webmanifest':
            self._send_body(200, 'application/manifest+json', json.dumps(WEB_MANIFEST).encode('utf-8'),
                            {'Cache-Control': 'public, max-age=86400'})
        elif parsed.path == '/api/status':
            self._send_json(status_payload())
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
        if self._misdirected():
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

        try:
            body = self.rfile.read(length)
        except (TimeoutError, ConnectionError):
            self._send_plain(408, 'request timeout')
            return
        if len(body) != length:
            self._send_plain(400, 'incomplete body')
            return

        if not origin_allowed(self.headers.get('Origin')):
            sys.stderr.write('rejected POST: origin is not a published panel host\n')
            self._send_plain(403, 'origin is not a published panel host')
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
        nonce = get_cookie(self.headers.get('Cookie'), CSRF_COOKIE_NAME)
        if not nonce or not re.fullmatch(r'[A-Za-z0-9_-]{32}', nonce):
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

    # -- logging: fixed routes only, no addresses or user-controlled text --

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        path = self.path.split('?', 1)[0]
        known = {'/', '/embed', '/healthz', '/readyz', '/api/status', '/api/latency',
                 '/select', '/manifest.webmanifest'}
        known.update('/static/' + name for name in STATIC_FILES)
        route = path if path in known else '(unknown route)'
        method = self.command if self.command in ('GET', 'POST', 'HEAD') else '(other method)'
        sys.stderr.write(
            f'{self.log_date_time_string()} {method} {route}\n'
        )


def _stop_on_sigterm(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt


def main() -> None:
    # As a container's PID 1 the panel ignores SIGTERM unless it handles it,
    # so every stop would wait out the engine's timeout and end in SIGKILL.
    signal.signal(signal.SIGTERM, _stop_on_sigterm)
    server = http.server.ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), PanelHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        # serve_forever has returned; shutdown() here would deadlock.
        server.server_close()


if __name__ == '__main__':
    main()

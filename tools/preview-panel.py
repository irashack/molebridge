#!/usr/bin/env python3
"""Run the panel locally against made-up exits, for working on its look.

    python3 tools/preview-panel.py [--port 8099] [--live] [--exits mullvad,pia]

Serves a Switchyard with a Mullvad exit and a PIA exit on 127.0.0.1. Their
state is fabricated in a temporary directory: nothing is switched, and a
selection only rewrites the fake exit's desired.json, which the preview then
"applies" a few seconds later so the switching states can be seen. --exits
picks the exits from mullvad, pia, nordvpn, and two on the gluetun backend:
mullvad-gluetun and surfshark (which has only the tunnel checks). --live fills the
native catalogues from the providers' public server lists instead of the
small built-in sample; gluetun's is always the sample. --fail <id> makes that
exit's switches fail, to see the failed state.
"""
from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from molebridge import providers  # noqa: E402
from molebridge.state import now_iso, read_json, write_json_atomic  # noqa: E402

KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
SAMPLE_MULLVAD = [
    ('se', 'sto', 'Sweden', 'Stockholm', 3), ('se', 'got', 'Sweden', 'Gothenburg', 2),
    ('us', 'chi', 'USA', 'Chicago', 4), ('us', 'nyc', 'USA', 'New York, NY', 3),
    ('ch', 'zrh', 'Switzerland', 'Zurich', 2), ('jp', 'tyo', 'Japan', 'Tokyo', 2),
    ('de', 'fra', 'Germany', 'Frankfurt', 3), ('ca', 'tor', 'Canada', 'Toronto', 2),
]
SAMPLE_PIA = [
    ('us_chicago', 'US', 'United States', 'Chicago', False), ('us_east', 'US', 'United States', 'East', False),
    ('ca_toronto', 'CA', 'Canada', 'Toronto', True), ('swiss', 'CH', 'Switzerland', 'Switzerland', True),
    ('japan', 'JP', 'Japan', 'Tokyo', True), ('de-frankfurt', 'DE', 'Germany', 'Frankfurt', True),
    ('uk', 'GB', 'United Kingdom', 'London', True), ('morocco', 'MA', 'Morocco', 'Morocco', True),
]
SAMPLE_NORDVPN = [
    ('us', 'US', 'United States', 'Chicago', 'us-chi', 4), ('us', 'US', 'United States', 'New York', 'us-ny', 3),
    ('ca', 'CA', 'Canada', 'Toronto', 'ca-tor', 2), ('de', 'DE', 'Germany', 'Frankfurt', 'de-fra', 3),
    ('nl', 'NL', 'Netherlands', 'Amsterdam', 'nl-ams', 3), ('jp', 'JP', 'Japan', 'Tokyo', 'jp-tyo', 2),
    ('ar', 'AR', 'Argentina', 'Buenos Aires', 'ar-bue', 1),
]
SAMPLE_SURFSHARK = [
    ('us-chi', 'United States', 'Chicago'), ('us-nyc', 'United States', 'New York'),
    ('ca-tor', 'Canada', 'Toronto'), ('de-fra', 'Germany', 'Frankfurt'),
    ('nl-ams', 'Netherlands', 'Amsterdam'), ('jp-tok', 'Japan', 'Tokyo'),
]
# Exit id -> (provider, the server it starts on).
EXITS = {'mullvad': ('mullvad', 'us-chi-wg-001'), 'pia': ('pia', 'us_chicago'),
         'nordvpn': ('nordvpn', 'us9001.nordvpn.com'), 'mullvad-gluetun': ('gluetun-mullvad', 'se-sto-wg-001'),
         'surfshark': ('gluetun-surfshark', 'us-chi.prod.surfshark.com')}


def sample(provider):
    relays = {}
    if provider == 'mullvad':
        n = 10
        for cc, city_code, country, city, count in SAMPLE_MULLVAD:
            for i in range(1, count + 1):
                host = f'{cc}-{city_code}-wg-{i:03d}'
                n += 1
                relays[host] = {'hostname': host, 'country': country, 'city': city,
                                'location_code': f'{cc}-{city_code}', 'public_key': KEY,
                                'ipv4_addr_in': f'127.0.0.{n}', 'owned': i % 2 == 1, 'stboot': True,
                                'provider': 'Example Hosting'}
    elif provider == 'nordvpn':
        n, number = 140, 9000
        for cc, code, country, city, location, count in SAMPLE_NORDVPN:
            for i in range(count):
                n, number = n + 1, number + 1
                host = f'{cc}{number}.nordvpn.com'
                relays[host] = {'hostname': host, 'public_key': KEY, 'ipv4_addr_in': f'127.0.0.{n}',
                                'city': city, 'country': country, 'country_code': code,
                                'location_code': location, 'load': (number * 7) % 60 + 4,
                                'virtual': cc == 'ar'}
    elif provider.startswith('gluetun-'):
        names = ([(f'{name}.prod.surfshark.com', country, city) for name, country, city in SAMPLE_SURFSHARK]
                 if provider == 'gluetun-surfshark' else
                 [(f'{cc}-{code}-wg-{i:03d}', country, city) for cc, code, country, city, count in SAMPLE_MULLVAD
                  for i in range(1, count + 1)])
        for n, (host, country, city) in enumerate(names, start=200):
            relays[host] = {'id': host, 'hostname': host, 'public_key': KEY, 'ipv4_addr_in': f'127.0.0.{n}',
                            'ipv6_addrs': [], 'city': city, 'country': country, 'selection_filter': 'hostnames'}
    else:
        for n, (rid, cc, country, city, pf) in enumerate(SAMPLE_PIA, start=100):
            relays[rid] = {'hostname': rid, 'country': country, 'city': city,
                           'location_code': f'{cc.lower()}-{rid}', 'ipv4_addr_in': f'127.0.0.{n}',
                           'port_forward': pf, 'geo': rid == 'morocco',
                           'servers': [{'ip': f'127.0.0.{n}', 'cn': f'{rid.replace("_", "")}401'}]}
    return relays


def live(provider):
    spec = providers.get(provider)
    with urllib.request.urlopen(spec.catalog_url, timeout=spec.catalog_timeout_s) as response:
        return spec.parse_catalog(response.read(spec.catalog_max_bytes + 1).decode())


def seed(state, exit_id, provider, relays, current):
    applier = state / exit_id / 'applier'
    snapshot = {'fetched_at': now_iso(), 'provider': provider, 'relays': relays}
    if providers.get(provider).backend == 'gluetun':
        snapshot.update(source='gluetun', data_timestamp=now_iso())
    write_json_atomic(applier / 'relays.json', snapshot, public=True)
    write_json_atomic(state / exit_id / 'panel' / 'desired.json',
                      {'server': current, 'requested_at': now_iso(), 'request_id': secrets.token_hex(16)})
    apply(state, exit_id, provider, relays)


def apply(state, exit_id, provider, relays, fail=False):
    """What an applier would record after a verified (or failed) switch."""
    desired = read_json(state / exit_id / 'panel' / 'desired.json') or {}
    previous = read_json(state / exit_id / 'applier' / 'result.json') or {}
    info = relays.get(desired.get('server'), {})
    result = {
        'server': desired.get('server'), 'request_id': desired.get('request_id'), 'status': 'ok',
        'checked_at': now_iso(), 'routing_ok': True, 'exit_confirmed': True, 'provider': provider,
        'egress_ip': '203.0.113.7', 'egress_city': info.get('city'), 'egress_country': info.get('country'),
        'handshake_age_s': 12, 'unreachable_fallback': True, 'message': 'Tunnel verified.',
        'egress_tier': providers.get(provider).egress_tier}
    if result['egress_tier'] == 'tunnel':
        result['exit_confirmed'] = False
    if fail:
        result.update(server=previous.get('server'), status='failed', exit_confirmed=False, egress_ip=None,
                      egress_tier=None,
                      message='No handshake with the new server; the exit stays closed.')
    write_json_atomic(state / exit_id / 'applier' / 'result.json', result, public=True)


def fake_appliers(state, exits, failing=''):
    # The seeded requests are already applied.
    seen = {exit_id: ((read_json(state / exit_id / 'panel' / 'desired.json') or {}).get('request_id'), float('inf'))
            for exit_id in exits}
    while True:
        for exit_id, (provider, relays) in exits.items():
            desired = read_json(state / exit_id / 'panel' / 'desired.json') or {}
            request = desired.get('request_id')
            if request != seen.get(exit_id, (None,))[0]:
                seen[exit_id] = (request, time.monotonic())
            elif time.monotonic() - seen[exit_id][1] > 4:
                apply(state, exit_id, provider, relays, fail=exit_id == failing)
                seen[exit_id] = (request, float('inf'))
        # Keep results fresh, as the real applier's periodic checks do.
        for exit_id, (provider, relays) in exits.items():
            result = read_json(state / exit_id / 'applier' / 'result.json') or {}
            desired = read_json(state / exit_id / 'panel' / 'desired.json') or {}
            if result.get('request_id') == desired.get('request_id'):
                result['checked_at'] = now_iso()
                write_json_atomic(state / exit_id / 'applier' / 'result.json', result, public=True)
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--port', type=int, default=8099)
    parser.add_argument('--live', action='store_true', help="use the providers' public server lists")
    parser.add_argument('--theme', default='auto')
    parser.add_argument('--style', default='provider')
    parser.add_argument('--fail', default='', metavar='ID', help="make this exit's switches fail")
    parser.add_argument('--exits', default='mullvad,pia', help='comma-separated, from ' + ', '.join(EXITS))
    args = parser.parse_args()
    chosen = [name.strip() for name in args.exits.split(',') if name.strip()]
    if not chosen or any(name not in EXITS for name in chosen):
        parser.error('--exits takes ' + ', '.join(EXITS))
    with tempfile.TemporaryDirectory(prefix='switchyard-preview-') as tmp:
        state = Path(tmp)
        exits = {}
        for exit_id in chosen:
            provider, current = EXITS[exit_id]
            native = providers.get(provider).backend == 'native'
            relays = live(provider) if args.live and native else sample(provider)
            if current not in relays:
                current = sorted(relays)[0]
            seed(state, exit_id, provider, relays, current)
            exits[exit_id] = (provider, relays)
        threading.Thread(target=fake_appliers, args=(state, exits, args.fail), daemon=True).start()
        env = dict(os.environ, STATE_DIR=str(state), PANEL_EXITS=','.join(f'{e}={EXITS[e][0]}' for e in chosen),
                   PANEL_THEME=args.theme, PANEL_STYLE=args.style, PANEL_HOST_LABEL='home')
        # The sample relays' addresses answer nothing, so their latency is made
        # up: steady per address, a spread from fast to slow, one timeout.
        fake = '' if args.live else (
            'import zlib, random; '
            'app.probe_tcp_rtt_ms = lambda ip, *a, **k: None if ip.endswith(".13") else '
            'round(8 + zlib.crc32(ip.encode()) % 220 + random.random() * 4, 1); ')
        script = (f'import sys; sys.path.insert(0, {str(ROOT / "panel")!r}); import app; {fake}'
                  f'app.LISTEN_HOST, app.LISTEN_PORT = "127.0.0.1", {args.port}; app.main()')
        print(f'Switchyard preview on http://127.0.0.1:{args.port}/ (Ctrl-C stops it)', flush=True)
        try:
            subprocess.run([sys.executable, '-c', script], env=env, check=False)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()

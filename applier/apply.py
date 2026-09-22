"""Own the relay catalogue, validate requests, switch peers and report health.

This is a trusted NET_ADMIN component. The config file is not mounted, but
namespace privileges can retrieve the live WireGuard key. Never use wg dump.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import signal
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

from molebridge.relays import MULLVAD_RELAYS_URL, REFRESH_INTERVAL_S, RelayCatalog, valid_key
from molebridge.routing import RETURN_PATH_SYSCTL, RoutingConfig, family_status, return_path_enabled
from molebridge.state import (MAX_CATALOG_BYTES, decode_json, desired_request, now_iso, read_json,
                              recent, request_token, write_json_atomic)

HANDSHAKE_FRESH_SEC = 180
SWITCH_TIMEOUT_SEC = 60
REFRESH_SEC = 60
POLL_SEC = 5


def command(args, *, timeout=5, limit=1024 * 1024):
    """Bound subprocess lifetimes; errors never include arguments or output."""
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=output,
                                  stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError('command unavailable or timed out') from exc
        if proc.returncode:
            raise RuntimeError('command failed')
        output.seek(0)
        raw = output.read(limit + 1)
    if len(raw) > limit:
        raise RuntimeError('command output exceeds limit')
    return raw.decode('utf-8', errors='strict')


class Applier:
    def __init__(self, state_dir: Path, config: RoutingConfig, *, run=command, clock=time.monotonic, sleep=time.sleep):
        self.directory = state_dir / 'applier'
        self.result_path = self.directory / 'result.json'
        self.desired_path = state_dir / 'panel' / 'desired.json'
        self.catalog = RelayCatalog(self.directory)
        self.config, self.run, self.clock, self.sleep = config, run, clock, sleep
        self.last_request = None
        self.request = None
        self.next_catalog = 0
        self.next_health = 0
        self.rejection = None
        self.pending = None

    def fetch_catalog(self):
        response = self.run(['curl', '--noproxy', '*', '--proto', '=https', '-fsS',
                             '--connect-timeout', '10', '--max-time', '20',
                             '--max-filesize', str(MAX_CATALOG_BYTES),
                             '--user-agent', 'molebridge-applier/0.2',
                             '--write-out', '\n%{http_code}', MULLVAD_RELAYS_URL],
                            timeout=22, limit=MAX_CATALOG_BYTES + 4)
        body, code = response.rsplit('\n', 1)
        if code != '200':
            raise ValueError('unexpected catalogue HTTP status; redirects refused')
        return body

    def tunnel_addresses(self):
        """Global tunnel addresses by family, read from the interface, never its routes.

        Exactly one address per family is supported: the return-path rule and
        the kernel's ICMP source selection both assume a single address."""
        links = decode_json(self.run(['ip', '-j', 'address', 'show', 'dev', self.config.exit_if]))
        if not isinstance(links, list) or len(links) != 1 or not isinstance(links[0], dict):
            raise ValueError('missing tunnel interface')
        addresses = links[0].get('addr_info')
        if not isinstance(addresses, list) or any(not isinstance(a, dict) for a in addresses):
            raise ValueError('invalid tunnel addresses')
        found = {}
        for entry in addresses:
            if entry.get('scope') != 'global' or entry.get('family') not in ('inet', 'inet6'):
                continue
            if not isinstance(entry.get('local'), str):
                raise ValueError('invalid tunnel address')
            address = ipaddress.ip_address(entry['local'])
            if address.version in found:
                raise ValueError('multiple tunnel addresses for one family')
            found[address.version] = str(address)
        if 4 not in found:
            raise ValueError('missing IPv4 tunnel address')
        return found

    def routing_status(self):
        checks = []
        try:
            self.run(['ip', 'link', 'show', 'dev', self.config.overlay_if])
            addresses = self.tunnel_addresses()
            return_path = return_path_enabled(self.run(['cat', RETURN_PATH_SYSCTL]))
            for family in (4, 6):
                rules = decode_json(self.run(['ip', '-j', f'-{family}', 'rule', 'show']))
                routes = decode_json(self.run(['ip', '-j', f'-{family}', 'route', 'show', 'table', self.config.table]))
                checks.append(family_status(rules, routes, self.config, family,
                                            tunnel_address=addresses.get(family)))
            return return_path and all(c[0] for c in checks), all(c[1] for c in checks)
        except (RuntimeError, ValueError, UnicodeError):
            return False, False

    def peers(self):
        keys = self.run(['wg', 'show', self.config.exit_if, 'peers']).split()
        if any(not valid_key(key) for key in keys):
            raise ValueError('invalid peer key')
        return keys

    def server_for(self, keys):
        if len(keys) != 1:
            return None
        matches = [host for host, relay in self.catalog.relays.items() if relay['public_key'] == keys[0]]
        return matches[0] if len(matches) == 1 else None

    def handshake_age(self, key):
        raw = self.run(['wg', 'show', self.config.exit_if, 'latest-handshakes'])
        for line in raw.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == key and fields[1].isdigit():
                timestamp = int(fields[1])
                age = int(time.time()) - timestamp
                return age if timestamp > 0 and age >= 0 else None
        return None

    def egress_family(self, family):
        # am.i.mullvad.net has no AAAA record; Mullvad publishes per-family names.
        raw = self.run(['curl', f'-{family}', '--interface', self.config.exit_if, '--noproxy', '*',
                        '--proto', '=https', '--max-filesize', '16384', '-fsS', '--max-time', '10',
                        f'https://ipv{family}.am.i.mullvad.net/json'], timeout=12, limit=16384)
        data = decode_json(raw)
        if not isinstance(data, dict) or type(data.get('mullvad_exit_ip')) is not bool:
            raise ValueError('invalid egress response')
        if not isinstance(data.get('ip'), str):
            raise ValueError('invalid egress address')
        ip = ipaddress.ip_address(data.get('ip', ''))
        if ip.version != family:
            raise ValueError('wrong egress address family')
        labels = [data.get('city'), data.get('country')]
        if any(not isinstance(v, str) or len(v) > 256 or any(ord(c) < 32 for c in v) for v in labels):
            raise ValueError('invalid egress location')
        return {'egress_ip': str(ip), 'egress_city': labels[0], 'egress_country': labels[1],
                'mullvad_exit_ip': data['mullvad_exit_ip']}

    def egress(self):
        probes = {family: self.egress_family(family) for family in sorted(self.tunnel_addresses())}
        return {**probes[4], 'mullvad_exit_ip': all(p['mullvad_exit_ip'] for p in probes.values()),
                'egress_ips': {str(f): p['egress_ip'] for f, p in probes.items()}}

    def publish(self, status, message, *, server=None, **fields):
        result = {'server': server, 'status': status, 'message': message, 'checked_at': now_iso(),
                  'request_id': request_token(self.request) if self.request else None,
                  'requested_server': self.request['server'] if self.request else None,
                  'routing_ok': False, 'unreachable_fallback': False, 'mullvad_exit_ip': False,
                  'handshake_age_s': None, 'egress_ip': None, 'egress_city': None, 'egress_country': None,
                  'egress_ips': {}}
        result.update(fields)
        write_json_atomic(self.result_path, result, public=True)
        return result

    def inspect(self, *, applying=False):
        routing_ok, fallback = self.routing_status()
        fields = {'routing_ok': routing_ok, 'unreachable_fallback': fallback}
        server = None

        def emit(status, message):
            if self.pending:
                status, message = 'failed', self.pending
            if applying and routing_ok and status == 'failed' and not self.rejection:
                status, message = 'applying', 'Waiting for tunnel verification.'
            return self.publish(status, message, server=server, **fields)

        try:
            keys = self.peers()
            server = self.server_for(keys)
            if len(keys) != 1:
                return emit('failed', 'Expected exactly one tunnel peer.')
            age = self.handshake_age(keys[0])
            fields['handshake_age_s'] = age
            if not routing_ok:
                return emit('failed', 'Routing protection is incomplete; run the recovery helper.')
            fields.update(self.egress())
            if self.rejection:
                return emit('failed', self.rejection)
            if age is None or age >= HANDSHAKE_FRESH_SEC:
                return emit('failed', 'Tunnel handshake is missing or stale; check the account and connectivity.')
            if fields['mullvad_exit_ip'] is not True:
                return emit('failed', 'Tunnel egress is not confirmed as Mullvad.')
            if not self.catalog.usable() or server is None:
                return emit('failed', 'Current peer cannot be verified against a fresh relay catalogue.')
            return emit('ok', 'Healthy.')
        except (RuntimeError, ValueError, UnicodeError):
            return emit('failed', self.rejection or 'Tunnel inspection or egress check failed.')

    def switch(self, request):
        # Also validate when called outside the polling loop (e.g. tests/tools).
        request = desired_request(request)
        self.request = request
        self.rejection = None
        self.pending = None
        if request is None:
            self.rejection = 'Invalid desired-state file; no change applied.'
            return self.inspect()
        if not self.catalog.usable():
            self.pending = 'Waiting for a fresh trusted relay catalogue; request will retry automatically.'
            return self.inspect()
        if request['server'] not in self.catalog.relays:
            self.rejection = 'Requested server is not in a fresh trusted relay catalogue; no change applied.'
            return self.inspect()
        routing_ok, fallback = self.routing_status()
        if not routing_ok:
            self.pending = 'Waiting for tunnel and overlay routing; request will retry automatically. Run recovery if this persists.'
            return self.inspect()
        relay = self.catalog.relays[request['server']]
        try:
            keys = self.peers()
        except (RuntimeError, ValueError, UnicodeError):
            self.pending = 'Waiting for the WireGuard interface; request will retry automatically.'
            return self.inspect()
        try:
            self.publish('applying', 'Applying the requested server.', server=self.server_for(keys),
                         routing_ok=True, unreachable_fallback=fallback)
            # A failed removal aborts before any new peer is added.
            for key in keys:
                if key != relay['public_key']:
                    self.run(['wg', 'set', self.config.exit_if, 'peer', key, 'remove'])
            self.run(['wg', 'set', self.config.exit_if, 'peer', relay['public_key'],
                      'endpoint', relay['ipv4_addr_in'] + ':51820', 'allowed-ips', '0.0.0.0/0,::/0',
                      'persistent-keepalive', '25'])
            deadline = self.clock() + SWITCH_TIMEOUT_SEC
            while self.clock() < deadline:
                result = self.inspect(applying=True)
                if result['status'] == 'ok' and result['server'] == request['server']:
                    return result
                if not result['routing_ok']:
                    self.rejection = 'Routing changed during the switch; choose a server again after recovery.'
                    return self.inspect()
                self.sleep(3)
            self.rejection = 'Switch verification timed out; choose a server again to retry.'
            return self.inspect()
        except (RuntimeError, ValueError, UnicodeError):
            self.rejection = 'Peer update failed; choose a server again to retry.'
            return self.inspect()

    def push_gatus(self, result):
        base, token = os.environ.get('GATUS_URL', ''), os.environ.get('GATUS_TOKEN', '')
        if not base or not token:
            return
        endpoint = urllib.parse.quote(os.environ.get('GATUS_ENDPOINT', 'molebridge'), safe='')
        if not base.startswith(('http://', 'https://')) or any(c in token for c in '\r\n'):
            return
        query = urllib.parse.urlencode({'success': str(result['status'] == 'ok').lower(), 'error': result['message']})
        # Keep the token out of argv and logs.
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / 'header'
            header.write_text('Authorization: Bearer ' + token + '\n', encoding='utf-8')
            os.chmod(header, 0o600)
            try:
                self.run(['curl', '--noproxy', '*', '--proto', '=http,https', '-fsS', '--max-time', '10',
                          '-X', 'POST', '-H', '@' + str(header), base.rstrip('/') + '/api/v1/endpoints/' + endpoint + '/external?' + query], timeout=12)
            except (RuntimeError, ValueError, UnicodeError):
                print('applier: monitoring push failed', flush=True)

    def tick(self):
        if self.clock() >= self.next_catalog:
            refreshed = self.catalog.refresh(self.fetch_catalog)
            self.next_catalog = self.clock() + (REFRESH_INTERVAL_S if refreshed else 60)
        raw = read_json(self.desired_path, 4096)
        request = desired_request(raw)
        if request is None and (raw is not None or self.desired_path.exists()):
            if self.last_request != 'invalid':
                self.next_health = 0
            self.last_request, self.request = 'invalid', None
            self.pending = None
            self.rejection = 'Invalid desired-state file; no change applied.'
        elif request and request_token(request) != self.last_request:
            result = self.switch(request)
            self.last_request = request_token(request)
            self.next_health = self.clock() + REFRESH_SEC
            self.push_gatus(result)
            return result
        elif request and self.pending and self.catalog.usable():
            # A pending request retries once its prerequisites can be met. A
            # stale catalogue is checked here without probing; routing and the
            # tunnel are re-checked by the switch itself.
            result = self.switch(request)
            self.next_health = self.clock() + REFRESH_SEC
            self.push_gatus(result)
            return result
        elif request and not self.rejection and not self.pending:
            # A recreated tunnel may start with the downloaded peer again.
            try:
                if self.server_for(self.peers()) != request['server']:
                    result = self.switch(request)
                    self.next_health = self.clock() + REFRESH_SEC
                    self.push_gatus(result)
                    return result
            except (RuntimeError, ValueError):
                pass
        elif request is None and not self.desired_path.exists():
            self.request, self.last_request, self.rejection = None, None, None
            self.pending = None
        if self.clock() >= self.next_health:
            result = self.inspect()
            self.next_health = self.clock() + REFRESH_SEC
            self.push_gatus(result)
            return result
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--healthcheck', action='store_true')
    parser.add_argument('--doctor', action='store_true')
    args = parser.parse_args()
    directory = Path(os.environ.get('STATE_DIR', '/state'))
    try:
        applier = Applier(directory, RoutingConfig.from_env(os.environ))
        if args.healthcheck:
            result = read_json(applier.result_path, 16384)
            completed = isinstance(result, dict) and result.get('status') in ('ok', 'failed')
            return 0 if (completed and recent(result.get('checked_at'))
                         and len(applier.peers()) == 1 and applier.routing_status()[0]) else 1
        if args.doctor:
            result = read_json(applier.result_path, 16384)
            result = result if isinstance(result, dict) else {}
            checks = {'recent applier check': recent(result.get('checked_at')),
                      'routing protection': applier.routing_status()[0],
                      'fresh relay catalogue': applier.catalog.usable(),
                      'verified Mullvad egress': recent(result.get('checked_at')) and result.get('status') == 'ok'}
            for label, passed in checks.items():
                print(('PASS ' if passed else 'FAIL ') + label)
            return 0 if all(checks.values()) else 1
        applier.publish('unknown', 'Applier starting; waiting for verification.')
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_args: stop.set())
        while not stop.is_set():
            try:
                applier.tick()
            except (OSError, ValueError, RuntimeError):
                print('applier: control cycle failed', flush=True)
            stop.wait(POLL_SEC)
    except (OSError, ValueError, RuntimeError):
        print('applier: invalid configuration or unavailable state', flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

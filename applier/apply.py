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

from molebridge import providers
from molebridge.egress import (ECHO_MAX_BYTES, ECHO_URLS, HOST_LACKS_FAMILY, exit_addresses, host_lacks_ipv6,
                               parse_echo, tunnel_verdict)
from molebridge.relays import REFRESH_INTERVAL_S, RelayCatalog, valid_key
from molebridge.routing import (RETURN_PATH_SYSCTL, RoutingConfig, family_status, netbird_firewall_present,
                                overlay_is_kernel_wireguard, return_path_enabled)
from molebridge.state import (decode_json, desired_request, now_iso, read_json, recent, request_token,
                              write_json_atomic)

HANDSHAKE_FRESH_SEC = 180
# A health check whose egress check gets no usable answer (a timeout, a
# refused or reset connection, an HTTP error, a malformed reply) asks once
# more after EGRESS_RETRY_SEC before it publishes a failure, unless the first
# attempt took longer than EGRESS_RETRY_WITHIN_SEC. The second attempt starts
# no request after EGRESS_RETRY_BUDGET_SEC, so with one request's own limit
# a check stays well inside the 150 seconds after which readers call a
# result unknown.
EGRESS_RETRY_SEC = 10
EGRESS_RETRY_WITHIN_SEC = 15
EGRESS_RETRY_BUDGET_SEC = 30
SWITCH_TIMEOUT_SEC = 60
REFRESH_SEC = 60
POLL_SEC = 5
NETBIRD_MODE_FAILED = ('NetBird is not running kernel WireGuard with its kernel firewall on the overlay '
                       'interface; see the troubleshooting guide.')


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
    """The Mullvad applier, and the base for every provider's applier. A
    subclass sets `provider` (its registry id) and overrides the provider seam:
    catalogue options, `apply_relay`, `server_for`, `egress` and `tick`. The
    registry entry (molebridge/providers.py) supplies everything else."""
    provider = 'mullvad'

    @property
    def spec(self):
        return providers.get(self.provider)

    @property
    def rejection(self):
        """Why the current request failed, shown until a new request, or
        until a later check finds that request met (`rejection_stands`)."""
        return self._rejection

    @rejection.setter
    def rejection(self, value):
        self._rejection = value
        # Every rejection is published by at least one check before any
        # check may clear it.
        self.rejection_reported = False

    @property
    def address_before_switch(self):
        """True when one tunnel address is valid on every server, so the
        interface must already carry it before a switch (Mullvad)."""
        return self.spec.address_before_switch

    def __init__(self, state_dir: Path, config: RoutingConfig, *, run=command, clock=time.monotonic, sleep=time.sleep):
        self.directory = state_dir / 'applier'
        self.result_path = self.directory / 'result.json'
        self.desired_path = state_dir / 'panel' / 'desired.json'
        self.catalog = self.make_catalog()
        self.config, self.run, self.clock, self.sleep = config, run, clock, sleep
        self.last_request = None
        self.request = None
        self.next_catalog = 0
        self.next_health = 0
        self.rejection = None
        self.pending = None
        # While a switch is being verified, the time it gives up.
        self.switch_deadline = None
        # While an egress check is asked a second time, the time after which
        # it starts no further request.
        self.retry_deadline = None

    @classmethod
    def from_env(cls, state_dir, config, env, **kwargs):
        """The applier for this provider's settings; subclasses read their own."""
        return cls(state_dir, config, **kwargs)

    def make_catalog(self):
        return RelayCatalog(self.directory, self.provider)

    def fetch_catalog(self):
        spec = self.spec
        response = self.run(['curl', '--noproxy', '*', '--proto', '=https', '-fsS',
                             '--connect-timeout', '10', '--max-time', str(spec.catalog_timeout_s),
                             '--max-filesize', str(spec.catalog_max_bytes),
                             '--user-agent', 'molebridge-applier/0.2',
                             '--write-out', '\n%{http_code}', spec.catalog_url],
                            timeout=spec.catalog_timeout_s + 2, limit=spec.catalog_max_bytes + 4)
        body, code = response.rsplit('\n', 1)
        if code != '200':
            raise ValueError('unexpected catalogue HTTP status; redirects refused')
        return body

    def tunnel_addresses(self, *, require_ipv4=True):
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
        if 4 not in found and require_ipv4:
            raise ValueError('missing IPv4 tunnel address')
        return found

    def routing_status(self, *, require_address=True):
        """(protected, fallback). Without `require_address` an interface that has
        no address yet passes when its guards are intact: a provider that
        assigns the address per server installs rule 94 with it."""
        checks = []
        try:
            self.run(['ip', 'link', 'show', 'dev', self.config.overlay_if])
            addresses = self.tunnel_addresses(require_ipv4=require_address)
            return_path = return_path_enabled(self.run(['cat', RETURN_PATH_SYSCTL]))
            for family in (4, 6):
                rules = decode_json(self.run(['ip', '-j', f'-{family}', 'rule', 'show']))
                routes = decode_json(self.run(['ip', '-j', f'-{family}', 'route', 'show', 'table', self.config.table]))
                checks.append(family_status(rules, routes, self.config, family,
                                            tunnel_address=addresses.get(family)))
            return return_path and all(c[0] for c in checks), all(c[1] for c in checks)
        except (RuntimeError, ValueError, UnicodeError):
            return False, False

    def netbird_native(self):
        """True when NetBird runs kernel WireGuard on the overlay interface and
        its own kernel firewall is in place, as Molebridge requires."""
        try:
            links = decode_json(self.run(['ip', '-d', '-j', 'link', 'show', 'dev', self.config.overlay_if]))
            if not overlay_is_kernel_wireguard(links, self.config.overlay_if):
                return False
            return netbird_firewall_present(decode_json(self.run(['nft', '-j', 'list', 'chains'])))
        except (RuntimeError, ValueError, UnicodeError):
            return False

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

    def apply_relay(self, relay, keys):
        """Point the tunnel at an approved relay. A failed removal aborts before
        any new peer is added."""
        for key in keys:
            if key != relay['public_key']:
                self.run(['wg', 'set', self.config.exit_if, 'peer', key, 'remove'])
        self.run(['wg', 'set', self.config.exit_if, 'peer', relay['public_key'],
                  'endpoint', relay['ipv4_addr_in'] + ':51820', 'allowed-ips', '0.0.0.0/0,::/0',
                  'persistent-keepalive', '25'])

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
        """Mullvad's check for every family the tunnel carries. The first
        family that Mullvad says is not its exit ends the check, so no later
        request can turn that answer into a retryable failure."""
        probes = {}
        for family in sorted(self.tunnel_addresses()):
            self.within_retry_budget()
            probes[family] = self.egress_family(family)
            if not probes[family]['mullvad_exit_ip']:
                break
        confirmed = all(p['mullvad_exit_ip'] for p in probes.values())
        first = probes.get(4) or next(iter(probes.values()))
        return {**first, 'mullvad_exit_ip': confirmed, 'exit_confirmed': confirmed,
                'egress_ips': {str(f): p['egress_ip'] for f, p in probes.items()}}

    def egress_for(self, server, handshake_age):
        """Egress fields for the current server. A provider with its own typed
        check confirms through `egress`; one without gets the tunnel checks."""
        if self.spec.egress_tier == 'tunnel':
            return self.tunnel_egress(server, handshake_age)
        return self.egress()

    def within_retry_budget(self):
        """Raise when a second egress attempt has used its time. Called
        before each request of a check that makes more than one."""
        if self.retry_deadline is not None and self.clock() > self.retry_deadline:
            raise RuntimeError('egress retry ran out of time')

    def checked_egress(self, server, handshake_age, *, applying):
        """`egress_for`, asked once more after EGRESS_RETRY_SEC when it gets
        no usable answer. An answer that does not confirm the provider is
        never asked again: each check returns it as soon as it has one,
        before any further request. There is no second attempt while a switch
        is verified (its own loop asks again until its timeout), when the
        check fails whatever the answer (a missing or stale handshake, a
        rejected or pending request, a peer not in a fresh catalogue), or when
        the first attempt took longer than EGRESS_RETRY_WITHIN_SEC; the second
        starts no request after EGRESS_RETRY_BUDGET_SEC. The previous result
        stays published until this check's own result replaces it."""
        started = self.clock()
        try:
            return self.egress_for(server, handshake_age)
        except (RuntimeError, ValueError, UnicodeError):
            fresh = type(handshake_age) is int and 0 <= handshake_age < HANDSHAKE_FRESH_SEC
            doomed = (not fresh or self.rejection_stands(server) or self.pending or server is None
                      or not self.catalog.usable())
            slow = self.clock() - started > EGRESS_RETRY_WITHIN_SEC
            if applying or self.switch_deadline is not None or doomed or slow:
                raise
        print('applier: egress check got no answer; asking once more', flush=True)
        self.sleep(EGRESS_RETRY_SEC)
        self.retry_deadline = self.clock() + EGRESS_RETRY_BUDGET_SEC
        try:
            return self.egress_for(server, handshake_age)
        except (RuntimeError, ValueError, UnicodeError):
            print('applier: egress check got no answer twice', flush=True)
            raise
        finally:
            self.retry_deadline = None

    def echo(self, url, family, *, tunnel):
        """The caller's address from an IP echo service, through the tunnel
        interface or, with tunnel=False, over the host's own route."""
        bind = ['--interface', self.config.exit_if] if tunnel else []
        raw = self.run(['curl', f'-{family}', *bind, '--noproxy', '*', '--proto', '=https',
                        '--max-filesize', str(ECHO_MAX_BYTES), '-fsS', '--max-time', '10', url],
                       timeout=12, limit=ECHO_MAX_BYTES)
        return parse_echo(raw, family)

    def host_address(self, family):
        """The host's own public address, measured off the tunnel. When that
        fails: HOST_LACKS_FAMILY for IPv6 only if the namespace provably has
        no IPv6 of its own, otherwise None: no usable answer, which
        `tunnel_egress` raises."""
        try:
            return self.echo(ECHO_URLS[family][0], family, tunnel=False)
        except (RuntimeError, ValueError, UnicodeError):
            if family == 6 and self.host_lacks_ipv6():
                return HOST_LACKS_FAMILY
            return None

    def host_lacks_ipv6(self):
        try:
            routes = decode_json(self.run(['ip', '-j', '-6', 'route', 'show', 'table', 'all']))
            links = decode_json(self.run(['ip', '-j', '-6', 'address', 'show', 'scope', 'global']))
        except (RuntimeError, ValueError, UnicodeError):
            return False
        return host_lacks_ipv6(routes, links, {self.config.exit_if, self.config.overlay_if})

    def tunnel_egress(self, server, handshake_age):
        """The "tunnel" tier (molebridge/egress.py), for every family the
        tunnel carries. `exit_confirmed` stays false: that field means the
        provider itself confirmed the egress. The first family that fails the
        checks ends them, and echo answers that disagree, or that the
        catalogue does not list as the server's exit, fail before the host's
        own address is measured, so no later request can turn a failed check
        into a retryable one."""
        relay = self.catalog.relays.get(server) if server else None
        verified, addresses = relay is not None, {}
        for family in sorted(self.tunnel_addresses()):
            echoes = []
            for url in ECHO_URLS[family]:
                self.within_retry_budget()
                echoes.append(self.echo(url, family, tunnel=True))
            addresses[str(family)] = echoes[0]
            expected = exit_addresses(relay, family)
            if len(set(echoes)) != 1 or (expected is not None and echoes[0] not in expected):
                verified = False
                break
            self.within_retry_budget()
            host = self.host_address(family)
            if host is None:
                raise RuntimeError('host address measurement failed')
            verified = tunnel_verdict(echoes, host, expected,
                                      handshake_age, max_handshake_age=HANDSHAKE_FRESH_SEC) and verified
            if not verified:
                break
        return {'egress_ip': addresses.get('4'), 'egress_city': None, 'egress_country': None,
                'exit_confirmed': False, 'egress_tier': 'tunnel' if verified else None,
                'egress_ips': addresses}

    def egress_tier(self, fields):
        """'provider' when the provider confirmed egress; 'tunnel' when the
        tunnel checks passed for a provider without its own check; else None."""
        if fields.get('exit_confirmed') is True:
            return 'provider'
        if self.spec.egress_tier == 'tunnel' and fields.get('egress_tier') == 'tunnel':
            return 'tunnel'
        return None

    def result_defaults(self):
        return {'mullvad_exit_ip': False}

    def publish(self, status, message, *, server=None, **fields):
        result = {'server': server, 'status': status, 'message': message, 'checked_at': now_iso(),
                  'request_id': request_token(self.request) if self.request else None,
                  'requested_server': self.request['server'] if self.request else None,
                  'provider': self.provider, 'routing_ok': False, 'unreachable_fallback': False,
                  'netbird_native': False, 'exit_confirmed': False, 'egress_tier': None,
                  **self.result_defaults(),
                  'handshake_age_s': None, 'egress_ip': None, 'egress_city': None, 'egress_country': None,
                  'egress_ips': {}}
        result.update(fields)
        write_json_atomic(self.result_path, result, public=True)
        return result

    def rejection_stands(self, server):
        """True when a rejection outlasts this check whatever it finds. Once
        it has been published, a check that finds the requested server live
        and passes every other check clears it: the request is met. That is
        the case after an automatic re-registration failed while the tunnel
        it meant to repair came back by itself."""
        return bool(self.rejection) and (not self.rejection_reported or bool(self.pending)
                                         or not self.request or server != self.request['server'])

    def inspect(self, *, applying=False):
        routing_ok, fallback = self.routing_status()
        native = self.netbird_native()
        fields = {'routing_ok': routing_ok, 'unreachable_fallback': fallback, 'netbird_native': native}
        server = None

        def emit(status, message):
            if self.pending:
                status, message = 'failed', self.pending
            if applying and routing_ok and native and status == 'failed' and not self.rejection:
                status, message = 'applying', 'Waiting for tunnel verification.'
            result = self.publish(status, message, server=server, **fields)
            if self.rejection and result['message'] == self.rejection:
                self.rejection_reported = True
            return result

        try:
            keys = self.peers()
            server = self.server_for(keys)
            if len(keys) != 1:
                return emit('failed', self.rejection or 'Expected exactly one tunnel peer.')
            age = self.handshake_age(keys[0])
            fields['handshake_age_s'] = age
            if not routing_ok:
                return emit('failed', 'Routing protection is incomplete; run the recovery helper.')
            if not native:
                return emit('failed', NETBIRD_MODE_FAILED)
            fields.update(self.checked_egress(server, age, applying=applying))
            fields['egress_tier'] = self.egress_tier(fields)
            failure = None
            if age is None or age >= HANDSHAKE_FRESH_SEC:
                failure = 'Tunnel handshake is missing or stale; check the account and connectivity.'
            elif fields['egress_tier'] is None:
                failure = ('Tunnel egress did not pass the tunnel checks.' if self.spec.egress_tier == 'tunnel'
                           else f'Tunnel egress is not confirmed as {self.spec.label}.')
            elif not self.catalog.usable() or server is None:
                failure = 'Current peer cannot be verified against a fresh relay catalogue.'
            if self.rejection and (failure or self.rejection_stands(server)):
                return emit('failed', self.rejection)
            if failure:
                return emit('failed', failure)
            if self.rejection:
                print('applier: the requested server passed every check; clearing the earlier failure', flush=True)
                self.rejection = None
            return emit('ok', 'Healthy.')
        except (RuntimeError, ValueError, UnicodeError):
            return emit('failed', self.rejection or 'Tunnel inspection or egress check failed.')

    def switch(self, request):
        # Also validate when called outside the polling loop (e.g. tests/tools).
        request = desired_request(request, self.provider)
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
        routing_ok, fallback = self.routing_status(require_address=self.address_before_switch)
        if not routing_ok:
            self.pending = 'Waiting for tunnel and overlay routing; request will retry automatically. Run recovery if this persists.'
            return self.inspect()
        if not self.netbird_native():
            self.pending = 'Waiting for NetBird to run kernel WireGuard with its kernel firewall; request will retry automatically.'
            return self.inspect()
        relay = self.catalog.relays[request['server']]
        try:
            keys = self.peers()
        except (RuntimeError, ValueError, UnicodeError):
            self.pending = 'Waiting for the WireGuard interface; request will retry automatically.'
            return self.inspect()
        try:
            self.publish('applying', 'Applying the requested server.', server=self.server_for(keys),
                         routing_ok=True, unreachable_fallback=fallback, netbird_native=True)
            self.apply_relay(relay, keys)
            deadline = self.switch_deadline = self.clock() + SWITCH_TIMEOUT_SEC
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
        finally:
            self.switch_deadline = None

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

    def doctor_checks(self):
        """Fixed labels and results for `--doctor`; no addresses or names."""
        result = read_json(self.result_path, 16384)
        result = result if isinstance(result, dict) else {}
        return {'recent applier check': recent(result.get('checked_at')),
                'routing protection': self.routing_status()[0],
                'NetBird kernel WireGuard and kernel firewall': self.netbird_native(),
                'fresh relay catalogue': self.catalog.usable(),
                f'verified {self.spec.label} egress': recent(result.get('checked_at')) and result.get('status') == 'ok'}

    def tick(self):
        if self.clock() >= self.next_catalog:
            refreshed = self.catalog.refresh(self.fetch_catalog)
            self.next_catalog = self.clock() + (REFRESH_INTERVAL_S if refreshed else 60)
        raw = read_json(self.desired_path, 4096)
        request = desired_request(raw, self.provider)
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
        spec = providers.from_env(os.environ)
        config = RoutingConfig.from_env(os.environ)
        if spec.applier == 'applier.apply:Applier':
            applier = Applier(directory, config)
        else:
            applier = spec.applier_class().from_env(directory, config, os.environ)
        if args.healthcheck:
            result = read_json(applier.result_path, 16384)
            completed = isinstance(result, dict) and result.get('status') in ('ok', 'failed')
            return 0 if (completed and recent(result.get('checked_at'))
                         and len(applier.peers()) == 1 and applier.routing_status()[0]
                         and applier.netbird_native()) else 1
        if args.doctor:
            checks = applier.doctor_checks()
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

"""Own the relay catalogue, admit selections, switch peers and report health.

This is a trusted NET_ADMIN component. The config file is not mounted, but
namespace privileges can retrieve the live WireGuard key. Never use wg dump.

Every change to the live selection goes through one admission pipeline
(`Applier.admit`, `Applier.run_pipeline`), whatever asked for it: the
configured SERVER, the panel's request, gluetun's restore, reconvergence and
automatic retries. Its state is the attempt record (applier/attempt.py). The
status record it publishes is schema 2 (molebridge/verdict.py), judged by
`molebridge.verdict.assess` wherever it is read.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from applier.attempt import UNIDENTIFIED_SEC, Attempt, backoff, read_boot_id
from molebridge import providers
from molebridge.egress import (ECHO_MAX_BYTES, ECHO_URLS, HOST_LACKS_FAMILY, exit_addresses, host_lacks_ipv6,
                               parse_echo, tunnel_verdict)
from molebridge.relays import REFRESH_INTERVAL_S, RelayCatalog, valid_key
from molebridge.routing import (RETURN_PATH_SYSCTL, RoutingConfig, family_status, netbird_firewall_present,
                                overlay_is_kernel_wireguard, return_path_enabled, owner_record_valid, parse_owner_record)
from molebridge.state import (SWITCH_TIMEOUTS, decode_json, desired_request, now_iso, read_json, recent,
                              request_token, write_json_atomic)
from molebridge.verdict import NOT_CHECKED_BY, SCHEMA, ExitConfig, Target, assess, fixed_checks, required_checks

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
SWITCH_TIMEOUT_SEC = SWITCH_TIMEOUTS['native']
REFRESH_SEC = 60
POLL_SEC = 5
# A panel request this recent is the operator asking now: it is applied
# even when the server is already live (a PIA region registers anew). An
# older one, as after an upgrade, is re-inspected first.
FRESH_REQUEST_SEC = 150
# A valid provider hostname fits within 253 characters. Bound invalid input
# too, so even JSON-escaped Unicode fits the readers' 16 KiB status limit.
SERVER_REPORT_CHARS = 256
NETBIRD_MODE_FAILED = ('NetBird is not running kernel WireGuard with its kernel firewall on the overlay '
                       'interface; see the troubleshooting guide.')
ROUTING_FAILED = 'Routing protection is incomplete; run the recovery helper.'
INVALID_DESIRED = 'Invalid desired-state file; no change applied.'
UNLISTED = 'Requested server is not in a fresh trusted relay catalogue; no change applied.'


class MutationRefused(RuntimeError):
    """The change was refused before it took effect (a definite outcome)."""


class CredentialRejected(MutationRefused):
    """The provider refused the account's login: retrying can't help until
    the credentials change or the operator retries."""


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


class Selection(Target):
    """A target with its identity: a panel request's token,
    'configured:<server>' or 'restore:<server>'. A new identity is a new
    target for the pipeline."""

    @property
    def key(self):
        if self.source == 'panel':
            return request_token(self.request)
        return f'{self.source}:{self.server}'


class Applier:
    """The Mullvad applier, and the base for every provider's applier. A
    subclass sets `provider` (its registry id) and overrides the provider seam:
    catalogue options, `apply_relay`, `server_for`, `egress` and `tick`. The
    registry entry (molebridge/providers.py) supplies everything else."""
    # The native exit's owner record (routing/molebridge-exit). main() sets
    # the path for the native backend; with None the check is skipped.
    owner_path = None
    owner_seen = None
    owner_generation = None
    provider = 'mullvad'
    switch_timeout = SWITCH_TIMEOUT_SEC

    @property
    def spec(self):
        return providers.get(self.provider)

    @property
    def address_before_switch(self):
        """True when one tunnel address is valid on every server, so the
        interface must already carry it before a switch (Mullvad)."""
        return self.spec.address_before_switch

    @property
    def kind(self):
        return self.config.kind

    @property
    def exit_config(self):
        return ExitConfig(self.provider, self.kind)

    def __init__(self, state_dir: Path, config: RoutingConfig, *, run=command, clock=time.monotonic, sleep=time.sleep,
                 server='', boot_id=None):
        self.configured_server = server
        self.configured_at = now_iso()
        self.directory = state_dir / 'applier'
        self.result_path = self.directory / 'result.json'
        self.attempt_path = self.directory / 'attempt.json'
        self.desired_path = state_dir / 'panel' / 'desired.json'
        self.config, self.run, self.clock, self.sleep = config, run, clock, sleep
        self.catalog = self.make_catalog()
        self.boot_id = boot_id or read_boot_id()
        self.attempt = Attempt.load(self.attempt_path, boot_id=self.boot_id, now=self.clock())
        # The panel's latest valid request (its acknowledgement), or the
        # configured one; whether desired.json is unreadable.
        self.request = None
        self.invalid_desired = False
        self.target = None
        self.next_catalog = 0
        self.next_health = 0
        # The last inspection's findings (`measure`).
        self.measurement = None
        # Since when a live peer the catalogue can't name has been seen.
        self.unidentified_since = None
        # While a switch is being verified, the time it gives up.
        self.switch_deadline = None
        # While an egress check is asked a second time, the time after which
        # it starts no further request.
        self.retry_deadline = None
        self.started = False

    @classmethod
    def from_env(cls, state_dir, config, env, **kwargs):
        """The applier for this provider's settings; subclasses read their own."""
        return cls(state_dir, config, server=env.get('SERVER', ''), **kwargs)

    def configured_request(self):
        """Use exactly the desired-state name validator; never read panel state."""
        return desired_request({'server': self.configured_server, 'requested_at': self.configured_at},
                               self.provider)

    def configuration_error(self):
        if not self.configured_server:
            return None
        # Quote untrusted text without allowing control characters into status/logs.
        quoted = json.dumps(self.configured_server[:SERVER_REPORT_CHARS], ensure_ascii=True)
        if self.configured_request() is None:
            return f'Invalid SERVER {quoted}; no change applied.'
        if self.catalog.usable() and self.configured_server not in self.catalog.relays:
            return f'Unknown SERVER {quoted}; not in a fresh trusted relay catalogue; no change applied.'
        return None

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

    def catalog_signature(self):
        """What a rejection for an unlisted server waits to change."""
        return sorted(self.catalog.relays) if self.catalog.usable() else None

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

    def owner_live(self):
        """True when the exit container's owner record is fresh and from this
        boot and this network namespace (molebridge/routing.py,
        owner_record_valid): its routing loop is running here. Without a
        path, as for the gluetun backend, there is nothing to check."""
        if self.owner_path is None:
            return True
        try:
            with open(self.owner_path, 'rb') as handle:
                text = handle.read(600).decode('ascii')
            # The same files routing/contract-rules reads, and the same overrides.
            boot = Path(os.environ.get('MOLEBRIDGE_BOOT_ID_FILE', '/proc/sys/kernel/random/boot_id')
                        ).read_text(encoding='ascii').strip()
            now = int(Path(os.environ.get('MOLEBRIDGE_UPTIME_FILE', '/proc/uptime')
                           ).read_text(encoding='ascii').split()[0].split('.')[0])
            namespace = os.stat(os.environ.get('MOLEBRIDGE_NETNS_PATH', '/proc/self/ns/net'))
        except (OSError, ValueError, UnicodeError, IndexError):
            return False
        record = parse_owner_record(text)
        if not owner_record_valid(record, boot=boot, now=now, netns=f'{namespace.st_dev}:{namespace.st_ino}',
                                  seen=self.owner_seen):
            return False
        self.owner_seen = (record['generation'], record['stamp'])
        self.owner_generation = record['generation']
        return True

    def routing_status(self, *, require_address=True, owner=True):
        """(protected, fallback). Without `require_address` an interface that has
        no address yet passes when its guards are intact: a provider that
        assigns the address per server installs rules 94 and 98 with it. With
        the native backend and `owner`, the exit's owner record must be live
        too."""
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
            live = self.owner_live() if owner else True
            return return_path and live and all(c[0] for c in checks), all(c[1] for c in checks)
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
                'egress_ips': {str(f): p['egress_ip'] for f, p in probes.items()},
                'families': {str(f): 'pass' if p['mullvad_exit_ip'] else 'fail' for f, p in probes.items()}}

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
        rejected or pending selection, a peer not in a fresh catalogue), or when
        the first attempt took longer than EGRESS_RETRY_WITHIN_SEC; the second
        starts no request after EGRESS_RETRY_BUDGET_SEC. The previous result
        stays published until this check's own result replaces it."""
        started = self.clock()
        try:
            return self.egress_for(server, handshake_age)
        except (RuntimeError, ValueError, UnicodeError):
            fresh = type(handshake_age) is int and 0 <= handshake_age < HANDSHAKE_FRESH_SEC
            doomed = (not fresh or self.attempt.state in ('pending', 'rejected') or self.request_rejected()
                      or server is None or not self.catalog.usable())
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
        interfaces = {self.config.exit_if} | ({self.config.overlay_if} if self.kind == 'overlay' else set())
        return host_lacks_ipv6(routes, links, interfaces)

    def tunnel_egress(self, server, handshake_age):
        """The "tunnel" tier (molebridge/egress.py), for every family the
        tunnel carries. `exit_confirmed` stays false: that field means the
        provider itself confirmed the egress. The first family that fails the
        checks ends them, and echo answers that disagree, or that the
        catalogue does not list as the server's exit, fail before the host's
        own address is measured, so no later request can turn a failed check
        into a retryable one."""
        relay = self.catalog.relays.get(server) if server else None
        verified, addresses, families = relay is not None, {}, {}
        for family in sorted(self.tunnel_addresses()):
            echoes = []
            for url in ECHO_URLS[family]:
                self.within_retry_budget()
                echoes.append(self.echo(url, family, tunnel=True))
            addresses[str(family)] = echoes[0]
            expected = exit_addresses(relay, family)
            if len(set(echoes)) != 1 or (expected is not None and echoes[0] not in expected):
                verified = False
                families[str(family)] = 'fail'
                break
            self.within_retry_budget()
            host = self.host_address(family)
            if host is None:
                raise RuntimeError('host address measurement failed')
            verified = tunnel_verdict(echoes, host, expected,
                                      handshake_age, max_handshake_age=HANDSHAKE_FRESH_SEC) and verified
            families[str(family)] = 'pass' if verified else 'fail'
            if not verified:
                break
        return {'egress_ip': addresses.get('4'), 'egress_city': None, 'egress_country': None,
                'exit_confirmed': False, 'egress_tier': 'tunnel' if verified else None,
                'egress_ips': addresses, 'families': families}

    def egress_tier(self, fields):
        """'provider' when the provider confirmed egress; 'tunnel' when the
        tunnel checks passed for a provider without its own check; else None."""
        if fields.get('exit_confirmed') is True:
            return 'provider'
        if self.spec.egress_tier == 'tunnel' and fields.get('egress_tier') == 'tunnel':
            return 'tunnel'
        return None

    # -- the status record (schema 2, molebridge/verdict.py) ------------------

    @property
    def backend(self):
        return self.exit_config.backend

    def result_defaults(self):
        return {}

    def blank_checks(self):
        """Every check, unmeasured: required ones `unknown`, the rest as the
        kind fixes them."""
        checks = {name: {'state': 'unknown'} for name in required_checks(self.kind, self.backend)}
        for name, state in fixed_checks(self.kind, self.backend).items():
            checks[name] = {'state': state}
            if state == 'not-checked':
                checks[name]['by'] = NOT_CHECKED_BY[name]
        return checks

    def wall(self, deadline):
        """A boot-clock deadline as wall-clock time, for display."""
        if deadline is None:
            return None
        moment = datetime.now(timezone.utc) + timedelta(seconds=max(0.0, deadline - self.clock()))
        return moment.strftime('%Y-%m-%dT%H:%M:%SZ')

    def request_rejected(self):
        """True while the panel's current request stands refused: it is
        acknowledged with its reason and never becomes the target (D12)."""
        if self.configured_server:
            return False
        if self.invalid_desired:
            return True
        rejected = self.attempt.rejected
        return bool(self.request and rejected and rejected.get('key') == request_token(self.request))

    def rejection_message(self):
        if self.invalid_desired:
            return INVALID_DESIRED
        return (self.attempt.rejected or {}).get('reason') or UNLISTED

    def selection_record(self):
        attempt = self.attempt
        if self.request_rejected():
            return {'source': 'panel', 'outcome': 'rejected', 'attempt': 0,
                    'target': self.request['server'] if self.request else None,
                    'next_action': None, 'next_action_at': None}
        return {'source': attempt.source or 'seed', 'outcome': attempt.outcome, 'attempt': attempt.attempts,
                'target': attempt.target, 'next_action': attempt.next_action,
                'next_action_at': self.wall(attempt.next_action_at) if attempt.next_action else None}

    def publish(self, status, message, *, server=None, checks=None, **fields):
        result = {'schema': SCHEMA, 'kind': self.kind, 'backend': self.backend, 'provider': self.provider,
                  'status': status, 'message': message, 'checked_at': now_iso(),
                  'server': server,
                  'requested_server': self.request['server'] if self.request else None,
                  'configured_server': self.configured_server[:SERVER_REPORT_CHARS] or None,
                  'request_id': request_token(self.request) if self.request else None,
                  'selection': self.selection_record(),
                  'checks': checks or self.blank_checks(),
                  'egress_ip': None, 'egress_ips': {}, 'egress_city': None, 'egress_country': None,
                  **self.result_defaults()}
        result.update(fields)
        write_json_atomic(self.result_path, result, public=True)
        return result

    def save_attempt(self):
        self.attempt.save(self.attempt_path)

    # -- inspection -------------------------------------------------------------

    def no_peer_message(self, keys):
        return 'Expected exactly one tunnel peer.'

    def measure_guards(self, checks, at, finding):
        """The overlay's own guards: the routing contract (traffic protection),
        NetBird's kernel mode and, on the native backend, the owner record."""
        protected, fallback = self.routing_status(owner=False)
        native = self.netbird_native()
        checks['routing'] = {'state': 'pass' if protected else 'fail', 'at': at, 'fallback': fallback}
        checks['traffic_protection'] = {'state': checks['routing']['state'], 'at': at, 'from': 'routing'}
        checks['netbird'] = {'state': 'pass' if native else 'fail', 'at': at}
        owner = True
        if 'owner_record' in required_checks(self.kind, self.backend):
            owner = self.owner_live()
            checks['owner_record'] = {'state': 'pass' if owner else 'fail', 'at': at}
        finding['safe'] = protected and native and owner
        if not protected or not owner:
            finding['guard'] = ROUTING_FAILED
        elif not native:
            finding['guard'] = NETBIRD_MODE_FAILED

    def measure(self, *, applying=False):
        """One inspection: every check this kind requires, each stamped with
        when it was measured, stopping where later checks can't pass. Returns
        the finding; `emit` publishes it."""
        at = now_iso()
        checks = self.blank_checks()
        finding = {'status': 'failed', 'message': None, 'server': None, 'checks': checks, 'fields': {},
                   'safe': True, 'guard': None, 'peers': None, 'age': None, 'at': self.clock()}
        selected = self.target
        if selected is None and self.configured_server:
            selected = self.configured_selection()
        target = selected.server if selected is not None else None
        error = self.configuration_error()
        if error:
            finding['message'] = error
            return finding
        try:
            if self.kind == 'overlay':
                self.measure_guards(checks, at, finding)
            keys = self.peers()
            finding['peers'] = len(keys)
            server = finding['server'] = self.server_for(keys)
            peer = {'state': 'fail', 'at': at, 'server': server}
            if not keys:
                peer['reason'] = 'no-peer'
            elif len(keys) > 1:
                peer['reason'] = 'multiple-peers'
            elif not self.catalog.usable():
                peer['reason'] = 'catalogue-stale'
            elif server is None:
                peer['reason'] = 'unidentified'
            elif target is not None and server != target:
                peer['reason'] = 'not-target'
            else:
                peer['state'] = 'pass'
            checks['peer'] = peer
            if len(keys) != 1:
                finding['message'] = self.no_peer_message(keys)
                return finding
            age = finding['age'] = self.handshake_age(keys[0])
            fresh = type(age) is int and 0 <= age < HANDSHAKE_FRESH_SEC
            checks['handshake'] = {'state': 'pass' if fresh else 'fail', 'at': at, 'server': server, 'age_s': age}
            if finding['guard']:
                finding['message'] = finding['guard']
                return finding
            expected = [str(f) for f in sorted(self.tunnel_addresses())]
        except (RuntimeError, ValueError, UnicodeError):
            finding['message'] = 'Tunnel inspection or egress check failed.'
            return finding
        try:
            egress = self.checked_egress(server, age, applying=applying)
        except (RuntimeError, ValueError, UnicodeError):
            checks['egress'] = {'state': 'fail', 'at': now_iso(), 'server': server, 'reason': 'unanswered',
                                'tier': None, 'expected_families': expected, 'families': {}}
            finding['message'] = 'Tunnel inspection or egress check failed.'
            return finding
        tier = self.egress_tier(egress)
        families = {f: v for f, v in (egress.get('families') or {}).items() if f in expected}
        if tier is not None:
            families = {f: 'pass' for f in expected}
        passing = {f for f, v in families.items() if v == 'pass'}
        reason = egress.get('reason') or ('tunnel-checks-failed' if self.spec.egress_tier == 'tunnel'
                                          else 'not-confirmed')
        check = {'state': 'pass' if tier else 'fail', 'at': now_iso(), 'server': server, 'tier': tier,
                 'expected_families': expected, 'families': {f: families.get(f, 'unknown') for f in expected}}
        if not tier:
            check['reason'] = reason
        checks['egress'] = check
        finding['fields'] = {'egress_ip': egress.get('egress_ip'), 'egress_city': egress.get('egress_city'),
                             'egress_country': egress.get('egress_country'),
                             'egress_ips': {f: ip for f, ip in (egress.get('egress_ips') or {}).items()
                                            if f in passing}}
        if not fresh:
            failure = 'Tunnel handshake is missing or stale; check the account and connectivity.'
        elif tier is None:
            failure = (egress.get('message') or
                       ('Tunnel egress did not pass the tunnel checks.' if self.spec.egress_tier == 'tunnel'
                        else f'Tunnel egress is not confirmed as {self.spec.label}.'))
        elif not self.catalog.usable() or server is None:
            failure = 'Current peer cannot be verified against a fresh relay catalogue.'
        elif target is not None and server != target:
            failure = ('The configured SERVER is not the current server; waiting for convergence.'
                       if self.configured_server else
                       'The live server is not the selected one; waiting for convergence.')
        else:
            failure = None
        finding['status'], finding['message'] = ('failed', failure) if failure else ('ok', 'Healthy.')
        return finding

    def emit(self, finding, *, applying=False):
        """Publish a finding, with the pipeline's own state taking precedence:
        a refused request, missing prerequisites or a failed mutation are
        what the exit reports until a check finds the target met."""
        status, message = finding['status'], finding['message']
        attempt = self.attempt
        held = attempt.state in ('pending', 'rejected') and (attempt.target is not None or self.configured_server)
        if self.request_rejected():
            status, message = 'failed', self.rejection_message()
        elif held:
            status, message = 'failed', attempt.message
        elif attempt.state == 'failed' and status != 'ok':
            status, message = 'failed', attempt.message
        elif applying and status == 'failed' and finding['safe']:
            # A switch being verified: what isn't there yet is expected.
            status, message = 'applying', self.waiting_message()
        return self.publish(status, message, server=finding['server'], checks=finding['checks'],
                            **finding['fields'])

    def waiting_message(self):
        return 'Waiting for tunnel verification.'

    def inspect(self, *, applying=False):
        """Measure and publish (tests and tools)."""
        finding = self.measurement = self.measure(applying=applying)
        return self.emit(finding, applying=applying)

    def check(self):
        """The periodic check: re-checks the selection, never switches."""
        finding = self.measurement = self.measure()
        attempt, target = self.attempt, self.target
        if target is not None and attempt.state not in ('pending', 'rejected', 'attempting'):
            on_target = finding['server'] == target.server
            if finding['status'] == 'ok' and on_target:
                if attempt.state != 'idle' or attempt.outcome != 'verified':
                    attempt.settle()
                    self.save_attempt()
                self.on_verified(target.server)
            elif on_target and attempt.state == 'idle':
                # Applied, not verified: re-checked, never switched again (D7).
                attempt.state, attempt.outcome, attempt.message = 'unverified', 'applied-unverified', None
                attempt.next_action = 'recheck'
                attempt.next_action_at = self.clock() + REFRESH_SEC
                attempt.mutation_certainty = None
                self.save_attempt()
            elif attempt.state == 'unverified':
                attempt.next_action_at = self.clock() + REFRESH_SEC
                self.save_attempt()
        if attempt.generation is None and self.owner_generation is not None:
            # Known from the start, so the exit container's next start is
            # seen as one even before this applier changes anything.
            attempt.generation = self.owner_generation
            self.save_attempt()
        self.next_health = self.clock() + REFRESH_SEC
        return self.emit(finding)

    def on_verified(self, server):
        """A check passed on `server` as the target (gluetun records it)."""

    def on_applied(self, server):
        """`server` is live after a mutation, verified or not."""

    # -- target resolution --------------------------------------------------------

    def resolve(self, *, peek=False):
        """The effective target: SERVER, else the panel's accepted request,
        else (gluetun) the server to restore, else None. With `peek`, nothing
        is remembered (the Gatus push and the doctor)."""
        if self.configured_server:
            if not peek:
                self.request, self.invalid_desired = self.configured_request(), False
            return self.configured_selection()
        raw = read_json(self.desired_path, 4096)
        request = desired_request(raw, self.provider)
        invalid = request is None and (raw is not None or self.desired_path.exists())
        if not peek:
            self.request, self.invalid_desired = request, invalid
        if request is not None and not self.refused(request):
            return Selection(request['server'], 'panel', request)
        return self.restore_target()

    def restore_target(self):
        return None

    def configured_selection(self):
        # An invalid SERVER can't match any server: kept bounded, as reported.
        return Selection(self.configured_server[:SERVER_REPORT_CHARS], 'configured')

    def refused(self, request):
        """True while `request` stands rejected: the same request, and
        nothing changed that could let it pass."""
        rejected = self.attempt.rejected
        return (bool(rejected) and rejected.get('key') == request_token(request)
                and rejected.get('release') == self.release_signature(rejected.get('why')))

    def release_signature(self, why):
        """What a rejection waits for: the catalogue for an unlisted server,
        the credentials for a refused login. Others are never released."""
        if why == 'catalogue':
            names = self.catalog_signature()
            return None if names is None else hashlib.sha256('\n'.join(names).encode('utf-8')).hexdigest()
        return why

    # -- admission ------------------------------------------------------------------

    def tick(self):
        self.maintain_catalog()
        self.target = self.resolve()
        result = None
        if not self.started:
            self.started = True
            result = self.resume()
        if result is None:
            result = self.admit(self.target)
        if result is None and self.clock() >= self.next_health:
            result = self.check()
        if result is not None:
            self.push_gatus(result)
        return result

    def maintain_catalog(self):
        if self.clock() >= self.next_catalog:
            refreshed = self.catalog.refresh(self.fetch_catalog)
            self.next_catalog = self.clock() + (REFRESH_INTERVAL_S if refreshed else 60)

    def resume(self):
        """At start, an attempt interrupted mid-mutation is inspected first,
        never replayed: its live server either is the target (verify) or not
        (a failed, uncertain attempt, re-applied on its backoff, which
        inspects again first)."""
        attempt = self.attempt
        if attempt.state != 'attempting':
            return None
        print('applier: an interrupted switch is inspected before anything else', flush=True)
        finding = self.measurement = self.measure()
        if attempt.target is not None and finding['server'] == attempt.target:
            if finding['status'] == 'ok':
                attempt.settle()
                self.on_verified(attempt.target)
            else:
                attempt.state, attempt.outcome, attempt.message = 'unverified', 'applied-unverified', None
                attempt.next_action, attempt.next_action_at = 'recheck', self.clock() + REFRESH_SEC
        else:
            attempt.state, attempt.outcome = 'failed', 'mutation-failed'
            attempt.mutation_certainty = 'uncertain'
            attempt.message = 'The last switch was interrupted; retrying automatically.'
            attempt.schedule('reapply', self.clock())
        self.save_attempt()
        self.next_health = self.clock() + REFRESH_SEC
        return self.emit(finding)

    def admit(self, target):
        """The triggers, in precedence order (docs/architecture.md):
        1-2. a new effective target (a new request id is "Retry now");
        3. no live peer: on the native backend at once from idle or
           unverified, and once per new owner generation whatever the
           state; on gluetun as 7;
        4. a due re-apply on the backoff;
        5. a lapsed registration (D15);
        6-7. a live peer that isn't the target, only from idle or unverified;
             after UNIDENTIFIED_SEC when the catalogue can't name it.
        Nothing re-applies within REAPPLY_GUARD_SEC of the last mutation."""
        attempt = self.attempt
        now = self.clock()
        key = target.key if target is not None else None
        if key != attempt.target_key:
            return self.start(target)
        if target is None or attempt.state == 'attempting':
            return None
        if attempt.state == 'pending':
            if self.gate(target) is not None:
                return None
            return self.run_pipeline(target, attempt.source or target.source, reinspect=not self.asked_now(target))
        if attempt.state == 'rejected':
            why = attempt.extra.get('why')
            if attempt.extra.get('release') != self.release_signature(why):
                return self.run_pipeline(target, attempt.source or target.source, reinspect=True)
            return None
        try:
            keys = self.peers()
        except (RuntimeError, ValueError, UnicodeError):
            return None
        guard = attempt.guard_passed(now)
        if not keys:
            # The native tunnel comes back from its config without the peer
            # (the exit's routing loop recreates a lost interface, NordVPN's
            # and PIA's configs have none): applied again at once from idle
            # or unverified, and once per new owner generation even while a
            # failure backs off. gluetun leaves its interface without a peer
            # for a moment while it reconnects by itself, so there no peer is
            # waited out like an unidentified one.
            generation = self.current_generation()
            fresh_owner = generation is not None and attempt.generation not in (None, generation)
            if guard and (fresh_owner or (self.backend == 'native' and attempt.state in ('idle', 'unverified'))):
                if fresh_owner:
                    print('applier: the exit container started again; applying the selection', flush=True)
                return self.run_pipeline(target, 'reconverge', reinspect=True)
        if attempt.next_action == 'reapply' and attempt.next_action_at is not None and now >= attempt.next_action_at:
            return self.run_pipeline(target, 'retry', reinspect=True)
        live = None
        if keys and self.catalog.usable():
            try:
                live = self.server_for(keys)
            except (RuntimeError, ValueError, UnicodeError):
                return None
            if (self.spec.registration_lapses and live == target.server
                    and attempt.state in ('idle', 'unverified') and self.registration_lapsed(now)
                    and (attempt.last_mutation_at is None
                         or now >= attempt.last_mutation_at + backoff(attempt.backoff_step))):
                return self.run_pipeline(target, 'retry', repair=True)
        elif keys:
            # A stale catalogue can't name anything: not drift.
            self.unidentified_since = None
            return None
        if live is not None:
            self.unidentified_since = None
            if live != target.server and attempt.state in ('idle', 'unverified') and guard:
                return self.run_pipeline(target, 'reconverge', reinspect=True)
            return None
        if self.unidentified_since is None:
            self.unidentified_since = now
        elif now - self.unidentified_since >= UNIDENTIFIED_SEC and attempt.state in ('idle', 'unverified') and guard:
            self.unidentified_since = None
            return self.run_pipeline(target, 'reconverge', reinspect=True)
        return None

    def current_generation(self):
        """The native exit's owner generation now, or None."""
        if self.owner_path is None:
            return None
        return self.owner_generation if self.owner_live() else None

    def registration_lapsed(self, now):
        """The last inspection, recent, found the target's handshake stale for
        HANDSHAKE_FRESH_SEC, or never completed that long after the last
        mutation. An egress failure alone never counts (D15)."""
        finding = self.measurement
        if not finding or now - finding['at'] > 2 * REFRESH_SEC or self.target is None:
            return False
        return finding['server'] == self.target.server and self.handshake_stale(finding, now)

    def handshake_stale(self, finding, now=None):
        age = finding.get('age')
        if finding.get('peers') != 1:
            return False
        if age is None:
            last = self.attempt.last_mutation_at
            return last is None or (now if now is not None else self.clock()) - last >= HANDSHAKE_FRESH_SEC
        return age >= HANDSHAKE_FRESH_SEC

    def start(self, target):
        """A new effective target: a new attempt, its backoff from the start."""
        previous = self.attempt
        self.unidentified_since = None
        if target is None:
            self.attempt = Attempt.new(source='seed', target=None, target_key=None, boot_id=self.boot_id,
                                       rejected=previous.rejected, generation=previous.generation)
            self.save_attempt()
            self.next_health = 0
            return None
        source = target.source
        if (source == 'panel' and previous.target == target.server
                and previous.state in ('failed', 'rejected', 'unverified', 'pending')):
            source = 'operator-retry'
        fresh = self.asked_now(target)
        self.attempt = Attempt.new(source=source, target=target.server, target_key=target.key, boot_id=self.boot_id,
                                   rejected=previous.rejected, generation=previous.generation)
        return self.run_pipeline(target, source, reinspect=not fresh)

    def asked_now(self, target):
        """True for a panel request made within FRESH_REQUEST_SEC: the
        operator asking now, applied even when the server is already live."""
        return target.source == 'panel' and recent(target.request.get('requested_at'), FRESH_REQUEST_SEC)

    def switch(self, request):
        """Apply a panel request now, as a new target (tests and tools)."""
        self.target = target = self.resolve_request(request)
        if target is None:
            return self.inspect()
        self.attempt = Attempt.new(source=target.source, target=target.server, target_key=target.key,
                                   boot_id=self.boot_id, rejected=self.attempt.rejected,
                                   generation=self.attempt.generation)
        return self.run_pipeline(target, target.source)

    def resolve_request(self, request):
        if self.configured_server:
            self.request, self.invalid_desired = self.configured_request(), False
            return self.configured_selection()
        request = desired_request(request, self.provider)
        self.request, self.invalid_desired = request, request is None
        return Selection(request['server'], 'panel', request) if request else None

    def gate(self, target):
        """None when the pipeline may mutate, else (state, message, why):
        `pending` (prerequisites missing) or `rejected` (invalid or unlisted)."""
        error = self.configuration_error()
        if error:
            return 'rejected', error, 'catalogue' if error.startswith('Unknown') else 'invalid'
        if not self.catalog.usable():
            return 'pending', 'Waiting for a fresh trusted relay catalogue; request will retry automatically.', None
        if target.server not in self.catalog.relays:
            return 'rejected', UNLISTED, 'catalogue'
        if self.kind == 'overlay':
            if not self.routing_status(require_address=self.address_before_switch)[0]:
                return 'pending', ('Waiting for tunnel and overlay routing; request will retry automatically. '
                                   'Run recovery if this persists.'), None
            if not self.netbird_native():
                return 'pending', ('Waiting for NetBird to run kernel WireGuard with its kernel firewall; '
                                   'request will retry automatically.'), None
        try:
            self.peers()
        except (RuntimeError, ValueError, UnicodeError):
            return 'pending', 'Waiting for the WireGuard interface; request will retry automatically.', None
        return None

    def run_pipeline(self, target, source, *, reinspect=False, repair=False):
        """Gates, then (after a fresh inspection when re-applying) the
        mutation and its verification. The same steps for every source."""
        attempt = self.attempt
        attempt.source = source
        gate = self.gate(target)
        if gate is not None:
            state, message, why = gate
            attempt.state, attempt.outcome, attempt.message = state, state, message
            attempt.next_action = attempt.next_action_at = None
            attempt.extra = {'why': why, 'release': self.release_signature(why)} if state == 'rejected' else {}
            if state == 'rejected' and target.source == 'panel':
                attempt.rejected = {'key': target.key, 'reason': message, 'why': why,
                                    'release': attempt.extra['release']}
            self.save_attempt()
            self.next_health = self.clock() + REFRESH_SEC
            return self.inspect()
        if attempt.rejected and attempt.rejected.get('key') == target.key:
            # Admitted again (what refused it changed): no longer refused.
            attempt.rejected = None
        attempt.extra = {}
        if reinspect or repair:
            finding = self.measurement = self.measure()
            if finding['server'] == target.server:
                if finding['status'] == 'ok':
                    attempt.settle()
                    self.save_attempt()
                    self.on_verified(target.server)
                    self.next_health = self.clock() + REFRESH_SEC
                    return self.emit(finding)
                if not (repair and self.handshake_stale(finding)):
                    attempt.state, attempt.outcome, attempt.message = 'unverified', 'applied-unverified', None
                    attempt.next_action, attempt.next_action_at = 'recheck', self.clock() + REFRESH_SEC
                    self.save_attempt()
                    self.next_health = self.clock() + REFRESH_SEC
                    return self.emit(finding)
                print('applier: the registration lapsed; registering the same server again', flush=True)
                # Repairs pace themselves on the backoff too (D15).
                attempt.backoff_step += 1
        return self.mutate(target)

    def mutate(self, target):
        attempt = self.attempt
        relay = self.catalog.relays[target.server]
        try:
            keys = self.peers()
            current = self.server_for(keys)
        except (RuntimeError, ValueError, UnicodeError):
            attempt.state, attempt.outcome = 'pending', 'pending'
            attempt.message = 'Waiting for the WireGuard interface; request will retry automatically.'
            self.save_attempt()
            return self.inspect()
        self.before_mutation(target)
        attempt.state, attempt.outcome, attempt.message = 'attempting', None, None
        attempt.attempts += 1
        attempt.last_mutation_at = self.clock()
        attempt.mutation_certainty = 'uncertain'
        attempt.next_action = attempt.next_action_at = None
        attempt.generation = self.current_generation() or attempt.generation
        # Recorded before any I/O: a lost response can hide success.
        self.save_attempt()
        self.publish('applying', 'Applying the requested server.', server=current)
        try:
            self.apply_relay(relay, keys)
        except CredentialRejected:
            attempt.state, attempt.outcome, attempt.mutation_certainty = 'rejected', 'rejected', 'definite'
            attempt.message = self.credentials_message()
            attempt.extra = {'why': 'credentials', 'release': self.release_signature('credentials')}
            if target.source == 'panel':
                attempt.rejected = {'key': target.key, 'reason': attempt.message, **attempt.extra}
            self.save_attempt()
            self.next_health = self.clock() + REFRESH_SEC
            return self.inspect()
        except (RuntimeError, ValueError, UnicodeError) as exc:
            attempt.state, attempt.outcome = 'failed', 'mutation-failed'
            attempt.mutation_certainty = 'definite' if isinstance(exc, MutationRefused) else 'uncertain'
            attempt.message = self.mutation_failed_message()
            attempt.schedule('reapply', self.clock())
            self.save_attempt()
            # The target may be live all the same: the check says so.
            return self.check()
        return self.verify(target)

    def before_mutation(self, target):
        """Just before the mutation's I/O (gluetun records its selection)."""

    def mutation_failed_message(self):
        return 'Peer update failed; retrying automatically.'

    def credentials_message(self):
        return f'{self.spec.label} refused the login; correct the credentials, or retry.'

    def verify(self, target):
        """Inspect until the target verifies or the provider's timeout. A lost
        protective guard aborts. At the timeout, a live target is applied but
        unverified (re-checked, D7); anything else is a failed attempt."""
        attempt = self.attempt
        deadline = self.switch_deadline = self.clock() + self.switch_timeout
        finding = None
        try:
            while self.clock() < deadline:
                finding = self.measurement = self.measure(applying=True)
                if finding['status'] == 'ok' and finding['server'] == target.server:
                    attempt.settle()
                    self.save_attempt()
                    self.on_applied(target.server)
                    self.on_verified(target.server)
                    self.next_health = self.clock() + REFRESH_SEC
                    return self.emit(finding)
                if not finding['safe']:
                    attempt.state, attempt.outcome = 'failed', 'mutation-failed'
                    attempt.message = 'Routing changed during the switch; retrying after recovery.'
                    attempt.schedule('reapply', self.clock())
                    self.save_attempt()
                    self.next_health = self.clock() + REFRESH_SEC
                    return self.emit(finding)
                self.emit(finding, applying=True)
                self.sleep(3)
        finally:
            self.switch_deadline = None
        # The loop's last inspection, seconds old, decides; measuring again
        # would only wait out the same answers.
        if finding is None:
            finding = self.measurement = self.measure()
        if finding['server'] == target.server:
            self.on_applied(target.server)
            if finding['status'] == 'ok':
                attempt.settle()
                self.on_verified(target.server)
            else:
                attempt.state, attempt.outcome, attempt.message = 'unverified', 'applied-unverified', None
                attempt.next_action, attempt.next_action_at = 'recheck', self.clock() + REFRESH_SEC
        else:
            attempt.state, attempt.outcome = 'failed', 'mutation-failed'
            attempt.message = 'Switch verification timed out; retrying automatically.'
            attempt.schedule('reapply', self.clock())
        self.save_attempt()
        self.next_health = self.clock() + REFRESH_SEC
        return self.emit(finding)

    # -- reporting ---------------------------------------------------------------------

    def assess(self, result, *, now=None):
        """This applier's verdict on a record, against its own target."""
        return assess(self.exit_config, result, self.resolve(peek=True), now)

    def push_gatus(self, result):
        """Push the verdict, not the raw status. Never `applying`: a switch in
        progress, or a request that arrived while one ran, isn't a sample."""
        base, token = os.environ.get('GATUS_URL', ''), os.environ.get('GATUS_TOKEN', '')
        if not base or not token:
            return
        endpoint = urllib.parse.quote(os.environ.get('GATUS_ENDPOINT', 'molebridge'), safe='')
        if not base.startswith(('http://', 'https://')) or any(c in token for c in '\r\n'):
            return
        verdict = self.assess(result)
        if verdict.state == 'applying':
            return
        success = verdict.state == 'ok'
        error = '' if success else (verdict.message or result.get('message') or verdict.label)
        query = urllib.parse.urlencode({'success': str(success).lower(), 'error': error})
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
        """Fixed labels and results for `--doctor`; no addresses or names. The
        last line is the verdict against this applier's own target, with its
        reason codes when it fails."""
        result = read_json(self.result_path, 16384)
        checks = {'recent applier check': isinstance(result, dict) and recent(result.get('checked_at'))}
        if self.kind == 'overlay':
            checks['routing protection'] = self.routing_status()[0]
            checks['NetBird kernel WireGuard and kernel firewall'] = self.netbird_native()
        checks['fresh relay catalogue'] = self.catalog.usable()
        checks.update(self.backend_checks())
        verdict = self.assess(result)
        label = f'verified {self.spec.label} egress'
        if verdict.state != 'ok':
            label = (label + ' - ' + ', '.join(verdict.reasons or (verdict.label,)))[:100]
        checks[label] = verdict.state == 'ok'
        return checks

    def backend_checks(self):
        return {}

    def healthy(self):
        """The container health check, operational only (D5): a fresh
        completed check, ok or failed, and an intact namespace for the kind.
        Whether the exit is verified is the verdict's, the doctor's and
        monitoring's question, never a reason to restart it. On the overlay
        a missing peer is the pipeline's to repair, not the health check's:
        killing the applier for it would only delay the repair."""
        result = read_json(self.result_path, 16384)
        completed = isinstance(result, dict) and result.get('status') in ('ok', 'failed')
        if not completed or not recent(result.get('checked_at')):
            return False
        if self.kind == 'sidecar':
            return self.control_answers() and len(self.peers()) == 1
        self.peers()  # the tunnel interface exists
        return self.routing_status()[0] and self.netbird_native()

    def control_answers(self):
        return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--healthcheck', action='store_true')
    parser.add_argument('--doctor', action='store_true')
    args = parser.parse_args()
    directory = Path(os.environ.get('STATE_DIR', '/state'))
    try:
        spec = providers.from_env(os.environ)
        config = RoutingConfig.from_env(os.environ)
        # Refuses a sidecar with a native provider, at start.
        ExitConfig(spec.id, config.kind)
        if spec.applier == 'applier.apply:Applier':
            applier = Applier(directory, config, server=os.environ.get('SERVER', ''))
        else:
            applier = spec.applier_class().from_env(directory, config, os.environ)
        if config.backend == 'wireguard':
            applier.owner_path = Path(os.environ.get('OWNER_RECORD', '/run/molebridge/exit-owner'))
        if args.healthcheck:
            try:
                return 0 if applier.healthy() else 1
            except (OSError, ValueError, RuntimeError):
                # No tunnel interface, or no readable state: unhealthy.
                return 1
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

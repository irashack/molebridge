"""The applier for the gluetun backend (compose.gluetun.yaml): gluetun owns the
tunnel, and this applier selects servers through gluetun's control server.

- Catalogue: gluetun's own server list, read from a read-only mount of its
  storage directory (GLUETUN_SERVERS_FILE), never downloaded. The file is
  untrusted: molebridge/gluetun_catalog.py reads it with the same limits as
  a download, and a file that fails (gluetun truncates it while writing)
  keeps the last good catalogue. The snapshot carries the provider data's
  own date (`data_timestamp`) besides when it was read.
- Switch: PUT /v1/vpn/settings with the server's exact hostname filter and
  every other filter cleared (applier/gluetun.py). gluetun then restarts its
  VPN loop in-process: its interface disappears and comes back, and the
  guard sidecar puts the exit route back. Those transitions are not
  failures; only the switch timeout is.
- Success needs what it needs on the default backend: exactly one peer whose
  endpoint and key identify the selected server (`wg show <if> endpoints`,
  gluetun_catalog.server_for_peer), a fresh handshake, intact routing guards
  including rules 88/89/91/92 and the host table, and egress at the
  provider's tier: Mullvad's and NordVPN's own checks through the tunnel
  where the provider has one, the tunnel checks otherwise.
- The selection Molebridge last put, the last one live after a PUT and the
  last one verified are kept in state/applier/gluetun-selection.json. gluetun
  starts from its environment (GLUETUN_SERVER_*), not from what was put at
  runtime. Without SERVER or an accepted panel request, the last verified
  server is the target (`restore`), and the admission pipeline puts it back
  like any other drift (applier/apply.py). A tunnel-tier sidecar is never
  verified, so it restores the last one live after a PUT.
- While a switch is verified, gluetun's reconnection states withhold
  readiness without aborting it; anything else the protective predicate
  refuses does (`molebridge.routing.gluetun_transition_status`).
- With EXIT_KIND=sidecar there is no routing contract and no NetBird:
  traffic protection is gluetun's firewall, and which containers use the
  tunnel is the host doctor's check (tools/molebridge.py).

The API key (GLUETUN_API_KEY_FILE, mode 0600) is full gluetun
administration; only this container mounts it. gluetun's control server
listens on the namespace's loopback.
"""
from __future__ import annotations

import functools
import http.client
import io
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from applier.apply import ROUTING_FAILED, NETBIRD_MODE_FAILED, Applier, Selection, command
from applier.gluetun import GluetunClient
from applier.nordvpn import NordApplier
from molebridge import gluetun_catalog, providers
from molebridge.egress import ECHO_MAX_BYTES, ECHO_URLS, parse_echo
from molebridge.relays import RelayCatalog, snapshot_limit
from molebridge.routing import (RETURN_PATH_SYSCTL, control_mark_value, family_status, gluetun_transition_status,
                                host_table_status, return_path_enabled)
from molebridge.state import SWITCH_TIMEOUTS, decode_json, now_iso, read_json, write_json_atomic

DEFAULT_CONTROL_URL = 'http://127.0.0.1:8000'
DEFAULT_API_KEY_FILE = '/run/secrets/gluetun/api_key'
DEFAULT_SERVERS_FILE = '/gluetun-servers/servers.json'
# gluetun restarts its VPN loop on a settings change: the interface goes and
# comes back, then the handshake and the egress checks follow.
GLUETUN_SWITCH_TIMEOUT_SEC = SWITCH_TIMEOUTS['gluetun']
# The server list is checked for changes this often and read again at least
# every CATALOG_REREAD_SEC, so a fresh read never ages past the 24-hour rule.
CATALOG_POLL_SEC = 60
CATALOG_REREAD_SEC = 6 * 60 * 60
DATA_STALE_SEC = gluetun_catalog.DATA_STALE_SEC
# One refresh of gluetun's server list after the applier starts, when the
# data is older than gluetun's updater period or than this, whichever is
# shorter: gluetun's own updater first runs one period after gluetun starts,
# and its built-in data can be years old.
UPDATE_IF_OLDER_SEC = 7 * 24 * 60 * 60
UPDATE_ATTEMPTS = 3
# A WireGuard handshake this recent means the tunnel answers. WireGuard
# renews it every two minutes while traffic flows.
UPDATE_HANDSHAKE_SEC = 150
UPDATE_RETRY_SEC = 5 * 60
# A run that hasn't finished by then counts as failed.
UPDATE_TIMEOUT_SEC = 15 * 60
DEFAULT_UPDATER_PERIOD = '24h'


def updater_period(value):
    """Seconds in gluetun's UPDATER_PERIOD (a Go duration such as 24h or
    1h30m; 0 turns the updater off), or ValueError."""
    if value in ('0', '0s'):
        return 0
    match = re.fullmatch(r'(?:([0-9]{1,4})h)?(?:([0-9]{1,4})m)?(?:([0-9]{1,6})s)?', value or '')
    if not value or match is None:
        raise ValueError('invalid GLUETUN_UPDATER_PERIOD')
    hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return hours * 3600 + minutes * 60 + seconds
# Linux's SO_MARK; Python names it only where the platform has it.
SO_MARK = getattr(socket, 'SO_MARK', 36)
SELECTION_KEYS = ('desired', 'last_put', 'last_applied', 'last_successful')
# A snapshot taken while gluetun's interface changes underneath is taken
# again, at most this many times; meanwhile the exit isn't ready.
TRANSITION_SAMPLES = 3


def iso(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class GluetunCatalog(RelayCatalog):
    """The applier's catalogue from gluetun's servers.json."""

    def __init__(self, directory: Path, provider, source: Path, *, clock=time.time):
        super().__init__(directory, provider)
        self.source, self.wallclock = Path(source), clock
        self.gluetun_provider = providers.get(provider).gluetun_provider
        self.signature = None
        self.read_at = None

    def refresh(self, fetch=None):
        """Read gluetun's file when it changed or the last read is getting old.
        `fetch` is ignored: nothing is downloaded."""
        try:
            info = os.stat(self.source, follow_symlinks=False)
            signature = (info.st_ino, info.st_size, info.st_mtime_ns)
            now = self.wallclock()
            if (signature == self.signature and self.read_at is not None
                    and now - self.read_at < CATALOG_REREAD_SEC and self.usable()):
                return True
            relays, timestamp = gluetun_catalog.read_gluetun_snapshot(self.source, self.gluetun_provider, now=now)
            entries = {}
            for server_id, relay in relays.items():
                entry = gluetun_catalog.validate_entry(gluetun_catalog.snapshot_entry(relay))
                if entry is not None and entry['hostname'] == server_id:
                    entries[server_id] = entry
            if not entries:
                raise ValueError('gluetun catalogue is empty')
            snapshot = {'fetched_at': now_iso(), 'provider': self.provider, 'source': 'gluetun',
                        'data_timestamp': iso(timestamp), 'relays': entries}
            write_json_atomic(self.path, snapshot, public=True, max_bytes=snapshot_limit(self.provider))
            self.snapshot, self.relays = snapshot, entries
            self.signature, self.read_at = signature, now
            write_json_atomic(self.error_path, {}, public=True)
            return True
        except (OSError, ValueError, RuntimeError, UnicodeError, RecursionError, OverflowError):
            # Never log the file's content, paths or exception bodies.
            write_json_atomic(self.error_path, {'message': "gluetun's server list is missing or invalid; "
                                                           'retaining the last good catalogue.',
                                                'checked_at': now_iso()}, public=True)
            return False


def _remaining(deadline):
    """Seconds left before `deadline` (time.monotonic), or TimeoutError."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError('echo deadline passed')
    return left


class _DeadlineReader(io.RawIOBase):
    """A socket's raw input stream where every read gets only the time left.
    It owns the stream, which keeps the socket open after the connection
    object closes its own reference, as http.client does for a response
    that ends the connection."""

    def __init__(self, sock, raw, deadline):
        super().__init__()
        self._sock, self._raw, self._deadline = sock, raw, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        self._sock.settimeout(_remaining(self._deadline))
        return self._raw.readinto(buffer)

    def close(self):
        if not self.closed:
            self._raw.close()
        super().close()


class _DeadlineResponse(http.client.HTTPResponse):
    def __init__(self, sock, *args, deadline, **kwargs):
        super().__init__(sock, *args, **kwargs)
        # Keep http.client's stream underneath; only its reads change.
        self.fp = io.BufferedReader(_DeadlineReader(sock, self.fp.detach(), deadline))


def _resolve(host, port, family, deadline):
    """getaddrinfo within the time left: a lookup still running at the
    deadline is left to finish on its own thread and the caller fails."""
    found = {}

    def lookup():
        try:
            found['addresses'] = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        except OSError as exc:
            found['error'] = exc
    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(_remaining(deadline))
    if worker.is_alive():
        raise TimeoutError('echo deadline passed')
    if 'error' in found:
        raise found['error']
    return found['addresses']


class _MarkedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS from a socket carrying `mark`, one address family only. The
    name lookup, every address tried, the TLS handshake, the request and each
    read get only the time left before `deadline`, so the whole exchange ends
    by then."""

    def __init__(self, host, family, mark, deadline):
        super().__init__(host, 443, timeout=_remaining(deadline), context=ssl.create_default_context())
        self._family, self._mark, self._deadline = family, mark, deadline
        self.response_class = functools.partial(_DeadlineResponse, deadline=deadline)

    def connect(self):
        family = socket.AF_INET if self._family == 4 else socket.AF_INET6
        for af, kind, proto, _name, address in _resolve(self.host, self.port, family, self._deadline)[:4]:
            sock = socket.socket(af, kind, proto)
            try:
                sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self._mark)
                sock.settimeout(_remaining(self._deadline))
                sock.connect(address)
                sock.settimeout(_remaining(self._deadline))
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            except TimeoutError:
                sock.close()
                raise
            except ssl.SSLError:
                sock.close()
                raise
            except OSError:
                sock.close()
                continue
            self.sock.settimeout(_remaining(self._deadline))
            return
        raise OSError('no address answered')


def marked_echo(url, family, mark, *, timeout=10):
    """An IP echo service's answer over the host's own route, from a socket
    carrying NetBird's control mark. In gluetun's namespace every unmarked
    socket goes into the tunnel (gluetun's rule 101), so this is the one way
    to measure the host's own address there: rule 88 sends the mark to the
    host table, and the post-rules accept output on HOST_IF. Needs NET_ADMIN,
    which the applier holds. The whole exchange ends within `timeout`
    seconds. Errors are RuntimeError, with no detail."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.port or parts.username or parts.query:
        raise RuntimeError('invalid echo URL')
    connection = None
    try:
        connection = _MarkedHTTPSConnection(parts.hostname, family, mark, time.monotonic() + timeout)
        connection.request('GET', parts.path or '/', headers={'User-Agent': 'molebridge-applier',
                                                               'Accept': 'text/plain'})
        response = connection.getresponse()
        body = response.read(ECHO_MAX_BYTES + 1)
        if response.status != 200 or len(body) > ECHO_MAX_BYTES:
            raise RuntimeError('echo failed')
        return body.decode('ascii')
    except (OSError, http.client.HTTPException, ssl.SSLError, UnicodeError):
        raise RuntimeError('echo failed') from None
    finally:
        if connection is not None:
            connection.close()


class GluetunApplier(Applier):
    """One subclass per registry entry (below) sets `provider`."""
    provider = ''
    switch_timeout = GLUETUN_SWITCH_TIMEOUT_SEC
    # NordVPN's typed egress check, reused as is for gluetun-nordvpn.
    insights = NordApplier.insights
    endpoints = NordApplier.endpoints

    def __init__(self, state_dir: Path, config, *, client, servers_file=DEFAULT_SERVERS_FILE, fetch_marked=None,
                 wallclock=time.time, updater_period_s=24 * 60 * 60, **kwargs):
        if not config.gluetun:
            raise ValueError('the gluetun applier needs TUNNEL_BACKEND=gluetun')
        self.servers_file, self.wallclock = Path(servers_file), wallclock
        super().__init__(state_dir, config, **kwargs)
        self.client = client
        self.fetch_marked = fetch_marked or marked_echo
        self.selection_path = self.directory / 'gluetun-selection.json'
        self.selection = self.load_selection()
        # The tunnel's addresses before the switch being verified: its rule
        # 94 may linger while gluetun reconnects.
        self.previous_addresses = {}
        # The one refresh of gluetun's server list this process may start:
        # None (not needed or not yet), 'updating', 'done' or 'failed'.
        self.update_threshold = min(UPDATE_IF_OLDER_SEC, updater_period_s) if updater_period_s else None
        self.update_state = None
        self.update_attempts = 0
        self.update_started = None
        self.next_update = 0

    @classmethod
    def from_env(cls, state_dir, config, env, **kwargs):
        client = GluetunClient(env.get('GLUETUN_CONTROL_URL') or DEFAULT_CONTROL_URL,
                               env.get('GLUETUN_API_KEY_FILE') or DEFAULT_API_KEY_FILE)
        return cls(state_dir, config, client=client,
                   servers_file=env.get('GLUETUN_SERVERS_FILE') or DEFAULT_SERVERS_FILE,
                   updater_period_s=updater_period(env.get('GLUETUN_UPDATER_PERIOD') or DEFAULT_UPDATER_PERIOD),
                   server=env.get('SERVER', ''),
                   **kwargs)

    def make_catalog(self):
        return GluetunCatalog(self.directory, self.provider, self.servers_file, clock=self.wallclock)

    def fetch_catalog(self):
        raise ValueError('with gluetun the server list is read from gluetun, not downloaded')

    # -- selection state --------------------------------------------------

    def load_selection(self):
        raw = read_json(self.selection_path, 4096)
        raw = raw if isinstance(raw, dict) else {}
        return {key: raw[key] if self.spec.valid_server_name(raw.get(key)) else None for key in SELECTION_KEYS}

    def save_selection(self, **changes):
        self.selection.update(changes)
        write_json_atomic(self.selection_path, self.selection)

    def put(self, relay):
        """Ask gluetun for exactly this server. Records it before the result
        is known: gluetun may apply a selection whose answer is lost."""
        self.save_selection(last_put=relay['hostname'])
        self.client.select_server(relay)

    def restore_target(self):
        """The server to put back when nothing else selects one."""
        key = 'last_successful'
        if self.kind == 'sidecar' and self.spec.egress_tier == 'tunnel':
            key = 'last_applied'
        server = self.selection.get(key)
        return Selection(server, 'restore') if server else None

    def before_mutation(self, target):
        if target.source in ('panel', 'operator-retry'):
            self.save_selection(desired=target.server)
        try:
            self.previous_addresses = self.tunnel_addresses(require_ipv4=False)
        except (RuntimeError, ValueError, UnicodeError):
            self.previous_addresses = {}

    def on_applied(self, server):
        if self.selection.get('last_applied') != server:
            self.save_selection(last_applied=server)

    def on_verified(self, server):
        if self.selection.get('last_successful') != server:
            self.save_selection(last_successful=server)

    def mutation_failed_message(self):
        return 'gluetun did not accept the server selection; retrying automatically.'

    def waiting_message(self):
        return 'Waiting for gluetun to connect to the requested server.'

    def control_answers(self):
        try:
            return self.client.vpn_status() in ('running', 'starting', 'stopping', 'stopped', 'crashed',
                                                'completed')
        except (RuntimeError, ValueError):
            return False

    # -- the provider seam -------------------------------------------------


    def server_for(self, keys):
        if len(keys) != 1:
            return None
        return gluetun_catalog.server_for_peer(self.catalog.relays, keys[0], self.endpoints().get(keys[0]))

    def apply_relay(self, relay, keys):
        self.put(relay)

    def egress_for(self, server, handshake_age):
        if self.spec.egress_check == 'nordvpn':
            return NordApplier.egress_for(self, server, handshake_age)
        if self.spec.egress_check == 'mullvad':
            return Applier.egress(self)
        if self.kind == 'sidecar':
            return self.unmeasurable_egress()
        return self.tunnel_egress(server, handshake_age)

    def unmeasurable_egress(self):
        """A tunnel-tier provider in a sidecar: in plain gluetun's namespace
        nothing leaves off the tunnel, so the host's own address can't be
        measured and the tunnel checks can't pass. The tunnel's address is
        still read, for display, from one echo service."""
        addresses = {}
        for family in sorted(self.tunnel_addresses()):
            try:
                addresses[str(family)] = self.echo(ECHO_URLS[family][0], family, tunnel=True)
            except (RuntimeError, ValueError, UnicodeError):
                continue
        return {'egress_ip': addresses.get('4'), 'egress_city': None, 'egress_country': None,
                'exit_confirmed': False, 'egress_tier': None, 'egress_ips': addresses, 'families': {},
                'reason': 'host-address-not-measurable',
                'message': "Switched; the egress couldn't be compared with this host's address."}

    def echo(self, url, family, *, tunnel):
        if tunnel:
            return super().echo(url, family, tunnel=True)
        return parse_echo(self.fetch_marked(url, family, control_mark_value(self.config.control_mark)), family)

    def tunnel_state(self):
        """(addresses by family, whether the interface is up), or (None, False)
        while gluetun has no tunnel interface."""
        try:
            links = decode_json(self.run(['ip', '-j', 'link', 'show', 'dev', self.config.exit_if]))
        except RuntimeError:
            return None, False
        if not isinstance(links, list) or len(links) != 1 or not isinstance(links[0], dict):
            raise ValueError('invalid tunnel interface')
        flags = links[0].get('flags')
        up = isinstance(flags, list) and 'UP' in flags
        try:
            return self.tunnel_addresses(require_ipv4=False), up
        except RuntimeError:
            return None, False

    def routing_status(self, *, require_address=True, owner=True):
        """(protected, fallback) for gluetun's namespace: the whole guard in
        both families, including the host table. gluetun's interface coming
        and going is not a routing failure: without it, or while it is down,
        no tunnel route belongs in the exit table and the fallback holds."""
        checks = []
        try:
            self.run(['ip', 'link', 'show', 'dev', self.config.overlay_if])
            addresses, up = self.tunnel_state()
            return_path = return_path_enabled(self.run(['cat', RETURN_PATH_SYSCTL]))
            for family in (4, 6):
                rules = decode_json(self.run(['ip', '-j', f'-{family}', 'rule', 'show']))
                routes = decode_json(self.run(['ip', '-j', f'-{family}', 'route', 'show', 'table', self.config.table]))
                host = decode_json(self.run(['ip', '-j', f'-{family}', 'route', 'show', 'table',
                                             self.config.host_table]))
                main = decode_json(self.run(['ip', '-j', f'-{family}', 'route', 'show', 'table', 'main']))
                protected, fallback = family_status(rules, routes, self.config, family,
                                                    tunnel_address=(addresses or {}).get(family), tunnel_route=up)
                checks.append((protected and host_table_status(host, self.config, family, main=main), fallback))
            return return_path and all(c[0] for c in checks), all(c[1] for c in checks)
        except (RuntimeError, ValueError, UnicodeError):
            return False, False

    def link_state(self):
        """(present, up, ifindex) of the tunnel interface."""
        try:
            links = decode_json(self.run(['ip', '-j', 'link', 'show', 'dev', self.config.exit_if]))
        except RuntimeError:
            return False, False, None
        if not isinstance(links, list) or len(links) != 1 or not isinstance(links[0], dict):
            raise ValueError('invalid tunnel interface')
        flags = links[0].get('flags')
        return True, isinstance(flags, list) and 'UP' in flags, links[0].get('ifindex')

    def transition_status(self):
        """(safe, ready) while a switch is verified, by the protective
        predicate. The interface, addresses and rules are read separately, so
        a sample is taken again when the interface changed during it (its
        presence or ifindex differ before and after, or it is present with
        detached rules); after TRANSITION_SAMPLES such samples the exit is
        safe so far and not ready."""
        for _ in range(TRANSITION_SAMPLES):
            before = self.link_state()
            self.run(['ip', 'link', 'show', 'dev', self.config.overlay_if])
            present, up, _ = before
            addresses = {}
            if present:
                try:
                    addresses = self.tunnel_addresses(require_ipv4=False)
                except RuntimeError:
                    addresses = None
            return_path = return_path_enabled(self.run(['cat', RETURN_PATH_SYSCTL]))
            snapshot = {}
            for family in (4, 6):
                rules = decode_json(self.run(['ip', '-j', f'-{family}', 'rule', 'show']))
                routes = decode_json(self.run(['ip', '-j', f'-{family}', 'route', 'show', 'table', self.config.table]))
                host = decode_json(self.run(['ip', '-j', f'-{family}', 'route', 'show', 'table',
                                             self.config.host_table]))
                main = decode_json(self.run(['ip', '-j', f'-{family}', 'route', 'show', 'table', 'main']))
                snapshot[family] = rules, routes, host, main
            after = self.link_state()
            detached = present and any(isinstance(r, dict) and ('iif_detached' in r or 'oif_detached' in r)
                                       for rules, *_ in snapshot.values() if isinstance(rules, list) for r in rules)
            if before != after or addresses is None or detached:
                continue
            safe = ready = return_path
            for family, (rules, routes, host, main) in snapshot.items():
                family_safe, family_ready = gluetun_transition_status(
                    rules, routes, self.config, family, tunnel_address=addresses.get(family),
                    previous_address=self.previous_addresses.get(family), interface_present=present,
                    interface_up=up)
                safe = safe and family_safe
                ready = ready and family_ready and host_table_status(host, self.config, family, main=main)
            return safe, ready
        return True, False

    def measure_guards(self, checks, at, finding):
        if self.switch_deadline is None:
            return super().measure_guards(checks, at, finding)
        try:
            safe, ready = self.transition_status()
        except (RuntimeError, ValueError, UnicodeError):
            safe = ready = False
        native = self.netbird_native()
        checks['routing'] = {'state': 'pass' if ready else 'fail', 'at': at, 'fallback': safe}
        if safe and not ready:
            checks['routing']['reason'] = 'reconnecting'
        checks['traffic_protection'] = {'state': checks['routing']['state'], 'at': at, 'from': 'routing'}
        checks['netbird'] = {'state': 'pass' if native else 'fail', 'at': at}
        finding['safe'] = safe and native
        if not ready:
            finding['guard'] = ROUTING_FAILED
        elif not native:
            finding['guard'] = NETBIRD_MODE_FAILED

    def tunnel_works(self):
        """gluetun's tunnel carries traffic now: one peer with a handshake
        in the last UPDATE_HANDSHAKE_SEC. gluetun's VPN status says 'running'
        while it still tries servers that don't answer, so the update waits
        for this instead of starting into a tunnel that fails."""
        try:
            keys = self.peers()
            age = self.handshake_age(keys[0]) if len(keys) == 1 else None
        except (RuntimeError, ValueError, UnicodeError):
            return False
        return age is not None and age < UPDATE_HANDSHAKE_SEC

    def update_servers(self):
        """Start one refresh of gluetun's server list when its data is old
        and gluetun's tunnel works, and follow it. gluetun's updater fetches the provider's public list
        through the tunnel, from gluetun's own process, and doesn't restart
        the VPN. Bounded: UPDATE_ATTEMPTS starts per applier process, each
        given UPDATE_TIMEOUT_SEC. The new data reaches the catalogue through
        its usual re-read when the file changes."""
        if self.update_threshold is None or self.update_state in ('done', 'failed'):
            return
        now = self.clock()
        if self.update_state == 'updating':
            try:
                status = self.client.updater_status()
            except (RuntimeError, ValueError):
                status = None
            if status == 'completed':
                self.update_state = 'done'
                self.next_catalog = 0
                print("applier: gluetun's server list update finished", flush=True)
                return
            if status in ('starting', 'running') and now - self.update_started < UPDATE_TIMEOUT_SEC:
                return
            self.update_state = None
            self.next_update = now + UPDATE_RETRY_SEC
            print("applier: gluetun's server list update failed", flush=True)
            if self.update_attempts >= UPDATE_ATTEMPTS:
                self.update_state = 'failed'
            return
        if now < self.next_update:
            return
        age = data_age(self.catalog.snapshot.get('data_timestamp'), self.wallclock())
        if not self.catalog.relays or (age is not None and age <= self.update_threshold):
            # Nothing read yet (gluetun hasn't written the file), or fresh enough.
            if self.catalog.relays:
                self.update_state = 'done'
            return
        if not self.tunnel_works():
            return
        try:
            if self.client.vpn_status() != 'running':
                return
            self.update_attempts += 1
            self.client.start_update()
        except (RuntimeError, ValueError):
            self.next_update = now + UPDATE_RETRY_SEC
            if self.update_attempts >= UPDATE_ATTEMPTS:
                self.update_state = 'failed'
            return
        self.update_state, self.update_started = 'updating', now
        self.next_health = 0
        print("applier: asked gluetun to update its server list", flush=True)

    def publish(self, status, message, *, server=None, **fields):
        fields.setdefault('server_list_update', self.update_state if self.update_state in ('updating', 'failed')
                          else None)
        return super().publish(status, message, server=server, **fields)

    def maintain_catalog(self):
        # gluetun's own list, checked every minute (the base would wait six
        # hours after a refresh).
        self.update_servers()
        if self.clock() >= self.next_catalog:
            self.catalog.refresh()
            self.next_catalog = self.clock() + CATALOG_POLL_SEC

    def backend_checks(self):
        checks = {"gluetun's control server answers with the API key": self.control_answers()}
        data = self.catalog.snapshot.get('data_timestamp')
        age = data_age(data, self.wallclock())
        checks["gluetun's server data less than 30 days old"] = age is not None and age <= DATA_STALE_SEC
        return checks


def data_age(value, now):
    """Seconds since gluetun's provider data was dated, or None."""
    if not isinstance(value, str):
        return None
    try:
        when = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    return now - when if when <= now else None


# One class per registry entry, so each knows its own registry id.
for _spec in providers.REGISTRY.values():
    if _spec.backend == 'gluetun':
        _module, _, _name = _spec.applier.partition(':')
        globals()[_name] = type(_name, (GluetunApplier,), {'provider': _spec.id, '__module__': __name__})
del _spec, _module, _name

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
- The selection Molebridge last put and the last one verified are kept in
  state/applier/gluetun-selection.json. gluetun starts from its environment
  (GLUETUN_SERVER_*), not from what was put at runtime; when the live server
  is not the one last put, and no pending request of the panel's covers it,
  the last verified one is put again.

The API key (GLUETUN_API_KEY_FILE, mode 0600) is full gluetun
administration; only this container mounts it. gluetun's control server
listens on the namespace's loopback.
"""
from __future__ import annotations

import http.client
import os
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from applier.apply import Applier, command
from applier.gluetun import GluetunClient
from applier.nordvpn import NordApplier
from molebridge import gluetun_catalog, providers
from molebridge.egress import ECHO_MAX_BYTES, parse_echo
from molebridge.relays import RelayCatalog, snapshot_limit
from molebridge.routing import (RETURN_PATH_SYSCTL, control_mark_value, family_status, host_table_status,
                                return_path_enabled)
from molebridge.state import decode_json, desired_request, now_iso, read_json, request_token, write_json_atomic

DEFAULT_CONTROL_URL = 'http://127.0.0.1:8000'
DEFAULT_API_KEY_FILE = '/run/secrets/gluetun/api_key'
DEFAULT_SERVERS_FILE = '/gluetun-servers/servers.json'
# gluetun restarts its VPN loop on a settings change: the interface goes and
# comes back, then the handshake and the egress checks follow.
GLUETUN_SWITCH_TIMEOUT_SEC = 90
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
SELECTION_KEYS = ('desired', 'last_put', 'last_successful')


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


class _MarkedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS from a socket carrying `mark`, one address family only."""

    def __init__(self, host, family, mark, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self._family, self._mark = family, mark

    def connect(self):
        family = socket.AF_INET if self._family == 4 else socket.AF_INET6
        for af, kind, proto, _name, address in socket.getaddrinfo(self.host, self.port, family,
                                                                   socket.SOCK_STREAM)[:4]:
            sock = socket.socket(af, kind, proto)
            try:
                sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self._mark)
                sock.settimeout(self.timeout)
                sock.connect(address)
            except OSError:
                sock.close()
                continue
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            return
        raise OSError('no address answered')


def marked_echo(url, family, mark, *, timeout=10):
    """An IP echo service's answer over the host's own route, from a socket
    carrying NetBird's control mark. In gluetun's namespace every unmarked
    socket goes into the tunnel (gluetun's rule 101), so this is the one way
    to measure the host's own address there: rule 88 sends the mark to the
    host table, and the post-rules accept output on HOST_IF. Needs NET_ADMIN,
    which the applier holds. Errors are RuntimeError, with no detail."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.port or parts.username or parts.query:
        raise RuntimeError('invalid echo URL')
    connection = _MarkedHTTPSConnection(parts.hostname, family, mark, timeout)
    try:
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
        connection.close()


class GluetunApplier(Applier):
    """One subclass per registry entry (below) sets `provider`."""
    provider = ''
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
        # The clock time of the last PUT; a restore waits a full switch
        # timeout after it, so a reconnect in progress is never mistaken for
        # gluetun having reverted.
        self.last_put_at = None
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
        self.last_put_at = self.clock()
        self.client.select_server(relay)

    # -- the provider seam -------------------------------------------------

    def result_defaults(self):
        return {'mullvad_exit_ip': False} if self.spec.egress_check == 'mullvad' else {}

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
        return self.tunnel_egress(server, handshake_age)

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

    def routing_status(self, *, require_address=True):
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
        # While a switch is being verified, gluetun restarting its tunnel is
        # expected: report it as switching, not as a failure.
        if (self.switch_deadline is not None and status == 'failed'
                and not self.rejection and not self.pending):
            status, message = 'applying', 'Waiting for gluetun to connect to the requested server.'
        fields.setdefault('server_list_update', self.update_state if self.update_state in ('updating', 'failed')
                          else None)
        return super().publish(status, message, server=server, **fields)

    def switch(self, request):
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
        routing_ok, fallback = self.routing_status()
        if not routing_ok:
            self.pending = ('Waiting for tunnel and overlay routing; request will retry automatically. '
                            'Run recovery if this persists.')
            return self.inspect()
        if not self.netbird_native():
            self.pending = ('Waiting for NetBird to run kernel WireGuard with its kernel firewall; '
                            'request will retry automatically.')
            return self.inspect()
        relay = self.catalog.relays[request['server']]
        try:
            current = self.server_for(self.peers())
        except (RuntimeError, ValueError, UnicodeError):
            current = None
        self.publish('applying', 'Applying the requested server.', server=current,
                     routing_ok=True, unreachable_fallback=fallback, netbird_native=True)
        self.save_selection(desired=request['server'])
        try:
            self.put(relay)
        except (RuntimeError, ValueError, UnicodeError):
            self.rejection = 'gluetun did not accept the server selection; choose a server again to retry.'
            return self.inspect()
        deadline = self.switch_deadline = self.clock() + GLUETUN_SWITCH_TIMEOUT_SEC
        try:
            while self.clock() < deadline:
                result = self.inspect(applying=True)
                if result['status'] == 'ok' and result['server'] == request['server']:
                    self.save_selection(last_successful=request['server'])
                    return result
                self.sleep(3)
            self.rejection = 'Switch verification timed out; choose a server again to retry.'
            return self.inspect()
        finally:
            self.switch_deadline = None

    def inspect(self, *, applying=False):
        result = super().inspect(applying=applying)
        if (result.get('status') == 'ok' and result.get('server')
                and result['server'] != self.selection.get('last_successful')
                and result['server'] == self.selection.get('last_put')):
            # A verified pass on the server last put, e.g. after a restore.
            self.save_selection(last_successful=result['server'])
        return result

    def restore(self):
        """Put the last verified server again when gluetun runs another one
        than Molebridge last put, as after gluetun restarts with its
        environment's selection. Only when the panel's request is absent or
        was refused: otherwise the request path applies the request again
        itself. Nothing happens until gluetun's peer can be identified, nor
        within a switch timeout of the last PUT."""
        target, last_put = self.selection.get('last_successful'), self.selection.get('last_put')
        if not target or target not in self.catalog.relays or not self.catalog.usable():
            return None
        if self.last_put_at is not None and self.clock() - self.last_put_at < GLUETUN_SWITCH_TIMEOUT_SEC:
            return None
        request = desired_request(read_json(self.desired_path, 4096), self.provider)
        # A request not yet handled, or handled and not refused, is the
        # request path's: it applies (or re-applies) the request itself.
        if request is not None and (request_token(request) != self.last_request or not self.rejection):
            return None
        try:
            live = self.server_for(self.peers())
        except (RuntimeError, ValueError, UnicodeError):
            return None
        if live is None or live == last_put:
            return None
        try:
            self.put(self.catalog.relays[target])
        except (RuntimeError, ValueError, UnicodeError):
            print('applier: gluetun did not accept the last verified server again', flush=True)
            return None
        print('applier: gluetun was not running the selected server; put the last verified one again', flush=True)
        self.next_health = 0
        return target

    def tick(self):
        # The catalogue is handled here, so the base tick never finds it due
        # (it would wait six hours after a refresh, not one minute).
        self.update_servers()
        if self.clock() >= self.next_catalog:
            self.catalog.refresh()
            self.next_catalog = self.clock() + CATALOG_POLL_SEC
        self.restore()
        return super().tick()

    def doctor_checks(self):
        checks = super().doctor_checks()
        try:
            answered = self.client.vpn_status() in ('running', 'starting', 'stopping', 'stopped', 'crashed',
                                                    'completed')
        except (RuntimeError, ValueError):
            answered = False
        checks["gluetun's control server answers with the API key"] = answered
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

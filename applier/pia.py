"""PIA: a key registered per server, a tunnel address per server, and an
optional forwarded port.

PIA has no account-wide WireGuard key. Each connection asks the chosen server
to accept the interface's public key (`addKey`, authenticated by a token that
the account login mints) and answers with that server's key and a tunnel
address valid only there. The applier therefore holds the PIA login and, on a
switch, sets the interface address and the priority-94 return-path rule as
well as the peer. The private key still never leaves the `wireguard`
container: registration needs only the public key.

The login, token and port-forwarding payload reach curl only through mode-0600
scratch files on the applier's tmpfs, never argv, logs or state files.
Registration and port forwarding verify the server's TLS name against PIA's
bundled CA, so a tampered region list can name an address but not
impersonate a PIA server.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import ipaddress
import os
import random
import re
import tempfile
from pathlib import Path

from applier.apply import HANDSHAKE_FRESH_SEC, Applier, command
from molebridge.relays import PIA_CN_RE, RelayCatalog, valid_ipv4, valid_key
from molebridge.state import decode_json, now_iso, read_json, write_json_atomic

PIA_TOKEN_URL = 'https://www.privateinternetaccess.com/api/client/v2/token'
# Answers from PIA's side whether the caller's address is a PIA exit.
PIA_STATUS_URL = 'https://www.privateinternetaccess.com/api/client/status'
PIA_CA = Path(__file__).resolve().with_name('pia-ca.rsa.4096.crt')
ADDKEY_PORT = 1337
FORWARD_API_PORT = 19999
# PIA tokens last 24 hours; mint a new one well before that.
TOKEN_MAX_AGE_SEC = 12 * 60 * 60
# A stale handshake re-registers the same region at most this often.
REREGISTER_SEC = 5 * 60
# PIA drops a forwarded port that is not re-bound within 15 minutes.
BIND_INTERVAL_SEC = 10 * 60
FORWARD_RETRY_SEC = 60
# A signature is valid for about two months; renew it long before.
SIGNATURE_MAX_AGE_SEC = 7 * 24 * 60 * 60
NFT_TABLE = 'molebridge_forward'
GUARD_TABLE = 'molebridge_guard'
# Tunnel-internal addresses PIA assigns; anything else is refused.
PRIVATE_V4 = tuple(ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
TOKEN_RE = re.compile(r'[A-Za-z0-9._~+/=-]{1,1024}')
SECRET_MAX_BYTES = 512
TRUE_WORDS, FALSE_WORDS = ('1', 'true', 'on', 'yes'), ('', '0', 'false', 'off', 'no')


def read_secret(path: Path) -> str:
    """One credential per file; one trailing newline tolerated, nothing else."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(SECRET_MAX_BYTES + 1)
    if len(raw) > SECRET_MAX_BYTES:
        raise ValueError('credential file too large')
    value = raw.decode('utf-8', errors='strict')
    value = value[:-1] if value.endswith('\n') else value
    value = value[:-1] if value.endswith('\r') else value
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid credential file')
    return value


@contextlib.contextmanager
def scratch(*values):
    """Mode-0600 files holding `values`, removed on exit, for curl's `@file`
    and `<file` inputs."""
    paths = []
    try:
        for value in values:
            fd, name = tempfile.mkstemp(prefix='.pia-')
            paths.append(name)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(value)
        yield paths
    finally:
        for name in paths:
            with contextlib.suppress(OSError):
                os.unlink(name)


def parse_flag(value, name):
    word = (value or '').strip().lower()
    if word in TRUE_WORDS:
        return True
    if word in FALSE_WORDS:
        return False
    raise ValueError(f'{name} must be on or off')


class PiaApplier(Applier):
    provider = 'pia'
    # The address arrives with each registration.
    address_before_switch = False

    def __init__(self, state_dir: Path, config, *, secrets_dir=Path('/run/secrets/pia'),
                 port_forward=False, forward_target=None, run=command, clock=None, sleep=None,
                 choose=random.SystemRandom().choice):
        # make_catalog, called by the base constructor, reads port_forward.
        self.port_forward = port_forward
        self.forward_target = forward_target
        kwargs = {k: v for k, v in (('clock', clock), ('sleep', sleep)) if v is not None}
        super().__init__(state_dir, config, run=run, **kwargs)
        self.secrets_dir = Path(secrets_dir)
        self.tunnel_path = self.directory / 'tunnel.json'
        self.choose = choose
        self.token = None
        self.token_at = None
        self.last_attempt = None
        self.last_result = None
        self.forward = None
        self.forward_error = None
        self.next_forward = 0
        self.nft_port = None
        self.forward_reconciled = False
        self.guard_installed = False

    @classmethod
    def from_env(cls, state_dir, config, env, **kwargs):
        port_forward = parse_flag(env.get('PIA_PORT_FORWARD'), 'PIA_PORT_FORWARD')
        target = env.get('PIA_PORT_FORWARD_TARGET', '')
        if port_forward:
            # A forwarded port is useful only when it reaches a device, and a
            # port with no destination would answer from the exit namespace.
            if not valid_ipv4(target) or ipaddress.IPv4Address(target) not in ipaddress.IPv4Network(config.overlay):
                raise ValueError('PIA_PORT_FORWARD needs PIA_PORT_FORWARD_TARGET, an overlay IPv4 address')
        elif target:
            raise ValueError('PIA_PORT_FORWARD_TARGET is set but PIA_PORT_FORWARD is off')
        return cls(state_dir, config, secrets_dir=Path(env.get('PIA_SECRETS_DIR', '/run/secrets/pia')),
                   port_forward=port_forward, forward_target=target or None, **kwargs)

    def make_catalog(self):
        return RelayCatalog(self.directory, 'pia', port_forward_only=self.port_forward)

    def result_defaults(self):
        port = self.forward['port'] if self.forward and self.forward.get('bound') else None
        fields = {'port_forward': self.port_forward, 'forwarded_port': port}
        if self.port_forward:
            fields['port_forward_error'] = self.forward_error
        return fields

    # -- PIA API ---------------------------------------------------------------

    def curl(self, *args, timeout=15):
        """HTTPS only, bounded, no proxy; callers add CA pinning where PIA's CA applies."""
        raw = self.run(['curl', '--noproxy', '*', '--proto', '=https', '-fsS',
                        '--max-time', str(timeout), '--max-filesize', '16384', *args],
                       timeout=timeout + 2, limit=16384)
        data = decode_json(raw)
        if not isinstance(data, dict):
            raise ValueError('invalid PIA response')
        return data

    def pia_token(self):
        if self.token and self.token_at is not None and self.clock() - self.token_at < TOKEN_MAX_AGE_SEC:
            return self.token
        username = read_secret(self.secrets_dir / 'username')
        password = read_secret(self.secrets_dir / 'password')
        with scratch(username, password) as (user_file, password_file):
            data = self.curl('--form', f'username=<{user_file}', '--form', f'password=<{password_file}',
                             PIA_TOKEN_URL)
        token = data.get('token')
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            raise ValueError('invalid PIA token response')
        self.token, self.token_at = token, self.clock()
        return token

    def public_key(self):
        key = self.run(['wg', 'show', self.config.exit_if, 'public-key']).strip()
        if not valid_key(key):
            raise ValueError('invalid interface public key')
        return key

    def pinned(self, cn, address, port, path, *fields, interface=None):
        """A GET to a PIA server by TLS name, connecting to `address`."""
        if not PIA_CN_RE.fullmatch(cn) or not valid_ipv4(address):
            raise ValueError('invalid PIA server')
        bind = ['--interface', self.config.exit_if] if interface else []
        encoded = [part for field in fields for part in ('--data-urlencode', field)]
        return self.curl(*bind, '--cacert', str(PIA_CA), '--connect-to', f'{cn}::{address}:',
                         '-G', *encoded, f'https://{cn}:{port}/{path}')

    def register(self, region):
        """Register the interface key on one of the region's servers."""
        server = self.choose(region['servers'])
        public_key = self.public_key()
        try:
            with scratch(self.pia_token()) as (token_file,):
                data = self.pinned(server['cn'], server['ip'], ADDKEY_PORT, 'addKey',
                                   f'pt@{token_file}', f'pubkey={public_key}')
            port = data.get('server_port')
            if data.get('status') != 'OK' or not valid_key(data.get('server_key')):
                raise ValueError('PIA refused the key registration')
        except (RuntimeError, ValueError):
            # An expired or revoked token looks like any other refusal.
            self.token = None
            raise
        if type(port) is not int or not 0 < port < 65536 or data.get('server_ip') != server['ip']:
            raise ValueError('invalid PIA registration response')
        if 'peer_pubkey' in data and data['peer_pubkey'] != public_key:
            raise ValueError('PIA registered a different key')
        for field in ('peer_ip', 'server_vip'):
            if not valid_ipv4(data.get(field)) or not any(
                    ipaddress.IPv4Address(data[field]) in network for network in PRIVATE_V4):
                raise ValueError('invalid PIA tunnel address')
        peer, vip = ipaddress.IPv4Address(data['peer_ip']), ipaddress.IPv4Address(data['server_vip'])
        taken = [ipaddress.IPv4Network(self.config.overlay), *self.namespace_networks()]
        if peer == vip or any(address in network for address in (peer, vip) for network in taken):
            raise ValueError('PIA tunnel address collides with this namespace')
        return {'region': region['hostname'], 'cn': server['cn'], 'server_ip': server['ip'],
                'server_port': port, 'server_key': data['server_key'], 'peer_ip': str(peer),
                'server_vip': data['server_vip']}

    def namespace_networks(self):
        """IPv4 prefixes on every interface except the tunnel: a registration
        that lands inside one would shadow the namespace's own routes."""
        links = decode_json(self.run(['ip', '-j', '-4', 'address', 'show']))
        if not isinstance(links, list):
            raise ValueError('invalid address listing')
        networks = []
        for link in links:
            if not isinstance(link, dict) or link.get('ifname') == self.config.exit_if:
                continue
            for entry in link.get('addr_info') or []:
                if isinstance(entry, dict) and isinstance(entry.get('local'), str):
                    prefix = entry.get('prefixlen', 32)
                    networks.append(ipaddress.IPv4Network(f"{entry['local']}/{prefix}", strict=False))
        return networks

    def return_path_sources(self):
        """Sources of the IPv4 priority-94 rules now installed."""
        rules = decode_json(self.run(['ip', '-j', '-4', 'rule', 'show']))
        if not isinstance(rules, list):
            raise ValueError('invalid rule listing')
        return [r.get('src') for r in rules if isinstance(r, dict) and r.get('priority') == 94
                and isinstance(r.get('src'), str)]

    # -- provider seam ---------------------------------------------------------

    def apply_relay(self, relay, keys):
        """Register first, so a refused registration changes nothing. Then
        replace the peer, the tunnel address and its return-path rule."""
        self.last_attempt = self.clock()
        registration = self.register(relay)
        exit_if, table = self.config.exit_if, self.config.table
        for key in keys:
            if key != registration['server_key']:
                self.run(['wg', 'set', exit_if, 'peer', key, 'remove'])
        self.forward = None
        self.next_forward = 0
        with contextlib.suppress(RuntimeError):
            self.remove_forward_rules()
        # The return-path rule for the new address goes in first and the old
        # one comes out last, so the exit's ICMP errors always have a rule
        # sending them into the tunnel. The new address is added before the
        # old one goes: when an interface loses its last IPv4 address the
        # kernel deletes every route through it, the tunnel default included,
        # which is re-asserted afterwards.
        new = registration['peer_ip']
        sources = self.return_path_sources()
        if new not in sources:
            self.run(['ip', '-4', 'rule', 'add', 'from', new, 'ipproto', 'icmp',
                      'lookup', table, 'priority', '94'])
        old = self.tunnel_addresses(require_ipv4=False).get(4)
        self.run(['ip', '-4', 'address', 'replace', new + '/32', 'dev', exit_if])
        if old and old != new:
            self.run(['ip', '-4', 'address', 'del', old + '/32', 'dev', exit_if])
        self.run(['ip', '-4', 'route', 'replace', 'default', 'dev', exit_if, 'table', table])
        for source in sources:
            if source != new:
                self.run(['ip', '-4', 'rule', 'del', 'priority', '94', 'from', source])
        # IPv4 only: PIA carries no IPv6, which stays on the unreachable fallback.
        self.run(['wg', 'set', exit_if, 'peer', registration['server_key'],
                  'endpoint', f"{registration['server_ip']}:{registration['server_port']}",
                  'allowed-ips', '0.0.0.0/0', 'persistent-keepalive', '25'])
        write_json_atomic(self.tunnel_path, {**registration, 'registered_at': now_iso()}, public=True)

    def registration(self, keys=None):
        """The recorded registration, only while it matches the live peer."""
        data = read_json(self.tunnel_path, 4096)
        if not isinstance(data, dict) or not valid_key(data.get('server_key')):
            return None
        keys = self.peers() if keys is None else keys
        return data if keys == [data['server_key']] else None

    def server_for(self, keys):
        if len(keys) != 1:
            return None
        data = self.registration(keys)
        region = data.get('region') if data else None
        return region if region in self.catalog.relays else None

    def egress(self):
        self.tunnel_addresses()
        data = self.curl('-4', '--interface', self.config.exit_if, PIA_STATUS_URL, timeout=10)
        if type(data.get('connected')) is not bool or not valid_ipv4(data.get('ip')):
            raise ValueError('invalid egress response')
        return {'egress_ip': data['ip'], 'egress_city': None, 'egress_country': None,
                'exit_confirmed': data['connected'], 'egress_ips': {'4': data['ip']}}

    def inspect(self, *, applying=False):
        if not applying and not self.request:
            try:
                unregistered = not self.peers()
            except (RuntimeError, ValueError, UnicodeError):
                unregistered = False
            if unregistered:
                routing_ok, fallback = self.routing_status(require_address=False)
                self.last_result = self.publish(
                    'failed', 'No PIA region is registered yet; choose one in the panel.',
                    routing_ok=False, unreachable_fallback=fallback)
                return self.last_result
        result = super().inspect(applying=applying)
        self.last_result = result
        return result

    def tick(self):
        if not self.guard_installed:
            with contextlib.suppress(RuntimeError):
                self.install_guard()
                self.guard_installed = True
        if not self.forward_reconciled:
            # A namespace that outlived the applier can still carry the table
            # from an earlier run, perhaps one with forwarding on. Retried
            # every tick until it succeeds.
            with contextlib.suppress(RuntimeError):
                self.remove_forward_rules()
                self.forward_reconciled = True
        result = super().tick()
        retry = self.retry_registration()
        result = retry or result
        if self.port_forward:
            if self.guard_installed and self.forward_reconciled:
                self.maintain_forward()
            else:
                # Never forward a port before the ingress guard is in place,
                # nor before the leftover cleanup that would delete new rules.
                self.forward_error = 'Waiting for the ingress guard; port forwarding is not started.'
        return result

    def switch(self, request):
        with contextlib.suppress(RuntimeError, ValueError, UnicodeError):
            self.reconcile_tunnel()
        return super().switch(request)

    def reconcile_tunnel(self):
        """Repair what an interrupted switch can leave behind: more than one
        IPv4 address on the tunnel, or return-path rules for addresses no
        longer on it. The recorded registration's address is kept when present.
        Without this, the routing check would refuse every later switch."""
        exit_if, table = self.config.exit_if, self.config.table
        links = decode_json(self.run(['ip', '-j', 'address', 'show', 'dev', exit_if]))
        if not isinstance(links, list) or len(links) != 1 or not isinstance(links[0], dict):
            return
        addresses = [a['local'] for a in links[0].get('addr_info') or []
                     if isinstance(a, dict) and a.get('family') == 'inet' and a.get('scope') == 'global'
                     and valid_ipv4(a.get('local'))]
        recorded = read_json(self.tunnel_path, 4096)
        recorded = recorded.get('peer_ip') if isinstance(recorded, dict) else None
        keep = recorded if recorded in addresses else (addresses[0] if addresses else None)
        sources = self.return_path_sources()
        if keep and keep not in sources:
            self.run(['ip', '-4', 'rule', 'add', 'from', keep, 'ipproto', 'icmp',
                      'lookup', table, 'priority', '94'])
        extra = [a for a in addresses if a != keep]
        for address in extra:
            self.run(['ip', '-4', 'address', 'del', address + '/32', 'dev', exit_if])
        if extra:
            self.run(['ip', '-4', 'route', 'replace', 'default', 'dev', exit_if, 'table', table])
        for source in sources:
            if source != keep:
                self.run(['ip', '-4', 'rule', 'del', 'priority', '94', 'from', source])

    def retry_registration(self):
        """Re-register the requested region when its handshake has gone stale:
        PIA forgets a key after a server restart or long inactivity. Never
        another region, and at most every REREGISTER_SEC."""
        request, last = self.request, self.last_result
        if not request or self.pending or not isinstance(last, dict) or last.get('status') != 'failed':
            return None
        if request['server'] not in self.catalog.relays or not last.get('routing_ok'):
            return None
        age = last.get('handshake_age_s')
        if age is not None and age < HANDSHAKE_FRESH_SEC:
            return None
        if self.last_attempt is not None and self.clock() - self.last_attempt < REREGISTER_SEC:
            return None
        result = self.switch(request)
        self.push_gatus(result)
        return result

    # -- optional port forwarding ----------------------------------------------

    def maintain_forward(self):
        """Keep one forwarded port bound on the current server and pointed at
        the configured overlay address. Runs only after a healthy check."""
        last = self.last_result
        if not isinstance(last, dict) or last.get('status') != 'ok' or self.clock() < self.next_forward:
            return
        try:
            current = self.registration()
            if current is None:
                raise ValueError('no current registration')
            forward = self.forward
            if (forward is None or forward['server_key'] != current['server_key']
                    or self.clock() - forward['signed_at'] >= SIGNATURE_MAX_AGE_SEC):
                forward = self.forward = self.get_signature(current)
            self.bind_port(current, forward)
            forward['bound'] = True
            self.apply_forward_rules(forward['port'])
            self.forward_error = None
            self.next_forward = self.clock() + BIND_INTERVAL_SEC
        except (OSError, RuntimeError, ValueError, UnicodeError):
            self.forward = None
            self.forward_error = 'Port forwarding is unavailable; retrying.'
            with contextlib.suppress(RuntimeError):
                self.remove_forward_rules()
            self.next_forward = self.clock() + FORWARD_RETRY_SEC
            print('applier: port forwarding failed', flush=True)

    def get_signature(self, current):
        with scratch(self.pia_token()) as (token_file,):
            data = self.pinned(current['cn'], current['server_vip'], FORWARD_API_PORT, 'getSignature',
                               f'token@{token_file}', interface=True)
        payload, signature = data.get('payload'), data.get('signature')
        if data.get('status') != 'OK' or not isinstance(payload, str) or not isinstance(signature, str):
            raise ValueError('PIA refused port forwarding')
        if not TOKEN_RE.fullmatch(payload) or not TOKEN_RE.fullmatch(signature):
            raise ValueError('invalid port forwarding response')
        try:
            decoded = decode_json(base64.b64decode(payload, validate=True))
        except binascii.Error as exc:
            raise ValueError('invalid port forwarding payload') from exc
        port = decoded.get('port') if isinstance(decoded, dict) else None
        if type(port) is not int or not 1024 <= port < 65536:
            raise ValueError('invalid forwarded port')
        return {'server_key': current['server_key'], 'payload': payload, 'signature': signature,
                'port': port, 'signed_at': self.clock(), 'bound': False}

    def bind_port(self, current, forward):
        with scratch(forward['payload'], forward['signature']) as (payload_file, signature_file):
            data = self.pinned(current['cn'], current['server_vip'], FORWARD_API_PORT, 'bindPort',
                               f'payload@{payload_file}', f'signature@{signature_file}', interface=True)
        if data.get('status') != 'OK':
            raise ValueError('PIA refused to bind the forwarded port')

    def forward_rules(self, port):
        target, exit_if, overlay_if = self.forward_target, self.config.exit_if, self.config.overlay_if
        # Declaring then deleting the table makes the load an atomic replace.
        return (f'table ip {NFT_TABLE}\ndelete table ip {NFT_TABLE}\n'
                f'table ip {NFT_TABLE} {{\n'
                f'  chain prerouting {{\n'
                f'    type nat hook prerouting priority dstnat; policy accept;\n'
                f'    iifname "{exit_if}" meta l4proto {{ tcp, udp }} th dport {port} dnat to {target}\n'
                f'  }}\n'
                f'  chain postrouting {{\n'
                # The target's WireGuard peer accepts only the exit's overlay
                # address from this peer, so forwarded connections carry it.
                f'    type nat hook postrouting priority srcnat; policy accept;\n'
                f'    oifname "{overlay_if}" ct status dnat ip daddr {target} masquerade\n'
                f'  }}\n'
                f'}}\n')

    def install_guard(self):
        """Forwarded tunnel ingress may leave only over the overlay. Normally
        that is only replies to clients; with port forwarding it includes
        inbound connections, whose conntrack mappings outlive their rules. If
        the overlay route vanished, `main` would otherwise hand them to the
        namespace's ordinary default route. Installed whatever the forwarding
        setting and never removed by the applier."""
        exit_if, overlay_if = self.config.exit_if, self.config.overlay_if
        with scratch(f'table inet {GUARD_TABLE}\ndelete table inet {GUARD_TABLE}\n'
                     f'table inet {GUARD_TABLE} {{\n'
                     f'  chain forward {{\n'
                     f'    type filter hook forward priority filter; policy accept;\n'
                     f'    iifname "{exit_if}" oifname != "{overlay_if}" drop\n'
                     f'  }}\n'
                     f'}}\n') as (rules_file,):
            self.run(['nft', '-f', rules_file])

    def apply_forward_rules(self, port):
        if self.nft_port == port:
            return
        with scratch(self.forward_rules(port)) as (rules_file,):
            self.run(['nft', '-f', rules_file])
        self.nft_port = port

    def remove_forward_rules(self):
        """Remove the forwarding table whether or not forwarding is on now."""
        self.nft_port = None
        with scratch(f'table ip {NFT_TABLE}\ndelete table ip {NFT_TABLE}\n') as (rules_file,):
            self.run(['nft', '-f', rules_file])

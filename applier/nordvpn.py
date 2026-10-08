"""NordVPN (NordLynx): shaped like Mullvad, with three differences.

- One account key and the tunnel address 10.5.0.2/32 work on every server, so
  the address is in the tunnel config before any switch, as with Mullvad. The
  config has no peer: a fresh exit carries no traffic until a server is
  chosen. NordLynx carries no IPv6, so forwarded IPv6 always hits the exit
  table's unreachable fallback, as with PIA.
- Server keys belong to a location, not a server: every server in a city can
  share one key. The current server is therefore the one whose address is
  the live peer's endpoint (`wg show <interface> endpoints`), and whose key
  is the peer's key. A switch replaces the peer even when the key stays the
  same, so the new server's handshake is a fresh one.
- Egress is confirmed by NordVPN's `ips/insights` (`protected`), IPv4 only.
  NordVPN serves that answer from a cache for up to an hour per address. An
  answer of `protected: false` for an address that is the selected server's
  own (NordLynx servers have so far exited from their entry address) is asked
  again every INSIGHTS_RETRY_SEC, for up to SWITCH_TIMEOUT_SEC and never past
  a running switch's own timeout, before it counts. If it still says false,
  the exit reports the failure; it is never accepted on the address alone.

The applier holds no NordVPN credential: tools/nordvpn-key.py fetches the
private key once at setup, into the tunnel config the applier never mounts.
"""
from __future__ import annotations

from applier.apply import SWITCH_TIMEOUT_SEC, Applier
from molebridge.nordvpn import NORD_INSIGHTS_URL, NORD_PORT, parse_insights, server_for_endpoint
from molebridge.relays import valid_key
from molebridge.state import decode_json

INSIGHTS_RETRY_SEC = 10
INSIGHTS_MAX_BYTES = 16384


class NordApplier(Applier):
    provider = 'nordvpn'

    def result_defaults(self):
        return {}

    def endpoints(self):
        """{peer key: 'ip:port'} from `wg show <interface> endpoints`."""
        found = {}
        for line in self.run(['wg', 'show', self.config.exit_if, 'endpoints']).splitlines():
            fields = line.split()
            if not fields:
                continue
            if len(fields) != 2 or not valid_key(fields[0]) or fields[0] in found:
                raise ValueError('invalid peer endpoint listing')
            found[fields[0]] = fields[1]
        return found

    def server_for(self, keys):
        if len(keys) != 1:
            return None
        host = server_for_endpoint(self.catalog.relays, self.endpoints().get(keys[0]))
        if host is None or self.catalog.relays[host]['public_key'] != keys[0]:
            return None
        return host

    def apply_relay(self, relay, keys):
        """Replace the peer. Every current peer goes first, including one with
        the new server's key, which another server in the same location may
        hold; a failed removal aborts before the new peer is added. IPv4 only."""
        for key in keys:
            self.run(['wg', 'set', self.config.exit_if, 'peer', key, 'remove'])
        self.run(['wg', 'set', self.config.exit_if, 'peer', relay['public_key'],
                  'endpoint', f"{relay['ipv4_addr_in']}:{NORD_PORT}", 'allowed-ips', '0.0.0.0/0',
                  'persistent-keepalive', '25'])

    def insights(self):
        self.tunnel_addresses()
        raw = self.run(['curl', '-4', '--interface', self.config.exit_if, '--noproxy', '*',
                        '--proto', '=https', '--max-filesize', str(INSIGHTS_MAX_BYTES), '-fsS',
                        '--max-time', '10', NORD_INSIGHTS_URL], timeout=12, limit=INSIGHTS_MAX_BYTES)
        fields = parse_insights(decode_json(raw))
        return {**fields, 'egress_ips': {'4': fields['egress_ip']}}

    def egress_for(self, server, handshake_age):
        relay = self.catalog.relays.get(server) if server else None
        deadline = self.clock() + SWITCH_TIMEOUT_SEC
        if self.switch_deadline is not None:
            # During a switch, never wait past the switch's own timeout.
            deadline = min(deadline, self.switch_deadline)
        while True:
            fields = self.insights()
            # Any of the server's entry addresses (the gluetun backend lists
            # them all; the native catalogue has one).
            entries = (relay.get('ipv4_addrs') or [relay['ipv4_addr_in']]) if relay is not None else []
            cached = fields['exit_confirmed'] is not True and fields['egress_ip'] in entries
            if not cached or self.clock() + INSIGHTS_RETRY_SEC > deadline:
                return fields
            self.sleep(INSIGHTS_RETRY_SEC)

    def egress(self):
        return self.egress_for(None, None)

    def inspect(self, *, applying=False):
        if not applying and not self.request:
            try:
                unselected = not self.peers()
            except (RuntimeError, ValueError, UnicodeError):
                unselected = False
            if unselected:
                routing_ok, fallback = self.routing_status()
                return self.publish('failed', 'No NordVPN server is selected yet; choose one in the panel.',
                                    routing_ok=routing_ok, unreachable_fallback=fallback,
                                    netbird_native=self.netbird_native())
        return super().inspect(applying=applying)

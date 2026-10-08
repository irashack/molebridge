"""Tunnel-verified egress: the "tunnel" tier of egress confirmation.

A provider with its own typed egress endpoint (Mullvad's am.i.mullvad.net,
PIA's status call, NordVPN's insights) confirms egress at the "provider"
tier. A provider without one can reach only the "tunnel" tier, and only when
every one of these holds, per address family the tunnel carries:

- the handshake is fresh;
- two independent IP echo services, asked through the tunnel interface,
  answer with the same public address;
- that address is not the host's own public address, measured off the
  tunnel. A failed measurement fails the check, with one exception: IPv6 on
  a namespace with independent evidence that it has no IPv6 of its own (no
  IPv6 route in any table but the tunnel's, the overlay's, refusing,
  link-local, multicast and loopback ones, and no global IPv6 address on any
  interface but the tunnel and the overlay, loopback included). Such a host
  has no IPv6 address to confuse with the tunnel's;
- where the catalogue lists exit addresses for the selected server (an
  `exit_ips` list in its entry), the address is one of them.

The applier runs the requests (Applier.tunnel_egress); this module only
judges the answers. Echo answers are untrusted input.
"""
from __future__ import annotations

import ipaddress

# Two operators, so one service cannot vouch for itself. Each answers with the
# caller's address as plain text.
ECHO_URLS = {4: ('https://api.ipify.org', 'https://ipv4.icanhazip.com'),
             6: ('https://api6.ipify.org', 'https://ipv6.icanhazip.com')}
ECHO_MAX_BYTES = 256
# The host was shown to have no address of its own in this family; distinct
# from None, which means the measurement failed and nothing is known.
HOST_LACKS_FAMILY = 'host-lacks-family'


def parse_echo(raw, family):
    """The address an echo service answered with, canonical, or ValueError."""
    if not isinstance(raw, str) or len(raw) > ECHO_MAX_BYTES:
        raise ValueError('invalid echo response')
    text = raw.strip(' \t\r\n')
    if not text or any(c.isspace() for c in text):
        raise ValueError('invalid echo response')
    address = ipaddress.ip_address(text)
    if address.version != family:
        raise ValueError('wrong echo address family')
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        raise ValueError('echo address cannot be an egress address')
    return str(address)


def exit_addresses(relay, family):
    """The selected server's exit addresses in this family, or None when the
    catalogue lists none for it. Malformed entries are ignored."""
    values = relay.get('exit_ips') if isinstance(relay, dict) else None
    if not isinstance(values, list):
        return None
    found = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value) if isinstance(value, str) else None
        except ValueError:
            continue
        if address is not None and address.version == family:
            found.add(str(address))
    return found or None


# IPv6 routes every namespace has that give no connectivity of its own:
# link-local and multicast, and loopback in the local table.
_LINK_LOCAL = ipaddress.IPv6Network('fe80::/10')
_MULTICAST = ipaddress.IPv6Network('ff00::/8')
_LOOPBACK = ipaddress.IPv6Address('::1')
_NO_PATH_TYPES = ('unreachable', 'blackhole', 'prohibit', 'throw')


def _route_gives_no_ipv6(route, ignore):
    """True for a route that cannot carry the host's own IPv6: one through the
    tunnel or the overlay, one that only refuses traffic, or a link-local,
    multicast or loopback one. Anything else, or anything unparseable, may."""
    if not isinstance(route, dict):
        return False
    if isinstance(route.get('dev'), str) and route['dev'] in ignore:
        return True
    if route.get('type') in _NO_PATH_TYPES and not any(k in route for k in ('gateway', 'nexthops', 'via')):
        return True
    destination = route.get('dst')
    if not isinstance(destination, str) or destination == 'default':
        return False
    try:
        network = ipaddress.IPv6Network(destination, strict=False)
    except ValueError:
        return False
    if network.subnet_of(_LINK_LOCAL) or network.subnet_of(_MULTICAST):
        return True
    return network.num_addresses == 1 and network.network_address == _LOOPBACK


def host_lacks_ipv6(routes, links, ignore):
    """Independent evidence that the namespace has no IPv6 of its own.

    `routes` is `ip -j -6 route show table all`, every table any rule can
    point to; `links` is `ip -j -6 address show scope global`; `ignore` names
    the tunnel and overlay interfaces. True only when no route but the
    tunnel's, the overlay's, refusing, link-local, multicast and loopback ones
    exists, and no interface but the tunnel and the overlay, loopback
    included, has a global IPv6 address (::1 is host scope, not global).
    Anything unexpected counts as evidence of IPv6."""
    if not isinstance(routes, list) or not isinstance(links, list):
        return False
    if not all(_route_gives_no_ipv6(route, ignore) for route in routes):
        return False
    for link in links:
        if not isinstance(link, dict) or not isinstance(link.get('ifname'), str):
            return False
        if link['ifname'] in ignore:
            continue
        addresses = link.get('addr_info', [])
        if not isinstance(addresses, list):
            return False
        for entry in addresses:
            if not isinstance(entry, dict) or (entry.get('family') == 'inet6' and entry.get('scope') != 'host'
                                               and entry.get('scope') != 'link'):
                return False
    return True


def tunnel_verdict(echoes, host_address, expected, handshake_age, *, max_handshake_age):
    """True only when every tunnel-tier condition holds for one family.

    `echoes` are the parsed answers through the tunnel; `host_address` the
    host's own address measured off the tunnel, HOST_LACKS_FAMILY when the
    host provably has none in this family, or None when the measurement
    failed, which fails the check; `expected` the catalogue's exit addresses
    or None."""
    if type(handshake_age) is not int or not 0 <= handshake_age < max_handshake_age:
        return False
    if len(echoes) < 2 or any(not isinstance(e, str) for e in echoes) or len(set(echoes)) != 1:
        return False
    address = echoes[0]
    if host_address is None or address == host_address:
        return False
    return expected is None or address in expected

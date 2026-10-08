"""Pure validation of configuration and iproute2 JSON snapshots."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# The exit's own ICMP errors (fragmentation needed, packet too big) must return
# through the tunnel. With this sysctl the kernel sources them from the tunnel
# address, and the priority-94 rule routes that address through the exit table.
RETURN_PATH_SYSCTL = '/proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr'

# The return-path rule carries a protocol qualifier so it cannot capture other
# traffic sourced from the tunnel address. iproute2 renders the selector by
# name where the host has a protocol database and by number where it does not;
# both forms mean the same rule.
ICMP_PROTOCOL = {4: 'icmp', 6: 'ipv6-icmp'}
PROTOCOL_ALIASES = {'1': 'icmp', '58': 'ipv6-icmp'}
TABLE_NAMES = {254: 'main', 255: 'local'}

# NetBird's own netfilter objects in the pinned release (0.79.0): the nftables
# backend creates table `netbird` (client/firewall/nftables/manager_linux.go:25,
# 748-763); the iptables backend creates chains such as NETBIRD-RT-FWD-IN
# (client/firewall/iptables/family_linux.go:40-46, chains_linux.go:16-36).
# NetBird picks iptables whenever its iptables lists filter chains
# (client/firewall/create_linux.go:157-201). `nft` sees those chains only when
# that iptables uses the nftables backend, Alpine's default, which the pinned
# Alpine-based image is expected to use; legacy iptables would fail this
# check, closed.
NETBIRD_NFT_TABLE = 'netbird'
NETBIRD_IPTABLES_PREFIX = 'NETBIRD-'


@dataclass(frozen=True)
class RoutingConfig:
    overlay: str
    overlay6: str = ''
    overlay_if: str = 'wt0'
    exit_if: str = 'mullvad'
    table: str = '51821'

    @classmethod
    def from_env(cls, env):
        overlay = ipaddress.IPv4Network(env.get('OVERLAY_CIDR', ''), strict=True)
        overlay6 = env.get('OVERLAY6_CIDR', '')
        if overlay.prefixlen == 0:
            raise ValueError('OVERLAY_CIDR cannot be a default route')
        if overlay6:
            network6 = ipaddress.IPv6Network(overlay6, strict=True)
            if network6.prefixlen == 0:
                raise ValueError('OVERLAY6_CIDR cannot be a default route')
            overlay6 = str(network6)
        interfaces = [env.get('OVERLAY_IF', 'wt0'), env.get('EXIT_IF', 'mullvad')]
        if any(not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}', i) for i in interfaces):
            raise ValueError('invalid interface name')
        if interfaces[0] == interfaces[1]:
            raise ValueError('overlay and exit interfaces must differ')
        table = env.get('EXIT_TABLE', '51821')
        if not re.fullmatch(r'[1-9][0-9]{0,9}', table) or not 256 <= int(table) <= 2147483647:
            raise ValueError('EXIT_TABLE must be an unreserved table number (256..2147483647)')
        return cls(str(overlay), overlay6, *interfaces, table)


def _normalize_prefix(rule, key, family):
    """iproute2 emits rule prefixes as separate <key>/<key>len fields; a host
    prefix omits the length. Return the canonical network or raise."""
    value = rule.get(key)
    if not isinstance(value, str):
        raise ValueError('invalid rule selector')
    if key + 'len' in rule:
        length = rule.pop(key + 'len')
        if type(length) is not int or '/' in value:
            raise ValueError('invalid rule prefix')
        value = f'{value}/{length}'
    network = ipaddress.ip_network(value, strict=True)
    if network.version != family:
        raise ValueError('wrong rule address family')
    return str(network)


def _table_name(value):
    return TABLE_NAMES.get(value, str(value)) if type(value) in (int, str) else None


def local_rule_admits_overlay(rule, overlay_if):
    """True when `rule` looks up the local table and could match a packet that
    arrives on the overlay interface.

    Only two shapes cannot: the local-delivery guard itself (inverted, with
    the overlay interface as its only selector) and a rule whose positive
    `iif` names another interface. The kernel's default priority-0 rule
    matches everything. Anything unparseable counts as admitting the overlay."""
    if not isinstance(rule, dict):
        return True
    if _table_name(rule.get('table')) != 'local':
        return False
    if 'not' in rule:
        selectors = set(rule) - {'priority', 'not', 'src', 'iif', 'iif_detached', 'table', 'protocol'}
        return selectors != set() or rule.get('src', 'all') != 'all' or rule.get('iif') != overlay_if
    iif = rule.get('iif')
    return not isinstance(iif, str) or iif == overlay_if


def family_status(rules, routes, config, family, *, tunnel_address=None):
    """Check exact selectors, rule ordering, terminal guard and safe table routes.

    `tunnel_address` is the family's global address on the exit interface, or
    None when the tunnel does not carry this family. With an address, the
    family must also have its tunnel default route and the priority-94
    return-path rule, for exactly that address and ICMP alone."""
    if not isinstance(rules, list) or not isinstance(routes, list):
        return False, False
    overlay = config.overlay if family == 4 else config.overlay6
    # Rule 1 replaces the kernel's priority-0 local lookup: packets arriving on
    # the overlay never get local delivery.
    expected = {1: {'not': True, 'iif': config.overlay_if, 'table': 'local'},
                95: {'iif': config.overlay_if, 'table': config.table},
                96: {'oif': config.exit_if, 'table': config.table},
                97: {'iif': config.overlay_if, 'action': 'unreachable'}}
    if overlay:
        expected[90] = {'iif': config.exit_if, 'dst': overlay, 'table': 'main'}
    if tunnel_address is not None:
        try:
            address = ipaddress.ip_network(tunnel_address, strict=True)
        except ValueError:
            return False, False
        if address.version != family or address.prefixlen != address.max_prefixlen:
            return False, False
        expected[94] = {'src': str(address), 'ipproto': ICMP_PROTOCOL[family],
                        'table': config.table}
    found = set()
    rules_ok = True
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get('priority'), int):
            return False, False
        if local_rule_admits_overlay(rule, config.overlay_if):
            rules_ok = False
        priority = rule['priority']
        if priority > 97:
            continue
        spec = expected.get(priority)
        if spec is None or priority in found:
            rules_ok = False
            continue
        found.add(priority)
        normalized = dict(rule)
        if 'table' in normalized:
            normalized['table'] = _table_name(normalized['table'])
            if normalized['table'] is None:
                rules_ok = False
                continue
        if 'not' in normalized:
            # iproute2 prints an inverted rule's flag as `"not": null`.
            if normalized['not'] not in (None, True):
                rules_ok = False
                continue
            normalized['not'] = True
        if 'ipproto' in normalized:
            if type(normalized['ipproto']) not in (int, str):
                rules_ok = False
                continue
            protocol = str(normalized['ipproto'])
            normalized['ipproto'] = PROTOCOL_ALIASES.get(protocol, protocol)
        try:
            for key in ('src', 'dst'):
                if key in normalized and normalized[key] != 'all':
                    normalized[key] = _normalize_prefix(normalized, key, family)
        except ValueError:
            rules_ok = False
            continue
        # Reject extra selectors, inversion other than rule 1's, suppressors
        # and goto actions.
        metadata = {'priority', 'protocol', 'src', 'dst', 'iif_detached', 'oif_detached'}
        if set(normalized) - (set(spec) | metadata):
            rules_ok = False
        for key in ('src', 'dst'):
            if normalized.get(key, 'all') != spec.get(key, 'all'):
                rules_ok = False
        if any(k not in normalized or normalized[k] != v for k, v in spec.items()):
            rules_ok = False
        # iproute2 prints these flags as null, so their presence is what counts.
        if 'iif_detached' in normalized or 'oif_detached' in normalized:
            rules_ok = False
    rules_ok = rules_ok and found == set(expected)
    fallback = False
    tunnel_default = False
    routes_ok = True
    for route in routes:
        if not isinstance(route, dict):
            return False, False
        kind = route.get('type', 'unicast')
        if kind == 'unreachable' and route.get('dst') == 'default' and route.get('metric') == 4096:
            fallback = True
        elif kind == 'unicast' and route.get('dev') == config.exit_if and not any(k in route for k in ('gateway', 'nexthops', 'via')):
            if route.get('dst') == 'default' and 'linkdown' not in route.get('flags', []):
                tunnel_default = True
        else:
            routes_ok = False
    return rules_ok and routes_ok and fallback and (tunnel_default or tunnel_address is None), fallback


def overlay_is_kernel_wireguard(links, overlay_if):
    """`ip -d -j link show dev <overlay>`: exactly one link, the overlay, and of
    kind wireguard, as Molebridge requires. A userspace bind (a tun device) or
    netstack mode is not wireguard or has no link."""
    if not isinstance(links, list) or len(links) != 1 or not isinstance(links[0], dict):
        return False
    info = links[0].get('linkinfo')
    return (links[0].get('ifname') == overlay_if and isinstance(info, dict)
            and info.get('info_kind') == 'wireguard')


def netbird_firewall_present(listing):
    """`nft -j list chains`: NetBird's kernel firewall has its IPv4 table or
    chains in place. With kernel WireGuard NetBird's engine does not start
    without that firewall (client/internal/engine.go:750-753)."""
    if not isinstance(listing, dict) or not isinstance(listing.get('nftables'), list):
        return False
    for item in listing['nftables']:
        chain = item.get('chain') if isinstance(item, dict) else None
        if not isinstance(chain, dict) or chain.get('family') != 'ip':
            continue
        name, table = chain.get('name'), chain.get('table')
        if table == NETBIRD_NFT_TABLE or (isinstance(name, str) and name.startswith(NETBIRD_IPTABLES_PREFIX)):
            return True
    return False


def return_path_enabled(value):
    """True when the sysctl file content says the kernel sources ICMP errors
    from the inbound interface address."""
    return isinstance(value, str) and value.strip() == '1'

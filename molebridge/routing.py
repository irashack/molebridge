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


def family_status(rules, routes, config, family, *, tunnel_address=None):
    """Check exact selectors, rule ordering, terminal guard and safe table routes.

    `tunnel_address` is the family's global address on the exit interface, or
    None when the tunnel does not carry this family. With an address, the
    family must also have its tunnel default route and the priority-94
    return-path rule, for exactly that address and ICMP alone."""
    if not isinstance(rules, list) or not isinstance(routes, list):
        return False, False
    overlay = config.overlay if family == 4 else config.overlay6
    expected = {0: {'table': 'local'},
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
            if type(normalized['table']) not in (int, str):
                rules_ok = False
                continue
            normalized['table'] = {254: 'main', 255: 'local'}.get(normalized['table'], str(normalized['table']))
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
        # Reject extra selectors, inversion, suppressors and goto actions.
        metadata = {'priority', 'protocol', 'src', 'dst', 'iif_detached', 'oif_detached'}
        if set(normalized) - (set(spec) | metadata):
            rules_ok = False
        for key in ('src', 'dst'):
            if normalized.get(key, 'all') != spec.get(key, 'all'):
                rules_ok = False
        if any(normalized.get(k) != v for k, v in spec.items()):
            rules_ok = False
        if normalized.get('iif_detached') or normalized.get('oif_detached'):
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


def return_path_enabled(value):
    """True when the sysctl file content says the kernel sources ICMP errors
    from the inbound interface address."""
    return isinstance(value, str) and value.strip() == '1'

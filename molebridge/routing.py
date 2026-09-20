"""Pure validation of configuration and iproute2 JSON snapshots."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


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


def family_status(rules, routes, config, family):
    """Check exact selectors, rule ordering, terminal guard and safe table routes."""
    if not isinstance(rules, list) or not isinstance(routes, list):
        return False, False
    overlay = config.overlay if family == 4 else config.overlay6
    expected = {0: {'table': 'local'},
                95: {'iif': config.overlay_if, 'table': config.table},
                96: {'oif': config.exit_if, 'table': config.table},
                97: {'iif': config.overlay_if, 'action': 'unreachable'}}
    if overlay:
        expected[90] = {'iif': config.exit_if, 'dst': overlay, 'table': 'main'}
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
        # Reject extra selectors, inversion, suppressors and goto actions.
        metadata = {'priority', 'protocol', 'src', 'dst', 'iif_detached', 'oif_detached'}
        if set(normalized) - (set(spec) | metadata):
            rules_ok = False
        if normalized.get('src', 'all') != 'all' or normalized.get('dst', 'all') != spec.get('dst', 'all'):
            rules_ok = False
        if any(normalized.get(k) != v for k, v in spec.items()):
            rules_ok = False
    rules_ok = rules_ok and found == set(expected)
    fallback = False
    routes_ok = True
    for route in routes:
        if not isinstance(route, dict):
            return False, False
        kind = route.get('type', 'unicast')
        if kind == 'unreachable' and route.get('dst') == 'default' and route.get('metric') == 4096:
            fallback = True
        elif kind == 'unicast' and route.get('dev') == config.exit_if and not any(k in route for k in ('gateway', 'nexthops', 'via')):
            pass
        else:
            routes_ok = False
    return rules_ok and routes_ok and fallback, fallback

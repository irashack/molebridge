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

# gluetun backend. Tables gluetun v3.41.3 and NetBird 0.79.0 use in the shared
# namespace: gluetun's WireGuard table and mark 51820
# (internal/wireguard/settings.go:60-67), its inbound table 200
# (internal/routing/inbound.go:11-12), NetBird's table 0x1BD0 = 7120
# (client/internal/routemanager/systemops/systemops_linux.go:47). NetBird's
# default mark base is 0x1BD00 with the low byte left for its offsets
# (client/net/fwmark.go:17-26).
BACKENDS = ('wireguard', 'gluetun')
RESERVED_TABLES = {'51820', '7120'}
DEFAULT_CONTROL_MARK = '0x1bd00'
# gluetun's WireGuard fwmark, fixed in v3.41.3 (internal/wireguard/settings.go:64-66).
GLUETUN_MARK = 51820
# gluetun's interface-name rule (internal/configuration/settings/wireguard.go).
GLUETUN_INTERFACE = re.compile(r'[a-zA-Z0-9_]{1,15}')
INTERFACE = re.compile(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}')


def _table_number(value, name):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,9}', value) or not 256 <= int(value) <= 2147483647:
        raise ValueError(f'{name} must be an unreserved table number (256..2147483647)')
    return value


def control_mark_value(mark):
    """The integer of a canonical control mark ("0x1bd00": lowercase hex, no
    leading zero, at most 32 bits, low byte zero, as NetBird requires of
    NB_FWMARK_BASE and as iproute2 prints it), or ValueError."""
    if not isinstance(mark, str) or not re.fullmatch(r'0x[1-9a-f][0-9a-f]{0,7}', mark):
        raise ValueError('CONTROL_MARK must be lowercase hexadecimal like 0x1bd00')
    value = int(mark, 16)
    if value & 0xFF:
        raise ValueError('CONTROL_MARK must leave the low byte zero')
    return value


@dataclass(frozen=True)
class RoutingConfig:
    overlay: str
    overlay6: str = ''
    overlay_if: str = 'wt0'
    exit_if: str = 'mullvad'
    table: str = '51821'
    # gluetun backend only; see routing/10-exit-routing.
    backend: str = 'wireguard'
    host_if: str = 'eth0'
    host_table: str = '51822'
    control_mark: str = DEFAULT_CONTROL_MARK

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
        backend = env.get('TUNNEL_BACKEND', 'wireguard')
        if backend not in BACKENDS:
            raise ValueError('TUNNEL_BACKEND must be wireguard or gluetun')
        if backend == 'wireguard':
            return cls(str(overlay), overlay6, *interfaces, table)
        if not GLUETUN_INTERFACE.fullmatch(interfaces[1]):
            raise ValueError('with gluetun, EXIT_IF may hold only letters, digits and underscores')
        host_if = env.get('HOST_IF', 'eth0')
        if not INTERFACE.fullmatch(host_if) or host_if == 'lo' or host_if in interfaces:
            raise ValueError("HOST_IF must name the namespace's host interface")
        host_table = _table_number(env.get('HOST_TABLE', '51822'), 'HOST_TABLE')
        if host_table == table:
            raise ValueError('HOST_TABLE and EXIT_TABLE must differ')
        if {table, host_table} & RESERVED_TABLES:
            raise ValueError('tables 51820 (gluetun) and 7120 (NetBird) are taken')
        mark = env.get('CONTROL_MARK', DEFAULT_CONTROL_MARK)
        control_mark_value(mark)
        return cls(str(overlay), overlay6, *interfaces, table, backend, host_if, host_table, mark)

    @property
    def gluetun(self):
        return self.backend == 'gluetun'


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


def family_status(rules, routes, config, family, *, tunnel_address=None, tunnel_route=True):
    """Check exact selectors, rule ordering, terminal guard and safe table routes.

    `tunnel_address` is the family's global address on the exit interface, or
    None when the tunnel does not carry this family. With an address, the
    family must also have its tunnel default route and the priority-94
    return-path rule, for exactly that address and ICMP alone. With
    tunnel_route=False the tunnel default may be missing (gluetun's interface
    exists with its address but is down; the guard removes the route then),
    though never replaced by another route.

    With the gluetun backend, rules 88 and 89 send locally generated packets
    carrying exactly NetBird's control mark to the host table, or nowhere,
    and rules 91 and 92 send locally generated packets for the overlay to
    the main table's overlay route, or nowhere.
    Rules 102-104 send the exit's own traffic carrying gluetun's WireGuard
    mark to the main table, let it reach HOST_IF's own subnets through the
    host table, and stop all other locally generated traffic that gluetun's
    rule 101 didn't take. gluetun's rules (98-101) and
    NetBird's (105, 110) are not judged here; check the host table with `host_table_status`."""
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
    if config.gluetun:
        mark = control_mark_value(config.control_mark)
        expected[88] = {'iif': 'lo', 'fwmark': mark, 'table': config.host_table}
        expected[89] = {'iif': 'lo', 'fwmark': mark, 'action': 'unreachable'}
        if overlay:
            # What the exit itself sends to the overlay (ICMP errors to
            # clients) uses only NetBird's overlay route, never main's
            # default route or gluetun's rule 101, and fails without it.
            expected[91] = {'iif': 'lo', 'dst': overlay, 'table': 'main', 'suppress_prefixlen': 0}
            expected[92] = {'iif': 'lo', 'dst': overlay, 'action': 'unreachable'}
        # The exit's own unmarked traffic leaves only by gluetun's rule 101
        # (its tunnel) or not at all; gluetun's WireGuard socket, which 101
        # skips, uses the main table.
        expected[102] = {'iif': 'lo', 'fwmark': GLUETUN_MARK, 'table': 'main'}
        # HOST_IF's own subnets, from the host table without its default.
        expected[103] = {'iif': 'lo', 'table': config.host_table, 'suppress_prefixlen': 0}
        expected[104] = {'iif': 'lo', 'action': 'unreachable'}
    owned_after_97 = (102, 103, 104) if config.gluetun else ()
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
        if priority > 97 and priority not in owned_after_97:
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
        if 'fwmark' in normalized or 'fwmask' in normalized:
            # iproute2 prints both as hex strings and hides an all-ones mask.
            try:
                for key in ('fwmark', 'fwmask'):
                    value = normalized.get(key, 0xFFFFFFFF)
                    if type(value) is str:
                        value = int(value, 16 if value.lower().startswith('0x') else 10)
                    elif type(value) is not int:
                        raise ValueError
                    normalized[key] = value
            except ValueError:
                rules_ok = False
                continue
            if normalized.pop('fwmask') != 0xFFFFFFFF:
                rules_ok = False
                continue
        if 'suppress_prefixlen' in normalized and type(normalized['suppress_prefixlen']) is not int:
            rules_ok = False
            continue
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
    tunnel_ok = tunnel_default or tunnel_address is None or not tunnel_route
    return rules_ok and routes_ok and fallback and tunnel_ok, fallback


def _host_routes(routes, config):
    """Destinations of the default and on-link unicast routes through the host
    interface, or None if any route is something else."""
    found = set()
    for route in routes:
        if not isinstance(route, dict) or route.get('type', 'unicast') != 'unicast':
            return None
        if route.get('dev') != config.host_if or any(k in route for k in ('nexthops', 'encap', 'nhid')):
            return None
        if 'gateway' in route and route.get('dst') != 'default':
            return None
        found.add(route.get('dst'))
    return found


def host_table_status(routes, config, family, *, main=None):
    """`ip -j route show table <host table>` for the gluetun backend: only
    default and on-link routes through the host interface, never the tunnel
    or the overlay, and for IPv4 a default route. NetBird's control traffic
    depends on it; the IPv6 table may be empty when the host has no IPv6
    route. With `main` (the main table's routes), the host table must hold
    the same destinations as main's default and on-link host routes."""
    if not isinstance(routes, list) or (main is not None and not isinstance(main, list)):
        return False
    found = _host_routes(routes, config)
    if found is None:
        return False
    if main is not None:
        wanted = {r.get('dst') for r in main if isinstance(r, dict) and r.get('type', 'unicast') == 'unicast'
                  and r.get('dev') == config.host_if and not any(k in r for k in ('nexthops', 'encap', 'nhid'))
                  and ('gateway' not in r or r.get('dst') == 'default')}
        if found != wanted:
            return False
    return 'default' in found or family == 6


# What gluetun v3.41.3's chain parser accepts in a rule line (internal/
# firewall/list.go): targets at :314-321, protocols at :324-340, and after
# the in/out/source/destination columns only the optional fields at
# :243-279, which iptables prints for `-m tcp/udp --dport N` and `-m
# conntrack --ctstate S`.
GLUETUN_TARGETS = frozenset({'ACCEPT', 'DROP', 'REJECT', 'REDIRECT'})
GLUETUN_PROTOCOLS = frozenset({'all', 'icmp', 'tcp', 'udp'})


def post_rule_parseable(rule):
    """True when an `-A <chain> ...` rule, once listed by iptables, is a line
    gluetun's chain parser accepts."""
    tokens = rule.split()
    if len(tokens) < 4 or tokens[0] != '-A' or tokens[-2] != '-j' or tokens[-1] not in GLUETUN_TARGETS:
        return False
    i, protocol, module, given = 2, None, None, set()
    body = tokens[2:-2]
    while i - 2 < len(body):
        option = tokens[i]
        value = tokens[i + 1] if i + 1 < len(tokens) - 2 else None
        if value is None:
            return False
        if option in ('-i', '-o', '-s', '-d'):
            pass
        elif option == '-p' and value in GLUETUN_PROTOCOLS and protocol is None:
            protocol = value
        elif option == '-m' and value in ('tcp', 'udp', 'conntrack') and module is None:
            module = value
        elif option == '--dport' and module in ('tcp', 'udp') and module == protocol and value.isdigit():
            pass
        elif option == '--ctstate' and module == 'conntrack':
            pass
        else:
            return False
        given.add(option)
        i += 2
    # A match module with nothing to print would leave a lone `udp` or
    # `tcp`, which gluetun's parser reads past the end of the line.
    return module is None or ('--dport' if module in ('tcp', 'udp') else '--ctstate') in given


def render_post_rules(config, wireguard_port, *, ipv6=True):
    """gluetun's /iptables/post-rules.txt for the gluetun backend.

    gluetun v3.41.3 runs each line that starts with `iptables ` or `ip6tables `
    (or their -nft/-legacy names) once, after enabling its firewall, split on
    whitespace without a shell (internal/firewall/iptables.go:260-330); any
    other line is ignored. A failing line disables the firewall and stops
    gluetun, and an ip6tables line fails when gluetun found no working
    ip6tables, so `ipv6=False` leaves those out for such a host.

    These accepts let the exit work under gluetun's DROP policies. They are
    not the guard: NetBird rewrites FORWARD, and policy routing holds the
    tunnel-only property.

    Every rule must also survive gluetun's own parser. To remove one of its
    rules (the old VPN endpoint and tunnel accepts on every reconnect,
    allowed ports), gluetun lists the whole chain with `iptables -L <chain>
    --line-numbers -n -v` and parses every line, ours included
    (internal/firewall/delete.go:71-99, list.go:37-94). A line it can't parse
    stops the removal, and its old accepts pile up. It accepts only the
    targets ACCEPT, DROP, REJECT and REDIRECT (list.go:314-321), so not a
    jump to a chain of our own, and after the address columns only `tcp
    dpt:N`, `udp dpt:N`, `redir ports N` and `ctstate S` (list.go:243-279),
    so no `-m mark`. POST_RULE_PARSEABLE checks that. The control mark
    therefore can't narrow the OUTPUT accept: it accepts everything leaving
    by HOST_IF, as gluetun's own `-o <tunnel> -j ACCEPT` does for the
    tunnel. Policy routing decides what leaves that way: NetBird's marked
    control traffic by rules 88/89, gluetun's WireGuard socket by rule 102,
    HOST_IF's subnets by 103; rule 104 stops the namespace's other unmarked
    traffic that gluetun's
    rule 101 didn't take; forwarded traffic never reaches OUTPUT."""
    if not config.gluetun:
        raise ValueError('post-rules are for the gluetun backend')
    if type(wireguard_port) is not int or not 1 <= wireguard_port <= 65535:
        raise ValueError('the NetBird WireGuard port must be 1..65535')
    control_mark_value(config.control_mark)
    overlay, tunnel, host = config.overlay_if, config.exit_if, config.host_if
    for name in (overlay, tunnel, host):
        if not INTERFACE.fullmatch(name):
            raise ValueError('invalid interface name')
    rules = [
        f'-A FORWARD -i {overlay} -o {tunnel} -j ACCEPT',
        f'-A FORWARD -i {tunnel} -o {overlay} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
        f'-A OUTPUT -o {host} -j ACCEPT',
        f'-A INPUT -i {host} -p udp -m udp --dport {wireguard_port} -j ACCEPT',
    ]
    if not all(post_rule_parseable(rule) for rule in rules):
        raise ValueError("a post-rule gluetun's chain parser would reject")
    lines = ['# Generated by tools/molebridge.py gluetun-post-rules; regenerate instead of editing.',
             "# gluetun runs these after enabling its firewall. They are not Molebridge's guard,",
             '# which is policy routing (docs/architecture.md#gluetun-backend).']
    lines += [f'iptables {rule}' for rule in rules]
    if ipv6:
        lines += [f'ip6tables {rule}' for rule in rules]
    return '\n'.join(lines) + '\n'


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

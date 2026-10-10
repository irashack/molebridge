"""The gluetun backend: routing guard, NetBird gate, validator and post-rules.

The shell tests run the real scripts against a small stateful stand-in for
iproute2, which prints rules and routes the way iproute2 does. Kernel
behavior itself is exercised by tools/check-routing.sh on Linux."""
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'routing' / 'contract-rules'
sys.path.insert(0, str(ROOT))
from molebridge.routing import (RoutingConfig, control_mark_value, family_status, host_table_status,  # noqa: E402
                                render_post_rules)

spec = importlib.util.spec_from_file_location('host_tools_gluetun', ROOT / 'tools' / 'molebridge.py')
host_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_tools)

pytestmark = pytest.mark.skipif(os.name != 'posix' or not shutil.which('sh'), reason='POSIX shell tests')

FAKE_IP = r'''
import ipaddress, json, os, sys

args = sys.argv[1:]
full = ' '.join(args)
with open(os.environ['FAKE_IP_STATE']) as f:
    state = json.load(f)
family = None
while args and args[0].startswith('-'):
    flag = args.pop(0)
    if flag in ('-4', '-6'):
        family = flag[1]
    elif flag != '-o':
        sys.exit('fake ip: unsupported flag ' + flag)
obj, cmd, rest = args[0], args[1], args[2:]
if cmd != 'show':
    with open(os.environ['FAKE_IP_LOG'], 'a') as f:
        f.write(full + '\n')
for fault in filter(None, os.environ.get('FAKE_IP_FAIL', '').split(';')):
    if fault in full:
        sys.exit(2)
fam = family or '4'


def save():
    with open(os.environ['FAKE_IP_STATE'], 'w') as f:
        json.dump(state, f)


def prefix(value):
    network = ipaddress.ip_network(value, strict=False)
    return str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)


def iface(name):
    return [name] if name == 'lo' or name in state['links'] else [name, '[detached]']


def parse_rule(tokens):
    rule, given, i = {'not': False, 'from': 'all'}, set(), 0
    while i < len(tokens):
        token = tokens[i]
        if token == 'not':
            rule['not'] = True
            i += 1
            continue
        if token in ('unreachable', 'prohibit', 'blackhole'):
            rule['action'] = token
            given.add('action')
            i += 1
            continue
        value = tokens[i + 1]
        if token in ('from', 'to'):
            rule[token] = 'all' if value == 'all' else prefix(value)
        elif token == 'fwmark':
            mark, _, mask = value.partition('/')
            mark, mask = int(mark, 0), int(mask, 0) if mask else 0xFFFFFFFF
            rule['fwmark'] = '%#x' % mark if mask == 0xFFFFFFFF else '%#x/%#x' % (mark, mask)
        elif token in ('iif', 'oif'):
            rule[token] = value
        elif token == 'ipproto':
            rule['ipproto'] = {'1': 'icmp', '58': 'ipv6-icmp'}.get(value, value)
        elif token in ('lookup', 'table'):
            rule['action'] = 'lookup ' + {'254': 'main', '255': 'local'}.get(value, value)
            token = 'action'
        elif token in ('priority', 'pref'):
            rule['priority'] = int(value)
        elif token == 'suppress_prefixlength':
            rule['suppress'] = value
        else:
            sys.exit('fake ip: unsupported rule selector ' + token)
        given.add(token)
        i += 2
    return rule, given


def rule_text(rule):
    out = ['not'] if rule['not'] else []
    out += ['from', rule['from']]
    if rule.get('to', 'all') != 'all':
        out += ['to', rule['to']]
    if 'fwmark' in rule:
        out += ['fwmark', rule['fwmark']]
    for key in ('iif', 'oif'):
        if key in rule:
            out += [key] + iface(rule[key])
    if 'ipproto' in rule:
        out += ['ipproto', rule['ipproto']]
    out.append(rule['action'])
    if 'suppress' in rule:
        out += ['suppress_prefixlength', rule['suppress']]
    return ' '.join(out)


def parse_route(tokens):
    route, i = {'table': 'main'}, 0
    if tokens[0] in ('unreachable', 'blackhole', 'prohibit', 'throw', 'unicast'):
        route['type'] = tokens[0]
        i = 1
    route['dst'] = 'default' if tokens[i] == 'default' else prefix(tokens[i])
    i += 1
    while i < len(tokens):
        if tokens[i] == 'onlink':
            route['onlink'] = True
            i += 1
            continue
        route[tokens[i]] = tokens[i + 1]
        i += 2
    route['table'] = {'254': 'main'}.get(route['table'], route['table'])
    if route.get('type') == 'unicast':
        del route['type']
    if 'metric' not in route and fam == '6':
        route['metric'] = '1024'
    return route


def route_text(route):
    out = [route['type']] if 'type' in route else []
    out.append(route['dst'])
    if 'via' in route:
        out += ['via', route['via']]
    dev = 'lo' if fam == '6' and 'type' in route else route.get('dev')
    if dev:
        out += ['dev', dev]
    if 'proto' in route:
        out += ['proto', route['proto']]
    if fam == '4' and 'type' not in route and 'via' not in route:
        out += ['scope', 'link']
    if 'src' in route:
        out += ['src', route['src']]
    if route.get('metric', '0') != '0':
        out += ['metric', route['metric']]
    if route.get('onlink'):
        out.append('onlink')
    if fam == '6':
        out += ['pref', 'medium']
    return ' '.join(out)


rules = state['rules'][fam]
if obj == 'rule' and cmd == 'show':
    wanted = int(rest[rest.index('priority') + 1]) if 'priority' in rest else None
    for priority, rule in sorted(rules, key=lambda r: r[0]):
        if wanted is None or priority == wanted:
            print('%d:\t%s' % (priority, rule_text(rule)))
elif obj == 'rule' and cmd == 'add':
    rule, _ = parse_rule(rest)
    priority = rule.pop('priority')
    if [priority, rule] in rules:
        sys.exit('RTNETLINK answers: File exists')
    rules.append([priority, rule])
    save()
elif obj == 'rule' and cmd == 'del':
    pattern, given = parse_rule(rest)
    for entry in rules:
        if entry[0] == pattern['priority'] and all(entry[1].get(k) == pattern.get(k) for k in given - {'priority'}) \
                and ('not' not in rest or entry[1]['not']):
            rules.remove(entry)
            save()
            break
    else:
        sys.exit('RTNETLINK answers: No such file or directory')
elif obj == 'route':
    tables = state['routes'][fam]
    table = rest[rest.index('table') + 1] if 'table' in rest else 'main'
    if cmd == 'show':
        if table not in tables:
            if fam == '4' and table != 'main':
                sys.exit('Error: ipv4: FIB table does not exist.\nDump terminated')
        for route in tables.get(table, []):
            print(route_text(route))
    elif cmd == 'flush':
        tables[table] = []
        save()
    elif cmd in ('replace', 'add'):
        route = parse_route(rest)
        entries = tables.setdefault(route.pop('table'), [])
        for existing in list(entries):
            if existing['dst'] == route['dst'] and existing.get('metric', '0') == route.get('metric', '0'):
                if cmd == 'add':
                    sys.exit('RTNETLINK answers: File exists')
                entries.remove(existing)
        entries.append(route)
        save()
    elif cmd == 'del':
        route = parse_route(rest)
        entries = tables.get(route.pop('table'), [])
        for existing in entries:
            if all(existing.get(k) == v for k, v in route.items() if k != 'metric' or v != '1024'):
                entries.remove(existing)
                save()
                break
        else:
            sys.exit('RTNETLINK answers: No such process')
    else:
        sys.exit('fake ip: unsupported route command')
elif obj in ('addr', 'link') and cmd == 'show':
    name = rest[rest.index('dev') + 1]
    link = state['links'].get(name)
    if link is None:
        sys.exit('Device "%s" does not exist.' % name)
    if obj == 'link':
        flags = 'POINTOPOINT,NOARP,UP,LOWER_UP' if link.get('up', True) else 'POINTOPOINT,NOARP'
        print('7: %s: <%s> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/none ' % (name, flags))
    else:
        for address in link.get('addr' + fam, []):
            print('7: %s    %s %s scope global %s\\       valid_lft forever preferred_lft forever'
                  % (name, 'inet' if fam == '4' else 'inet6', address, name))
else:
    sys.exit('fake ip: unsupported command ' + full)
'''

ENV = {'TUNNEL_BACKEND': 'gluetun', 'OVERLAY_CIDR': '192.0.2.0/24', 'OVERLAY6_CIDR': '2001:db8:1::/64',
       'OVERLAY_IF': 'wt0', 'EXIT_IF': 'wg0', 'EXIT_TABLE': '51821', 'HOST_IF': 'eth0', 'HOST_TABLE': '51822',
       'CONTROL_MARK': '0x1bd00'}

# The kernel's boot clock and boot id, as the guard and the gate read them
# (/proc/uptime, /proc/sys/kernel/random/boot_id), stood in for by two files:
# the uptime one advances with time.monotonic().
BOOT_ID = '00000000-0000-4000-8000-000000000001'
CLOCK_DIR = Path(tempfile.mkdtemp(prefix='molebridge-clock-'))
BOOT_FILE = CLOCK_DIR / 'boot_id'
UPTIME_FILE = CLOCK_DIR / 'uptime'
_CLOCK_START = time.monotonic()


def uptime():
    return 1000 + int(time.monotonic() - _CLOCK_START)


def _tick():
    while True:
        temporary = CLOCK_DIR / 'uptime.tmp'
        temporary.write_text(f'{1000 + time.monotonic() - _CLOCK_START:.2f} 0.00\n')
        os.replace(temporary, UPTIME_FILE)
        time.sleep(0.1)


BOOT_FILE.write_text(BOOT_ID + '\n')
UPTIME_FILE.write_text('1000.00 0.00\n')
threading.Thread(target=_tick, daemon=True).start()
CLOCK_ENV = {'MOLEBRIDGE_BOOT_ID_FILE': str(BOOT_FILE), 'MOLEBRIDGE_UPTIME_FILE': str(UPTIME_FILE)}


# A namespace as gluetun leaves it, with NetBird's rules after a first run.
STATE = {
    'links': {'lo': {}, 'eth0': {}, 'wt0': {},
              'wg0': {'up': True, 'addr4': ['203.0.113.1/32'], 'addr6': ['2001:db8:3::1/128']}},
    'rules': {
        '4': [[0, {'not': False, 'from': 'all', 'action': 'lookup local'}],
              [98, {'not': False, 'from': 'all', 'to': '198.51.100.0/28', 'action': 'lookup main'}],
              [100, {'not': False, 'from': '198.51.100.1', 'action': 'lookup 200'}],
              [101, {'not': True, 'from': 'all', 'fwmark': '0xca6c', 'action': 'lookup 51820'}],
              [32766, {'not': False, 'from': 'all', 'action': 'lookup main'}],
              [32767, {'not': False, 'from': 'all', 'action': 'lookup default'}]],
        '6': [[0, {'not': False, 'from': 'all', 'action': 'lookup local'}],
              [101, {'not': True, 'from': 'all', 'fwmark': '0xca6c', 'action': 'lookup 51820'}],
              [32766, {'not': False, 'from': 'all', 'action': 'lookup main'}]],
    },
    'routes': {
        '4': {'main': [{'dst': '198.51.100.0/28', 'dev': 'eth0', 'proto': 'kernel', 'src': '198.51.100.1'},
                       {'dst': 'default', 'via': '198.51.100.2', 'dev': 'eth0'},
                       {'dst': '192.0.2.0/24', 'dev': 'wt0', 'proto': 'kernel', 'src': '192.0.2.1'}],
              '51820': [{'dst': 'default', 'dev': 'wg0'}],
              '200': [{'dst': 'default', 'via': '198.51.100.2', 'dev': 'eth0'}]},
        '6': {'main': [{'dst': '2001:db8:2::/64', 'dev': 'eth0', 'proto': 'kernel', 'metric': '256'},
                       {'dst': 'fe80::/64', 'dev': 'eth0', 'proto': 'kernel', 'metric': '256'},
                       {'dst': 'default', 'via': 'fe80::1', 'dev': 'eth0', 'proto': 'ra', 'metric': '1024'},
                       {'dst': '2001:db8:1::/64', 'dev': 'wt0', 'proto': 'kernel', 'metric': '256'}],
              '51820': [{'dst': 'default', 'dev': 'wg0', 'metric': '1024'}]},
    },
}


class Namespace:
    """The fake iproute2's state file, command log and the guard's files."""

    def __init__(self, path, state=None):
        self.path = path
        self.bin = path / 'bin'
        self.bin.mkdir()
        ip = self.bin / 'ip'
        ip.write_text(f'#!{sys.executable} -SE\n' + FAKE_IP)
        ip.chmod(0o755)
        wg = self.bin / 'wg'
        wg.write_text('#!/bin/sh\n[ -n "$FAKE_WG_FWMARK" ] || exit 1\nprintf \'%s\\n\' "$FAKE_WG_FWMARK"\n')
        wg.chmod(0o755)
        # The gate starts NetBird in its own process group; where the host
        # has no setsid (macOS), a stand-in that runs the command as is.
        if not shutil.which('setsid'):
            setsid = self.bin / 'setsid'
            setsid.write_text('#!/bin/sh\nexec "$@"\n')
            setsid.chmod(0o755)
        self.state_file = path / 'state.json'
        self.log = path / 'commands'
        self.ready = path / 'ready'
        self.status = path / 'overlay-fwmark'
        self.write(copy.deepcopy(STATE) if state is None else state)

    def write(self, state):
        self.state_file.write_text(json.dumps(state))

    def read(self):
        return json.loads(self.state_file.read_text())

    def commands(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def env(self, **changes):
        env = {k: v for k, v in os.environ.items() if not k.startswith(('NB_', 'WT_'))}
        env.update(ENV, PATH=f'{self.bin}:{os.environ["PATH"]}', FAKE_IP_STATE=str(self.state_file),
                   GLUETUN_RULES=str(RULES), **CLOCK_ENV,
                   FAKE_IP_LOG=str(self.log), ROUTING_READY_FILE=str(self.ready),
                   GUARD_STATUS_FILE=str(self.status))
        env.update(changes)
        return env

    def guard(self, *args, **changes):
        return subprocess.run(['sh', str(ROOT / 'routing' / '10-exit-routing'), *args], env=self.env(**changes),
                              capture_output=True, text=True, timeout=30)

    def rules(self, family):
        result = subprocess.run(['ip', f'-{family}', 'rule', 'show'], env=self.env(), capture_output=True,
                                text=True, check=True)
        return [tuple(line.split('\t', 1)) for line in result.stdout.splitlines()]

    def routes(self, family, table):
        return [r for r in self.read()['routes'][str(family)].get(table, [])]


@pytest.fixture
def ns(tmp_path):
    return Namespace(tmp_path)


def guard_rules(ns, family):
    return [(p, text) for p, text in ns.rules(family) if int(p.rstrip(':')) <= 97 or p in ('102:', '103:', '104:')]


def expected_rules(family, address='203.0.113.1', overlay='192.0.2.0/24'):
    if family == 6:
        address, overlay = '2001:db8:3::1', '2001:db8:1::/64'
    icmp = 'icmp' if family == 4 else 'ipv6-icmp'
    return [('1:', 'not from all iif wt0 lookup local'),
            ('88:', 'from all fwmark 0x1bd00 iif lo lookup 51822'),
            ('89:', 'from all fwmark 0x1bd00 iif lo unreachable'),
            ('90:', f'from all to {overlay} iif wg0 lookup main'),
            ('91:', f'from all to {overlay} iif lo lookup main suppress_prefixlength 0'),
            ('92:', f'from all to {overlay} iif lo unreachable'),
            ('94:', f'from {address} ipproto {icmp} lookup 51821'),
            ('95:', 'from all iif wt0 lookup 51821'),
            ('96:', 'from all oif wg0 lookup 51821'),
            ('97:', 'from all iif wt0 unreachable'),
            ('102:', 'from all fwmark 0xca6c iif lo lookup main'),
            ('103:', 'from all iif lo lookup 51822 suppress_prefixlength 0'),
            ('104:', 'from all iif lo unreachable')]


def test_install_builds_the_whole_contract(ns):
    result = ns.guard('--once')
    assert result.returncode == 0, result.stderr
    assert ns.ready.exists()
    for family in (4, 6):
        assert guard_rules(ns, family) == expected_rules(family)
        # gluetun's own rules are left alone.
        assert any(text.startswith('not from all fwmark 0xca6c') for _, text in ns.rules(family))
    state = ns.read()
    assert state['routes']['4']['51821'] == [{'type': 'unreachable', 'dst': 'default', 'metric': '4096'},
                                              {'dst': 'default', 'dev': 'wg0'}]
    assert {'dst': 'default', 'dev': 'wg0', 'metric': '1024'} in state['routes']['6']['51821']
    # Only the host interface's on-link and default routes, on-link first.
    assert state['routes']['4']['51822'] == [{'dst': '198.51.100.0/28', 'dev': 'eth0', 'src': '198.51.100.1'},
                                              {'dst': 'default', 'via': '198.51.100.2', 'dev': 'eth0'}]
    assert [r['dst'] for r in state['routes']['6']['51822']] == ['2001:db8:2::/64', 'fe80::/64', 'default']
    assert all(r['dev'] == 'eth0' for f in '46' for r in state['routes'][f]['51822'])
    calls = ns.commands()
    for family in ('-4', '-6'):
        local = calls.index(f'{family} rule add not iif wt0 lookup local priority 1')
        kernel = calls.index(f'{family} rule del priority 0')
        guard = calls.index(f'{family} rule add iif wt0 unreachable priority 80')
        control = calls.index(f'{family} rule add iif lo fwmark 0x1bd00/0xffffffff lookup 51822 priority 88')
        forward = calls.index(f'{family} rule add iif wt0 lookup 51821 priority 95')
        unblock = len(calls) - 1 - calls[::-1].index(f'{family} rule del iif wt0 unreachable priority 80')
        assert local < kernel < guard < control < unblock and guard < forward < unblock
    assert 'every rule and route in place' in result.stdout


def test_a_second_pass_changes_nothing(ns):
    assert ns.guard('--once').returncode == 0
    before = ns.read()
    ns.log.unlink()
    result = ns.guard('--reconcile')
    assert result.returncode == 0, result.stderr
    assert not any(' add ' in c or ' del ' in c or 'flush' in c or 'replace' in c for c in ns.commands())
    assert ns.read() == before


@pytest.mark.parametrize('overlay6', ['2001:DB8:1:0::/64', '2001:0db8:0001:0000:0000:0000:0000:0000/64'])
def test_non_canonical_ipv6_overlay_is_compared_as_iproute2_prints_it(ns, overlay6):
    assert ns.guard('--once', OVERLAY6_CIDR=overlay6).returncode == 0
    ns.log.unlink()
    assert ns.guard('--reconcile', OVERLAY6_CIDR=overlay6).returncode == 0
    assert not any('rule' in c for c in ns.commands())


@pytest.mark.parametrize('network', ['2001:db8::/32', '2001:db8:0:1::/64', '2001:db8:1:0:0:1::/96',
                                     'fd00::/8', '2001:db8:0:0:1:0:0:0/80', 'fd12:3456:789a:1::/64'])
def test_ipv6_canonical_form_matches_python(tmp_path, network):
    import ipaddress
    script = RULES.read_text()
    start = script.index('canonical_cidr6() {')
    end = script.index('\n}\n', start) + 3
    text = network.upper().replace('DB8', '0DB8')
    result = subprocess.run(['sh', '-c', script[start:end] + 'canonical_cidr6 "$1"', 'sh', text],
                            capture_output=True, text=True, check=True)
    assert result.stdout.strip() == str(ipaddress.IPv6Network(network))


@pytest.mark.parametrize('bad', ['2001:db8::1::/64', '2001:db8:/64', '1:2:3:4:5:6:7:8:9/64', '2001:db8::g/64',
                                 '12345::/64', '::ffff:192.0.2.1/128'])
def test_ipv6_canonical_form_rejects_malformed_addresses(bad):
    script = RULES.read_text()
    start = script.index('canonical_cidr6() {')
    end = script.index('\n}\n', start) + 3
    result = subprocess.run(['sh', '-c', script[start:end] + 'canonical_cidr6 "$1"', 'sh', bad],
                            capture_output=True, text=True)
    assert result.returncode != 0


def test_reconcile_repairs_rules_without_removing_correct_ones(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    rules = state['rules']['4']
    # Rule 88 without `iif lo` would send forwarded packets marked 0x1bd00 to
    # the host; rule 95 is gone; a stray rule sits in Molebridge's range; a
    # second rule shares priority 97 with the terminal guard.
    rules[:] = [r for r in rules if r[0] not in (88, 95)]
    rules.append([88, {'not': False, 'from': 'all', 'fwmark': '0x1bd00', 'action': 'lookup 51822'}])
    rules.append([50, {'not': False, 'from': 'all', 'iif': 'wt0', 'action': 'lookup main'}])
    rules.append([97, {'not': False, 'from': 'all', 'iif': 'wt0', 'action': 'lookup main'}])
    ns.write(state)
    ns.log.unlink()
    result = ns.guard('--reconcile')
    assert result.returncode == 0, result.stderr
    assert guard_rules(ns, 4) == expected_rules(4)
    calls = ns.commands()
    assert '-4 rule del priority 50 from all iif wt0 lookup main' in calls
    # The extra rule at 97 has an attribute the terminal guard lacks, so it can
    # be removed by its selectors and the correct rules 1 and 97 stay.
    assert '-4 rule del priority 97 from all iif wt0 lookup main' in calls
    assert not any(c.startswith('-4 rule del priority 97') and 'lookup main' not in c for c in calls)
    assert not any(c.startswith('-4 rule del priority 1 ') or c == '-4 rule del priority 1' for c in calls)
    # The wrong rule 88 is a subset of the right one: deleting it by its
    # selectors could take the right one, so 88 is rebuilt behind a copy at 87.
    copy = calls.index('-4 rule add iif lo fwmark 0x1bd00/0xffffffff lookup 51822 priority 87')
    cleared = calls.index('-4 rule del priority 88')
    restored = calls.index('-4 rule add iif lo fwmark 0x1bd00/0xffffffff lookup 51822 priority 88', cleared)
    removed = calls.index('-4 rule del iif lo fwmark 0x1bd00/0xffffffff lookup 51822 priority 87')
    assert copy < cleared < restored < removed
    # Missing rules go in before wrong ones come out.
    assert calls.index('-4 rule add iif wt0 lookup 51821 priority 95') < calls.index(
        '-4 rule del priority 50 from all iif wt0 lookup main')


def test_reconcile_owns_102_to_104_but_not_the_rules_around_them(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    rules = state['rules']['4']
    # gluetun reconnecting: its rule 101 is gone for a moment.
    rules[:] = [r for r in rules if r[0] != 101]
    rules.append([102, {'not': False, 'from': 'all', 'action': 'lookup main'}])
    rules.append([106, {'not': False, 'from': 'all', 'action': 'lookup main'}])
    ns.write(state)
    ns.log.unlink()
    assert ns.guard('--reconcile').returncode == 0
    assert guard_rules(ns, 4) == expected_rules(4)
    calls = ns.commands()
    # The stray rule's selectors are a subset of rule 102's, so 102 is rebuilt
    # behind a copy at 101, which comes out again.
    assert calls[0] == '-4 rule add iif lo fwmark 0xca6c/0xffffffff lookup main priority 101'
    assert calls[-2:] == ['-4 rule add iif lo fwmark 0xca6c/0xffffffff lookup main priority 102',
                          '-4 rule del iif lo fwmark 0xca6c/0xffffffff lookup main priority 101']
    assert set(calls[1:-2]) == {'-4 rule del priority 102'}
    # Priorities that aren't Molebridge's stay as they are, and the guard
    # doesn't put gluetun's 101 back.
    assert ('106:', 'from all lookup main') in ns.rules(4)
    assert not any(p == '101:' for p, _ in ns.rules(4))


def test_rebuild_keeps_a_correct_rule_listed_before_a_wrong_subset(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    # Added after the guard's own rule: a kernel delete by these selectors
    # would match the correct rule first.
    state['rules']['4'].append([97, {'not': False, 'from': 'all', 'action': 'unreachable'}])
    ns.write(state)
    ns.log.unlink()
    assert ns.guard('--reconcile').returncode == 0
    assert guard_rules(ns, 4) == expected_rules(4)
    calls = ns.commands()
    assert calls[0] == '-4 rule add iif wt0 unreachable priority 96'
    assert calls[-1] == '-4 rule del iif wt0 unreachable priority 96'


def test_rule_91_without_suppression_is_rebuilt_behind_a_copy(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    # Without suppress_prefixlength the rule would hand the exit's own overlay
    # traffic to main's default route. Its selectors are a subset of the
    # right rule's, so it is rebuilt behind a copy at 90, and the real rule 90
    # stays.
    state['rules']['4'] = [r for r in state['rules']['4'] if r[0] != 91]
    state['rules']['4'].append([91, {'not': False, 'from': 'all', 'to': '192.0.2.0/24', 'iif': 'lo',
                                     'action': 'lookup main'}])
    ns.write(state)
    ns.log.unlink()
    assert ns.guard('--reconcile').returncode == 0
    assert guard_rules(ns, 4) == expected_rules(4)
    calls = ns.commands()
    copy = '-4 rule add iif lo to 192.0.2.0/24 lookup main suppress_prefixlength 0 priority 90'
    assert copy in calls
    assert calls[-1] == '-4 rule del iif lo to 192.0.2.0/24 lookup main suppress_prefixlength 0 priority 90'
    assert not any(c.startswith('-4 rule del priority 90') or 'iif wg0' in c for c in calls)


def test_the_kill_switch_waits_for_the_host_table(ns):
    # On a fresh namespace the host table must hold HOST_IF's on-link routes
    # (rule 103's exception) before rule 104 goes in: the kernel validates a
    # gateway such as gluetun's table-200 default with a lookup that passes
    # these rules as local traffic.
    assert ns.guard('--once', FAKE_IP_FAIL='-4 route replace 198.51.100.0/28').returncode != 0
    assert not any(p == '104:' for p, _ in ns.rules(4))
    assert any(p == '104:' for p, _ in ns.rules(6))
    calls = ns.commands()
    assert calls.index('-6 route replace 2001:db8:2::/64 dev eth0 metric 256 table 51822') < \
        calls.index('-6 rule add iif lo unreachable priority 104')
    assert calls.index('-6 rule add iif lo lookup 51822 suppress_prefixlength 0 priority 103') < \
        calls.index('-6 rule add iif lo unreachable priority 104')
    result = ns.guard('--reconcile')
    assert result.returncode == 0, result.stderr
    assert guard_rules(ns, 4) == expected_rules(4)


def test_held_kill_switch_and_a_missing_host_interface_are_reported(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    del state['links']['eth0']
    ns.write(state)
    result = ns.guard('--reconcile')
    assert result.returncode != 0
    assert 'eth0 is not in this namespace' in result.stderr and 'recover' in result.stderr


def test_reconcile_follows_a_recreated_tunnel_interface(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    # gluetun recreates its interface: the link, its routes and addresses go,
    # and it comes back with another address.
    del state['links']['wg0']
    for family in '46':
        state['routes'][family]['51821'] = [r for r in state['routes'][family]['51821'] if r.get('dev') != 'wg0']
        state['routes'][family]['51820'] = []
    ns.write(state)
    result = ns.guard('--reconcile')
    assert result.returncode == 0, result.stderr
    assert ns.read()['routes']['4']['51821'] == [{'type': 'unreachable', 'dst': 'default', 'metric': '4096'}]
    # Rules naming the missing interface stay, detached; rule 94 waits for an address.
    assert ('96:', 'from all oif wg0 [detached] lookup 51821') in ns.rules(4)
    assert not any(p == '94:' for p, _ in ns.rules(4))
    state = ns.read()
    state['links']['wg0'] = {'up': True, 'addr4': ['203.0.113.9/32'], 'addr6': []}
    ns.write(state)
    result = ns.guard('--reconcile')
    assert result.returncode == 0, result.stderr
    assert 'IPv4 tunnel route through wg0 restored' in result.stdout
    assert guard_rules(ns, 4) == expected_rules(4, address='203.0.113.9')
    assert not any(p == '94:' for p, _ in ns.rules(6))
    routes6 = ns.read()['routes']['6']['51821']
    assert routes6 == [{'type': 'unreachable', 'dst': 'default', 'metric': '4096'}]


def test_reconcile_removes_foreign_exit_and_host_routes(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    state['routes']['4']['51821'].append({'dst': '198.51.100.0/28', 'via': '198.51.100.2', 'dev': 'eth0'})
    state['routes']['4']['51822'].append({'dst': '10.0.0.0/8', 'dev': 'wg0'})
    ns.write(state)
    assert ns.guard('--reconcile').returncode == 0
    state = ns.read()
    assert all(r.get('dev') != 'eth0' for r in state['routes']['4']['51821'])
    assert all(r['dev'] == 'eth0' for r in state['routes']['4']['51822'])
    assert {'type': 'unreachable', 'dst': 'default', 'metric': '4096'} in state['routes']['4']['51821']


def test_host_table_follows_the_main_table(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    main = state['routes']['4']['main']
    main[:] = [{'dst': '198.51.100.16/28', 'dev': 'eth0', 'proto': 'kernel', 'src': '198.51.100.17'},
               {'dst': 'default', 'via': '198.51.100.18', 'dev': 'eth0'}]
    ns.write(state)
    result = ns.guard('--reconcile')
    assert result.returncode == 0, result.stderr
    assert ns.read()['routes']['4']['51822'] == [
        {'dst': '198.51.100.16/28', 'dev': 'eth0', 'src': '198.51.100.17'},
        {'dst': 'default', 'via': '198.51.100.18', 'dev': 'eth0'}]


def test_no_ipv4_default_through_the_host_interface_is_not_ready(ns):
    state = ns.read()
    state['routes']['4']['main'] = [r for r in state['routes']['4']['main'] if r['dst'] != 'default']
    state['routes']['4']['main'].append({'dst': 'default', 'dev': 'wg0'})
    ns.write(state)
    result = ns.guard('--once')
    assert result.returncode != 0
    assert not ns.ready.exists()
    assert 'no IPv4 default route through eth0' in result.stderr
    # The rules are installed all the same, and nothing via the tunnel was copied.
    assert guard_rules(ns, 4) == expected_rules(4)
    assert all(r['dev'] == 'eth0' for r in ns.read()['routes']['4']['51822'])


def test_tunnel_down_keeps_the_guard_ready_and_drops_the_tunnel_route(ns):
    assert ns.guard('--once').returncode == 0
    state = ns.read()
    state['links']['wg0']['up'] = False
    ns.write(state)
    assert ns.guard('--reconcile').returncode == 0
    assert ns.ready.exists()
    assert ns.read()['routes']['4']['51821'] == [{'type': 'unreachable', 'dst': 'default', 'metric': '4096'}]


def test_failed_install_leaves_the_temporary_guard(ns):
    result = ns.guard('--once', FAKE_IP_FAIL='-6 rule add iif wt0 lookup 51821')
    assert result.returncode != 0
    assert not ns.ready.exists()
    assert ('80:', 'from all iif wt0 unreachable') in ns.rules(6)
    assert 'temporary guard (priority 80) stays' in result.stderr


def test_status_file_reports_the_overlay_fwmark(ns):
    assert ns.guard('--once', FAKE_WG_FWMARK='0x1bd00').returncode == 0
    boot, stamp, value = ns.status.read_text().split()
    assert boot == BOOT_ID and value == '0x1bd00' and 0 <= uptime() - int(stamp) < 30
    assert ns.guard('--reconcile').returncode == 0
    assert ns.status.read_text().split()[2] == 'absent'
    assert ns.guard('--reconcile', FAKE_WG_FWMARK='off').returncode == 0
    assert ns.status.read_text().split()[2] == 'off'


def test_status_file_is_not_written_without_the_boot_clock(ns):
    result = ns.guard('--once', FAKE_WG_FWMARK='0x1bd00', MOLEBRIDGE_UPTIME_FILE='/nonexistent')
    assert result.returncode == 0
    assert not ns.status.exists()
    assert 'cannot read the boot clock' in result.stderr


def run_guard_loop(ns, seconds, *, midway=None, **changes):
    """Run the guard's long-lived loop for a while, calling midway() after 3
    seconds (past its first pass); return the fwmark records it wrote, as
    (boot-clock stamp, value), one per change."""
    process = subprocess.Popen(['sh', str(ROOT / 'routing' / '10-exit-routing')], env=ns.env(**changes),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    records = []
    try:
        started = time.monotonic()
        while time.monotonic() < started + seconds:
            if midway and time.monotonic() > started + 3:
                midway()
                midway = None
            try:
                _, stamp, value = ns.status.read_text().split()
            except (OSError, ValueError):
                stamp = None
            if stamp and (not records or records[-1][0] != int(stamp)):
                records.append((int(stamp), value))
            time.sleep(0.2)
    finally:
        process.terminate()
        process.wait(timeout=10)
    return records


@pytest.mark.parametrize('interval,repaired', [('60', False), ('2', True)])
def test_fwmark_records_do_not_wait_for_the_reconcile_interval(ns, interval, repaired):
    assert ns.guard('--once', FAKE_WG_FWMARK='0x1bd00').returncode == 0

    def break_rule_95():
        state = ns.read()
        state['rules']['4'] = [r for r in state['rules']['4'] if r[0] != 95]
        ns.write(state)
    records = run_guard_loop(ns, 10, midway=break_rule_95, FAKE_WG_FWMARK='0x1bd00',
                             ROUTING_RECONCILE_INTERVAL=interval)
    # A record every couple of seconds whatever the interval; the gate's
    # shortest grace is 5 seconds.
    assert len(records) >= 3 and all(value == '0x1bd00' for _, value in records)
    assert max(b[0] - a[0] for a, b in zip(records, records[1:])) <= 3
    # Only the 2-second loop has reconciled the broken rule within the window.
    assert any(p == '95:' for p, _ in ns.rules(4)) is repaired


@pytest.mark.parametrize('setting,value', [
    ('CONTROL_MARK', '0x1bd01'), ('CONTROL_MARK', '0x1BD00'), ('CONTROL_MARK', '113920'),
    ('CONTROL_MARK', '0x01bd00'), ('CONTROL_MARK', '0x1bd000000'), ('HOST_TABLE', '51821'),
    ('HOST_TABLE', '7120'), ('EXIT_TABLE', '51820'), ('HOST_TABLE', '255'), ('EXIT_IF', 'wg-0'),
    ('HOST_IF', 'lo'), ('HOST_IF', 'wt0'), ('HOST_IF', 'wg0'), ('ROUTING_RECONCILE_INTERVAL', '0'),
    ('ROUTING_RECONCILE_INTERVAL', '61'),
    ('OVERLAY6_CIDR', '2001:db8::1::/64'), ('TUNNEL_BACKEND', 'other'),
])
def test_bad_gluetun_settings_change_nothing(ns, setting, value):
    result = ns.guard('--once', **{setting: value})
    assert result.returncode != 0
    assert '10-exit-routing:' in result.stderr
    assert not ns.commands() and not ns.ready.exists()


# The NetBird gate in gluetun mode. It checks the namespace with the guard's
# own definitions, so these tests run it against the same stand-in for
# iproute2, after a real guard pass.


_INSTALLED = {}


class Gate:
    def __init__(self, path):
        self.path = path
        if not _INSTALLED:
            # One real guard pass, reused: every test starts from its result.
            (path / 'install').mkdir()
            first = Namespace(path / 'install')
            result = first.guard('--once')
            assert result.returncode == 0, result.stderr
            _INSTALLED.update(first.read())
        self.ns = Namespace(path, copy.deepcopy(_INSTALLED))
        (path / 'state').mkdir()
        self.log = path / 'client.log'
        self.status = self.ns.status

    def change(self, edit):
        """Edit the namespace state: edit(state) changes it in place."""
        state = self.ns.read()
        edit(state)
        self.ns.write(state)

    def run(self, command, *, timeout=20, wait_fake=False, **changes):
        if wait_fake:
            # Stop at the first wait instead of waiting for guards.
            (self.ns.bin / 'sleep').write_text('#!/bin/sh\nexit 42\n')
            (self.ns.bin / 'sleep').chmod(0o755)
        env = self.ns.env()
        env.update(GATE_DIR=str(self.path), TUNNEL_BACKEND='gluetun', NB_INTERFACE_NAME='wt0',
                   NB_DISABLE_USERSPACE_ROUTING='true', NB_STATE_DIR=str(self.path / 'state'),
                   NB_LOG_FILE=f'console,{self.log}', NB_FWMARK_BASE='0x1bd00')
        env.update(changes)
        return subprocess.run(['sh', str(ROOT / 'routing' / 'wait-for-guards'), 'sh', '-c', command],
                              env=env, capture_output=True, text=True, timeout=timeout)


@pytest.fixture
def gate(tmp_path):
    return Gate(tmp_path)


def fresh_status(gate, value='0x1bd00', ahead=0, boot=BOOT_ID):
    gate.status.write_text(f'{boot} {uptime() + ahead} {value}\n')


@pytest.mark.parametrize('name,value', [
    ('NB_USE_LEGACY_ROUTING', 'true'), ('NB_SKIP_SOCKET_MARK', '1'), ('NB_DISABLE_CUSTOM_ROUTING', 'T'),
    ('NB_DISABLE_CUSTOM_ROUTING', 'TRUE'), ('NB_FWMARK_BASE', '0x2bd00'), ('NB_FWMARK_BASE', '0x1BD00'),
    ('NB_FWMARK_BASE', '113920'), ('CONTROL_MARK', '0x1bd01'), ('CONTROL_MARK', '0x1bd00 '),
    ('NB_LOG_FILE', 'console'), ('HOST_TABLE', '0'), ('HOST_IF', 'lo'), ('FWMARK_GRACE', '31'), ('FWMARK_GRACE', '4'), ('FWMARK_GRACE', '0'),
    ('OVERLAY_CIDR', ''), ('OVERLAY_CIDR', '192.0.2.1/24'), ('OVERLAY6_CIDR', '2001:db8::1::/64'),
    ('EXIT_IF', 'wg-0'), ('EXIT_TABLE', '51820'), ('HOST_TABLE', '51821'),
    ('GLUETUN_RULES', '/nonexistent/gluetun-rules'),
])
def test_gluetun_gate_refuses_bad_settings(gate, name, value):
    result = gate.run('touch "$GATE_DIR/started"', **{name: value})
    assert result.returncode == 1
    assert 'NetBird gate: refusing to start NetBird: ' in result.stderr
    assert not (gate.path / 'started').exists()


def test_gluetun_gate_check_config_covers_the_gluetun_settings(gate):
    result = gate.run('true', NB_SKIP_SOCKET_MARK='true')
    assert result.returncode == 1
    env = gate.ns.env()
    env.update(TUNNEL_BACKEND='gluetun', NB_INTERFACE_NAME='wt0', NB_DISABLE_USERSPACE_ROUTING='true',
               NB_STATE_DIR=str(gate.path / 'state'), NB_LOG_FILE=f'console,{gate.log}', NB_SKIP_SOCKET_MARK='1')
    result = subprocess.run(['sh', str(ROOT / 'routing' / 'wait-for-guards'), '--check-config'], env=env,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 1 and 'NB_SKIP_SOCKET_MARK is set' in result.stderr
    del env['NB_SKIP_SOCKET_MARK']
    result = subprocess.run(['sh', str(ROOT / 'routing' / 'wait-for-guards'), '--check-config'], env=env,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0 and 'configuration accepted' in result.stdout


@pytest.mark.parametrize('name,value', [('NB_USE_LEGACY_ROUTING', 'false'), ('NB_SKIP_SOCKET_MARK', '0'),
                                        ('NB_DISABLE_CUSTOM_ROUTING', 'no'), ('NB_FWMARK_BASE', '')])
def test_gluetun_gate_accepts_values_netbird_reads_as_false(gate, name, value):
    fresh_status(gate)
    result = gate.run('touch "$GATE_DIR/started"', **{name: value})
    assert result.returncode == 0, result.stderr
    assert (gate.path / 'started').exists()


def rule_change(family, edit):
    def change(state):
        edit(state['rules'][family])
    return change


def drop(*priorities):
    return lambda rules: rules.__setitem__(slice(None), [r for r in rules if r[0] not in priorities])


def add(priority, **rule):
    return lambda rules: rules.append([priority, dict({'not': False, 'from': 'all'}, **rule)])


def replace(priority, **rule):
    def edit(rules):
        drop(priority)(rules)
        add(priority, **rule)(rules)
    return edit


RULE_BREAKS = {
    'no 88': drop(88),
    'no 89': drop(89),
    'no 90': drop(90),
    'no 91': drop(91),
    'no 92': drop(92),
    '91 without suppress_prefixlength': replace(91, to='192.0.2.0/24', iif='lo', action='lookup main'),
    'no 94': drop(94),
    'no 95': drop(95),
    'no 96': drop(96),
    'no 97': drop(97),
    'no 102': drop(102),
    'no 103': drop(103),
    'no 104': drop(104),
    '104 without iif lo': replace(104, action='unreachable'),
    '103 without suppress_prefixlength': replace(103, iif='lo', action='lookup 51822'),
    'second rule at 102': add(102, action='lookup main'),
    'kernel rule 0 back': add(0, action='lookup local'),
    '88 without iif lo': replace(88, fwmark='0x1bd00', action='lookup 51822'),
    '89 with a narrow mask': replace(89, fwmark='0x1bd00/0xff00', iif='lo', action='unreachable'),
    '88 to the exit table': replace(88, fwmark='0x1bd00', iif='lo', action='lookup 51821'),
    'second rule at 88': add(88, fwmark='0x1bd00', action='lookup main'),
    'early main-table bypass': add(50, iif='wt0', action='lookup main'),
    'temporary guard left': add(80, iif='wt0', action='unreachable'),
    '90 for another range': replace(90, to='198.51.100.0/24', iif='wg0', action='lookup main'),
}


@pytest.mark.parametrize('break_name', sorted(RULE_BREAKS))
@pytest.mark.parametrize('family', ['4', '6'])
def test_gluetun_gate_waits_for_the_whole_rule_set(gate, break_name, family):
    if break_name == '90 for another range' and family == '6':
        edit = replace(90, to='2001:db8:9::/64', iif='wg0', action='lookup main')
    else:
        edit = RULE_BREAKS[break_name]
    gate.change(rule_change(family, edit))
    result = gate.run('touch "$GATE_DIR/started"', wait_fake=True)
    assert result.returncode == 42, result.stderr
    assert not (gate.path / 'started').exists()


def routes_change(family, table, edit):
    def change(state):
        edit(state['routes'][family].setdefault(table, []))
    return change


@pytest.mark.parametrize('family,table,edit', [
    ('4', '51821', lambda r: r.append({'dst': '198.51.100.0/28', 'via': '198.51.100.2', 'dev': 'eth0'})),
    ('6', '51821', lambda r: r.append({'dst': 'default', 'via': 'fe80::1', 'dev': 'eth0', 'metric': '100'})),
    ('4', '51821', lambda r: r.__setitem__(slice(None), [x for x in r if x.get('type') != 'unreachable'])),
    ('4', '51821', lambda r: r.__setitem__(slice(None), [x for x in r if x.get('dev') != 'wg0'])),
    ('4', '51822', lambda r: r.clear()),
    ('4', '51822', lambda r: r.__setitem__(slice(None), [x for x in r if x['dst'] != 'default'])),
    ('4', '51822', lambda r: r.append({'dst': '10.0.0.0/8', 'dev': 'wg0'})),
    ('6', '51822', lambda r: r.append({'dst': '2001:db8:1::/64', 'dev': 'wt0', 'metric': '256'})),
    ('6', '51822', lambda r: r.clear()),
])
def test_gluetun_gate_waits_for_the_exit_and_host_tables(gate, family, table, edit):
    gate.change(routes_change(family, table, edit))
    result = gate.run('touch "$GATE_DIR/started"', wait_fake=True)
    assert result.returncode == 42, result.stderr
    assert not (gate.path / 'started').exists()


def test_gluetun_gate_accepts_an_empty_ipv6_host_table(gate):
    def no_ipv6_host_routes(state):
        state['routes']['6']['main'] = [r for r in state['routes']['6']['main'] if r['dev'] != 'eth0']
        state['routes']['6']['51822'] = []
    gate.change(no_ipv6_host_routes)
    fresh_status(gate)
    result = gate.run('touch "$GATE_DIR/started"')
    assert result.returncode == 0, result.stderr


def test_gluetun_gate_accepts_a_tunnel_that_is_down(gate):
    # gluetun reconnecting: no interface, so no tunnel route and no rule 94 belong.
    def tunnel_gone(state):
        del state['links']['wg0']
        for family in '46':
            state['routes'][family]['51821'] = [r for r in state['routes'][family]['51821'] if r.get('dev') != 'wg0']
            state['rules'][family] = [r for r in state['rules'][family] if r[0] != 94]
    gate.change(tunnel_gone)
    fresh_status(gate)
    result = gate.run('touch "$GATE_DIR/started"')
    assert result.returncode == 0, result.stderr


def test_gluetun_gate_stops_netbird_that_logs_legacy_routing(gate):
    gate.log.write_text('2026-01-01T00:00:00Z WARN client/net/env_linux.go:66: system doesn\'t support '
                        'required routing features, falling back to legacy routing\n')
    # An old run's line does not count; one from this launch does.
    command = ('touch "$GATE_DIR/started"; sleep 3; echo "2026-01-01T00:00:05Z WARN client/net/env_linux.go:66: '
               'system doesn\'t support required routing features, falling back to legacy routing" '
               '>> "$GATE_DIR/client.log"; exec sleep 30')
    fresh_status(gate)
    started = time.monotonic()
    result = gate.run(command)
    assert result.returncode == 1
    assert time.monotonic() - started > 3
    assert 'NetBird gate: stopping NetBird: NetBird logged that it runs without advanced routing' in result.stderr


def test_gluetun_gate_stops_netbird_without_the_control_mark(gate):
    fresh_status(gate, 'off')
    result = gate.run('touch "$GATE_DIR/started"; exec sleep 30', FWMARK_GRACE='5')
    assert (gate.path / 'started').exists()
    assert result.returncode == 1
    assert 'wt0 has not carried the control mark 0x1bd00 for 5 seconds (last reported: off)' in result.stderr


def test_gluetun_gate_ignores_a_status_older_than_the_launch(gate):
    fresh_status(gate, ahead=-100)
    result = gate.run('exec sleep 30', FWMARK_GRACE='5')
    assert result.returncode == 1
    assert 'has not carried the control mark' in result.stderr


@pytest.mark.parametrize('record', ['future', 'other boot', 'old format', 'garbage'])
def test_gluetun_gate_trusts_no_record_from_another_boot_or_the_future(gate, record):
    text = {'future': f'{BOOT_ID} {uptime() + 120} 0x1bd00',
            'other boot': f'00000000-0000-4000-8000-000000000002 {uptime()} 0x1bd00',
            'old format': f'{int(time.time()) + 60} 0x1bd00',
            'garbage': f'{BOOT_ID} 12x 0x1bd00'}[record]
    gate.status.write_text(text + '\n')
    started = time.monotonic()
    result = gate.run('exec sleep 30', FWMARK_GRACE='5')
    assert result.returncode == 1
    assert 'has not carried the control mark' in result.stderr
    assert time.monotonic() - started < 16


def test_gluetun_gate_counts_a_record_from_when_it_was_written(gate):
    # One good record, never renewed: rereading it must not keep NetBird
    # running past the grace period after it was written.
    fresh_status(gate)
    started = time.monotonic()
    result = gate.run('exec sleep 30', FWMARK_GRACE='5')
    assert result.returncode == 1
    assert 'has not carried the control mark 0x1bd00 for 5 seconds (last reported: 0x1bd00)' in result.stderr
    assert time.monotonic() - started < 14


def test_gluetun_gate_refuses_without_the_boot_clock(gate):
    result = gate.run('touch "$GATE_DIR/started"', MOLEBRIDGE_BOOT_ID_FILE='/nonexistent')
    assert result.returncode == 1 and 'cannot read the boot clock' in result.stderr
    assert not (gate.path / 'started').exists()


@pytest.mark.parametrize('lose', ['ip -6 rule del priority 97', 'ip -4 rule add iif wt0 lookup main priority 50',
                                  'ip -4 route add 198.51.100.0/28 via 198.51.100.2 dev eth0 table 51821'])
def test_gluetun_gate_stops_netbird_when_guards_stay_missing(gate, lose):
    command = (lose + '; while :; do read -r up _ < "$MOLEBRIDGE_UPTIME_FILE"; '
               'echo "$(cat "$MOLEBRIDGE_BOOT_ID_FILE") ${up%%.*} 0x1bd00" > "$GUARD_STATUS_FILE"; sleep 1; done')
    result = gate.run(command, FWMARK_GRACE='5', timeout=30)
    assert result.returncode == 1
    assert 'routing guards not intact for 5 seconds' in result.stderr


def test_gluetun_gate_passes_on_netbird_exit_status(gate):
    fresh_status(gate)
    result = gate.run('sleep 1; exit 3')
    assert result.returncode == 3
    assert 'NetBird exited with status 3' in result.stderr


def test_wireguard_gate_needs_the_native_contract(gate):
    # The native gate checks the whole contract too, from the definitions
    # compose.yaml mounts; tools/test_host_and_routing.py covers it in full.
    result = gate.run('echo started', TUNNEL_BACKEND='wireguard', GLUETUN_RULES='')
    assert result.returncode == 1 and 'routing contract definitions are missing' in result.stderr
    assert 'started' not in result.stdout


# Validator, post-rules and host tool.

def gluetun_config(**changes):
    env = dict(ENV, **changes)
    return RoutingConfig.from_env(env)


def json_rules(family):
    overlay = ('192.0.2.0', 24) if family == 4 else ('2001:db8:1::', 64)
    address = '203.0.113.1' if family == 4 else '2001:db8:3::1'
    return [{'priority': 1, 'not': None, 'src': 'all', 'iif': 'wt0', 'table': 'local'},
            {'priority': 88, 'src': 'all', 'fwmark': '0x1bd00', 'iif': 'lo', 'table': '51822'},
            {'priority': 89, 'src': 'all', 'fwmark': '0x1bd00', 'iif': 'lo', 'action': 'unreachable'},
            {'priority': 90, 'src': 'all', 'dst': overlay[0], 'dstlen': overlay[1], 'iif': 'wg0', 'table': 'main'},
            {'priority': 91, 'src': 'all', 'dst': overlay[0], 'dstlen': overlay[1], 'iif': 'lo', 'table': 'main',
             'suppress_prefixlen': 0},
            {'priority': 92, 'src': 'all', 'dst': overlay[0], 'dstlen': overlay[1], 'iif': 'lo',
             'action': 'unreachable'},
            {'priority': 94, 'src': address, 'ipproto': 'icmp' if family == 4 else 'ipv6-icmp', 'table': '51821'},
            {'priority': 95, 'src': 'all', 'iif': 'wt0', 'table': '51821'},
            {'priority': 96, 'src': 'all', 'oif': 'wg0', 'table': '51821'},
            {'priority': 97, 'src': 'all', 'iif': 'wt0', 'action': 'unreachable'},
            {'priority': 98, 'src': 'all', 'dst': '198.51.100.0', 'dstlen': 28, 'table': 'main'},
            {'priority': 101, 'not': None, 'src': 'all', 'fwmark': '0xca6c', 'table': '51820'},
            {'priority': 102, 'src': 'all', 'fwmark': '0xca6c', 'iif': 'lo', 'table': 'main'},
            {'priority': 103, 'src': 'all', 'iif': 'lo', 'table': '51822', 'suppress_prefixlen': 0},
            {'priority': 104, 'src': 'all', 'iif': 'lo', 'action': 'unreachable'},
            {'priority': 105, 'src': 'all', 'table': 'main', 'suppress_prefixlen': 0},
            {'priority': 110, 'not': None, 'src': 'all', 'fwmark': '0x1bd00', 'table': '7120'}]


EXIT_ROUTES = [{'dst': 'default', 'dev': 'wg0', 'flags': []},
               {'type': 'unreachable', 'dst': 'default', 'metric': 4096, 'flags': []}]


def status(rules, family, config=None):
    address = '203.0.113.1' if family == 4 else '2001:db8:3::1'
    return family_status(rules, EXIT_ROUTES, config or gluetun_config(), family, tunnel_address=address)


@pytest.mark.parametrize('family', [4, 6])
def test_validator_accepts_the_gluetun_rule_set(family):
    assert status(json_rules(family), family) == (True, True)


@pytest.mark.parametrize('change', [
    lambda r: r.remove(next(x for x in r if x['priority'] == 88)),
    lambda r: r.remove(next(x for x in r if x['priority'] == 89)),
    lambda r: next(x for x in r if x['priority'] == 88).pop('iif'),
    lambda r: next(x for x in r if x['priority'] == 88).update(fwmark='0x1bd21'),
    lambda r: next(x for x in r if x['priority'] == 89).update(fwmask='0xff00'),
    lambda r: next(x for x in r if x['priority'] == 88).update(table='main'),
    lambda r: next(x for x in r if x['priority'] == 89).update(fwmark='junk'),
    lambda r: r.append({'priority': 89, 'src': 'all', 'fwmark': '0x1bd00', 'table': 'main'}),
    lambda r: r.remove(next(x for x in r if x['priority'] == 91)),
    lambda r: r.remove(next(x for x in r if x['priority'] == 92)),
    lambda r: next(x for x in r if x['priority'] == 91).pop('suppress_prefixlen'),
    lambda r: next(x for x in r if x['priority'] == 91).update(suppress_prefixlen=False),
    lambda r: next(x for x in r if x['priority'] == 91).update(table='51822'),
    lambda r: next(x for x in r if x['priority'] == 92).pop('iif'),
    lambda r: next(x for x in r if x['priority'] == 92).update(dstlen=25),
    lambda r: next(x for x in r if x['priority'] == 95).update(suppress_prefixlen=0),
    lambda r: r.remove(next(x for x in r if x['priority'] == 102)),
    lambda r: r.remove(next(x for x in r if x['priority'] == 103)),
    lambda r: next(x for x in r if x['priority'] == 102).update(fwmark='0x1bd00'),
    lambda r: next(x for x in r if x['priority'] == 102).update(table='51821'),
    lambda r: next(x for x in r if x['priority'] == 104).pop('iif'),
    lambda r: r.remove(next(x for x in r if x['priority'] == 104)),
    lambda r: next(x for x in r if x['priority'] == 103).pop('suppress_prefixlen'),
    lambda r: next(x for x in r if x['priority'] == 103).update(table='main'),
    lambda r: r.append({'priority': 102, 'src': 'all', 'table': 'main'}),
])
@pytest.mark.parametrize('family', [4, 6])
def test_validator_rejects_broken_control_plane_rules(change, family):
    rules = json_rules(family)
    change(rules)
    assert status(rules, family)[0] is False


def test_validator_accepts_an_explicit_all_ones_mask_and_numeric_mark():
    rules = json_rules(4)
    next(x for x in rules if x['priority'] == 88).update(fwmark=113920, fwmask='0xffffffff')
    assert status(rules, 4) == (True, True)


def test_wireguard_backend_keeps_rejecting_mark_rules():
    # gluetun's own 98 (local subnets) goes too: natively, 98 is the backstop behind 94.
    rules = [r for r in json_rules(4) if r['priority'] not in (88, 89, 91, 92, 98, 102, 103, 104)]
    rules.append({'priority': 98, 'src': '203.0.113.1', 'ipproto': 'icmp', 'action': 'unreachable'})
    wireguard = RoutingConfig('192.0.2.0/24', '2001:db8:1::/64', exit_if='wg0')
    assert status(rules, 4, wireguard) == (True, True)
    assert status(json_rules(4), 4, wireguard)[0] is False


@pytest.mark.parametrize('changes,message', [
    ({'EXIT_IF': 'wg-0'}, 'letters, digits'), ({'HOST_IF': 'lo'}, 'HOST_IF'), ({'HOST_IF': 'wg0'}, 'HOST_IF'),
    ({'HOST_TABLE': '51821'}, 'differ'), ({'HOST_TABLE': '7120'}, 'taken'), ({'EXIT_TABLE': '51820'}, 'taken'),
    ({'HOST_TABLE': '200'}, 'HOST_TABLE'), ({'CONTROL_MARK': '0x1bd01'}, 'low byte'),
    ({'CONTROL_MARK': '0x1BD00'}, 'hexadecimal'), ({'CONTROL_MARK': '0x01bd00'}, 'hexadecimal'),
    ({'TUNNEL_BACKEND': 'other'}, 'TUNNEL_BACKEND'),
])
def test_gluetun_config_validation(changes, message):
    with pytest.raises(ValueError, match=message):
        gluetun_config(**changes)


def test_wireguard_config_ignores_gluetun_settings():
    config = RoutingConfig.from_env({'OVERLAY_CIDR': '192.0.2.0/24', 'HOST_TABLE': 'junk', 'EXIT_TABLE': '51820'})
    assert config.backend == 'wireguard' and config.table == '51820' and not config.gluetun


def test_control_mark_value():
    assert control_mark_value('0x1bd00') == 0x1BD00
    assert control_mark_value('0xffffff00') == 0xFFFFFF00
    for bad in ('0x0', '0x1bd00 ', '0x100000000', 'bd00', None):
        with pytest.raises(ValueError):
            control_mark_value(bad)


@pytest.mark.parametrize('routes,family,ok', [
    ([{'dst': '198.51.100.0/28', 'dev': 'eth0'}, {'dst': 'default', 'gateway': '198.51.100.2', 'dev': 'eth0'}], 4, True),
    ([{'dst': '198.51.100.0/28', 'dev': 'eth0'}], 4, False),
    ([], 6, True),
    ([], 4, False),
    ([{'dst': 'default', 'gateway': '198.51.100.2', 'dev': 'eth0'}, {'dst': '10.0.0.0/8', 'dev': 'wg0'}], 4, False),
    ([{'dst': 'default', 'dev': 'wt0'}], 6, False),
    ([{'type': 'unreachable', 'dst': 'default'}], 6, False),
    ([{'dst': 'default', 'nexthops': [], 'dev': 'eth0'}], 4, False),
    ('junk', 4, False),
])
def test_host_table_status(routes, family, ok):
    assert host_table_status(routes, gluetun_config(), family) is ok


def test_host_table_status_compares_with_the_main_table():
    main = [{'dst': '198.51.100.0/28', 'dev': 'eth0', 'protocol': 'kernel'},
            {'dst': 'default', 'gateway': '198.51.100.2', 'dev': 'eth0'},
            {'dst': '192.0.2.0/24', 'dev': 'wt0'}, {'dst': '10.0.0.0/8', 'gateway': '198.51.100.3', 'dev': 'eth0'}]
    copy = [{'dst': '198.51.100.0/28', 'dev': 'eth0'}, {'dst': 'default', 'gateway': '198.51.100.2', 'dev': 'eth0'}]
    assert host_table_status(copy, gluetun_config(), 4, main=main)
    assert not host_table_status(copy[1:], gluetun_config(), 4, main=main)
    assert not host_table_status([], gluetun_config(), 6, main=[{'dst': 'default', 'gateway': 'fe80::1', 'dev': 'eth0'}])
    assert host_table_status([], gluetun_config(), 6, main=[])


def test_post_rules_match_gluetuns_parser():
    text = render_post_rules(gluetun_config(), 51820)
    lines = [line for line in text.splitlines() if line.startswith(('iptables ', 'ip6tables '))]
    assert len(lines) == 8
    assert 'iptables -A FORWARD -i wt0 -o wg0 -j ACCEPT' in lines
    assert 'ip6tables -A FORWARD -i wg0 -o wt0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' in lines
    assert 'iptables -A OUTPUT -o eth0 -j ACCEPT' in lines
    assert 'ip6tables -A INPUT -i eth0 -p udp -m udp --dport 51820 -j ACCEPT' in lines
    # gluetun ignores every other line, so comments are safe; nothing needs a shell.
    assert all(line.startswith('#') for line in text.splitlines() if line not in lines)
    assert not any(c in line for line in lines for c in '"\'$`;|&')
    ipv4 = render_post_rules(gluetun_config(CONTROL_MARK='0x2000', HOST_IF='enp3s0'), 40000, ipv6=False)
    assert 'ip6tables' not in ipv4 and '-o enp3s0 ' in ipv4 and '--dport 40000 ' in ipv4
    assert '-m mark' not in ipv4 and '-m mark' not in text


def test_every_post_rule_survives_gluetuns_chain_parser():
    # gluetun lists and parses whole INPUT and OUTPUT chains to remove its own
    # rules; one line it can't parse leaves its old accepts behind on every
    # reconnect (seen live with a `-m mark` rule).
    from molebridge.routing import post_rule_parseable
    for config in (gluetun_config(), gluetun_config(HOST_IF='enp3s0', CONTROL_MARK='0x2000')):
        rules = [line.split(' ', 1)[1] for line in render_post_rules(config, 51820).splitlines()
                 if line.startswith(('iptables ', 'ip6tables '))]
        assert rules and all(post_rule_parseable(rule) for rule in rules)
        assert {rule.split()[1] for rule in rules} == {'FORWARD', 'OUTPUT', 'INPUT'}


@pytest.mark.parametrize('rule,ok', [
    ('-A OUTPUT -o eth0 -j ACCEPT', True),
    ('-A INPUT -i eth0 -p udp -m udp --dport 51820 -j ACCEPT', True),
    ('-A FORWARD -i wg0 -o wt0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT', True),
    ('-A OUTPUT -d 198.51.100.1 -o eth0 -p udp -m udp --dport 51820 -j ACCEPT', True),
    ('-A OUTPUT -o eth0 -m mark --mark 0x1bd00 -j ACCEPT', False),
    ('-A OUTPUT -o eth0 -j MOLEBRIDGE-OUT', False),
    ('-A OUTPUT -o eth0 -g MOLEBRIDGE-OUT', False),
    ('-A OUTPUT -o eth0 -m comment --comment x -j ACCEPT', False),
    ('-A OUTPUT -o eth0 -p udp -m udp --sport 51820 -j ACCEPT', False),
    ('-A OUTPUT -o eth0 -p tcp -m udp --dport 1 -j ACCEPT', False),
    ('-A OUTPUT -o eth0 -m owner --uid-owner 0 -j ACCEPT', False),
    ('-A OUTPUT -o eth0 -j LOG', False),
    ('-I OUTPUT -o eth0 -j ACCEPT', False),
    ('-A INPUT -i eth0 -p udp -m udp -j ACCEPT', False),
    ('-A INPUT -i eth0 -m conntrack -j ACCEPT', False),
])
def test_post_rule_parseability_follows_gluetuns_parser(rule, ok):
    from molebridge.routing import post_rule_parseable
    assert post_rule_parseable(rule) is ok


@pytest.mark.parametrize('port', [0, 65536, '51820', True])
def test_post_rules_refuse_bad_ports(port):
    with pytest.raises(ValueError):
        render_post_rules(gluetun_config(), port)


def test_post_rules_need_the_gluetun_backend():
    with pytest.raises(ValueError):
        render_post_rules(RoutingConfig('192.0.2.0/24'), 51820)


def gluetun_compose_config(**guard_changes):
    guard = dict(ENV, ROUTING_READY_FILE='/run/molebridge/routing-ready')
    guard.update(guard_changes)
    return {'services': {'gluetun': {}, 'guard': {'environment': guard},
                         'netbird': {'environment': {'NB_WIREGUARD_PORT': '51820'}}}}


ENV_FILE = """# A .env as docs/configuration.md describes it.
COMPOSE_FILE=compose.gluetun.yaml
OVERLAY_CIDR=192.0.2.0/24
export OVERLAY6_CIDR="2001:db8:1::/64"
EXIT_IF='wg0'
HOST_IF=eth0   # the namespace's interface
"""


def no_engine(*args, **kwargs):
    raise AssertionError('the post-rules command must not need a container engine')


@pytest.fixture
def clean_environment(monkeypatch):
    for name in host_tools.GLUETUN_DEFAULTS:
        monkeypatch.delenv(name, raising=False)


def test_host_tool_writes_post_rules_from_env_without_an_engine(tmp_path, clean_environment):
    (tmp_path / '.env').write_text(ENV_FILE)
    host = host_tools.Host(tmp_path, run=no_engine)
    path = host.gluetun_post_rules()
    assert path == tmp_path / 'tunnel' / 'gluetun' / 'post-rules.txt'
    assert path.read_text() == render_post_rules(gluetun_config(), 51820)
    assert (path.stat().st_mode & 0o777) == 0o644
    host.gluetun_post_rules(ipv6=False)
    assert 'ip6tables' not in path.read_text()


def test_host_tool_post_rules_follow_compose_precedence(tmp_path, clean_environment, monkeypatch):
    (tmp_path / '.env').write_text(ENV_FILE + 'CONTROL_MARK=0x2000\nNB_WIREGUARD_PORT=40000\n')
    monkeypatch.setenv('HOST_IF', 'enp3s0')
    text = host_tools.Host(tmp_path, run=no_engine).gluetun_post_rules().read_text()
    assert '-o enp3s0 ' in text and '--dport 40000 ' in text


@pytest.mark.parametrize('extra', [
    'CONTROL_MARK=0x1bd01', 'NB_WIREGUARD_PORT=x', 'OVERLAY_CIDR=', 'HOST_TABLE=51821', 'EXIT_IF=wg-0',
    'HOST_IF=${OTHER}',
])
def test_host_tool_refuses_bad_post_rule_settings(tmp_path, clean_environment, extra):
    (tmp_path / '.env').write_text(ENV_FILE + extra + '\n')
    host = host_tools.Host(tmp_path, run=no_engine)
    with pytest.raises(host_tools.CheckError):
        host.gluetun_post_rules()
    assert not (tmp_path / 'tunnel').exists()


def test_env_file_reader(tmp_path):
    path = tmp_path / '.env'
    path.write_text('A=1\n# B=2\nexport C = "x y" \nD=v # note\nE=w#x\nF\nG=\'#\'\n')
    assert host_tools.read_env_file(path, {'A', 'B', 'C', 'D', 'E', 'F', 'G'}) == {
        'A': '1', 'C': 'x y', 'D': 'v', 'E': 'w#x', 'G': '#'}
    assert host_tools.read_env_file(tmp_path / 'missing', {'A'}) == {}


def resolved_gluetun_config(root):
    """compose.gluetun.yaml as `docker compose config --format json` resolves
    it: the parts the host tool checks."""
    def bind(source, target, read_only=True):
        return {'type': 'bind', 'source': str(root / source), 'target': target, 'read_only': read_only}
    guard_env = dict(ENV)
    return {'services': {
        'gluetun': {'environment': {'VPN_SERVICE_PROVIDER': 'ivpn'},
                    'entrypoint': ['/bin/sh', '/usr/local/bin/molebridge-gluetun-preflight', '/gluetun-entrypoint'],
                    'sysctls': {'net.ipv4.icmp_errors_use_inbound_ifaddr': '1'},
                    'volumes': [{'type': 'volume', 'source': 'gluetun-data', 'target': '/gluetun'},
                                bind('secrets/gluetun/wireguard_private_key', '/run/secrets/wireguard_private_key'),
                                bind('secrets/gluetun/auth.toml', '/gluetun/auth/config.toml'),
                                bind('tunnel/gluetun/post-rules.txt', '/iptables/post-rules.txt')]},
        'guard': {'environment': guard_env},
        'netbird': {'environment': {'NB_DISABLE_USERSPACE_ROUTING': 'true', 'NB_INTERFACE_NAME': 'wt0'}},
        'applier': {'environment': dict(guard_env, PROVIDER='gluetun-ivpn'),
                    'volumes': [bind('state/panel', '/state/panel'),
                                bind('state/applier', '/state/applier', False),
                                {'type': 'volume', 'source': 'gluetun-servers', 'target': '/gluetun-servers',
                                 'read_only': True},
                                bind('secrets/gluetun/api_key', '/run/secrets/gluetun/api_key')]},
        'control-panel': {'cap_drop': ['ALL'],
                          'volumes': [bind('state/panel', '/state/panel', False),
                                      bind('state/applier', '/state/applier')]},
    }, 'volumes': {'netbird-data': {'name': 'molebridge_netbird-data'}}}


def test_doctor_accepts_the_gluetun_compose_file(tmp_path):
    (tmp_path / '.env').write_text('')
    config = resolved_gluetun_config(tmp_path)
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(config))
    assert host.owner(host.config()) == 'gluetun'
    assert host.routing_env(config)['EXIT_IF'] == 'wg0'


def _break(config, change):
    change(config['services'])
    return config


@pytest.mark.parametrize('change', [
    lambda s: s['applier']['volumes'].append({'type': 'bind', 'source': '/x/secrets/gluetun/auth.toml',
                                              'target': '/auth.toml', 'read_only': True}),
    lambda s: s['applier']['volumes'].append({'type': 'bind', 'source': '/x/secrets/gluetun/wireguard_private_key',
                                              'target': '/key', 'read_only': True}),
    lambda s: s['applier']['volumes'][3].update(read_only=False),
    lambda s: s['control-panel']['volumes'].append({'type': 'bind', 'source': '/x/secrets/gluetun/api_key',
                                                    'target': '/key', 'read_only': True}),
    lambda s: s['applier']['environment'].update(PROVIDER='gluetun-nordvpn'),
    lambda s: s['applier']['environment'].update(PROVIDER='nordvpn'),
    lambda s: s['applier']['environment'].update(HOST_TABLE='51823'),
    lambda s: s['gluetun'].update(ports=['127.0.0.1:8000:8000']),
    lambda s: s['gluetun'].pop('entrypoint'),
    lambda s: s['gluetun']['environment'].update(HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE='{"auth":"none"}'),
    lambda s: s['gluetun']['volumes'].pop(2),
    lambda s: s['gluetun']['sysctls'].clear(),
    lambda s: s['guard']['environment'].update(TUNNEL_BACKEND='wireguard'),
    lambda s: s['netbird']['environment'].update(NB_FORCE_USERSPACE_ROUTER='true'),
])
def test_doctor_refuses_a_broken_gluetun_compose_file(tmp_path, change):
    (tmp_path / '.env').write_text('')
    config = _break(resolved_gluetun_config(tmp_path), change)
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(config))
    with pytest.raises(host_tools.CheckError):
        host.config()


def test_gluetun_files_must_exist_with_mode_0600(tmp_path):
    host = host_tools.Host(tmp_path, run=no_engine)
    with pytest.raises(host_tools.CheckError, match='wireguard_private_key'):
        host.check_gluetun_files()
    (tmp_path / 'secrets' / 'gluetun').mkdir(parents=True)
    key = tmp_path / 'secrets' / 'gluetun' / 'wireguard_private_key'
    key.write_text('x\n')
    key.chmod(0o600)
    assert host.gluetun_auth() is True
    (tmp_path / 'tunnel' / 'gluetun').mkdir(parents=True)
    (tmp_path / 'tunnel' / 'gluetun' / 'post-rules.txt').write_text('')
    host.check_gluetun_files()
    key.chmod(0o644)
    with pytest.raises(host_tools.CheckError, match='0600'):
        host.check_gluetun_files()


def test_gluetun_auth_writes_one_key_into_both_files(tmp_path, capsys):
    import tomllib
    from applier.gluetun import ROUTES
    host = host_tools.Host(tmp_path, run=no_engine)
    assert host.gluetun_auth() is True
    directory = tmp_path / 'secrets' / 'gluetun'
    key = (directory / 'api_key').read_text().strip()
    auth = tomllib.loads((directory / 'auth.toml').read_text())
    assert auth == {'roles': [{'name': 'molebridge', 'auth': 'apikey', 'apikey': key, 'routes': list(ROUTES)}]}
    assert set(ROUTES) == {'PUT /v1/vpn/settings', 'GET /v1/vpn/status', 'GET /v1/publicip/ip',
                           'GET /v1/updater/status', 'PUT /v1/updater/status'}
    for name in ('api_key', 'auth.toml'):
        assert (directory / name).stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in directory.iterdir()) == ['api_key', 'auth.toml']
    # Kept unless asked; replaced together with --rotate.
    assert host.gluetun_auth() is False and (directory / 'api_key').read_text().strip() == key
    assert host.gluetun_auth(rotate=True) is True
    rotated = (directory / 'api_key').read_text().strip()
    assert rotated != key and tomllib.loads((directory / 'auth.toml').read_text())['roles'][0]['apikey'] == rotated
    (directory / 'api_key').unlink()
    with pytest.raises(host_tools.CheckError, match='--rotate'):
        host.gluetun_auth()


def test_gluetun_auth_command_never_prints_the_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(host_tools, 'ROOT', tmp_path)
    monkeypatch.setattr(host_tools.Host.__init__, '__defaults__', (tmp_path, host_tools.execute))
    assert host_tools.main(['gluetun-auth']) == 0
    key = (tmp_path / 'secrets' / 'gluetun' / 'api_key').read_text().strip()
    out = capsys.readouterr()
    assert key not in out.out + out.err and 'key not shown' in out.out


def test_gluetun_compose_file_wires_the_guard_and_gate():
    yaml = pytest.importorskip('yaml')
    compose = yaml.safe_load((ROOT / 'compose.gluetun.yaml').read_text())
    services = compose['services']
    assert set(services) == {'gluetun', 'guard', 'netbird', 'applier', 'control-panel'}
    gluetun = services['gluetun']
    assert gluetun['image'].startswith('docker.io/qmcgaw/gluetun:v3.41.3@sha256:')
    env = gluetun['environment']
    assert env['VPN_TYPE'] == 'wireguard' and env['WIREGUARD_IMPLEMENTATION'] == 'kernelspace'
    assert env['HTTP_CONTROL_SERVER_ADDRESS'] == '127.0.0.1:8000'
    assert env['WIREGUARD_PRIVATE_KEY_SECRETFILE'] == '/run/secrets/wireguard_private_key'
    assert 'ports' not in gluetun
    assert gluetun['entrypoint'] == ['/bin/sh', '/usr/local/bin/molebridge-gluetun-preflight', '/gluetun-entrypoint']
    assert './routing/gluetun-preflight:/usr/local/bin/molebridge-gluetun-preflight:ro' in gluetun['volumes']
    binds = {v['target']: v for v in gluetun['volumes'] if isinstance(v, dict)}
    # Compose must fail rather than start gluetun without its role file:
    # without one, gluetun answers PUT /v1/vpn/status with no authentication.
    for target in ('/iptables/post-rules.txt', '/gluetun/auth/config.toml', '/run/secrets/wireguard_private_key'):
        assert binds[target]['read_only'] is True and binds[target]['bind'] == {'create_host_path': False}
    assert env['STORAGE_FILEPATH'] == '/gluetun/servers/servers.json'
    assert 'gluetun-servers:/gluetun/servers' in gluetun['volumes']
    applier = services['applier']
    assert applier['network_mode'] == 'service:gluetun' and applier['read_only'] is True
    assert applier['cap_drop'] == ['ALL'] and applier['cap_add'] == ['NET_ADMIN', 'NET_RAW', 'DAC_OVERRIDE']
    aenv = applier['environment']
    assert aenv['TUNNEL_BACKEND'] == 'gluetun' and aenv['PROVIDER'].startswith('gluetun-${GLUETUN_PROVIDER')
    assert aenv['GLUETUN_SERVERS_FILE'] == '/gluetun-servers/servers.json'
    assert 'gluetun-servers:/gluetun-servers:ro' in applier['volumes']
    applier_binds = {v['target']: v for v in applier['volumes'] if isinstance(v, dict)}
    assert applier_binds['/run/secrets/gluetun/api_key']['read_only'] is True
    assert applier_binds['/run/secrets/gluetun/api_key']['bind'] == {'create_host_path': False}
    assert not any('auth.toml' in str(v) or 'wireguard_private_key' in str(v) for v in applier['volumes'])
    for name in ('HOST_IF', 'HOST_TABLE', 'CONTROL_MARK', 'EXIT_IF', 'EXIT_TABLE', 'OVERLAY_IF', 'OVERLAY_CIDR'):
        assert aenv[name] == services['guard']['environment'][name], name
    assert services['netbird']['init'] is True
    panel = services['control-panel']
    assert panel['environment']['PROVIDER'] == aenv['PROVIDER']
    assert 'volumes' not in panel
    assert gluetun['sysctls']['net.ipv4.icmp_errors_use_inbound_ifaddr'] == '1'
    guard = services['guard']
    assert guard['network_mode'] == 'service:gluetun'
    assert guard['cap_drop'] == ['ALL'] and guard['cap_add'] == ['NET_ADMIN']
    assert guard['environment']['TUNNEL_BACKEND'] == 'gluetun'
    # The image's own entrypoint (tini, then routing/molebridge-exit) runs the guard.
    assert 'entrypoint' not in guard
    netbird = services['netbird']
    assert netbird['network_mode'] == 'service:gluetun'
    assert netbird['depends_on']['guard']['condition'] == 'service_healthy'
    nenv = netbird['environment']
    assert nenv['TUNNEL_BACKEND'] == 'gluetun' and nenv['NB_DISABLE_USERSPACE_ROUTING'] == 'true'
    assert nenv['NB_FWMARK_BASE'] == nenv['CONTROL_MARK'] == guard['environment']['CONTROL_MARK']
    assert nenv['NB_EXTRA_IFACE_BLACKLIST'] == guard['environment']['EXIT_IF'] == env['VPN_INTERFACE']
    assert nenv['HOST_TABLE'] == guard['environment']['HOST_TABLE']
    assert not set(host_tools.NETBIRD_MUST_BE_OFF) & set(nenv)
    assert netbird['entrypoint'] == ['/bin/sh', '/usr/local/bin/molebridge-wait-for-guards',
                                     '/usr/local/bin/netbird-entrypoint.sh']
    assert any(v.endswith(':/run/molebridge:ro') for v in netbird['volumes'])
    assert services['control-panel']['extends'] == {'file': 'compose.yaml', 'service': 'control-panel'}
    for name, service in services.items():
        if 'logging' in service:
            assert service['logging']['driver'] == 'json-file', name


def test_namespace_check_covers_every_gluetun_member(tmp_path):
    calls = []
    host = host_tools.Host(tmp_path, run=lambda args, **kw: calls.append(args) or 'net:[4026531840]\n')
    host.namespace_checks('gluetun')
    assert [c[4] for c in calls] == ['gluetun', 'guard', 'netbird', 'applier']


# gluetun's role-file check (routing/gluetun-preflight), before gluetun starts.

PREFLIGHT = ROOT / 'routing' / 'gluetun-preflight'
PREFLIGHT_KEY = 'Zx9-_' + 'k' * 38


def run_preflight(tmp_path, text, **env):
    auth = tmp_path / 'config.toml'
    if text is not None:
        auth.write_bytes(text.encode() if isinstance(text, str) else text)
    started = tmp_path / 'started'
    environment = {'PATH': os.environ['PATH'], 'HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH': str(auth)}
    environment.update(env)
    result = subprocess.run(['sh', str(PREFLIGHT), 'sh', '-c', 'touch "$1"; echo "args:$2"', 'gluetun',
                             str(started), 'healthcheck'], env=environment, capture_output=True, text=True,
                            timeout=20)
    return result, started.exists()


def valid_role_file():
    from applier.gluetun import gluetun_auth_file
    return gluetun_auth_file(PREFLIGHT_KEY)


def test_preflight_hands_a_valid_role_file_to_gluetun(tmp_path):
    result, started = run_preflight(tmp_path, valid_role_file())
    assert result.returncode == 0 and started, result.stderr
    # gluetun's entrypoint gets its arguments unchanged.
    assert result.stdout.strip() == 'args:healthcheck'
    assert PREFLIGHT_KEY not in result.stdout + result.stderr


BROKEN_ROLE_FILES = {
    'misspelled key field': lambda t: t.replace('apikey = ', 'api_key = '),
    'extra field': lambda t: t + 'password = "' + PREFLIGHT_KEY + '"\n',
    'extra field inside': lambda t: t.replace('auth = "apikey"\n', 'auth = "apikey"\nusername = "x"\n'),
    'wrong route': lambda t: t.replace('GET /v1/vpn/status', 'GET /v1/vpn/settings'),
    'extra route': lambda t: t.replace('"PUT /v1/updater/status"', '"PUT /v1/updater/status", "PUT /v1/vpn/status"'),
    'older route list': lambda t: t.replace(', "GET /v1/updater/status", "PUT /v1/updater/status"', ''),
    'basic auth': lambda t: t.replace('auth = "apikey"', 'auth = "basic"'),
    'none auth': lambda t: t.replace('auth = "apikey"', 'auth = "none"'),
    'second role': lambda t: t + t,
    'short key': lambda t: t.replace(PREFLIGHT_KEY, 'k' * 31),
    'quote in key': lambda t: t.replace(PREFLIGHT_KEY, PREFLIGHT_KEY[:-1] + '"'),
    'crlf': lambda t: t.replace('\n', '\r\n'),
    'blank line': lambda t: '\n' + t,
    'empty': lambda t: '',
}


@pytest.mark.parametrize('name', sorted(BROKEN_ROLE_FILES))
def test_preflight_refuses_anything_else_without_printing_it(tmp_path, name):
    text = BROKEN_ROLE_FILES[name](valid_role_file())
    result, started = run_preflight(tmp_path, text)
    assert result.returncode == 1 and not started
    assert result.stderr.startswith('molebridge: not starting gluetun: ')
    assert PREFLIGHT_KEY not in result.stdout + result.stderr and 'k' * 20 not in result.stderr
    from applier.gluetun import valid_auth_file
    assert valid_auth_file(text) is False


def test_preflight_refuses_a_missing_file_a_symlink_and_a_default_role(tmp_path):
    result, started = run_preflight(tmp_path, None)
    assert result.returncode == 1 and not started and 'missing' in result.stderr
    target = tmp_path / 'real.toml'
    target.write_text(valid_role_file())
    (tmp_path / 'config.toml').symlink_to(target)
    result, started = run_preflight(tmp_path, None)
    assert result.returncode == 1 and not started
    (tmp_path / 'config.toml').unlink()
    result, started = run_preflight(tmp_path, valid_role_file(),
                                    HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE='{"auth":"none"}')
    assert result.returncode == 1 and not started and 'DEFAULT_ROLE' in result.stderr


# gluetun's image sets HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE="{}" and
# HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=/gluetun/auth/config.toml
# (Dockerfile:205-206 at v3.41.3); the check must start gluetun with both.
@pytest.mark.parametrize('value,ok', [
    (None, True), ('', True), ('{}', True), (' {} ', True), ('\t{}\t', True),
    ('{"auth":"none"}', False), ('{"auth":"apikey","apikey":"x"}', False), ('{ }', False), ('{}x', False),
    ('{}\n{"auth":"none"}', False), ('null', False),
])
def test_preflight_default_role(tmp_path, value, ok):
    from applier.gluetun import default_role_allowed
    env = {} if value is None else {'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE': value}
    result, started = run_preflight(tmp_path, valid_role_file(), **env)
    assert (result.returncode == 0 and started) is ok, result.stderr
    assert default_role_allowed(value) is ok


def test_preflight_accepts_gluetuns_image_defaults(tmp_path):
    dockerfile_defaults = {'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE': '{}',
                           'HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH': '/gluetun/auth/config.toml'}
    script = PREFLIGHT.read_text()
    # The script reads no other gluetun setting.
    assert set(re.findall(r'\$\{?(HTTP_[A-Z_]+)', script)) == set(dockerfile_defaults)
    assert 'auth_file=${HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH:-/gluetun/auth/config.toml}' in script
    result, started = run_preflight(tmp_path, valid_role_file(),
                                    HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE=dockerfile_defaults[
                                        'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE'])
    assert result.returncode == 0 and started, result.stderr


def test_python_and_preflight_agree_on_the_generated_file():
    from applier.gluetun import valid_auth_file
    assert valid_auth_file(valid_role_file())
    assert valid_auth_file(valid_role_file().rstrip('\n'))


def test_doctor_refuses_an_invalid_role_file(tmp_path):
    host = host_tools.Host(tmp_path, run=no_engine)
    assert host.gluetun_auth() is True
    key = tmp_path / 'secrets' / 'gluetun' / 'wireguard_private_key'
    key.write_text('x\n')
    key.chmod(0o600)
    (tmp_path / 'tunnel' / 'gluetun').mkdir(parents=True)
    (tmp_path / 'tunnel' / 'gluetun' / 'post-rules.txt').write_text('')
    host.check_gluetun_files()
    auth = tmp_path / 'secrets' / 'gluetun' / 'auth.toml'
    auth.write_text(auth.read_text().replace('apikey = ', 'api_key = '))
    with pytest.raises(host_tools.CheckError, match='gluetun-auth --rotate') as error:
        host.check_gluetun_files()
    assert (tmp_path / 'secrets' / 'gluetun' / 'api_key').read_text().strip() not in str(error.value)

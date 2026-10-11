"""gluetun's reconnection during a switch: the protective predicate
(molebridge.routing.gluetun_transition_status) and the applier's collection
of it (applier/gluetun_applier.py, transition_status), against snapshots and
a fake that behaves as Linux and the guard do. Nothing touches a kernel."""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from molebridge.routing import family_status, gluetun_transition_status
from test_gluetun_applier import CONFIG, HOST_A, HOST_B, TUNNEL4, Kernel, make, request, rules

OLD, NEW, THIRD = TUNNEL4, '10.64.0.9', '10.64.0.77'
FALLBACK = {'type': 'unreachable', 'dst': 'default', 'metric': 4096}
TUNNEL_ROUTE = {'dst': 'default', 'dev': 'wg0'}


def rule94(address):
    return {'priority': 94, 'src': address, 'ipproto': 'icmp', 'table': '51821'}


def snapshot(*, return_paths=(OLD,), detached=False):
    table = [r for r in rules(4) if r['priority'] != 94]
    for rule in table:
        if detached and rule['priority'] == 90:
            rule['iif_detached'] = None
        if detached and rule['priority'] == 96:
            rule['oif_detached'] = None
    table += [rule94(a) for a in return_paths]
    return sorted(table, key=lambda r: r['priority'])


def status(table, routes, *, address=None, present=True, up=True):
    return gluetun_transition_status(table, routes, CONFIG, 4, tunnel_address=address, previous_address=OLD,
                                     interface_present=present, interface_up=up)


# Every intermediate snapshot of an ordinary switch, in order, then its negative twin.
STEPS = [
    ('interface removed, rules detached',
     dict(table=snapshot(return_paths=(OLD,), detached=True), routes=[FALLBACK], present=False),
     dict(table=snapshot(return_paths=(OLD, THIRD), detached=True), routes=[FALLBACK], present=False)),
    ('interface removed, the guard already took rule 94',
     dict(table=snapshot(return_paths=(), detached=True), routes=[FALLBACK], present=False),
     dict(table=[r for r in snapshot(return_paths=(), detached=True) if r['priority'] != 97],
          routes=[FALLBACK], present=False)),
    ('interface up, no address yet',
     dict(table=snapshot(return_paths=(OLD,)), routes=[FALLBACK]),
     dict(table=snapshot(return_paths=(OLD,), detached=True), routes=[FALLBACK])),
    ('address present, rule 94 missing',
     dict(table=snapshot(return_paths=()), routes=[FALLBACK], address=NEW),
     dict(table=snapshot(return_paths=()), routes=[], address=NEW)),
    ('old and new rule 94 together',
     dict(table=snapshot(return_paths=(OLD, NEW)), routes=[FALLBACK], address=NEW),
     dict(table=snapshot(return_paths=(NEW, NEW)), routes=[FALLBACK], address=NEW)),
    ('old rule removed, route still missing',
     dict(table=snapshot(return_paths=(NEW,)), routes=[FALLBACK], address=NEW),
     dict(table=snapshot(return_paths=(NEW,)), routes=[FALLBACK, {'dst': 'default', 'gateway': '198.51.100.2',
                                                                    'dev': 'eth0'}], address=NEW)),
]


@pytest.mark.parametrize('name,good,bad', STEPS, ids=[s[0] for s in STEPS])
def test_each_reconnection_state_is_safe_and_its_twin_is_not(name, good, bad):
    for case, safe in ((good, True), (bad, False)):
        case = dict(case)
        table, routes = case.pop('table'), case.pop('routes')
        found = status(table, routes, **case)
        assert found[0] is safe, name
        assert found[1] is False


def test_the_route_restored_is_ready():
    assert status(snapshot(return_paths=(NEW,)), [TUNNEL_ROUTE, FALLBACK], address=NEW) == (True, True)
    # Its twin: the fallback gone.
    assert status(snapshot(return_paths=(NEW,)), [TUNNEL_ROUTE], address=NEW)[0] is False


@pytest.mark.parametrize('change', [
    # A missing or altered rule outside the tolerated states.
    lambda t: [r for r in t if r['priority'] != 1],
    lambda t: [r for r in t if r['priority'] != 88],
    lambda t: [r for r in t if r['priority'] != 89],
    lambda t: [r for r in t if r['priority'] != 91],
    lambda t: [r for r in t if r['priority'] != 92],
    lambda t: [r for r in t if r['priority'] != 95],
    lambda t: [r for r in t if r['priority'] != 97],
    lambda t: [r for r in t if r['priority'] != 102],
    lambda t: [r for r in t if r['priority'] != 103],
    lambda t: [r for r in t if r['priority'] != 104],
    lambda t: t + [{'priority': 95, 'src': 'all', 'iif': 'wt0', 'table': '51821'}],
    lambda t: t + [rule94(THIRD)],
    lambda t: t + [{'priority': 0, 'src': 'all', 'table': 'local'}],
    lambda t: [dict(r, table='main') if r['priority'] == 96 else r for r in t],
    lambda t: [{**r, 'iif_detached': None} if r['priority'] == 95 else r for r in t],
])
def test_anything_else_still_aborts(change):
    for present, address in ((False, None), (True, None), (True, NEW)):
        table = change(snapshot(return_paths=(OLD,), detached=not present))
        assert status(table, [FALLBACK], address=address, present=present)[0] is False


def test_a_rule_94_not_in_its_exact_form_aborts():
    loose = snapshot(return_paths=())
    loose.append({'priority': 94, 'src': OLD, 'table': '51821'})  # no protocol selector
    assert status(loose, [FALLBACK], address=NEW)[0] is False


def test_rules_90_to_92_are_conditional_on_the_overlay_range():
    v6 = [r for r in rules(6) if r['priority'] not in (94,)]
    assert gluetun_transition_status(v6, [FALLBACK], CONFIG, 6, interface_present=True)[0] is True


def test_outside_a_switch_the_full_validation_applies():
    table = snapshot(return_paths=(OLD,), detached=True)
    assert family_status(table, [FALLBACK], CONFIG, 4)[0] is False


# The applier's collection --------------------------------------------------------

class Reconnecting(Kernel):
    """gluetun's reconnection as Linux and the guard show it: while the
    interface is gone, rules 90 and 96 are detached; the new interface comes
    up first, its address next, and the guard adds rule 94 for it before
    deleting the old one, then puts the route back."""

    def __init__(self):
        super().__init__()
        self.phase = None
        self.address = OLD
        self.ifindex = 7

    def put(self, host):
        self.phase = ['gone', 'gone', 'up', 'addressed', 'both', 'new-only', 'routed']
        self.next_host = host

    def advance(self):
        if self.phase:
            self.phase.pop(0)
            if self.phase and self.phase[0] == 'up':
                self.ifindex += 1
            if not self.phase or self.phase[0] == 'routed':
                self.tunnel, self.phase, self.address = self.next_host, None, NEW

    @property
    def current(self):
        return self.phase[0] if self.phase else 'routed'

    def run(self, args, **kwargs):
        phase = self.current
        if args[1:6] == ['-j', 'link', 'show', 'dev', 'wg0']:
            self.calls.append(args)
            self.advance()
            if self.current == 'gone':
                raise RuntimeError('command failed')
            return json.dumps([{'ifname': 'wg0', 'ifindex': self.ifindex, 'flags': ['UP', 'LOWER_UP']}])
        if args[1:6] == ['-j', 'address', 'show', 'dev', 'wg0']:
            self.calls.append(args)
            if phase == 'gone':
                raise RuntimeError('command failed')
            addresses = [] if phase == 'up' else [NEW if self.phase else self.address]
            return json.dumps([{'addr_info': [{'family': 'inet', 'scope': 'global', 'local': a}
                                              for a in addresses]}])
        if args[0] == 'ip' and args[3:4] == ['rule'] and args[2] == '-4':
            self.calls.append(args)
            returns = {'gone': (OLD,), 'up': (OLD,), 'addressed': (OLD,), 'both': (OLD, NEW),
                       'new-only': (NEW,)}.get(phase, (self.address,))
            if phase == 'addressed':
                returns = ()
            return json.dumps(snapshot(return_paths=returns, detached=phase == 'gone'))
        if args[0] == 'ip' and args[-1] == '51821' and args[2] == '-4':
            self.calls.append(args)
            routes = [FALLBACK] if self.phase else [TUNNEL_ROUTE, FALLBACK]
            return json.dumps(routes)
        if args[:3] == ['wg', 'show', 'wg0'] and self.phase:
            self.calls.append(args)
            self.advance()
            raise RuntimeError('command failed')
        return super().run(args, **kwargs)


def reconnecting(tmp_path):
    kernel = Reconnecting()
    applier, _, gluetun = make(tmp_path, kernel=kernel)
    real = gluetun.select_server

    def select(relay):
        gluetun.puts.append(relay['hostname'])
        kernel.put(relay['hostname'])
        return 'settings updated'
    gluetun.select_server = select
    return applier, kernel, gluetun


def test_an_ordinary_switch_with_every_reconnection_state_succeeds(tmp_path):
    applier, kernel, gluetun = reconnecting(tmp_path)
    statuses = []
    real = applier.publish

    def record(status, message, **fields):
        statuses.append(status)
        return real(status, message, **fields)
    applier.publish = record
    result = applier.switch(request(HOST_B))
    assert result['status'] == 'ok' and result['server'] == HOST_B, result['message']
    assert 'failed' not in statuses and applier.attempt.state == 'idle'


def test_a_stable_violation_during_the_switch_aborts(tmp_path):
    applier, kernel, gluetun = reconnecting(tmp_path)
    real = kernel.run

    def third(args, **kwargs):
        out = real(args, **kwargs)
        if args[0] == 'ip' and args[3:4] == ['rule'] and args[2] == '-4' and kernel.phase:
            table = json.loads(out) + [rule94(THIRD)]
            return json.dumps(table)
        return out
    applier.run = third
    result = applier.switch(request(HOST_B))
    assert result['status'] == 'failed' and applier.attempt.state == 'failed'
    assert result['message'] == 'Routing changed during the switch; retrying after recovery.'


def test_a_sample_taken_while_the_interface_changed_is_taken_again(tmp_path):
    applier, kernel, _ = make(tmp_path)
    links = iter([1, 2, 2, 2])

    def link_state():
        return True, True, next(links)
    applier.link_state = link_state
    applier.previous_addresses = {4: TUNNEL4}
    applier.switch_deadline = 1
    assert applier.transition_status() == (True, True)


def test_three_contradictory_samples_withhold_readiness_without_aborting(tmp_path):
    applier, kernel, _ = make(tmp_path)
    counter = iter(range(100))
    applier.link_state = lambda: (True, True, next(counter))
    applier.previous_addresses = {4: TUNNEL4}
    assert applier.transition_status() == (True, False)


def test_an_interface_present_with_detached_rules_is_sampled_again(tmp_path):
    applier, kernel, _ = make(tmp_path)
    real = kernel.run

    def detached(args, **kwargs):
        out = real(args, **kwargs)
        if args[0] == 'ip' and args[3:4] == ['rule'] and args[2] == '-4':
            table = json.loads(out)
            for rule in table:
                if rule['priority'] == 96:
                    rule['oif_detached'] = None
            return json.dumps(table)
        return out
    applier.run = detached
    applier.previous_addresses = {4: TUNNEL4}
    assert applier.transition_status() == (True, False)

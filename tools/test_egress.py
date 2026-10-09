"""The egress tiers: "provider" (the provider's own check) and "tunnel" (the
shared tunnel checks for a provider without one). No current provider uses
the tunnel tier, so a made-up registry entry exercises it here."""
import dataclasses
import json

import pytest

from test_runtime import CONFIG, ENTRY, HOST, KEY, Kernel, delayed, request, unanswered
from applier.apply import EGRESS_RETRY_BUDGET_SEC, EGRESS_RETRY_SEC, EGRESS_RETRY_WITHIN_SEC, Applier
from molebridge import egress, providers
from molebridge.egress import (ECHO_URLS, HOST_LACKS_FAMILY, exit_addresses, host_lacks_ipv6, parse_echo,
                               tunnel_verdict)
from molebridge.state import egress_tier, now_iso, status_view, write_json_atomic

TUNNEL_IP, HOST_IP = '203.0.113.10', '198.51.100.99'
TUNNEL_IP6, HOST_IP6 = '2001:db8:3::10', '2001:db8:4::99'
ALL_ECHO_URLS = {url for urls in ECHO_URLS.values() for url in urls}


# -- the pure checks -----------------------------------------------------------

def test_echo_services_are_two_independent_https_hosts_per_family():
    for family, urls in ECHO_URLS.items():
        hosts = {url.split('/')[2] for url in urls}
        assert len(urls) == 2 and len({h.split('.', 1)[1] for h in hosts}) == 2, family
        assert all(url.startswith('https://') for url in urls)


@pytest.mark.parametrize('raw,family,expected', [
    ('203.0.113.10\n', 4, '203.0.113.10'), ('  203.0.113.10\r\n', 4, '203.0.113.10'),
    ('2001:DB8:3:0::10\n', 6, '2001:db8:3::10'),
])
def test_echo_answers_are_parsed_to_canonical_addresses(raw, family, expected):
    assert parse_echo(raw, family) == expected


@pytest.mark.parametrize('raw,family', [
    ('', 4), ('\n', 4), ('not an address', 4), ('203.0.113.10 203.0.113.11', 4), ('203.0.113.10', 6),
    ('2001:db8::1', 4), ('127.0.0.1', 4), ('0.0.0.0', 4), ('::1', 6), ('fe80::1', 6), ('224.0.0.1', 4),
    ('203.0.113.10' + ' ' * 300, 4), (None, 4), (b'203.0.113.10', 4), ('{"ip": "203.0.113.10"}', 4),
])
def test_echo_answers_that_are_not_one_usable_address_are_refused(raw, family):
    with pytest.raises(ValueError):
        parse_echo(raw, family)


def test_exit_addresses_come_only_from_the_entry_and_its_family():
    relay = {'exit_ips': ['203.0.113.10', '2001:db8:3::10', 'bogus', 7, '203.0.113.011']}
    assert exit_addresses(relay, 4) == {'203.0.113.10'}
    assert exit_addresses(relay, 6) == {'2001:db8:3::10'}
    for relay in (None, {}, {'exit_ips': []}, {'exit_ips': 'x'}, {'exit_ips': ['bogus']}):
        assert exit_addresses(relay, 4) is None
    assert exit_addresses({'exit_ips': ['2001:db8:3::10']}, 4) is None


@pytest.mark.parametrize('echoes,host,expected,age,ok', [
    ([TUNNEL_IP, TUNNEL_IP], HOST_IP, None, 5, True),
    ([TUNNEL_IP6, TUNNEL_IP6], HOST_LACKS_FAMILY, None, 5, True),
    # A failed measurement is unverified, never skipped.
    ([TUNNEL_IP, TUNNEL_IP], None, None, 5, False),
    ([TUNNEL_IP6, TUNNEL_IP6], None, None, 5, False),
    ([TUNNEL_IP, TUNNEL_IP], HOST_IP, {TUNNEL_IP}, 5, True),
    ([TUNNEL_IP, TUNNEL_IP], HOST_IP, {'203.0.113.11'}, 5, False),
    ([TUNNEL_IP, '203.0.113.11'], HOST_IP, None, 5, False),
    ([TUNNEL_IP], HOST_IP, None, 5, False),
    ([], HOST_IP, None, 5, False),
    ([TUNNEL_IP, TUNNEL_IP], TUNNEL_IP, None, 5, False),
    ([TUNNEL_IP, TUNNEL_IP], HOST_IP, None, None, False),
    ([TUNNEL_IP, TUNNEL_IP], HOST_IP, None, 180, False),
    ([TUNNEL_IP, TUNNEL_IP], HOST_IP, None, -1, False),
    ([TUNNEL_IP, TUNNEL_IP], HOST_IP, None, True, False),
    ([None, None], HOST_IP, None, 5, False),
])
def test_tunnel_verdict_needs_every_condition(echoes, host, expected, age, ok):
    assert tunnel_verdict(echoes, host, expected, age, max_handshake_age=180) is ok


IGNORE = {'mullvad', 'wt0'}
# What a namespace with no IPv6 of its own still lists, in every table.
NO_HOST_ROUTES6 = [
    {'dst': 'fe80::/64', 'dev': 'eth0', 'protocol': 'kernel', 'metric': 256},
    {'dst': '2001:db8:1::/64', 'dev': 'wt0', 'protocol': 'kernel', 'metric': 256},
    {'dst': 'default', 'dev': 'mullvad', 'table': '51821'},
    {'type': 'unreachable', 'dst': 'default', 'table': '51821', 'metric': 4096},
    {'type': 'local', 'dst': '::1', 'table': 'local', 'dev': 'lo'},
    {'type': 'local', 'dst': 'fe80::2', 'table': 'local', 'dev': 'eth0'},
    {'type': 'local', 'dst': TUNNEL_IP6, 'table': 'local', 'dev': 'mullvad'},
    {'type': 'anycast', 'dst': 'fe80::', 'table': 'local', 'dev': 'eth0'},
    {'type': 'multicast', 'dst': 'ff00::/8', 'table': 'local', 'dev': 'eth0'},
]
GLOBAL_ON = lambda name: {'ifname': name, 'addr_info': [  # noqa: E731
    {'family': 'inet6', 'scope': 'global', 'local': HOST_IP6, 'prefixlen': 128}]}


@pytest.mark.parametrize('routes,links,lacks', [
    ([], [], True),
    (NO_HOST_ROUTES6, [], True),
    (NO_HOST_ROUTES6, [GLOBAL_ON('mullvad'), GLOBAL_ON('wt0'), {'ifname': 'eth0', 'addr_info': []}, {'ifname': 'eth1'},
                       {'ifname': 'lo', 'addr_info': [{'family': 'inet6', 'scope': 'host', 'local': '::1'}]}], True),
    # Any route that could carry the host's own IPv6, in any table.
    ([{'dst': 'default', 'gateway': 'fe80::1', 'dev': 'eth0'}], [], False),
    ([{'dst': 'default', 'gateway': 'fe80::1', 'dev': 'eth0', 'table': '200'}], [], False),
    ([{'dst': '2001:db8:4::/48', 'dev': 'eth0', 'table': '200'}], [], False),
    ([{'type': 'local', 'dst': HOST_IP6, 'table': 'local', 'dev': 'lo'}], [], False),
    ([{'type': 'unreachable', 'dst': 'default', 'gateway': 'fe80::1'}], [], False),
    ([{'dst': 'not a prefix', 'dev': 'eth0'}], [], False),
    ([{'dev': 'eth0'}], [], False),
    (['default'], [], False),
    # A global address anywhere but the tunnel and the overlay, loopback included.
    ([], [GLOBAL_ON('eth0')], False),
    ([], [GLOBAL_ON('lo')], False),
    ([], [{'ifname': 'lo', 'addr_info': [{'family': 'inet6', 'local': HOST_IP6}]}], False),
    ([], [{'ifname': 'eth0', 'addr_info': 'x'}], False),
    ([], [{'addr_info': []}], False),
    ([], ['eth0'], False),
    (None, [], False), ({}, [], False), ([], None, False),
])
def test_only_independent_evidence_shows_a_host_without_ipv6(routes, links, lacks):
    assert host_lacks_ipv6(routes, links, IGNORE) is lacks


# -- the status model ----------------------------------------------------------

@pytest.fixture
def tunnel_provider(monkeypatch):
    """A registry entry for a provider without a typed egress check."""
    spec = dataclasses.replace(providers.get('mullvad'), id='tunnelvpn', label='Tunnel Example',
                               egress_tier='tunnel', validate_entry=lambda entry: dict(entry))
    monkeypatch.setitem(providers.REGISTRY, 'tunnelvpn', spec)
    return spec


def ok_result(**changes):
    return {'status': 'ok', 'checked_at': now_iso(), 'routing_ok': True, 'netbird_native': True,
            'server': HOST, 'exit_confirmed': False, 'egress_tier': 'tunnel', **changes}


def test_tunnel_tier_counts_only_for_a_provider_without_its_own_check(tunnel_provider):
    assert status_view(None, ok_result(), 'tunnelvpn') == ('ok', 'connected')
    assert egress_tier(ok_result(), 'tunnelvpn') == 'tunnel'
    for provider in ('mullvad', 'pia'):
        assert status_view(None, ok_result(), provider) == ('failed', 'verification failed')
        assert egress_tier(ok_result(), provider) is None
    assert status_view(None, ok_result(egress_tier=None), 'tunnelvpn') == ('failed', 'verification failed')
    assert status_view(None, ok_result(egress_tier='TUNNEL'), 'tunnelvpn') == ('failed', 'verification failed')
    assert status_view(None, ok_result(), 'examplevpn') == ('failed', 'verification failed')


def test_provider_tier_keeps_meaning_provider_confirmed(tunnel_provider):
    for provider in ('mullvad', 'pia', 'tunnelvpn'):
        result = ok_result(exit_confirmed=True, egress_tier='provider')
        assert status_view(None, result, provider) == ('ok', 'connected')
        assert egress_tier(result, provider) == 'provider'
    # Results written before tiers existed.
    assert egress_tier({'exit_confirmed': True}) == 'provider'
    assert egress_tier({'mullvad_exit_ip': True}) == 'provider'
    assert egress_tier({'exit_confirmed': False, 'mullvad_exit_ip': True}) is None


# -- the applier ---------------------------------------------------------------

class EchoKernel(Kernel):
    """The runtime fake, plus IP echo services on and off the tunnel."""

    def __init__(self):
        super().__init__()
        self.echo = {(4, True): [TUNNEL_IP, TUNNEL_IP], (4, False): HOST_IP,
                     (6, True): [TUNNEL_IP6, TUNNEL_IP6], (6, False): HOST_IP6}
        self.echo_down = set()
        # The namespace's own IPv6: a default route and a global address.
        self.host_routes6 = NO_HOST_ROUTES6 + [{'dst': 'default', 'gateway': 'fe80::1', 'dev': 'eth0'}]
        self.host_links6 = [{'ifname': 'eth0', 'addr_info': [{'family': 'inet6', 'scope': 'global', 'local': HOST_IP6}]}]

    def run(self, args, **kwargs):
        if args == ['ip', '-j', '-6', 'route', 'show', 'table', 'all']:
            self.calls.append(args)
            return json.dumps(self.host_routes6)
        if args == ['ip', '-j', '-6', 'address', 'show', 'scope', 'global']:
            self.calls.append(args)
            return json.dumps(self.host_links6)
        if args[0] == 'curl' and args[-1] in ALL_ECHO_URLS:
            self.calls.append(args)
            family = 4 if '-4' in args else 6
            assert f'-{family}' in args and args[-1] in ECHO_URLS[family]
            tunnel = '--interface' in args
            if tunnel:
                assert args[args.index('--interface') + 1] == CONFIG.exit_if
            assert '--noproxy' in args and '--max-filesize' in args and kwargs['limit'] == egress.ECHO_MAX_BYTES
            if (family, tunnel) in self.echo_down:
                raise RuntimeError('injected echo failure')
            answer = self.echo[(family, tunnel)]
            if tunnel:
                answer = answer[ECHO_URLS[family].index(args[-1])]
            return answer + '\n'
        assert not (args[0] == 'curl' and 'am.i.mullvad.net' in args[-1]), 'tunnel tier asked the provider'
        return super().run(args, **kwargs)


class TunnelApplier(Applier):
    provider = 'tunnelvpn'


@pytest.fixture
def tunnel_runtime(tmp_path, tunnel_provider):
    write_json_atomic(tmp_path / 'applier' / 'relays.json',
                      {'fetched_at': now_iso(), 'provider': 'tunnelvpn', 'relays': {HOST: ENTRY}})
    kernel = EchoKernel()
    applier = TunnelApplier(tmp_path, CONFIG, run=kernel.run, clock=lambda: kernel.now, sleep=kernel.sleep)
    applier.next_catalog = float('inf')
    return applier, kernel


def test_tunnel_checks_connect_a_provider_without_its_own_check(tunnel_runtime):
    app, kernel = tunnel_runtime
    result = app.inspect()
    assert result['status'] == 'ok' and result['server'] == HOST
    assert result['exit_confirmed'] is False and result['egress_tier'] == 'tunnel'
    assert result['egress_ip'] == TUNNEL_IP and result['egress_ips'] == {'4': TUNNEL_IP, '6': TUNNEL_IP6}
    assert status_view(None, json.loads(app.result_path.read_text()), 'tunnelvpn') == ('ok', 'connected')
    echoes = [c for c in kernel.calls if c[0] == 'curl']
    assert len(echoes) == 6  # two through the tunnel and one off it, per family


@pytest.mark.parametrize('change', [
    lambda k: k.echo.update({(4, True): [TUNNEL_IP, '203.0.113.11']}),
    lambda k: k.echo.update({(6, True): [TUNNEL_IP6, '2001:db8:3::11']}),
    lambda k: k.echo.update({(4, False): TUNNEL_IP}),
    lambda k: k.echo_down.add((4, False)),
    lambda k: k.echo_down.add((4, True)),
    lambda k: k.echo.update({(4, True): ['not an address', 'not an address']}),
    lambda k: setattr(k, 'age', 500),
])
def test_any_failed_tunnel_check_fails_the_exit(tunnel_runtime, change):
    app, kernel = tunnel_runtime
    change(kernel)
    result = app.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None
    assert result['message'] in ('Tunnel egress did not pass the tunnel checks.',
                                 'Tunnel inspection or egress check failed.',
                                 'Tunnel handshake is missing or stale; check the account and connectivity.')


def test_a_host_shown_to_have_no_ipv6_of_its_own_still_verifies(tunnel_runtime):
    app, kernel = tunnel_runtime
    kernel.echo_down.add((6, False))
    kernel.host_routes6, kernel.host_links6 = list(NO_HOST_ROUTES6), []
    assert app.inspect()['egress_tier'] == 'tunnel'


@pytest.mark.parametrize('evidence', [
    {'links': [GLOBAL_ON('lo')]},
    {'routes': [{'dst': '2001:db8:4::/48', 'dev': 'eth0', 'table': '200'}]},
])
def test_ipv6_on_loopback_or_in_a_policy_table_keeps_the_measurement_required(tunnel_runtime, evidence):
    app, kernel = tunnel_runtime
    kernel.echo_down.add((6, False))
    # Even a tunnel answer equal to the host's own address must not pass.
    kernel.echo[(6, True)] = [HOST_IP6, HOST_IP6]
    kernel.host_routes6 = list(NO_HOST_ROUTES6) + evidence.get('routes', [])
    kernel.host_links6 = evidence.get('links', [])
    result = app.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None


@pytest.mark.parametrize('failure', ['down', 'malformed'])
@pytest.mark.parametrize('evidence', ['default route', 'global address', 'unreadable'])
def test_a_failed_ipv6_measurement_is_unverified_without_evidence(tunnel_runtime, failure, evidence):
    app, kernel = tunnel_runtime
    if failure == 'down':
        kernel.echo_down.add((6, False))
    else:
        kernel.echo[(6, False)] = 'not an address'
    if evidence == 'default route':
        kernel.host_links6 = []
    elif evidence == 'global address':
        kernel.host_routes6 = list(NO_HOST_ROUTES6)
    else:
        kernel.host_routes6 = 'not a list'
    result = app.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None
    # No usable measurement is no answer: asked once more, then the check fails.
    assert result['message'] == 'Tunnel inspection or egress check failed.'
    assert kernel.now == EGRESS_RETRY_SEC
    assert status_view(None, json.loads(app.result_path.read_text()), 'tunnelvpn')[0] == 'failed'


def test_a_host_measurement_that_fails_once_is_asked_once_more(tunnel_runtime):
    app, kernel = tunnel_runtime
    off_tunnel = lambda args: args[0] == 'curl' and args[-1] in ALL_ECHO_URLS and '--interface' not in args
    calls = unanswered(app, kernel, off_tunnel)
    result = app.inspect()
    assert result['status'] == 'ok' and result['egress_tier'] == 'tunnel'
    assert kernel.now == 10 + EGRESS_RETRY_SEC and len(calls) == 3  # IPv4 twice, then IPv6


def test_echoes_that_disagree_fail_before_the_host_measurement(tunnel_runtime):
    app, kernel = tunnel_runtime
    kernel.echo[(4, True)] = [TUNNEL_IP, '203.0.113.11']
    kernel.echo_down.add((4, False))
    result = app.inspect()
    assert result['message'] == 'Tunnel egress did not pass the tunnel checks.' and kernel.now == 0
    assert not any(c[0] == 'curl' and c[-1] in ALL_ECHO_URLS and '--interface' not in c for c in kernel.calls)


def test_a_failed_family_ends_the_tunnel_checks_before_the_next_one(tunnel_runtime):
    app, kernel = tunnel_runtime
    kernel.echo[(4, False)] = TUNNEL_IP  # the "tunnel" answer is the host's own
    kernel.echo_down.add((6, True))
    result = app.inspect()
    assert result['message'] == 'Tunnel egress did not pass the tunnel checks.' and kernel.now == 0
    assert not any(c[0] == 'curl' and '-6' in c for c in kernel.calls)


def test_an_address_the_catalogue_does_not_list_fails_before_the_host_measurement(tunnel_runtime):
    app, kernel = tunnel_runtime
    app.catalog.relays[HOST] = {**ENTRY, 'exit_ips': ['203.0.113.11']}
    kernel.echo_down.add((4, False))
    result = app.inspect()
    assert result['message'] == 'Tunnel egress did not pass the tunnel checks.' and kernel.now == 0
    assert not any(c[0] == 'curl' and c[-1] in ALL_ECHO_URLS and '--interface' not in c for c in kernel.calls)


def test_a_second_tunnel_attempt_stays_within_its_budget(tunnel_runtime):
    app, kernel = tunnel_runtime
    echo = lambda args: args[0] == 'curl' and args[-1] in ALL_ECHO_URLS
    # First attempt: the first echo unanswered. Second: every request takes
    # 11 seconds, so the IPv6 echoes are never started.
    calls = delayed(app, kernel, echo, [(10, False)] + [(11, True)] * 6)
    result = app.inspect()
    assert result['message'] == 'Tunnel inspection or egress check failed.'
    assert kernel.now == 10 + EGRESS_RETRY_SEC + 33 and len(calls) == 4
    assert kernel.now <= EGRESS_RETRY_WITHIN_SEC + EGRESS_RETRY_SEC + EGRESS_RETRY_BUDGET_SEC + 12


def test_echo_services_that_disagree_are_never_asked_again(tunnel_runtime):
    app, kernel = tunnel_runtime
    kernel.echo[(4, True)] = [TUNNEL_IP, '203.0.113.11']
    result = app.inspect()
    assert result['message'] == 'Tunnel egress did not pass the tunnel checks.' and kernel.now == 0


def test_a_failed_ipv4_measurement_is_unverified_even_without_ipv6(tunnel_runtime):
    app, kernel = tunnel_runtime
    kernel.echo_down.add((4, False))
    kernel.host_routes6, kernel.host_links6 = [], []
    result = app.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None


def test_catalogue_exit_addresses_must_match(tmp_path, tunnel_runtime):
    app, kernel = tunnel_runtime
    for listed, status in (([TUNNEL_IP, TUNNEL_IP6], 'ok'), (['203.0.113.11'], 'failed'),
                           ([TUNNEL_IP], 'ok'), (['2001:db8:3::11'], 'failed')):
        app.catalog.relays[HOST] = {**ENTRY, 'exit_ips': listed}
        assert app.inspect()['status'] == status, listed


def test_unknown_peer_is_never_tunnel_verified(tunnel_runtime):
    app, kernel = tunnel_runtime
    kernel.keys = ['AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=']
    result = app.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None


def test_a_switch_completes_on_the_tunnel_tier(tunnel_runtime):
    app, kernel = tunnel_runtime
    kernel.keys = ['AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=']
    result = app.switch(request())
    assert result['status'] == 'ok' and result['egress_tier'] == 'tunnel' and kernel.keys == [KEY]


def test_provider_tier_results_carry_the_tier(tmp_path):
    write_json_atomic(tmp_path / 'applier' / 'relays.json', {'fetched_at': now_iso(), 'relays': {HOST: ENTRY}})
    kernel = Kernel()
    app = Applier(tmp_path, CONFIG, run=kernel.run, clock=lambda: kernel.now, sleep=kernel.sleep)
    result = app.inspect()
    assert result['status'] == 'ok' and result['exit_confirmed'] is True and result['egress_tier'] == 'provider'
    kernel.probe = {**kernel.probe, 'mullvad_exit_ip': False}
    result = app.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None
    assert result['message'] == 'Tunnel egress is not confirmed as Mullvad.'
    assert not any(c[-1] in ALL_ECHO_URLS for c in kernel.calls)
    kernel.egress_ok = False
    assert app.publish('unknown', 'x')['egress_tier'] is None

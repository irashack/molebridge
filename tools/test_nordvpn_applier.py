"""The NordVPN applier against a fake kernel and fake NordVPN answers. Nothing
here contacts NordVPN or touches a tunnel."""
import copy
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_runtime import delayed, unanswered
from applier import nordvpn as nord_applier
from applier.apply import EGRESS_RETRY_BUDGET_SEC, EGRESS_RETRY_SEC, EGRESS_RETRY_WITHIN_SEC, SWITCH_TIMEOUT_SEC
from applier.nordvpn import INSIGHTS_RETRY_SEC, NordApplier
from molebridge import providers, relays
from molebridge.nordvpn import NORD_ADDRESS, NORD_INSIGHTS_URL, parse_nord_catalog, validate_entry
from molebridge.routing import RoutingConfig
from molebridge.state import now_iso, read_json, status_view, write_json_atomic

FIXTURES = Path(__file__).parent / 'fixtures' / 'nordvpn'
CONFIG = RoutingConfig('192.0.2.0/24', '2001:db8:1::/64', exit_if='nordvpn')
TUNNEL4 = NORD_ADDRESS.split('/')[0]
US, DE, US2 = 'us9001.nordvpn.com', 'de9002.nordvpn.com', 'us9004.nordvpn.com'
US_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DE_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE='
STATION = {US: '198.51.100.11', DE: '198.51.100.22', US2: '198.51.100.14'}


def catalogue():
    """The fixture plus a second Dallas server sharing the location's key."""
    data = json.loads((FIXTURES / 'nordvpn-servers.json').read_text())
    clone = copy.deepcopy(data['servers'][0])
    clone.update(hostname=US2, station=STATION[US2], id=990004)
    clone['ips'][0]['ip']['ip'] = STATION[US2]
    data['servers'].append(clone)
    return parse_nord_catalog(data)


def request(server=US):
    return {'server': server, 'requested_at': now_iso(), 'request_id': 'a' * 32}


def rules(family):
    destination, prefix = (CONFIG.overlay if family == 4 else CONFIG.overlay6).split('/')
    table = [{'priority': 1, 'not': None, 'src': 'all', 'iif': 'wt0', 'table': 'local'},
             {'priority': 90, 'src': 'all', 'iif': 'nordvpn', 'dst': destination, 'dstlen': int(prefix),
              'table': 'main'},
             {'priority': 95, 'src': 'all', 'iif': 'wt0', 'table': 51821},
             {'priority': 96, 'src': 'all', 'oif': 'nordvpn', 'table': 51821},
             {'priority': 97, 'src': 'all', 'iif': 'wt0', 'action': 'unreachable'}]
    if family == 4:
        # IPv4 only: routing initialization reads 10.5.0.2 from the config.
        table.insert(2, {'priority': 94, 'src': TUNNEL4, 'ipproto': 'icmp', 'table': 51821})
    return table


class NordKernel:
    """Just enough of iproute2, wg, nft and NordVPN's insights call."""

    def __init__(self):
        self.calls = []
        self.rules = {4: rules(4), 6: rules(6)}
        self.routes = {4: [{'dst': 'default', 'dev': 'nordvpn'}, {'type': 'unreachable', 'dst': 'default', 'metric': 4096}],
                       6: [{'type': 'unreachable', 'dst': 'default', 'metric': 4096}]}
        self.peers = {}  # key -> endpoint
        self.age = 1
        self.now = 0
        self.fail_remove = False
        self.endpoint_listing = None
        # Each insights call takes the next answer; the last one repeats.
        self.insights = [{'ip': '198.51.100.11', 'country': 'United States', 'city': 'Dallas',
                          'country_code': 'US', 'protected': True}]

    def sleep(self, seconds):
        self.now += seconds

    def run(self, args, **kwargs):
        self.calls.append(args)
        if args[0] == 'ip':
            if args[1:4] == ['link', 'show', 'dev']:
                return ''
            if args[1:7] == ['-d', '-j', 'link', 'show', 'dev', 'wt0']:
                return json.dumps([{'ifname': 'wt0', 'linkinfo': {'info_kind': 'wireguard'}}])
            if args[1:4] == ['-j', 'address', 'show']:
                return json.dumps([{'addr_info': [{'family': 'inet', 'scope': 'global', 'local': TUNNEL4}]}])
            family = int(args[2][1:])
            return json.dumps(self.rules[family] if args[3] == 'rule' else self.routes[family])
        if args[:3] == ['wg', 'show', 'nordvpn']:
            if args[3] == 'peers':
                return '\n'.join(self.peers)
            if args[3] == 'endpoints':
                if self.endpoint_listing is not None:
                    return self.endpoint_listing
                return '\n'.join(f'{key}\t{endpoint}' for key, endpoint in self.peers.items())
            assert args[3] == 'latest-handshakes'
            return '\n'.join(f'{key}\t{int(time.time()) - self.age}' for key in self.peers)
        if args[:3] == ['wg', 'set', 'nordvpn']:
            if args[-1] == 'remove':
                if self.fail_remove:
                    raise RuntimeError('injected command failure')
                del self.peers[args[4]]
            else:
                assert args[5] == 'endpoint' and args[7:] == ['allowed-ips', '0.0.0.0/0', 'persistent-keepalive', '25']
                self.peers[args[4]] = args[6]
            return ''
        if args[0] == 'cat':
            return '1\n'
        if args == ['nft', '-j', 'list', 'chains']:
            return json.dumps({'nftables': [{'chain': {'family': 'ip', 'table': 'netbird', 'name': 'netbird-rt-fwd'}}]})
        if args[0] == 'curl':
            assert args[-1] == NORD_INSIGHTS_URL
            assert args[1] == '-4' and args[args.index('--interface') + 1] == 'nordvpn'
            assert '--noproxy' in args and '--max-filesize' in args and kwargs['limit'] == 16384
            answer = self.insights[0] if len(self.insights) == 1 else self.insights.pop(0)
            return answer if isinstance(answer, str) else json.dumps(answer)
        raise AssertionError('unexpected command: ' + ' '.join(args))

    @property
    def mutations(self):
        return [c for c in self.calls if c[:2] == ['wg', 'set']]

    @property
    def insight_calls(self):
        return [c for c in self.calls if c[0] == 'curl']


@pytest.fixture
def nord(tmp_path):
    write_json_atomic(tmp_path / 'applier' / 'relays.json',
                      {'fetched_at': now_iso(), 'provider': 'nordvpn', 'relays': catalogue()}, public=True)
    kernel = NordKernel()
    applier = NordApplier(tmp_path, CONFIG, run=kernel.run, clock=lambda: kernel.now, sleep=kernel.sleep)
    applier.next_catalog = float('inf')
    return applier, kernel


def connect(kernel, host=US):
    key = US_KEY if host != DE else DE_KEY
    kernel.peers = {key: f'{STATION[host]}:51820'}


# -- catalogue -----------------------------------------------------------------

def test_snapshot_round_trip_keeps_every_relay_field(nord):
    app, _ = nord
    assert app.catalog.relays == catalogue() and app.catalog.usable()
    assert set(app.catalog.relays) == {US, DE, US2}
    assert app.catalog.relays[US2]['public_key'] == app.catalog.relays[US]['public_key'] == US_KEY
    assert relays.snapshot_relays(read_json(app.catalog.path), 'nordvpn') == catalogue()
    assert relays.snapshot_relays(read_json(app.catalog.path), 'mullvad') == {}


@pytest.mark.parametrize('change', [
    {'hostname': 'se-sto-wg-001'}, {'hostname': 'US9001.nordvpn.com'}, {'public_key': 'x'},
    {'ipv4_addr_in': '198.51.100.011'}, {'city': ''}, {'country': 'x' * 257}, {'country_code': 'us'},
    {'location_code': 'us dallas'}, {'location_code': 'US-dallas'}, {'virtual': 'false'}, {'city': 'a\nb'},
])
def test_snapshot_entries_are_validated_again(change):
    entry = {**catalogue()[US], **change}
    assert validate_entry(entry) is None


def test_snapshot_drops_malformed_optional_load():
    entry = catalogue()[US]
    assert validate_entry({**entry, 'load': 101}) == {k: v for k, v in entry.items() if k != 'load'}
    assert validate_entry({**entry, 'load': True}) == {k: v for k, v in entry.items() if k != 'load'}
    assert validate_entry({**entry, 'extra': 1}) == entry


def test_refresh_parses_with_the_nord_parser_and_keeps_the_last_good_catalogue(nord):
    app, _ = nord
    raw = (FIXTURES / 'nordvpn-servers.json').read_text()
    assert app.catalog.refresh(lambda: raw) is True and set(app.catalog.relays) == {US, DE}
    assert app.catalog.refresh(lambda: '{"servers": []}') is False
    assert set(app.catalog.relays) == {US, DE}
    assert read_json(app.catalog.error_path)['message'] == 'Relay refresh failed; retaining the last good catalogue.'


# -- switching -----------------------------------------------------------------

def test_switch_sets_key_endpoint_ipv4_only_and_keepalive(nord):
    app, kernel = nord
    result = app.switch(request(US))
    assert result['status'] == 'ok' and result['server'] == US
    assert kernel.mutations == [['wg', 'set', 'nordvpn', 'peer', US_KEY, 'endpoint', '198.51.100.11:51820',
                                 'allowed-ips', '0.0.0.0/0', 'persistent-keepalive', '25']]
    # The address is the config's; a switch never changes it.
    assert not any(c[0] == 'ip' and c[1] in ('-4', '-6') and c[2] in ('address', 'rule', 'route')
                   and c[3] in ('add', 'del', 'replace') for c in kernel.calls)


def test_switch_replaces_every_peer_first_even_with_the_same_key(nord):
    app, kernel = nord
    connect(kernel, US)
    result = app.switch(request(US2))
    assert result['status'] == 'ok' and result['server'] == US2
    assert kernel.mutations == [['wg', 'set', 'nordvpn', 'peer', US_KEY, 'remove'],
                                ['wg', 'set', 'nordvpn', 'peer', US_KEY, 'endpoint', '198.51.100.14:51820',
                                 'allowed-ips', '0.0.0.0/0', 'persistent-keepalive', '25']]


def test_switch_to_another_location_removes_the_old_peer(nord):
    app, kernel = nord
    connect(kernel, DE)
    kernel.insights = [{'ip': '198.51.100.11', 'country': 'United States', 'city': 'Dallas', 'country_code': 'US',
                        'protected': True}]
    assert app.switch(request(US))['status'] == 'ok'
    assert kernel.mutations[0] == ['wg', 'set', 'nordvpn', 'peer', DE_KEY, 'remove']
    assert kernel.peers == {US_KEY: '198.51.100.11:51820'}


def test_failed_removal_adds_no_peer(nord):
    app, kernel = nord
    connect(kernel, DE)
    kernel.fail_remove = True
    result = app.switch(request(US))
    assert result['status'] == 'failed'
    assert result['message'] == 'Peer update failed; choose a server again to retry.'
    assert kernel.peers == {DE_KEY: '198.51.100.22:51820'}
    assert all(c[-1] == 'remove' for c in kernel.mutations)


def test_unlisted_server_changes_nothing(nord):
    app, kernel = nord
    connect(kernel, US)
    result = app.switch(request('uk9003.nordvpn.com'))
    assert result['status'] == 'failed' and not kernel.mutations
    assert result['message'] == 'Requested server is not in a fresh trusted relay catalogue; no change applied.'


# -- which server is live ------------------------------------------------------

@pytest.mark.parametrize('peers,expected', [
    ({US_KEY: '198.51.100.11:51820'}, US),
    ({US_KEY: '198.51.100.14:51820'}, US2),
    ({DE_KEY: '198.51.100.22:51820'}, DE),
    # A location's key on another location's server is not that server.
    ({US_KEY: '198.51.100.22:51820'}, None),
    ({DE_KEY: '198.51.100.11:51820'}, None),
    ({US_KEY: '198.51.100.11:51821'}, None),
    ({US_KEY: '203.0.113.99:51820'}, None),
    ({US_KEY: '(none)'}, None),
    ({US_KEY: '[2001:db8::1]:51820'}, None),
    ({US_KEY: '198.51.100.11:51820', DE_KEY: '198.51.100.22:51820'}, None),
    ({}, None),
])
def test_server_is_identified_by_live_endpoint_and_key(nord, peers, expected):
    app, kernel = nord
    kernel.peers = dict(peers)
    assert app.server_for(app.peers()) == expected


@pytest.mark.parametrize('listing', [
    'not-a-key\t198.51.100.11:51820',
    f'{US_KEY}\t198.51.100.11:51820\textra',
    f'{US_KEY}',
    f'{US_KEY}\t198.51.100.11:51820\n{US_KEY}\t198.51.100.14:51820',
])
def test_malformed_endpoint_listing_is_refused(nord, listing):
    app, kernel = nord
    connect(kernel, US)
    kernel.endpoint_listing = listing
    with pytest.raises(ValueError):
        app.server_for([US_KEY])
    result = app.inspect()
    assert result['status'] == 'failed' and result['server'] is None


def test_recreated_tunnel_gets_the_selection_back(nord):
    app, kernel = nord
    app.desired_path.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(app.desired_path, request(US2))
    assert app.tick()['status'] == 'ok' and kernel.peers == {US_KEY: '198.51.100.14:51820'}
    kernel.peers = {}  # the wireguard container came back from its config, which has no peer
    kernel.calls.clear()
    assert app.tick()['status'] == 'ok' and kernel.peers == {US_KEY: '198.51.100.14:51820'}
    # Same key, other server in the location: still not the selection, so it is applied again.
    kernel.peers = {US_KEY: '198.51.100.11:51820'}
    assert app.tick()['server'] == US2


# -- egress --------------------------------------------------------------------

def test_protected_egress_is_the_provider_tier(nord):
    app, kernel = nord
    connect(kernel, US)
    result = app.inspect()
    assert result['status'] == 'ok' and result['exit_confirmed'] is True and result['egress_tier'] == 'provider'
    assert (result['egress_ip'], result['egress_city'], result['egress_country']) == ('198.51.100.11', 'Dallas',
                                                                                       'United States')
    assert result['egress_ips'] == {'4': '198.51.100.11'} and result['provider'] == 'nordvpn'
    assert 'mullvad_exit_ip' not in result
    assert status_view(None, read_json(app.result_path), 'nordvpn') == ('ok', 'connected')
    assert len(kernel.insight_calls) == 1


def test_unprotected_egress_elsewhere_fails_at_once(nord):
    app, kernel = nord
    connect(kernel, US)
    kernel.insights = [json.loads((FIXTURES / 'nordvpn-insights-unprotected.json').read_text())]
    result = app.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None and result['exit_confirmed'] is False
    assert result['message'] == 'Tunnel egress is not confirmed as NordVPN.'
    assert len(kernel.insight_calls) == 1 and kernel.now == 0


def test_cached_answer_for_the_servers_own_address_is_asked_again(nord):
    app, kernel = nord
    connect(kernel, US)
    stale = {'ip': '198.51.100.11', 'country': 'Unknown', 'city': 'Unknown', 'country_code': 'Unknown', 'protected': False}
    kernel.insights = [stale, stale, {**stale, 'protected': True, 'city': 'Dallas'}]
    result = app.inspect()
    assert result['status'] == 'ok' and result['egress_tier'] == 'provider'
    assert len(kernel.insight_calls) == 3 and kernel.now == 2 * INSIGHTS_RETRY_SEC


def test_cached_answer_that_never_changes_fails_within_the_switch_timeout(nord):
    app, kernel = nord
    connect(kernel, US)
    kernel.insights = [{'ip': '198.51.100.11', 'country': 'Unknown', 'city': 'Unknown', 'country_code': 'Unknown', 'protected': False}]
    result = app.inspect()
    assert result['status'] == 'failed' and result['message'] == 'Tunnel egress is not confirmed as NordVPN.'
    assert kernel.now <= SWITCH_TIMEOUT_SEC
    assert len(kernel.insight_calls) == SWITCH_TIMEOUT_SEC // INSIGHTS_RETRY_SEC + 1


def test_a_switch_waits_out_a_cached_answer_within_its_own_timeout(nord):
    app, kernel = nord
    connect(kernel, DE)
    stale = {'ip': '198.51.100.11', 'country': 'Unknown', 'city': 'Unknown', 'country_code': 'Unknown', 'protected': False}
    kernel.insights = [stale] * 3 + [{**stale, 'protected': True}]
    result = app.switch(request(US))
    assert result['status'] == 'ok' and result['server'] == US and kernel.now < SWITCH_TIMEOUT_SEC
    kernel.insights = [stale]
    connect(kernel, DE)
    kernel.now = 0
    result = app.switch(request(US) | {'request_id': 'b' * 32})
    assert result['status'] == 'failed' and kernel.now <= SWITCH_TIMEOUT_SEC + 3
    assert result['message'] == 'Switch verification timed out; choose a server again to retry.'
    assert app.switch_deadline is None


@pytest.mark.parametrize('answer', [
    (FIXTURES / 'nordvpn-insights-unknown.json').read_text(),
    '{"ip": "198.51.100.11", "protected": "true"}', '{"ip": "2001:db8::1", "protected": true}',
    'not json', '[]', '{"ip": "198.51.100.11", "protected": true, "protected": false}',
])
def test_unusable_insights_answers_fail_closed(nord, answer):
    app, kernel = nord
    connect(kernel, US)
    kernel.insights = [answer]
    result = app.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None
    if 'Unknown' not in answer:
        assert result['message'] == 'Tunnel inspection or egress check failed.'


def test_ipv6_is_never_tunnelled_or_probed(nord):
    app, kernel = nord
    connect(kernel, US)
    assert app.routing_status() == (True, True)
    assert app.tunnel_addresses() == {4: TUNNEL4}
    assert app.inspect()['status'] == 'ok'
    assert not any(c[0] == 'curl' and '-6' in c for c in kernel.calls)
    assert not any('::/0' in ','.join(c) for c in kernel.mutations)
    # An IPv6 return-path rule would mean the config carries IPv6, which NordLynx does not.
    kernel.rules[6].insert(2, {'priority': 94, 'src': '2001:db8:3::1', 'ipproto': 'ipv6-icmp', 'table': 51821})
    assert app.routing_status()[0] is False


def test_missing_tunnel_address_blocks_a_switch(nord):
    app, kernel = nord
    kernel.run_original = kernel.run

    def no_address(args, **kwargs):
        if args[0] == 'ip' and args[1:4] == ['-j', 'address', 'show']:
            return json.dumps([{'addr_info': []}])
        return kernel.run_original(args, **kwargs)
    app.run = no_address
    result = app.switch(request(US))
    assert result['status'] == 'failed' and not kernel.mutations
    assert app.pending.startswith('Waiting for tunnel and overlay routing')


def test_fresh_exit_asks_for_a_server(nord):
    app, kernel = nord
    result = app.inspect()
    assert result['status'] == 'failed'
    assert result['message'] == 'No NordVPN server is selected yet; choose one in the panel.'
    assert result['routing_ok'] is True and result['netbird_native'] is True and not kernel.insight_calls


def test_applier_is_built_from_the_registry(tmp_path, monkeypatch):
    spec = providers.get('nordvpn')
    assert spec.applier_class() is NordApplier and nord_applier.NordApplier.provider == 'nordvpn'
    app = NordApplier.from_env(tmp_path, CONFIG, {'PROVIDER': 'nordvpn'})
    assert isinstance(app, NordApplier) and app.address_before_switch is True and app.spec.ipv6 is False


# -- setup, routing initialization and the doctor --------------------------------

def nord_conf():
    from test_nordvpn import nk
    return nk.build_nord_conf('A' * 42 + 'Q=', '51821')


def test_routing_init_accepts_the_generated_nordvpn_config(tmp_path):
    from test_host_and_routing import routing_run
    result, calls, ready = routing_run(tmp_path, conf_text=nord_conf(), PROVIDER='nordvpn')
    assert result.returncode == 0, result.stderr
    assert ready.exists()
    assert f'-4 rule add from {TUNNEL4} ipproto icmp lookup 51821 priority 94' in calls
    assert not any('-6 rule add from' in call for call in calls)


@pytest.mark.parametrize('change,message', [
    (lambda text: text.replace(NORD_ADDRESS, NORD_ADDRESS + ', 2001:db8:3::1/128'), 'NordVPN tunnels carry no IPv6'),
    (lambda text: text.replace(f'Address = {NORD_ADDRESS}\n', ''), 'needs an IPv4 Address'),
])
def test_routing_init_refuses_ipv6_or_a_missing_address(tmp_path, change, message):
    from test_host_and_routing import routing_run
    result, calls, ready = routing_run(tmp_path, conf_text=change(nord_conf()), PROVIDER='nordvpn')
    assert result.returncode != 0 and message in result.stderr
    assert not ready.exists() and not calls


@pytest.mark.skipif(sys.platform == 'win32', reason='mode 0600 files')
@pytest.mark.parametrize('extra,message', [
    ('', None),
    ('[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = 198.51.100.11:51820\n', None),
])
def test_doctor_accepts_the_generated_config_without_account_files(tmp_path, extra, message):
    from test_host_and_routing import compose_config, host_tools
    path = tmp_path / 'tunnel' / 'wg_confs' / 'nordvpn.conf'
    path.parent.mkdir(parents=True)
    path.write_text(nord_conf() + extra)
    path.chmod(0o600)
    config = compose_config()
    config['services']['wireguard']['environment'].update(EXIT_IF='nordvpn', PROVIDER='nordvpn')
    host_tools.Host(tmp_path, run=lambda *a, **kw: '').check_files(config)
    path.write_text(nord_conf().replace(NORD_ADDRESS, NORD_ADDRESS + ', 2001:db8:3::1/128'))
    with pytest.raises(host_tools.CheckError, match='NordVPN tunnels carry no IPv6'):
        host_tools.Host(tmp_path, run=lambda *a, **kw: '').check_files(config)
    config['services']['wireguard']['environment'].update(PROVIDER='examplevpn')
    with pytest.raises(host_tools.CheckError, match='PROVIDER must be one of: mullvad, pia, nordvpn'):
        host_tools.Host(tmp_path, run=lambda *a, **kw: '').check_files(config)


def test_compose_override_passes_server_and_raises_the_appliers_memory():
    yaml = pytest.importorskip('yaml')
    compose = yaml.safe_load((ROOT / 'compose.yaml').read_text())
    nord = yaml.safe_load((ROOT / 'compose.nordvpn.yaml').read_text())
    assert nord == {'services': {'applier': {'environment': {'SERVER': '${SERVER:-}'},
                                           'deploy': {'resources': {'limits': {'memory': '512m'}}}}}}
    # The whole capped download fits in the applier's scratch space.
    tmpfs = compose['services']['applier']['tmpfs']
    assert len(tmpfs) == 1 and tmpfs[0].startswith('/tmp:size=48m,')
    assert 48 * 1024 * 1024 > providers.get('nordvpn').catalog_max_bytes + 4


# -- egress check retry --------------------------------------------------------

def insights_call(args):
    return args[0] == 'curl' and args[-1] == NORD_INSIGHTS_URL


def test_an_unanswered_insights_check_is_asked_once_more(nord):
    app, kernel = nord
    assert app.switch(request(US))['status'] == 'ok'
    calls = unanswered(app, kernel, insights_call)
    start = kernel.now
    result = app.inspect()
    assert result['status'] == 'ok' and result['exit_confirmed'] is True
    assert len(calls) == 2 and kernel.now - start == 10 + EGRESS_RETRY_SEC


def test_an_insights_check_unanswered_twice_fails(nord):
    app, kernel = nord
    assert app.switch(request(US))['status'] == 'ok'
    calls = unanswered(app, kernel, insights_call, times=2)
    result = app.inspect()
    assert result['status'] == 'failed' and result['message'] == 'Tunnel inspection or egress check failed.'
    assert len(calls) == 2


def test_unprotected_from_another_address_is_never_asked_again(nord):
    app, kernel = nord
    assert app.switch(request(US))['status'] == 'ok'
    kernel.insights = [{'ip': '203.0.113.99', 'country': 'United States', 'city': 'Dallas',
                        'country_code': 'US', 'protected': False}]
    calls = unanswered(app, kernel, insights_call, times=0)
    start = kernel.now
    assert app.inspect()['message'] == 'Tunnel egress is not confirmed as NordVPN.'
    assert len(calls) == 1 and kernel.now == start


def test_a_second_attempt_waits_for_the_cache_only_within_its_budget(nord):
    app, kernel = nord
    assert app.switch(request(US))['status'] == 'ok'
    # The server's own address, unprotected: the cache answer NordVPN can serve.
    kernel.insights = [{'ip': '198.51.100.11', 'country': 'United States', 'city': 'Dallas',
                        'country_code': 'US', 'protected': False}]
    unanswered(app, kernel, insights_call)
    start = kernel.now
    result = app.inspect()
    assert result['message'] == 'Tunnel egress is not confirmed as NordVPN.'
    assert kernel.now - start == 10 + EGRESS_RETRY_SEC + EGRESS_RETRY_BUDGET_SEC


def test_a_cache_wait_then_no_answer_is_not_asked_again(nord):
    app, kernel = nord
    assert app.switch(request(US))['status'] == 'ok'
    kernel.insights = [{'ip': '198.51.100.11', 'country': 'United States', 'city': 'Dallas',
                        'country_code': 'US', 'protected': False}]
    # One cached answer, the 10-second wait, then no answer: over the limit
    # for a second attempt.
    calls = delayed(app, kernel, insights_call, [(0, True), (10, False)])
    start = kernel.now
    result = app.inspect()
    assert result['message'] == 'Tunnel inspection or egress check failed.'
    assert kernel.now - start == INSIGHTS_RETRY_SEC + 10 > EGRESS_RETRY_WITHIN_SEC and len(calls) == 2

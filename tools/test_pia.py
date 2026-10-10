"""PIA provider: catalogue, registration, switching and port forwarding, with a
fake kernel and fake PIA API. No account, tunnel or host routes are touched."""
import base64
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_runtime import unanswered
from applier import pia as pia_module
from applier.apply import EGRESS_RETRY_SEC
from applier.pia import PiaApplier, read_secret, scratch
from molebridge import relays
from molebridge.routing import RoutingConfig
from molebridge.state import desired_request, now_iso, read_json, status_view, write_json_atomic

ROOT = Path(__file__).resolve().parents[1]
CONFIG = RoutingConfig('192.0.2.0/24', '2001:db8:1::/64', exit_if='pia')
OUR_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
SERVER_KEY = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
OTHER_KEY = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
USERNAME, PASSWORD, TOKEN = 'p0000000', 'correct horse', 'tok-EXAMPLE-0123456789'
REGION = 'ex_example'


def region(**changes):
    base = {'id': REGION, 'name': 'EX Example City', 'country': 'EX', 'offline': False,
            'port_forward': True, 'geo': False, 'auto_region': True, 'dns': 'example.test',
            'servers': {'wg': [{'ip': '198.51.100.20', 'cn': 'example401'}],
                        'meta': [{'ip': '198.51.100.21', 'cn': 'example401'}]}}
    return {**base, **changes}


def serverlist(*regions):
    return json.dumps({'groups': {}, 'regions': list(regions or [region()])}) + '\n\nSIGNATURE-NOT-JSON'


def entry(**changes):
    return {**relays.parse_catalog(serverlist(region()), 'pia')[REGION], **changes}


def rules(family, tunnel=None):
    destination, prefix = (CONFIG.overlay if family == 4 else CONFIG.overlay6).split('/')
    table = [{'priority': 1, 'not': None, 'src': 'all', 'iif': 'wt0', 'table': 'local'},
             {'priority': 90, 'src': 'all', 'iif': 'pia', 'dst': destination, 'dstlen': int(prefix), 'table': 'main'},
             {'priority': 95, 'src': 'all', 'iif': 'wt0', 'table': 51821},
             {'priority': 96, 'src': 'all', 'oif': 'pia', 'table': 51821},
             {'priority': 97, 'src': 'all', 'iif': 'wt0', 'action': 'unreachable'}]
    if tunnel:
        table.insert(2, {'priority': 94, 'src': tunnel, 'ipproto': 'icmp', 'table': 51821})
        table.append({'priority': 98, 'src': tunnel, 'ipproto': 'icmp', 'action': 'unreachable'})
    return table


class PiaKernel:
    """Just enough of iproute2, wg, nft and PIA's HTTPS API."""

    def __init__(self):
        self.calls = []
        self.addresses = []
        self.expected_rule_source = '10.0.0.2'
        self.rules = {4: rules(4), 6: rules(6)}
        self.routes = {4: [{'dst': 'default', 'dev': 'pia'}, {'type': 'unreachable', 'dst': 'default', 'metric': 4096}],
                       6: [{'type': 'unreachable', 'dst': 'default', 'metric': 4096}]}
        self.keys = []
        self.age = 1
        self.now = 0
        self.connected = True
        self.addkey = {'status': 'OK', 'server_key': SERVER_KEY, 'server_port': 1337,
                       'server_ip': '198.51.100.20', 'server_vip': '10.0.0.1', 'peer_ip': '10.0.0.2',
                       'peer_pubkey': OUR_KEY, 'dns_servers': ['10.0.0.243']}
        self.addkey_fail = False
        self.token_fail = False
        self.port = 43210
        self.bind_fail = False
        self.nft = []
        self.scratch_seen = []
        self.return_path_gaps = 0
        self.both_missing = 0
        # A one-shot failure: the first command it matches raises.
        self.fail_when = None

    def sleep(self, seconds):
        self.now += seconds

    def note_return_path(self):
        """Record whether every tunnel address in use had both its rule 94 and
        its backstop 98 at this step."""
        found = {p: {r['src'] for r in self.rules[4] if r['priority'] == p} for p in (94, 98)}
        for priority in (94, 98):
            self.return_path_gaps += bool(set(self.addresses) - found[priority])
        self.both_missing += bool(set(self.addresses) - found[94] - found[98])

    def argument_files(self, args):
        """Contents of every @file/<file argument, which must be 0600 scratch."""
        found = {}
        for arg in args:
            for marker in ('@', '<'):
                if marker in arg and '/' in arg.split(marker, 1)[1]:
                    path = arg.split(marker, 1)[1]
                    assert os.stat(path).st_mode & 0o777 == 0o600
                    found[arg.split(marker, 1)[0].rstrip('=')] = Path(path).read_text()
                    self.scratch_seen.append(path)
        return found

    def run(self, args, **kwargs):
        self.calls.append(args)
        if self.fail_when and self.fail_when(args):
            self.fail_when = None
            raise RuntimeError('injected failure')
        text = ' '.join(args)
        for secret in (PASSWORD, TOKEN):
            assert secret not in text, 'secret in argv'
        if args[0] == 'ip':
            if args[1:4] == ['link', 'show', 'dev']:
                return ''
            if args[1:7] == ['-d', '-j', 'link', 'show', 'dev', 'wt0']:
                return json.dumps([{'ifname': 'wt0', 'linkinfo': {'info_kind': 'wireguard'}}])
            if args[1:5] == ['-j', '-4', 'address', 'show']:
                # Every interface: the namespace's container network and the tunnel.
                return json.dumps([{'ifname': 'eth0', 'addr_info': [{'local': '10.89.0.5', 'prefixlen': 24}]},
                                   {'ifname': 'pia', 'addr_info': [{'local': a, 'prefixlen': 32}
                                                                   for a in self.addresses]}])
            if args[1:4] == ['-j', 'address', 'show']:
                return json.dumps([{'addr_info': [{'family': 'inet', 'scope': 'global', 'local': a}
                                                  for a in self.addresses]}])
            if args[1:4] == ['-4', 'address', 'replace']:
                if args[4].split('/')[0] not in self.addresses:
                    self.addresses.append(args[4].split('/')[0])
                return ''
            if args[1:4] == ['-4', 'address', 'del']:
                self.addresses.remove(args[4].split('/')[0])
                self.note_return_path()
                if not self.addresses:
                    # The kernel drops routes through an interface with no IPv4 address.
                    self.routes[4] = [r for r in self.routes[4] if r.get('dev') != 'pia']
                return ''
            if args[1:4] == ['-4', 'route', 'replace']:
                assert args[4:] == ['default', 'dev', 'pia', 'table', '51821']
                self.routes[4] = [r for r in self.routes[4] if r.get('dev') != 'pia'] + [{'dst': 'default', 'dev': 'pia'}]
                return ''
            if args[1:4] == ['-4', 'rule', 'del']:
                assert args[4] == 'priority' and args[5] in ('94', '98') and args[6:7] in ([], ['from'])
                match = [r for r in self.rules[4] if r['priority'] == int(args[5])
                         and (len(args) == 6 or r['src'] == args[7])]
                if not match:
                    raise RuntimeError('no such rule')
                self.rules[4].remove(match[0])
                self.note_return_path()
                return ''
            if args[1:4] == ['-4', 'rule', 'add']:
                if args[-1] == '94':
                    assert args[4:] == ['from', self.expected_rule_source, 'ipproto', 'icmp', 'lookup', '51821', 'priority', '94']
                    rule = {'priority': 94, 'src': args[5], 'ipproto': 'icmp', 'table': 51821}
                else:
                    assert args[4:] == ['from', self.expected_rule_source, 'ipproto', 'icmp', 'unreachable', 'priority', '98']
                    rule = {'priority': 98, 'src': args[5], 'ipproto': 'icmp', 'action': 'unreachable'}
                self.rules[4] = sorted(self.rules[4] + [rule], key=lambda r: r['priority'])
                self.note_return_path()
                return ''
            family = int(args[2][1:])
            return json.dumps(self.rules[family] if args[3] == 'rule' else self.routes[family])
        if args[:2] == ['wg', 'show']:
            if args[-1] == 'public-key':
                return OUR_KEY + '\n'
            if args[-1] == 'peers':
                return '\n'.join(self.keys)
            return '\n'.join(f'{key}\t{int(time.time()) - self.age}' for key in self.keys)
        if args[:2] == ['wg', 'set']:
            if args[-1] == 'remove':
                self.keys.remove(args[4])
            else:
                assert args[5:] == ['endpoint', '198.51.100.20:1337', 'allowed-ips', '0.0.0.0/0',
                                    'persistent-keepalive', '25']
                self.keys = [args[4]]
            return ''
        if args[0] == 'cat':
            return '1\n'
        if args == ['nft', '-j', 'list', 'chains']:
            return json.dumps({'nftables': [{'chain': {'family': 'ip', 'table': 'netbird', 'name': 'netbird-rt-fwd'}}]})
        if args[0] == 'nft':
            self.nft.append(self.argument_files(['f@' + args[2]])['f'])
            return ''
        if args[0] == 'curl':
            assert args[1:4] == ['--noproxy', '*', '--proto']
            files = self.argument_files(args)
            url = args[-1]
            if url == pia_module.PIA_TOKEN_URL:
                if self.token_fail:
                    raise RuntimeError('command failed')
                assert files == {'username': USERNAME, 'password': PASSWORD}
                return json.dumps({'token': TOKEN})
            if url == pia_module.PIA_STATUS_URL:
                assert args[args.index('--interface') + 1] == 'pia'
                return json.dumps({'connected': self.connected, 'ip': '203.0.113.30'})
            assert args[args.index('--cacert') + 1] == str(pia_module.PIA_CA)
            if url == 'https://example401:1337/addKey':
                assert args[args.index('--connect-to') + 1] == 'example401::198.51.100.20:'
                assert files == {'pt': TOKEN} and f'pubkey={OUR_KEY}' in args
                if self.addkey_fail:
                    raise RuntimeError('command failed')
                return json.dumps(self.addkey)
            assert args[args.index('--interface') + 1] == 'pia'
            assert args[args.index('--connect-to') + 1] == 'example401::10.0.0.1:'
            if url == 'https://example401:19999/getSignature':
                assert files == {'token': TOKEN}
                payload = base64.b64encode(json.dumps({'token': 'x', 'port': self.port,
                                                       'expires_at': '2026-12-01T00:00:00Z'}).encode()).decode()
                return json.dumps({'status': 'OK', 'payload': payload, 'signature': 'SIG'})
            if url == 'https://example401:19999/bindPort':
                assert set(files) == {'payload', 'signature'}
                return json.dumps({'status': 'ERROR' if self.bind_fail else 'OK', 'message': 'x'})
        raise AssertionError('unexpected command: ' + args[0])

    @property
    def mutations(self):
        return [c for c in self.calls if c[:2] == ['wg', 'set'] or c[1:3] in (['-4', 'address'], ['-4', 'rule'], ['-4', 'route'])
                and c[3] in ('replace', 'add', 'del')]


@pytest.fixture
def secrets_dir(tmp_path):
    directory = tmp_path / 'secrets'
    directory.mkdir()
    (directory / 'username').write_text(USERNAME + '\n')
    (directory / 'password').write_text(PASSWORD)
    return directory


def make(tmp_path, secrets_dir, **kwargs):
    write_json_atomic(tmp_path / 'applier' / 'relays.json',
                      {'fetched_at': now_iso(), 'provider': 'pia', 'relays': {REGION: entry()}})
    kernel = PiaKernel()
    applier = PiaApplier(tmp_path, CONFIG, secrets_dir=secrets_dir, run=kernel.run,
                         clock=lambda: kernel.now, sleep=kernel.sleep, choose=lambda items: items[0], **kwargs)
    applier.next_catalog = float('inf')
    return applier, kernel


@pytest.fixture
def runtime(tmp_path, secrets_dir):
    return make(tmp_path, secrets_dir)


def request(server=REGION):
    return {'server': server, 'requested_at': now_iso(), 'request_id': '1' * 32}


def desire(applier, server=REGION):
    write_json_atomic(applier.desired_path, request(server))


# -- catalogue ---------------------------------------------------------------

def test_region_catalogue_keeps_only_validated_fields():
    found = relays.parse_catalog(serverlist(region()), 'pia')[REGION]
    assert found == {'hostname': REGION, 'country': 'EX', 'city': 'Example City', 'location_code': 'ex-ex_example',
                     'ipv4_addr_in': '198.51.100.21', 'port_forward': True, 'geo': False,
                     'servers': [{'ip': '198.51.100.20', 'cn': 'example401'}]}


def test_country_names_come_from_unprefixed_regions_and_known_prefixes():
    found = relays.parse_catalog(serverlist(
        region(id='ex_one', name='EX One'), region(id='exland', name='Exampleland'),
        region(id='uk_x', name='UK Example', country='GB'), region(id='us_x', name='US East', country='US')), 'pia')
    assert (found['ex_one']['country'], found['ex_one']['city']) == ('Exampleland', 'One')
    assert (found['exland']['country'], found['exland']['city']) == ('Exampleland', 'Exampleland')
    assert (found['uk_x']['country'], found['uk_x']['city']) == ('United Kingdom', 'Example')
    assert (found['us_x']['country'], found['us_x']['city']) == ('United States', 'East')


@pytest.mark.parametrize('changes', [
    {'offline': True}, {'offline': None}, {'id': '--evil'}, {'id': 'A'}, {'id': 'x' * 49},
    {'country': 'example'}, {'name': ''}, {'name': 'x\n'}, {'port_forward': 'yes'}, {'geo': None},
    {'servers': {'wg': []}}, {'servers': {'wg': [{'ip': '198.51.100.999', 'cn': 'example401'}]}},
    {'servers': {'wg': [{'ip': '198.51.100.20', 'cn': 'bad name'}]}},
    {'servers': {'wg': [{'ip': '198.51.100.20', 'cn': 'x'}] * 17}}, {'servers': []}])
def test_invalid_regions_are_dropped(changes):
    assert relays.parse_catalog(serverlist(region(**changes)), 'pia') == {}


def test_duplicate_region_rejected():
    with pytest.raises(ValueError):
        relays.parse_catalog(serverlist(region(), region()), 'pia')


def test_port_forward_only_catalogue():
    raw = serverlist(region(), region(id='ex_nopf', port_forward=False))
    assert set(relays.parse_catalog(raw, 'pia')) == {REGION, 'ex_nopf'}
    assert set(relays.parse_catalog(raw, 'pia', port_forward_only=True)) == {REGION}


def test_snapshot_of_another_provider_has_no_authority():
    pia_snapshot = {'fetched_at': now_iso(), 'provider': 'pia', 'relays': {REGION: entry()}}
    assert set(relays.snapshot_relays(pia_snapshot, 'pia')) == {REGION}
    assert relays.snapshot_relays(pia_snapshot, 'mullvad') == {}
    assert relays.snapshot_relays({**pia_snapshot, 'provider': 'mullvad'}, 'pia') == {}
    # Pre-provider snapshots are Mullvad catalogues.
    assert relays.snapshot_relays({k: v for k, v in pia_snapshot.items() if k != 'provider'}, 'pia') == {}


def test_request_names_are_provider_specific():
    assert desired_request(request(), 'pia')
    assert desired_request(request(), 'mullvad') is None
    assert desired_request(request('se-sto-wg-001'), 'mullvad')
    assert desired_request(request('Bad'), 'pia') is None


def test_status_uses_the_generic_confirmation():
    desired = request()
    result = {'checked_at': now_iso(), 'request_id': '1' * 32, 'status': 'ok', 'routing_ok': True}
    assert status_view(desired, {**result, 'exit_confirmed': True}, 'pia')[0] == 'ok'
    assert status_view(desired, {**result, 'exit_confirmed': False, 'mullvad_exit_ip': True}, 'pia')[0] == 'failed'


# -- secrets -----------------------------------------------------------------

def test_scratch_files_are_private_and_removed():
    with scratch('a', 'b') as paths:
        assert all(os.stat(p).st_mode & 0o777 == 0o600 for p in paths)
    assert not any(os.path.exists(p) for p in paths)


@pytest.mark.parametrize('content', [b'', b'\n', b'a\nb', b'a\x00', b'x' * 600])
def test_malformed_credentials_refused(tmp_path, content):
    (tmp_path / 'c').write_bytes(content)
    with pytest.raises(ValueError):
        read_secret(tmp_path / 'c')


def test_credentials_never_reach_argv_or_state(runtime, tmp_path):
    applier, kernel = runtime
    applier.switch(request())
    assert kernel.scratch_seen and not any(os.path.exists(p) for p in kernel.scratch_seen)
    for path in (tmp_path / 'applier').iterdir():
        text = path.read_text()
        assert PASSWORD not in text and TOKEN not in text and USERNAME not in text


# -- switching ---------------------------------------------------------------

def test_switch_registers_then_sets_address_rule_and_peer(runtime, tmp_path):
    applier, kernel = runtime
    result = applier.switch(request())
    assert result['status'] == 'ok' and result['server'] == REGION
    assert result['exit_confirmed'] is True and result['provider'] == 'pia' and 'mullvad_exit_ip' not in result
    assert kernel.keys == [SERVER_KEY] and kernel.addresses == ['10.0.0.2']
    assert [r['src'] for r in kernel.rules[4] if r['priority'] == 94] == ['10.0.0.2']
    assert not any(r['priority'] == 94 for r in kernel.rules[6])
    tunnel = read_json(tmp_path / 'applier' / 'tunnel.json')
    assert tunnel['region'] == REGION and tunnel['server_key'] == SERVER_KEY and tunnel['peer_ip'] == '10.0.0.2'
    order = [' '.join(c[:2]) if c[0] != 'ip' else ' '.join(c[1:4]) for c in kernel.calls]
    assert order.index('curl --noproxy') < order.index('-4 address replace') < order.index('wg set')


def test_switch_replaces_previous_server_and_address(runtime):
    applier, kernel = runtime
    applier.switch(request())
    kernel.addkey = {**kernel.addkey, 'server_key': OTHER_KEY, 'peer_ip': '10.0.0.3'}
    kernel.expected_rule_source = '10.0.0.3'
    assert applier.switch({**request(), 'request_id': '2' * 32})['status'] == 'ok'
    assert kernel.keys == [OTHER_KEY] and kernel.addresses == ['10.0.0.3']
    assert [r['src'] for r in kernel.rules[4] if r['priority'] == 94] == ['10.0.0.3']
    assert {'dst': 'default', 'dev': 'pia'} in kernel.routes[4]
    calls = [' '.join(c[1:5]) for c in kernel.calls if c[0] == 'ip' and c[3] in ('replace', 'del')]
    assert calls.index('-4 address replace 10.0.0.3/32') < calls.index('-4 address del 10.0.0.2/32')


@pytest.mark.parametrize('change', [
    {'status': 'ERROR'}, {'server_key': 'bad'}, {'server_port': '1337'}, {'server_port': True},
    {'server_port': 70000}, {'server_ip': '198.51.100.99'}, {'peer_ip': '203.0.113.5'},
    {'peer_ip': '192.0.2.5'}, {'server_vip': 'x'}, {'peer_pubkey': OTHER_KEY},
    {'peer_ip': '10.0.0.1'}, {'peer_ip': '10.89.0.7'}, {'server_vip': '10.89.0.1'}])
def test_bad_registration_changes_nothing(runtime, change):
    applier, kernel = runtime
    kernel.addkey = {**kernel.addkey, **change}
    result = applier.switch(request())
    assert result['status'] == 'failed' and kernel.mutations == []
    assert kernel.keys == [] and kernel.addresses == []


def test_json_refusal_also_drops_the_token(runtime):
    applier, kernel = runtime
    kernel.addkey = {**kernel.addkey, 'status': 'ERROR'}
    applier.switch(request())
    assert applier.token is None and kernel.mutations == []


def test_reregistration_never_leaves_the_address_without_a_return_path(runtime):
    applier, kernel = runtime
    applier.switch(request())
    applier.switch({**request(), 'request_id': '2' * 32})
    kernel.addkey = {**kernel.addkey, 'server_key': OTHER_KEY, 'peer_ip': '10.0.0.3'}
    kernel.expected_rule_source = '10.0.0.3'
    applier.switch({**request(), 'request_id': '3' * 32})
    assert kernel.return_path_gaps == 0
    assert [r['src'] for r in kernel.rules[4] if r['priority'] == 94] == ['10.0.0.3']
    # The same address again adds and removes no rule.
    before = len([c for c in kernel.calls if c[1:3] == ['-4', 'rule']])
    applier.switch({**request(), 'request_id': '4' * 32})
    assert len([c for c in kernel.calls if c[1:3] == ['-4', 'rule']]) == before


def test_refused_registration_drops_the_token(runtime):
    applier, kernel = runtime
    kernel.addkey_fail = True
    applier.switch(request())
    assert applier.token is None and kernel.mutations == []
    kernel.addkey_fail = False
    tokens = sum(1 for c in kernel.calls if c[-1] == pia_module.PIA_TOKEN_URL)
    applier.switch({**request(), 'request_id': '2' * 32})
    assert sum(1 for c in kernel.calls if c[-1] == pia_module.PIA_TOKEN_URL) == tokens + 1


def test_token_is_reused_until_it_ages(runtime):
    applier, kernel = runtime
    applier.switch(request())
    applier.switch({**request(), 'request_id': '2' * 32})
    assert sum(1 for c in kernel.calls if c[-1] == pia_module.PIA_TOKEN_URL) == 1
    kernel.now += pia_module.TOKEN_MAX_AGE_SEC
    applier.switch({**request(), 'request_id': '3' * 32})
    assert sum(1 for c in kernel.calls if c[-1] == pia_module.PIA_TOKEN_URL) == 2


def test_login_failure_changes_nothing(runtime):
    applier, kernel = runtime
    kernel.token_fail = True
    assert applier.switch(request())['status'] == 'failed' and kernel.mutations == []


def test_unlisted_region_refused(runtime):
    applier, kernel = runtime
    result = applier.switch(request('ex_other'))
    assert result['status'] == 'failed' and 'not in a fresh' in result['message']
    assert not any(c[0] == 'curl' and 'addKey' in c[-1] for c in kernel.calls)


def test_egress_must_be_confirmed_by_pia(runtime):
    applier, kernel = runtime
    kernel.connected = False
    result = applier.switch(request())
    assert result['status'] == 'failed' and result['exit_confirmed'] is False
    assert result['message'] == 'Switch verification timed out; choose a server again to retry.'
    applier.rejection = None
    assert applier.inspect()['message'] == 'Tunnel egress is not confirmed as PIA.'


def test_unregistered_exit_says_so(runtime):
    applier, _ = runtime
    result = applier.inspect()
    assert result['status'] == 'failed' and 'No PIA region' in result['message']


def test_saved_region_is_registered_after_tunnel_recreation(runtime):
    applier, kernel = runtime
    desire(applier)
    assert applier.tick()['status'] == 'ok'
    # The wireguard container was recreated: no peer, no address, no rule 94.
    kernel.keys, kernel.addresses = [], []
    kernel.rules[4] = rules(4)
    kernel.now += 1
    assert applier.tick()['status'] == 'ok' and kernel.keys == [SERVER_KEY]


def test_stale_handshake_reregisters_the_same_region_with_backoff(runtime):
    applier, kernel = runtime
    desire(applier)
    applier.tick()
    kernel.age = 10_000
    kernel.now += 30
    applier.next_health = 0
    assert applier.tick()['status'] == 'failed'
    registrations = sum(1 for c in kernel.calls if c[-1].endswith('/addKey'))
    kernel.now += 30
    applier.next_health = 0
    applier.tick()
    assert sum(1 for c in kernel.calls if c[-1].endswith('/addKey')) == registrations
    kernel.now += pia_module.REREGISTER_SEC
    applier.next_health = 0
    applier.tick()
    assert sum(1 for c in kernel.calls if c[-1].endswith('/addKey')) == registrations + 1
    assert {c[4] for c in kernel.calls if c[:2] == ['wg', 'set'] and c[-1] != 'remove'} == {SERVER_KEY}


def test_failed_registration_on_a_fresh_tunnel_is_retried_with_backoff(runtime):
    # A recreated tunnel has no peer and no address; PIA's API was down for the
    # first registration. Once it answers, the applier registers on its own.
    applier, kernel = runtime
    desire(applier)
    kernel.keys, kernel.addresses = [], []
    kernel.rules[4] = rules(4)
    kernel.token_fail = True
    result = applier.tick()
    assert result['status'] == 'failed' and result['message'].startswith('Peer update failed')
    kernel.token_fail = False
    kernel.now += 30
    applier.next_health = 0
    applier.tick()
    assert kernel.keys == []
    kernel.now += pia_module.REREGISTER_SEC
    applier.next_health = 0
    assert applier.tick()['status'] == 'ok' and kernel.keys == [SERVER_KEY]


def test_container_healthcheck_needs_a_registered_tunnel(runtime):
    applier, kernel = runtime
    assert applier.routing_status() == (False, False)
    assert applier.routing_status(require_address=False)[0] is True
    applier.switch(request())
    assert applier.routing_status()[0] is True


# -- configuration -----------------------------------------------------------

@pytest.mark.parametrize('env', [
    {'PIA_PORT_FORWARD': 'on'}, {'PIA_PORT_FORWARD': 'on', 'PIA_PORT_FORWARD_TARGET': '203.0.113.1'},
    {'PIA_PORT_FORWARD': 'maybe'}, {'PIA_PORT_FORWARD_TARGET': '192.0.2.10'}])
def test_port_forward_configuration_refused(tmp_path, env):
    with pytest.raises(ValueError):
        PiaApplier.from_env(tmp_path, CONFIG, env)


def test_port_forward_configuration_accepted(tmp_path):
    applier = PiaApplier.from_env(tmp_path, CONFIG, {'PIA_PORT_FORWARD': 'on', 'PIA_PORT_FORWARD_TARGET': '192.0.2.10'})
    assert applier.port_forward and applier.forward_target == '192.0.2.10'
    assert not PiaApplier.from_env(tmp_path, CONFIG, {}).port_forward


# -- port forwarding ---------------------------------------------------------

@pytest.fixture
def forwarding(tmp_path, secrets_dir):
    return make(tmp_path, secrets_dir, port_forward=True, forward_target='192.0.2.10')


def test_port_forward_binds_and_points_at_the_target(forwarding):
    applier, kernel = forwarding
    desire(applier)
    applier.tick()
    assert applier.forward['port'] == 43210 and applier.forward['bound']
    rules_text = kernel.nft[-1]
    assert 'iifname "pia" meta l4proto { tcp, udp } th dport 43210 dnat to 192.0.2.10' in rules_text
    assert 'oifname "wt0" ct status dnat ip daddr 192.0.2.10 masquerade' in rules_text
    assert 'drop' not in rules_text
    assert applier.inspect()['forwarded_port'] == 43210


def test_port_forward_rebinds_on_schedule_without_new_signature(forwarding):
    applier, kernel = forwarding
    desire(applier)
    applier.tick()
    loads = len(kernel.nft)
    kernel.now += pia_module.BIND_INTERVAL_SEC
    applier.next_health = 0
    applier.tick()
    urls = [c[-1] for c in kernel.calls if c[0] == 'curl']
    assert urls.count('https://example401:19999/getSignature') == 1
    assert urls.count('https://example401:19999/bindPort') == 2
    assert len(kernel.nft) == loads


def test_port_forward_failure_clears_the_port_and_rules(forwarding):
    applier, kernel = forwarding
    desire(applier)
    applier.tick()
    kernel.bind_fail = True
    kernel.now += pia_module.BIND_INTERVAL_SEC
    applier.next_health = 0
    applier.tick()
    assert applier.forward is None and applier.forward_error
    assert 'dnat' not in kernel.nft[-1]
    result = applier.inspect()
    assert result['forwarded_port'] is None and result['port_forward_error']


def test_switch_drops_the_old_port(forwarding):
    applier, kernel = forwarding
    desire(applier)
    applier.tick()
    kernel.addkey = {**kernel.addkey, 'server_key': OTHER_KEY}
    kernel.port = 45678
    write_json_atomic(applier.desired_path, {**request(), 'request_id': '2' * 32})
    kernel.now += 1
    applier.tick()
    assert applier.forward['port'] == 45678 and applier.forward['server_key'] == OTHER_KEY
    assert 'th dport 45678' in kernel.nft[-1]


GUARD = 'type filter hook forward priority filter; policy accept;\n    iifname "pia" oifname != "wt0" drop'
REMOVE_FORWARD = 'table ip molebridge_forward\ndelete table ip molebridge_forward\n'


def test_ingress_guard_and_leftover_cleanup_run_once_even_with_forwarding_off(runtime):
    applier, kernel = runtime
    applier.tick()
    assert GUARD in kernel.nft[0] and kernel.nft[0].startswith('table inet molebridge_guard\n')
    assert kernel.nft[1] == REMOVE_FORWARD
    loads = len(kernel.nft)
    applier.tick()
    assert len(kernel.nft) == loads
    # Removing forwarding rules never removes the guard.
    assert not any('delete table inet molebridge_guard\n' == text for text in kernel.nft)


def test_failed_guard_or_cleanup_is_retried(runtime, monkeypatch):
    applier, kernel = runtime
    real = kernel.run
    failures = {'nft': 2}

    def flaky(args, **kwargs):
        if args[0] == 'nft' and failures['nft']:
            failures['nft'] -= 1
            kernel.calls.append(args)
            raise RuntimeError('command failed')
        return real(args, **kwargs)
    applier.run = flaky
    applier.tick()
    assert not applier.guard_installed and not applier.forward_reconciled
    applier.tick()
    assert applier.guard_installed and applier.forward_reconciled
    assert any(GUARD in text for text in kernel.nft) and REMOVE_FORWARD in kernel.nft


def test_no_forwarding_until_guard_and_cleanup_succeed(forwarding):
    applier, kernel = forwarding
    real = kernel.run

    def no_nft(args, **kwargs):
        if args[0] == 'nft':
            kernel.calls.append(args)
            raise RuntimeError('command failed')
        return real(args, **kwargs)
    applier.run = no_nft
    desire(applier)
    applier.tick()
    assert applier.forward is None and 'guard' in applier.forward_error
    assert not any(c[-1].endswith(('/getSignature', '/bindPort')) for c in kernel.calls)
    applier.run = real
    kernel.now += 1
    applier.tick()
    assert applier.forward['bound'] and 'dnat' in kernel.nft[-1]
    # The cleanup already ran, so the next tick keeps the new rules.
    loads = len(kernel.nft)
    kernel.now += 1
    applier.tick()
    assert len(kernel.nft) == loads


def test_interrupted_switch_is_repaired_before_the_next_one(runtime):
    applier, kernel = runtime
    applier.switch(request())
    # A switch died after adding the next address and its rule.
    kernel.addresses.append('10.0.0.9')
    kernel.rules[4] = sorted(kernel.rules[4] + [{'priority': 94, 'src': '10.0.0.9', 'ipproto': 'icmp',
                                                'table': 51821},
                                               {'priority': 98, 'src': '10.0.0.9', 'ipproto': 'icmp',
                                                'action': 'unreachable'}], key=lambda r: r['priority'])
    assert applier.routing_status(require_address=False)[0] is False
    result = applier.switch({**request(), 'request_id': '2' * 32})
    assert result['status'] == 'ok' and kernel.addresses == ['10.0.0.2']
    assert [r['src'] for r in kernel.rules[4] if r['priority'] == 94] == ['10.0.0.2']
    assert [r['src'] for r in kernel.rules[4] if r['priority'] == 98] == ['10.0.0.2']
    assert kernel.return_path_gaps == 0


def test_non_forwarding_region_is_not_selectable(tmp_path, secrets_dir):
    applier, _ = make(tmp_path, secrets_dir, port_forward=True, forward_target='192.0.2.10')
    assert applier.catalog.refresh(lambda: serverlist(region(), region(id='ex_nopf', port_forward=False)))
    assert set(applier.catalog.relays) == {REGION}


# -- tools and routing -------------------------------------------------------

def load_prepare():
    spec = importlib.util.spec_from_file_location('prepare', ROOT / 'tools' / 'prepare-tunnel-config.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pia_tunnel_config_has_key_but_no_address_or_peer(tmp_path):
    prepare = load_prepare()
    output = tmp_path / 'pia.conf'
    assert prepare.main(['prepare', '--pia', str(output)]) == 0
    text = output.read_text()
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert 'PrivateKey = ' in text and 'Address' not in text and '[Peer]' not in text
    assert 'ip -6' not in text and 'Table = off' in text
    key = base64.b64decode(text.split('PrivateKey = ')[1].split('\n')[0])
    assert len(key) == 32 and key[0] & 7 == 0 and key[31] & 0xC0 == 0x40
    assert prepare.main(['prepare', '--pia', str(output)]) == 1
    assert output.read_text() == text


def test_routing_init_accepts_an_address_less_pia_tunnel():
    script = (ROOT / 'routing' / '10-exit-routing').read_text()
    assert 'pia) [ -z "$tunnel6" ]' in script
    assert 'mullvad) [ -n "$tunnel4" ] || fail' in script


def test_compose_passes_the_provider_everywhere():
    yaml = pytest.importorskip('yaml')
    compose = yaml.safe_load((ROOT / 'compose.yaml').read_text())
    for service in ('wireguard', 'applier', 'control-panel'):
        assert compose['services'][service]['environment']['PROVIDER'] == '${PROVIDER:-mullvad}'
    override = yaml.safe_load((ROOT / 'compose.pia.yaml').read_text())
    assert override['services'] == {'applier': {'environment': {'SERVER': '${SERVER:-}'},
                                               'volumes': ['./secrets/pia:/run/secrets/pia:ro']}}


# -- egress check retry --------------------------------------------------------

def pia_status(args):
    return args[0] == 'curl' and args[-1] == pia_module.PIA_STATUS_URL


def test_an_unanswered_pia_status_call_is_asked_once_more(runtime):
    applier, kernel = runtime
    assert applier.switch(request())['status'] == 'ok'
    calls = unanswered(applier, kernel, pia_status)
    start = kernel.now
    result = applier.inspect()
    assert result['status'] == 'ok' and result['exit_confirmed'] is True
    assert len(calls) == 2 and kernel.now - start == 10 + EGRESS_RETRY_SEC


def test_a_pia_status_call_unanswered_twice_fails(runtime):
    applier, kernel = runtime
    assert applier.switch(request())['status'] == 'ok'
    calls = unanswered(applier, kernel, pia_status, times=2)
    result = applier.inspect()
    assert result['status'] == 'failed' and result['message'] == 'Tunnel inspection or egress check failed.'
    assert len(calls) == 2


def test_pia_saying_not_connected_is_never_asked_again(runtime):
    applier, kernel = runtime
    assert applier.switch(request())['status'] == 'ok'
    kernel.connected = False
    calls = unanswered(applier, kernel, pia_status, times=0)
    start = kernel.now
    assert applier.inspect()['message'] == 'Tunnel egress is not confirmed as PIA.'
    assert len(calls) == 1 and kernel.now == start


def test_a_failed_reregistration_clears_once_the_tunnel_recovers_by_itself(runtime):
    """The tunnel stalls, the automatic re-registration is refused, then the
    old registration's tunnel comes back: the exit reports healthy again
    without anyone choosing the region again."""
    applier, kernel = runtime
    desire(applier)
    assert applier.tick()['status'] == 'ok'
    kernel.age, kernel.addkey_fail = 10_000, True
    kernel.now += pia_module.REREGISTER_SEC
    applier.next_health = 0
    result = applier.tick()
    assert result['status'] == 'failed' and result['message'].startswith('Peer update failed')
    registrations = sum(1 for c in kernel.calls if c[-1].endswith('/addKey'))
    kernel.age = 1
    kernel.now += 60
    applier.next_health = 0
    result = applier.tick()
    assert result['status'] == 'ok' and result['server'] == REGION and applier.rejection is None
    assert sum(1 for c in kernel.calls if c[-1].endswith('/addKey')) == registrations


# -- rules 94 and 98: the applier owns both for PIA's per-server address -------

def pair(kernel, priority):
    return sorted(r['src'] for r in kernel.rules[4] if r['priority'] == priority)


def test_switch_installs_and_confirms_both_rules_before_the_address(runtime):
    applier, kernel = runtime
    applier.switch(request())
    kernel.calls.clear()
    kernel.addkey = {**kernel.addkey, 'server_key': OTHER_KEY, 'peer_ip': '10.0.0.3'}
    kernel.expected_rule_source = '10.0.0.3'
    assert applier.switch({**request(), 'request_id': '2' * 32})['status'] == 'ok'
    steps = [' '.join(c[1:6]) for c in kernel.calls if c[0] == 'ip' and c[3] in ('add', 'del', 'replace')]
    add94 = steps.index('-4 rule add from 10.0.0.3')
    add98 = steps.index('-4 rule add from 10.0.0.3', add94 + 1)
    address = steps.index('-4 address replace 10.0.0.3/32 dev')
    old = steps.index('-4 address del 10.0.0.2/32 dev')
    del94 = steps.index('-4 rule del priority 94')
    del98 = steps.index('-4 rule del priority 98')
    assert add94 < add98 < address < old < del94 < del98
    assert pair(kernel, 94) == pair(kernel, 98) == ['10.0.0.3']
    assert kernel.return_path_gaps == 0 and kernel.both_missing == 0


STEPS = ['rule add from 10.0.0.3 ipproto icmp lookup', 'rule add from 10.0.0.3 ipproto icmp unreachable',
         'address replace 10.0.0.3/32', 'address del 10.0.0.2/32', 'route replace default',
         'rule del priority 94 from 10.0.0.2', 'rule del priority 98 from 10.0.0.2']


@pytest.mark.parametrize('step', STEPS)
def test_an_interrupted_switch_never_leaves_an_address_unprotected(runtime, step):
    applier, kernel = runtime
    applier.switch(request())
    kernel.addkey = {**kernel.addkey, 'server_key': OTHER_KEY, 'peer_ip': '10.0.0.3'}
    kernel.expected_rule_source = '10.0.0.3'
    kernel.fail_when = lambda args: ' '.join(args[2:]).startswith(step)
    applier.switch({**request(), 'request_id': '2' * 32})
    assert kernel.fail_when is None, 'the step was never reached'
    assert kernel.return_path_gaps == 0 and kernel.both_missing == 0
    # The next pass (every tick) repairs whatever the interruption left.
    kernel.expected_rule_source = kernel.addresses[0] if len(kernel.addresses) == 1 else '10.0.0.2'
    applier.reconcile_tunnel()
    assert len(kernel.addresses) == 1
    assert pair(kernel, 94) == pair(kernel, 98) == kernel.addresses
    assert kernel.return_path_gaps == 0 and kernel.both_missing == 0


def test_every_tick_restores_a_deleted_backstop(runtime):
    applier, kernel = runtime
    applier.switch(request())
    kernel.rules[4] = [r for r in kernel.rules[4] if r['priority'] != 98]
    assert applier.routing_status()[0] is False
    applier.tick()
    assert pair(kernel, 98) == ['10.0.0.2']
    assert applier.routing_status()[0] is True


def test_an_orphaned_backstop_is_removed(runtime):
    applier, kernel = runtime
    applier.switch(request())
    # An earlier switch died between removing the old 94 and the old 98.
    kernel.rules[4].append({'priority': 98, 'src': '10.0.0.9', 'ipproto': 'icmp', 'action': 'unreachable'})
    applier.reconcile_tunnel()
    assert pair(kernel, 94) == pair(kernel, 98) == ['10.0.0.2']


@pytest.mark.parametrize('priority,bad', [
    (94, {'priority': 94, 'src': '10.0.0.2', 'ipproto': 'icmp', 'table': 'main'}),
    (94, {'priority': 94, 'src': '10.0.0.2', 'table': 51821}),
    (98, {'priority': 98, 'src': '10.0.0.2', 'ipproto': 'icmp', 'table': 51821}),
    (98, {'priority': 98, 'src': '10.0.0.2', 'ipproto': 'icmp', 'action': 'unreachable', 'iif': 'wt0'}),
])
def test_a_rule_not_in_its_exact_form_is_replaced_and_its_partner_holds(runtime, priority, bad):
    applier, kernel = runtime
    applier.switch(request())
    kernel.rules[4] = [r for r in kernel.rules[4] if r['priority'] != priority] + [bad]
    applier.reconcile_tunnel()
    exact = [r for r in kernel.rules[4] if r['priority'] == priority]
    assert len(exact) == 1 and applier.return_path_exact(exact[0], priority, '10.0.0.2')
    assert kernel.both_missing == 0

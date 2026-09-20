"""Fault injection without touching a live tunnel, account or host routes."""
import copy
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from applier.apply import Applier, command
from molebridge import relays
from molebridge.routing import RoutingConfig, family_status
from molebridge.state import (decode_json, desired_request, now_iso, read_json,
                              request_token, status_view, write_json_atomic)

KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
HOST = 'se-sto-wg-001'
CONFIG = RoutingConfig('192.0.2.0/24', '2001:db8:1::/64')
ENTRY = {'hostname': HOST, 'public_key': KEY, 'ipv4_addr_in': '198.51.100.10',
         'city': 'Example City', 'country': 'Example', 'location_code': 'se-sto'}


def timestamp(seconds_ago):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).strftime('%Y-%m-%dT%H:%M:%SZ')


def request(**changes):
    return {'server': HOST, 'requested_at': now_iso(), 'request_id': '0' * 32, **changes}


def payload(**changes):
    relay = {**ENTRY, 'active': True, 'location': 'se-sto', **changes}
    return {'locations': {'se-sto': {'city': 'Example City', 'country': 'Example'}},
            'wireguard': {'relays': [relay]}}


def rules(family):
    destination, prefix = (CONFIG.overlay if family == 4 else CONFIG.overlay6).split('/')
    return [{'priority': 0, 'src': 'all', 'table': 'local'},
            {'priority': 90, 'src': 'all', 'iif': 'mullvad', 'dst': destination, 'dstlen': int(prefix), 'table': 'main'},
            {'priority': 95, 'src': 'all', 'iif': 'wt0', 'table': 51821},
            {'priority': 96, 'src': 'all', 'oif': 'mullvad', 'table': 51821},
            {'priority': 97, 'src': 'all', 'iif': 'wt0', 'action': 'unreachable'},
            {'priority': 105, 'src': 'all', 'table': 7120}]


def routes():
    return [{'dst': 'default', 'dev': 'mullvad'},
            {'type': 'unreachable', 'dst': 'default', 'metric': 4096}]


class Kernel:
    def __init__(self):
        self.calls = []
        self.rules = {4: rules(4), 6: rules(6)}
        self.routes = {4: routes(), 6: routes()}
        self.keys = [KEY]
        self.now = 0
        self.egress_ok = True
        self.fail_set = False
        self.age = 1
        self.probe = {'ip': '203.0.113.10', 'city': 'Example City', 'country': 'Example', 'mullvad_exit_ip': True}

    def sleep(self, seconds):
        self.now += seconds

    def run(self, args, **kwargs):
        self.calls.append(args)
        if args[0] == 'ip':
            family = int(args[2][1:])
            return json.dumps(self.rules[family] if args[3] == 'rule' else self.routes[family])
        if args[:2] == ['wg', 'show']:
            if args[-1] == 'peers':
                return '\n'.join(self.keys)
            return '\n'.join(f'{key}\t{int(time.time()) - self.age}' for key in self.keys)
        if args[:2] == ['wg', 'set']:
            if self.fail_set:
                raise RuntimeError('injected command failure')
            if args[-1] == 'remove':
                self.keys.remove(args[4])
            else:
                self.keys = [args[4]]
            return ''
        if args[0] == 'curl':
            if not self.egress_ok:
                raise RuntimeError('injected probe failure')
            assert '--interface' in args and args[args.index('--interface') + 1] == 'mullvad'
            return json.dumps(self.probe)
        raise AssertionError('unexpected command')

    @property
    def mutations(self):
        return [c for c in self.calls if c[:2] == ['wg', 'set']]


@pytest.fixture
def runtime(tmp_path):
    write_json_atomic(tmp_path / 'applier' / 'relays.json', {'fetched_at': now_iso(), 'relays': {HOST: ENTRY}})
    kernel = Kernel()
    applier = Applier(tmp_path, CONFIG, run=kernel.run, clock=lambda: kernel.now, sleep=kernel.sleep)
    applier.next_catalog = float('inf')
    return applier, kernel


@pytest.mark.parametrize('changes', [{'active': False}, {'hostname': '--evil'}, {'public_key': 'bad'},
                                   {'public_key': KEY + '\n'}, {'ipv4_addr_in': '198.51.100.999'},
                                   {'location': []}, {'location': 'absent'}, {'hostname': HOST + '\n'}])
def test_remote_relay_validation(changes):
    assert relays.parse_relay_response(payload(**changes)) == {}


def test_valid_relay_and_escaped_location():
    data = payload()
    data['locations']['se-sto']['city'] = '<script>not trusted</script>'
    result = relays.parse_relay_response(data)
    assert result[HOST]['city'] == '<script>not trusted</script>'


@pytest.mark.parametrize('bad', [None, [], {}, {'locations': {}, 'wireguard': []}])
def test_bad_relay_schema(bad):
    with pytest.raises(ValueError):
        relays.parse_relay_response(bad)


def test_duplicate_relays_rejected():
    data = payload()
    data['wireguard']['relays'] *= 2
    with pytest.raises(ValueError):
        relays.parse_relay_response(data)


@pytest.mark.parametrize('response', [b'not json', b'{}', b'{"locations":{},"wireguard":{"relays":[]}}'])
def test_failed_refresh_preserves_last_good_catalogue(runtime, response):
    app, _ = runtime
    before = app.catalog.path.read_bytes()
    assert not app.catalog.refresh(lambda: response)
    assert app.catalog.path.read_bytes() == before
    assert read_json(app.catalog.error_path)['message']


def test_refresh_recovery(runtime):
    app, _ = runtime
    assert app.catalog.refresh(lambda: json.dumps(payload()).encode())
    assert app.catalog.usable()
    assert read_json(app.catalog.error_path) == {}


def test_panel_owned_catalogue_cannot_authorize_endpoint(tmp_path):
    write_json_atomic(tmp_path / 'panel' / 'relays.json', {'fetched_at': now_iso(), 'relays': {HOST: ENTRY}})
    kernel = Kernel()
    app = Applier(tmp_path, CONFIG, run=kernel.run)
    assert app.switch(request())['status'] == 'failed'
    assert kernel.mutations == []


@pytest.mark.parametrize('change', [{'server': '--flag'}, {'server': HOST + '\n'}, {'server': []},
                                  {'request_id': 2}, {'requested_at': 'bad'}, {'endpoint': '198.51.100.1'}])
def test_untrusted_request_cannot_mutate(runtime, change):
    app, kernel = runtime
    assert app.switch(request(**change))['status'] == 'failed'
    assert not kernel.mutations


def test_stale_catalogue_refuses_switch(runtime):
    app, kernel = runtime
    app.catalog.snapshot['fetched_at'] = timestamp(86401)
    assert app.switch(request())['status'] == 'failed'
    assert not kernel.mutations


def test_switch_and_observed_initial_peer(runtime):
    app, kernel = runtime
    assert app.inspect()['server'] == HOST
    result = app.switch(request())
    assert result['status'] == 'ok' and result['routing_ok']
    assert result['request_id'] == '0' * 32
    assert len(kernel.mutations) == 1
    assert all('dump' not in c and 'private-key' not in c and 'showconf' not in c for c in kernel.calls)


@pytest.mark.parametrize('family', [4, 6])
@pytest.mark.parametrize('priority', [90, 95, 96, 97])
def test_missing_rule_prevents_success_and_switch(runtime, family, priority):
    app, kernel = runtime
    kernel.rules[family] = [r for r in kernel.rules[family] if r['priority'] != priority]
    assert app.switch(request())['status'] == 'failed'
    assert not kernel.mutations


def test_missing_fallback_prevents_switch_success(runtime):
    app, kernel = runtime
    kernel.routes[6] = kernel.routes[6][:1]
    result = app.switch(request())
    assert result['status'] == 'failed' and not result['unreachable_fallback']
    assert not kernel.mutations


@pytest.mark.parametrize('extra', [{'fwmark': '0x1'}, {'src': '192.0.2.5'}, {'not': True}, {'suppress_prefixlen': 0}])
def test_narrowed_or_inverted_rule_is_not_healthy(extra):
    table = rules(4)
    table[2].update(extra)
    assert not family_status(table, routes(), CONFIG, 4)[0]


def test_earlier_rule_and_unsafe_table_route_rejected():
    assert not family_status([{'priority': 50, 'table': 'main'}, *rules(4)], routes(), CONFIG, 4)[0]
    assert not family_status(rules(4), [*routes(), {'dst': '192.0.2.0/24', 'dev': 'eth0'}], CONFIG, 4)[0]


@pytest.mark.parametrize('family', [4, 6])
def test_iproute2_separate_destination_prefix_and_cidr(family):
    table = rules(family)
    assert family_status(table, routes(), CONFIG, family) == (True, True)
    table[1]['dst'] += '/' + str(table[1].pop('dstlen'))
    assert family_status(table, routes(), CONFIG, family) == (True, True)


@pytest.mark.parametrize('prefix', [0, 23, 25, None, '24', True, [], 129])
def test_wrong_or_malformed_rule_prefix_rejected(prefix):
    table = rules(4)
    table[1]['dstlen'] = prefix
    assert not family_status(table, routes(), CONFIG, 4)[0]


def test_host_rule_prefix_omits_dstlen():
    table = rules(4)
    del table[1]['dstlen']
    config = RoutingConfig('192.0.2.0/32')
    assert family_status(table, routes(), config, 4) == (True, True)


def test_switch_timeout_does_not_repeat_or_failover(runtime):
    app, kernel = runtime
    kernel.egress_ok = False
    write_json_atomic(app.desired_path, request())
    result = app.tick()
    assert result['status'] == 'failed'
    assert kernel.now >= 60 and len(kernel.mutations) == 1
    app.tick()
    assert len(kernel.mutations) == 1
    kernel.egress_ok = True
    write_json_atomic(app.desired_path, request(request_id='1' * 32))
    assert app.tick()['status'] == 'ok'
    assert len(kernel.mutations) == 2


def test_peer_update_failure_not_hidden(runtime):
    app, kernel = runtime
    kernel.fail_set = True
    result = app.switch(request())
    assert result['status'] == 'failed'
    assert 'update failed' in result['message']


@pytest.mark.parametrize('value', ['true', 1, None, {}])
def test_egress_boolean_must_be_boolean(runtime, value):
    app, kernel = runtime
    kernel.probe['mullvad_exit_ip'] = value
    assert app.inspect()['status'] == 'failed'


def test_clock_in_future_is_not_fresh_handshake(runtime):
    app, kernel = runtime
    kernel.age = -60
    assert app.inspect()['status'] == 'failed'


def test_catalogue_fetch_is_bounded_and_does_not_follow_redirect(runtime):
    app, _ = runtime
    calls = []
    def response(args, **kwargs):
        calls.append((args, kwargs))
        return json.dumps(payload()) + '\n200'
    app.run = response
    assert relays.parse_relay_response(decode_json(app.fetch_catalog()))[HOST]['public_key'] == KEY
    args, limits = calls[0]
    assert '--max-time' in args and '--max-filesize' in args and '--noproxy' in args
    assert '-L' not in args and limits['timeout'] == 22
    app.run = lambda *a, **kw: '{}\n302'
    with pytest.raises(ValueError, match='redirects refused'):
        app.fetch_catalog()


def test_truncated_or_malformed_desired_json_is_reported_without_mutation(runtime):
    app, kernel = runtime
    app.desired_path.parent.mkdir(parents=True, exist_ok=True)
    app.desired_path.write_text('{"server":')
    result = app.tick()
    assert result['status'] == 'failed'
    assert 'Invalid desired-state' in result['message']
    assert not kernel.mutations


def test_failure_removing_old_peer_aborts_before_addition(runtime):
    app, kernel = runtime
    # A symbolic old peer isolates the removal-error branch; no real key is used.
    app.peers = lambda: ['old-peer']
    kernel.fail_set = True
    result = app.switch(request())
    assert result['status'] == 'failed'
    assert len(kernel.mutations) == 1 and kernel.mutations[0][-1] == 'remove'


def test_duplicate_json_and_special_files_rejected(tmp_path):
    path = tmp_path / 'request.json'
    path.write_text('{"server":"a","server":"b"}')
    assert read_json(path) is None
    path.write_bytes(b'x' * 4097)
    assert read_json(path, 4096) is None
    assert read_json(tmp_path) is None
    with pytest.raises(ValueError):
        decode_json('{"value":NaN}')


@pytest.mark.skipif(os.name != 'posix', reason='POSIX symlinks/FIFOs')
def test_symlink_and_fifo_requests_never_followed_or_block(tmp_path):
    original = tmp_path / 'original'
    write_json_atomic(original, request())
    link = tmp_path / 'link'; link.symlink_to(original)
    fifo = tmp_path / 'fifo'; os.mkfifo(fifo)
    assert read_json(link) is None
    assert read_json(fifo) is None


@pytest.mark.parametrize('when', [timestamp(151), timestamp(-60), 'broken', None])
def test_status_never_trusts_old_invalid_or_future_checks(when):
    result = {'status': 'ok', 'checked_at': when, 'routing_ok': True, 'mullvad_exit_ip': True}
    assert status_view(None, result)[0] == 'unknown'


def test_status_requires_routing_and_request_ack():
    req = request()
    result = {'status': 'ok', 'checked_at': now_iso(), 'routing_ok': False, 'mullvad_exit_ip': True,
              'request_id': request_token(req)}
    assert status_view(req, result)[0] == 'failed'
    result['routing_ok'] = True
    assert status_view(req, result)[0] == 'ok'
    assert status_view(request(request_id='1' * 32), result)[0] == 'applying'
    assert status_view(request(request_id='1' * 32, requested_at=timestamp(151)), result)[0] == 'unknown'


@pytest.mark.parametrize('env', [{'EXIT_TABLE': '254'}, {'EXIT_TABLE': '0'}, {'EXIT_TABLE': '0256'},
                                {'OVERLAY_CIDR': '0.0.0.0/0'}, {'OVERLAY_IF': 'mullvad'},
                                {'OVERLAY_IF': '../bad'}, {'OVERLAY6_CIDR': '::/0'}])
def test_unsafe_configuration_is_refused(env):
    with pytest.raises(ValueError):
        RoutingConfig.from_env({'OVERLAY_CIDR': '192.0.2.0/24', **env})


def test_command_timeout_and_error_do_not_echo_sensitive_output():
    with pytest.raises(RuntimeError, match='timed out'):
        command([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.05)
    with pytest.raises(RuntimeError, match='command failed') as error:
        command([sys.executable, '-c', 'print("synthetic-sensitive-output"); raise SystemExit(1)'])
    assert 'synthetic-sensitive-output' not in str(error.value)

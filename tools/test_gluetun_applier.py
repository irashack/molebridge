"""The gluetun backend's applier against a fake kernel, a fake gluetun control
server and a gluetun server list in a temporary directory. Nothing here
contacts gluetun, a provider or a tunnel."""
import functools
import http.client
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_runtime import unanswered
from applier import gluetun_applier
from applier.apply import EGRESS_RETRY_SEC
from molebridge.egress import ECHO_URLS
from applier.gluetun_applier import (CATALOG_REREAD_SEC, GLUETUN_SWITCH_TIMEOUT_SEC, GluetunApplier, GluetunCatalog,
                                     marked_echo)
from molebridge import gluetun_catalog, providers, relays
from molebridge.routing import RoutingConfig
from molebridge.state import now_iso, read_json, status_view, write_json_atomic

CONFIG = RoutingConfig.from_env({'TUNNEL_BACKEND': 'gluetun', 'OVERLAY_CIDR': '192.0.2.0/24',
                                 'OVERLAY6_CIDR': '2001:db8:1::/64', 'EXIT_IF': 'wg0'})
KEY_A = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
KEY_B = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE='
HOST_A, HOST_B, HOST_C = 'one.example.test', 'two.example.test', 'three.example.test'
ENDPOINT = {HOST_A: '198.51.100.11', HOST_B: '198.51.100.22', HOST_C: '198.51.100.33'}
TUNNEL4 = '10.64.0.2'
EXIT4 = '203.0.113.50'
HOST4 = '198.51.100.200'


def servers_json(provider, *, timestamp=None, hosts=(HOST_A, HOST_B, HOST_C)):
    servers = [{'vpn': 'wireguard', 'country': 'Exampleland', 'city': f'City {i}', 'hostname': host,
                'wgpubkey': KEY_A if host != HOST_B else KEY_B, 'ips': [ENDPOINT[host]]}
               for i, host in enumerate(hosts)]
    if provider == 'nordvpn':
        for server in servers:
            server['categories'] = ['Standard VPN servers', 'P2P']
        servers.append({'vpn': 'wireguard', 'country': 'Exampleland', 'city': 'City 9',
                        'hostname': 'dedicated.example.test', 'categories': ['Dedicated IP'],
                        'wgpubkey': KEY_A, 'ips': ['198.51.100.99']})
    block = {'version': 1, 'timestamp': int(time.time()) - 3600 if timestamp is None else timestamp,
             'servers': servers}
    return json.dumps({'version': 1, provider: block})


def rules(family):
    overlay, length = ('192.0.2.0', 24) if family == 4 else ('2001:db8:1::', 64)
    table = [{'priority': 1, 'not': None, 'src': 'all', 'iif': 'wt0', 'table': 'local'},
             {'priority': 88, 'src': 'all', 'fwmark': '0x1bd00', 'iif': 'lo', 'table': '51822'},
             {'priority': 89, 'src': 'all', 'fwmark': '0x1bd00', 'iif': 'lo', 'action': 'unreachable'},
             {'priority': 90, 'src': 'all', 'dst': overlay, 'dstlen': length, 'iif': 'wg0', 'table': 'main'},
             {'priority': 91, 'src': 'all', 'dst': overlay, 'dstlen': length, 'iif': 'lo', 'table': 'main',
              'suppress_prefixlen': 0},
             {'priority': 92, 'src': 'all', 'dst': overlay, 'dstlen': length, 'iif': 'lo', 'action': 'unreachable'},
             {'priority': 95, 'src': 'all', 'iif': 'wt0', 'table': '51821'},
             {'priority': 96, 'src': 'all', 'oif': 'wg0', 'table': '51821'},
             {'priority': 97, 'src': 'all', 'iif': 'wt0', 'action': 'unreachable'},
             {'priority': 101, 'not': None, 'src': 'all', 'fwmark': '0xca6c', 'table': '51820'},
             {'priority': 102, 'src': 'all', 'fwmark': '0xca6c', 'iif': 'lo', 'table': 'main'},
             {'priority': 103, 'src': 'all', 'iif': 'lo', 'table': '51822', 'suppress_prefixlen': 0},
             {'priority': 104, 'src': 'all', 'iif': 'lo', 'action': 'unreachable'}]
    if family == 4:
        table.insert(6, {'priority': 94, 'src': TUNNEL4, 'ipproto': 'icmp', 'table': '51821'})
    return table


HOST_ROUTES = {4: [{'dst': '198.51.100.0/28', 'dev': 'eth0'},
                   {'dst': 'default', 'gateway': '198.51.100.2', 'dev': 'eth0'}],
               6: []}


class FakeGluetun:
    """gluetun's control server and the tunnel it manages: a PUT restarts the
    tunnel, which is gone for `restart_ticks` kernel reads, then comes back
    with the selected server's peer."""

    def __init__(self, kernel):
        self.kernel = kernel
        self.puts = []
        self.fail = False
        self.restart_ticks = 2
        self.connect_to = None  # override the server gluetun ends up on

    def select_server(self, relay):
        if self.fail:
            raise RuntimeError('gluetun control request failed')
        self.puts.append(relay['hostname'])
        self.kernel.tunnel = None
        self.kernel.pending = (self.restart_ticks, self.connect_to or relay['hostname'])
        return 'settings updated'

    def vpn_status(self):
        return self.status

    status = 'running'
    updates = 0
    updater = 'stopped'
    update_fails = False

    def start_update(self):
        if self.update_fails:
            raise RuntimeError('gluetun control request failed')
        self.updates += 1
        self.updater = 'running'
        return 'running'

    def updater_status(self):
        return self.updater


class Kernel:
    def __init__(self, catalog_hosts=(HOST_A, HOST_B, HOST_C)):
        self.calls = []
        self.now = 0
        # The live server, or None while gluetun has no interface.
        self.tunnel = HOST_A
        self.pending = None
        self.age = 1
        self.rules = {4: rules(4), 6: rules(6)}
        self.host_routes = {4: list(HOST_ROUTES[4]), 6: list(HOST_ROUTES[6])}
        self.egress = EXIT4
        self.mullvad_exit = True
        self.insights_protected = True
        self.tunnel_route_present = True
        self.endpoint_override = None

    def sleep(self, seconds):
        self.now += seconds

    def advance(self):
        if self.pending:
            ticks, host = self.pending
            if ticks <= 0:
                self.tunnel, self.pending = host, None
            else:
                self.pending = (ticks - 1, host)

    def exit_routes(self, family):
        routes = [{'type': 'unreachable', 'dst': 'default', 'metric': 4096}]
        if family == 4 and self.tunnel and self.tunnel_route_present:
            routes.insert(0, {'dst': 'default', 'dev': 'wg0'})
        return routes

    def run(self, args, **kwargs):
        self.calls.append(args)
        if args[0] == 'ip':
            if args[1:4] == ['link', 'show', 'dev']:
                return ''
            if args[1:7] == ['-d', '-j', 'link', 'show', 'dev', 'wt0']:
                return json.dumps([{'ifname': 'wt0', 'linkinfo': {'info_kind': 'wireguard'}}])
            if args[1:6] == ['-j', 'link', 'show', 'dev', 'wg0']:
                self.advance()
                if self.tunnel is None:
                    raise RuntimeError('command failed')
                return json.dumps([{'ifname': 'wg0', 'flags': ['POINTOPOINT', 'NOARP', 'UP', 'LOWER_UP']}])
            if args[1:6] == ['-j', 'address', 'show', 'dev', 'wg0']:
                if self.tunnel is None:
                    raise RuntimeError('command failed')
                return json.dumps([{'addr_info': [{'family': 'inet', 'scope': 'global', 'local': TUNNEL4}]}])
            family = int(args[2][1:])
            if args[3] == 'rule':
                rules_now = [dict(r) for r in self.rules[family]]
                if self.tunnel is None:
                    rules_now = [r for r in rules_now if r['priority'] != 94]
                return json.dumps(rules_now)
            table = args[-1]
            if table == '51821':
                return json.dumps(self.exit_routes(family))
            if table == '51822':
                return json.dumps(self.host_routes[family])
            if table == 'main':
                return json.dumps(HOST_ROUTES[family] + [{'dst': '192.0.2.0/24', 'dev': 'wt0'}])
            raise AssertionError('unexpected table ' + table)
        if args[:3] == ['wg', 'show', 'wg0']:
            self.advance()
            if self.tunnel is None:
                raise RuntimeError('command failed')
            key = KEY_A if self.tunnel != HOST_B else KEY_B
            if args[3] == 'peers':
                return key
            if args[3] == 'endpoints':
                return f'{key}\t{self.endpoint_override or ENDPOINT[self.tunnel] + ":51820"}'
            assert args[3] == 'latest-handshakes'
            return f'{key}\t{int(time.time()) - self.age}'
        if args[0] == 'cat':
            return '1\n'
        if args == ['nft', '-j', 'list', 'chains']:
            return json.dumps({'nftables': [{'chain': {'family': 'ip', 'table': 'netbird', 'name': 'netbird-rt-fwd'}}]})
        if args[0] == 'curl':
            assert args[args.index('--interface') + 1] == 'wg0'
            assert '--noproxy' in args and '--max-filesize' in args
            if self.tunnel is None:
                raise RuntimeError('command failed')
            url = args[-1]
            if 'am.i.mullvad.net' in url:
                return json.dumps({'ip': self.egress, 'mullvad_exit_ip': self.mullvad_exit,
                                   'city': 'City 0', 'country': 'Exampleland'})
            if url.endswith('/ips/insights'):
                return json.dumps({'ip': self.egress, 'protected': self.insights_protected,
                                   'city': 'City 0', 'country': 'Exampleland', 'country_code': 'EX'})
            return self.egress + '\n'
        raise AssertionError('unexpected command: ' + ' '.join(args))


def make(tmp_path, provider='ivpn', *, kernel=None, write=True, **kwargs):
    kernel = kernel or Kernel()
    servers = tmp_path / 'gluetun-servers' / 'servers.json'
    servers.parent.mkdir(exist_ok=True)
    if write:
        servers.write_text(servers_json(provider))
    gluetun = FakeGluetun(kernel)
    cls = providers.get(f'gluetun-{provider}').applier_class()
    marked = []

    def fetch_marked(url, family, mark):
        marked.append((url, family, mark))
        return HOST4 + '\n'
    applier = cls(tmp_path, CONFIG, client=gluetun, servers_file=servers, run=kernel.run,
                  clock=lambda: kernel.now, sleep=kernel.sleep, fetch_marked=fetch_marked, **kwargs)
    applier.catalog.refresh()
    applier.marked = marked
    return applier, kernel, gluetun


def request(server=HOST_B, request_id='a' * 32):
    return {'server': server, 'requested_at': now_iso(), 'request_id': request_id}


def published(applier):
    return read_json(applier.result_path)


# Catalogue ---------------------------------------------------------------

def test_catalogue_comes_from_gluetuns_file_with_the_datas_own_date(tmp_path):
    applier, kernel, _ = make(tmp_path)
    snapshot = read_json(tmp_path / 'applier' / 'relays.json')
    assert snapshot['provider'] == 'gluetun-ivpn' and snapshot['source'] == 'gluetun'
    stamp = json.loads(servers_json('ivpn'))['ivpn']['timestamp']
    assert snapshot['data_timestamp'] == gluetun_applier.iso(stamp)
    assert set(snapshot['relays']) == {HOST_A, HOST_B, HOST_C}
    # The panel reads the same snapshot through the registry.
    assert set(relays.snapshot_relays(snapshot, 'gluetun-ivpn')) == {HOST_A, HOST_B, HOST_C}
    assert applier.catalog.usable()
    with pytest.raises(ValueError):
        applier.fetch_catalog()
    assert not any(c[0] == 'curl' for c in kernel.calls)


def test_a_broken_file_keeps_the_last_good_catalogue(tmp_path):
    applier, _, _ = make(tmp_path)
    before = (tmp_path / 'applier' / 'relays.json').read_bytes()
    source = applier.servers_file
    # gluetun truncates the file in place while it writes.
    source.write_text(servers_json('ivpn')[:100])
    assert applier.catalog.refresh() is False
    assert (tmp_path / 'applier' / 'relays.json').read_bytes() == before
    assert set(applier.catalog.relays) == {HOST_A, HOST_B, HOST_C}
    assert read_json(tmp_path / 'applier' / 'relay-error.json')['message'] == (
        "gluetun's server list is missing or invalid; retaining the last good catalogue.")
    source.unlink()
    source.symlink_to(tmp_path / 'elsewhere.json')
    (tmp_path / 'elsewhere.json').write_text(servers_json('ivpn'))
    assert applier.catalog.refresh() is False


def test_another_providers_block_is_not_this_catalogue(tmp_path):
    applier, _, _ = make(tmp_path, write=False)
    applier.servers_file.write_text(servers_json('nordvpn'))
    assert applier.catalog.refresh() is False and not applier.catalog.relays


def test_the_file_is_read_again_only_when_it_changes_or_ages(tmp_path, monkeypatch):
    applier, _, _ = make(tmp_path)
    reads = []
    real = gluetun_catalog.read_gluetun_snapshot
    monkeypatch.setattr(gluetun_catalog, 'read_gluetun_snapshot', lambda *a, **kw: reads.append(1) or real(*a, **kw))
    assert applier.catalog.refresh() and not reads
    applier.servers_file.write_text(servers_json('ivpn', hosts=(HOST_A, HOST_B)))
    os.utime(applier.servers_file, ns=(1, 1))
    assert applier.catalog.refresh() and len(reads) == 1 and set(applier.catalog.relays) == {HOST_A, HOST_B}
    applier.catalog.read_at -= CATALOG_REREAD_SEC
    assert applier.catalog.refresh() and len(reads) == 2


# Switching ---------------------------------------------------------------

def test_switch_puts_the_server_and_waits_out_gluetuns_restart(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    statuses = []
    real_publish = applier.publish

    def record(status, message, **fields):
        statuses.append(status)
        return real_publish(status, message, **fields)
    applier.publish = record
    result = applier.switch(request(HOST_B))
    assert gluetun.puts == [HOST_B]
    assert result['status'] == 'ok' and result['server'] == HOST_B, result
    # The interface going away during the switch was not a failure.
    assert 'failed' not in statuses and statuses.count('applying') >= 2
    assert result['egress_tier'] == 'tunnel' and result['exit_confirmed'] is False
    assert applier.selection == {'desired': HOST_B, 'last_put': HOST_B, 'last_successful': HOST_B}
    assert read_json(tmp_path / 'applier' / 'gluetun-selection.json') == applier.selection
    # The host's own address was measured off the tunnel, with NetBird's control mark.
    assert applier.marked and all(mark == 0x1bd00 for _, _, mark in applier.marked)
    view = status_view(request(HOST_B) | {'request_id': result['request_id']}, result, 'gluetun-ivpn')
    assert view == ('ok', 'connected')


def test_a_refused_selection_fails_without_waiting(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    gluetun.fail = True
    result = applier.switch(request(HOST_B))
    assert result['status'] == 'failed'
    assert result['message'] == 'gluetun did not accept the server selection; choose a server again to retry.'
    assert kernel.now == 0


def test_a_switch_that_lands_elsewhere_times_out(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    gluetun.connect_to = HOST_C
    result = applier.switch(request(HOST_B))
    assert result['status'] == 'failed'
    assert result['message'] == 'Switch verification timed out; choose a server again to retry.'
    assert kernel.now >= GLUETUN_SWITCH_TIMEOUT_SEC
    assert applier.selection['last_successful'] is None


def test_unlisted_and_invalid_requests_change_nothing(tmp_path):
    applier, _, gluetun = make(tmp_path)
    assert applier.switch(request('four.example.test'))['status'] == 'failed'
    assert applier.switch({'server': '../x', 'requested_at': now_iso()})['status'] == 'failed'
    assert gluetun.puts == []


def test_tunnel_checks_fail_when_the_echo_is_the_hosts_own_address(tmp_path):
    applier, kernel, _ = make(tmp_path)
    kernel.egress = HOST4
    result = applier.inspect()
    assert result['status'] == 'failed' and result['egress_tier'] is None
    assert result['message'] == 'Tunnel egress did not pass the tunnel checks.'


def test_mullvad_through_gluetun_uses_mullvads_own_check(tmp_path):
    applier, kernel, _ = make(tmp_path, 'mullvad')
    result = applier.inspect()
    assert result['status'] == 'ok' and result['egress_tier'] == 'provider' and result['mullvad_exit_ip'] is True
    assert any('am.i.mullvad.net' in c[-1] for c in kernel.calls if c[0] == 'curl')
    kernel.mullvad_exit = False
    result = applier.inspect()
    assert result['status'] == 'failed' and result['message'] == 'Tunnel egress is not confirmed as Mullvad.'


def test_nordvpn_through_gluetun_uses_nordvpns_own_check(tmp_path):
    applier, kernel, _ = make(tmp_path, 'nordvpn')
    result = applier.inspect()
    assert result['status'] == 'ok' and result['egress_tier'] == 'provider'
    assert any(c[-1].endswith('/ips/insights') for c in kernel.calls if c[0] == 'curl')
    assert 'mullvad_exit_ip' not in result


# Routing -----------------------------------------------------------------

@pytest.mark.parametrize('priority', [88, 89, 91, 92, 95, 97, 102, 103, 104])
def test_a_missing_guard_rule_holds_the_request(tmp_path, priority):
    applier, kernel, gluetun = make(tmp_path)
    kernel.rules[6] = [r for r in kernel.rules[6] if r['priority'] != priority]
    assert applier.routing_status()[0] is False
    result = applier.switch(request(HOST_B))
    assert gluetun.puts == [] and result['status'] == 'failed'
    assert applier.pending.startswith('Waiting for tunnel and overlay routing')


def test_the_host_table_is_part_of_the_guard(tmp_path):
    applier, kernel, _ = make(tmp_path)
    assert applier.routing_status() == (True, True)
    kernel.host_routes[4] = kernel.host_routes[4][:1]
    assert applier.routing_status()[0] is False
    kernel.host_routes[4] = HOST_ROUTES[4] + [{'dst': 'default', 'dev': 'wg0', 'metric': 10}]
    assert applier.routing_status()[0] is False


def test_no_tunnel_interface_is_not_a_routing_failure(tmp_path):
    applier, kernel, _ = make(tmp_path)
    kernel.tunnel = None
    assert applier.routing_status() == (True, True)
    result = applier.inspect()
    assert result['routing_ok'] is True and result['status'] == 'failed'


def test_a_tunnel_without_its_route_is_not_protected(tmp_path):
    applier, kernel, _ = make(tmp_path)
    kernel.tunnel_route_present = False
    assert applier.routing_status()[0] is False


# Restoring after gluetun restarts ---------------------------------------------

def settled(applier, kernel, *, last_put=HOST_B, last_successful=HOST_B, live=HOST_A):
    applier.save_selection(desired=last_put, last_put=last_put, last_successful=last_successful)
    kernel.tunnel = live
    applier.next_health = float('inf')
    return applier


def test_gluetun_on_its_start_up_server_gets_the_last_verified_one_back(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    settled(applier, kernel)
    assert applier.restore() == HOST_B and gluetun.puts == [HOST_B]
    # Not again within a switch timeout, even if the peer has not changed yet.
    kernel.pending = None
    kernel.tunnel = HOST_A
    assert applier.restore() is None and gluetun.puts == [HOST_B]
    kernel.now += GLUETUN_SWITCH_TIMEOUT_SEC
    assert applier.restore() == HOST_B


def test_no_restore_while_gluetun_runs_what_was_last_put(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    settled(applier, kernel, last_put=HOST_C, last_successful=HOST_B, live=HOST_C)
    assert applier.restore() is None and gluetun.puts == []


def test_no_restore_when_the_live_server_is_unknown(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    settled(applier, kernel)
    kernel.tunnel = None
    assert applier.restore() is None and gluetun.puts == []


def test_the_panels_request_takes_precedence(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    settled(applier, kernel)
    write_json_atomic(applier.desired_path, request(HOST_C))
    # Not yet handled: the request path applies it.
    assert applier.restore() is None
    applier.tick()
    assert gluetun.puts == [HOST_C]
    assert applier.selection['last_successful'] == HOST_C
    # Handled and verified, then gluetun restarts: the request path puts it again.
    kernel.tunnel = HOST_A
    kernel.now += GLUETUN_SWITCH_TIMEOUT_SEC
    assert applier.restore() is None
    applier.tick()
    assert gluetun.puts == [HOST_C, HOST_C]


def test_a_refused_request_falls_back_to_the_last_verified_server_after_a_restart(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    settled(applier, kernel, live=HOST_B)
    write_json_atomic(applier.desired_path, request('four.example.test'))
    applier.tick()
    assert applier.rejection and gluetun.puts == []
    kernel.tunnel = HOST_A
    applier.tick()
    assert gluetun.puts == [HOST_B]


# Doctor and setup ----------------------------------------------------------

def test_doctor_checks_gluetuns_control_server_and_data_age(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    checks = applier.doctor_checks()
    assert checks["gluetun's control server answers with the API key"] is True
    assert checks["gluetun's server data less than 30 days old"] is True
    gluetun.vpn_status = lambda: (_ for _ in ()).throw(RuntimeError('gluetun control request failed'))
    applier.servers_file.write_text(servers_json('ivpn', timestamp=1000))
    os.utime(applier.servers_file, ns=(2, 2))
    assert applier.catalog.refresh()
    checks = applier.doctor_checks()
    assert checks["gluetun's control server answers with the API key"] is False
    assert checks["gluetun's server data less than 30 days old"] is False


def test_from_env_reads_the_key_file_and_needs_the_gluetun_backend(tmp_path):
    key = tmp_path / 'api_key'
    key.write_text('k' * 43 + '\n')
    key.chmod(0o600)
    cls = providers.get('gluetun-ivpn').applier_class()
    env = {'GLUETUN_API_KEY_FILE': str(key), 'GLUETUN_SERVERS_FILE': str(tmp_path / 'servers.json')}
    applier = cls.from_env(tmp_path, CONFIG, env, run=Kernel().run)
    assert applier.client.base_url == 'http://127.0.0.1:8000'
    assert applier.servers_file == tmp_path / 'servers.json'
    with pytest.raises(ValueError, match='TUNNEL_BACKEND=gluetun'):
        cls.from_env(tmp_path, RoutingConfig('192.0.2.0/24'), env)
    key.chmod(0o644)
    with pytest.raises(ValueError):
        cls.from_env(tmp_path, CONFIG, env)


@pytest.mark.parametrize('url', ['http://api.ipify.org', 'https://api.ipify.org:8443', 'https://user@x.test/',
                                 'https://x.test/?q=1', 'file:///etc/passwd'])
def test_marked_echo_takes_only_plain_https_urls(url):
    with pytest.raises(RuntimeError):
        marked_echo(url, 4, 0x1bd00)


class SlowSocket:
    """A socket whose connect waits out its whole timeout on a fake clock,
    or is refused at once."""

    def __init__(self, clock, refused, *args):
        self.clock, self.refused, self.timeout = clock, refused, None

    def setsockopt(self, *args):
        pass

    def settimeout(self, value):
        self.timeout = value

    def connect(self, address):
        if address in self.refused:
            raise ConnectionRefusedError()
        self.clock[0] += self.timeout
        raise TimeoutError()

    def close(self):
        pass


@pytest.mark.parametrize('refused', [set(), {('192.0.2.1', 443)}])
def test_marked_echo_ends_within_its_timeout_however_many_addresses(monkeypatch, refused):
    clock, made = [0.0], []
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (f'192.0.2.{n}', 443)) for n in range(1, 5)]
    monkeypatch.setattr(gluetun_applier.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(gluetun_applier.socket, 'getaddrinfo', lambda *args: addresses)
    monkeypatch.setattr(gluetun_applier.socket, 'socket',
                        lambda *args: made.append(SlowSocket(clock, refused)) or made[-1])
    with pytest.raises(RuntimeError):
        marked_echo('https://echo.test/', 4, 0x1bd00, timeout=10)
    assert clock[0] == 10 and len(made) == len(refused) + 1


@pytest.mark.parametrize('head, body', [
    (b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 12\r\n\r\n', b'203.0.113.9\n'),
    (b'HTTP/1.0 200 OK\r\n\r\n', b'203.0.113.9\n'),
    (b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n', b'203.0.113.9\n'),
    (b'HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n',
     b'c\r\n203.0.113.9\n\r\n0\r\n\r\n'),
])
def test_a_deadline_response_reads_a_body_sent_after_the_headers(head, body):
    """Real http.client over a local socket: the headers, a pause, then the
    body, including responses that close the connection."""
    server = socket.create_server(('127.0.0.1', 0))

    def serve():
        conn, _ = server.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(head)
            time.sleep(0.2)
            conn.sendall(body)
    threading.Thread(target=serve, daemon=True).start()
    connection = http.client.HTTPConnection('127.0.0.1', server.getsockname()[1], timeout=5)
    connection.response_class = functools.partial(gluetun_applier._DeadlineResponse,
                                                  deadline=time.monotonic() + 5)
    try:
        connection.request('GET', '/')
        response = connection.getresponse()
        assert response.status == 200 and response.read(4096) == b'203.0.113.9\n'
    finally:
        connection.close()
        server.close()


def test_marked_echo_bounds_a_slow_name_lookup(monkeypatch):
    monkeypatch.setattr(gluetun_applier.socket, 'getaddrinfo', lambda *args: time.sleep(3) or [])
    started = time.monotonic()
    with pytest.raises(RuntimeError):
        marked_echo('https://echo.test/', 4, 0x1bd00, timeout=0.3)
    assert time.monotonic() - started < 1.5


def test_marked_echo_reads_get_only_the_time_left(monkeypatch):
    clock, timeouts = [0.0], []

    class Dribble:
        def settimeout(self, value):
            timeouts.append(value)

        def readinto(self, buffer):
            clock[0] += 4
            buffer[:1] = b'x'
            return 1

        def close(self):
            pass
    monkeypatch.setattr(gluetun_applier.time, 'monotonic', lambda: clock[0])
    dribble = Dribble()
    reader = gluetun_applier._DeadlineReader(dribble, dribble, 10)
    buffer = bytearray(1)
    assert [reader.readinto(buffer) for _ in range(3)] == [1, 1, 1]
    with pytest.raises(TimeoutError):
        reader.readinto(buffer)
    assert timeouts == [10, 6, 2]


def test_every_gluetun_entry_has_its_own_applier_class():
    for spec in providers.REGISTRY.values():
        if spec.backend == 'gluetun':
            cls = spec.applier_class()
            assert issubclass(cls, GluetunApplier) and cls.provider == spec.id
            assert spec.gluetun_provider in gluetun_catalog.SUPPORTED_PROVIDERS
            assert spec.egress_tier == ('provider' if spec.egress_check else 'tunnel')


def test_catalogue_class_is_the_gluetun_one(tmp_path):
    applier, _, _ = make(tmp_path)
    assert isinstance(applier.catalog, GluetunCatalog)
    assert applier.catalog.gluetun_provider == 'ivpn'


def test_auth_file_takes_only_url_safe_keys():
    from applier.gluetun import gluetun_auth_file
    assert 'apikey = "' + 'k' * 43 + '"' in gluetun_auth_file('k' * 43)
    for bad in ('short', 'k' * 42 + '"', 'k' * 42 + '\n', 'k' * 129, None):
        with pytest.raises(ValueError):
            gluetun_auth_file(bad)


def test_panel_shows_the_backend_and_the_datas_date():
    sys.path.insert(0, str(ROOT / 'panel'))
    import app as panel_app
    assert panel_app.provider_note('gluetun-nordvpn') == ' <span class="provider-note">via gluetun</span>'
    assert panel_app.provider_note('nordvpn') == ''
    # Every gluetun exit takes gluetun's style, accented in its provider's colour.
    assert panel_app.provider_css('gluetun-nordvpn') == 'gluetun' and panel_app.provider_css('gluetun-ivpn') == 'gluetun'
    assert panel_app.provider_accent('gluetun-nordvpn') == ' data-accent="nordvpn"'
    assert panel_app.provider_css('nordvpn') == 'nordvpn' and panel_app.provider_accent('nordvpn') == ''
    fresh = {'source': 'gluetun', 'data_timestamp': gluetun_applier.iso(time.time() - 86400)}
    old = {'source': 'gluetun', 'data_timestamp': gluetun_applier.iso(time.time() - 40 * 86400)}
    assert panel_app.catalogue_age_text(fresh, 'now') == f'read now; gluetun data from {fresh["data_timestamp"]}'
    assert panel_app.catalogue_age_text(old, 'now').endswith('(stale: older than 30 days)')
    assert panel_app.catalogue_age_text({'fetched_at': 'x'}, 'x') == 'fetched x'
    with __import__('unittest.mock').mock.patch.multiple(panel_app, PROVIDER='gluetun-nordvpn'):
        page = panel_app.render_index_html(None, None, {'source': 'gluetun', 'provider': 'gluetun-nordvpn',
                                                         'data_timestamp': fresh['data_timestamp'],
                                                         'fetched_at': now_iso(), 'relays': {}}, None, None, 'tok')
    assert '<html lang="en" data-theme="auto" data-style="provider" data-provider="gluetun" data-accent="nordvpn">' in page
    assert 'via gluetun' in page and 'gluetun data from' in page


# Refreshing gluetun's server list --------------------------------------------

def stale(tmp_path, provider='ivpn', **kwargs):
    applier, kernel, gluetun = make(tmp_path, provider, write=False, **kwargs)
    applier.servers_file.write_text(servers_json(provider, timestamp=int(time.time()) - 400 * 86400))
    assert applier.catalog.refresh()
    applier.next_catalog = float('inf')
    return applier, kernel, gluetun


def test_old_data_starts_one_update_and_follows_it(tmp_path):
    applier, kernel, gluetun = stale(tmp_path)
    applier.update_servers()
    assert gluetun.updates == 1 and applier.update_state == 'updating'
    assert applier.inspect()['server_list_update'] == 'updating'
    applier.update_servers()
    assert gluetun.updates == 1
    # gluetun finished and wrote newer data; the catalogue re-reads it at once.
    gluetun.updater = 'completed'
    applier.servers_file.write_text(servers_json('ivpn'))
    os.utime(applier.servers_file, ns=(5, 5))
    applier.tick()
    assert applier.update_state == 'done' and gluetun.updates == 1
    # The next look at the file is a minute away, not six hours.
    assert applier.next_catalog == kernel.now + gluetun_applier.CATALOG_POLL_SEC
    age = gluetun_applier.data_age(applier.catalog.snapshot['data_timestamp'], time.time())
    assert age < 2 * 3600
    assert applier.inspect()['server_list_update'] is None


def test_fresh_data_starts_no_update(tmp_path):
    applier, _, gluetun = make(tmp_path)
    applier.update_servers()
    assert gluetun.updates == 0 and applier.update_state == 'done'


def test_no_update_before_the_tunnel_runs_or_with_the_updater_off(tmp_path):
    applier, _, gluetun = stale(tmp_path)
    gluetun.status = 'starting'
    applier.update_servers()
    assert gluetun.updates == 0 and applier.update_state is None
    (tmp_path / 'off').mkdir()
    applier, _, gluetun = stale(tmp_path / 'off', updater_period_s=0)
    applier.update_servers()
    assert gluetun.updates == 0


def test_a_short_updater_period_lowers_the_threshold(tmp_path):
    applier, _, gluetun = make(tmp_path, write=False, updater_period_s=3600)
    applier.servers_file.write_text(servers_json('ivpn', timestamp=int(time.time()) - 2 * 3600))
    assert applier.catalog.refresh()
    applier.update_servers()
    assert gluetun.updates == 1


def test_failed_updates_are_retried_a_bounded_number_of_times(tmp_path):
    applier, kernel, gluetun = stale(tmp_path)
    for attempt in range(1, gluetun_applier.UPDATE_ATTEMPTS + 1):
        applier.update_servers()
        assert gluetun.updates == attempt and applier.update_state == 'updating'
        gluetun.updater = 'crashed'
        applier.update_servers()
        assert applier.update_state == ('failed' if attempt == gluetun_applier.UPDATE_ATTEMPTS else None)
        applier.update_servers()
        assert gluetun.updates == attempt  # waits before the next try
        kernel.now += gluetun_applier.UPDATE_RETRY_SEC
    applier.update_servers()
    assert gluetun.updates == gluetun_applier.UPDATE_ATTEMPTS
    assert applier.inspect()['server_list_update'] == 'failed'


def test_an_update_that_never_finishes_times_out(tmp_path):
    applier, kernel, gluetun = stale(tmp_path)
    applier.update_servers()
    kernel.now += gluetun_applier.UPDATE_TIMEOUT_SEC
    applier.update_servers()
    assert applier.update_state is None and applier.update_attempts == 1
    gluetun.update_fails = True
    kernel.now += gluetun_applier.UPDATE_RETRY_SEC
    applier.update_servers()
    assert applier.update_attempts == 2 and applier.update_state is None


@pytest.mark.parametrize('value,seconds', [('24h', 86400), ('1h30m', 5400), ('90s', 90), ('0', 0), ('0s', 0)])
def test_updater_period(value, seconds):
    assert gluetun_applier.updater_period(value) == seconds


@pytest.mark.parametrize('value', ['', '1d', '24', 'h', '-1h', '1.5h'])
def test_bad_updater_period(value):
    with pytest.raises(ValueError):
        gluetun_applier.updater_period(value)


def test_panel_shows_a_server_list_update():
    sys.path.insert(0, str(ROOT / 'panel'))
    import app as panel_app
    from unittest import mock
    result = {'status': 'ok', 'checked_at': now_iso(), 'server_list_update': 'updating'}
    with mock.patch.multiple(panel_app, PROVIDER='gluetun-ivpn'):
        page = panel_app.render_index_html(None, result, None, None, None, 'tok')
    assert '; updating server list' in page


def test_a_dedicated_ip_server_never_reaches_the_snapshot(tmp_path):
    applier, _, gluetun = make(tmp_path, 'nordvpn')
    snapshot = read_json(tmp_path / 'applier' / 'relays.json')
    assert 'dedicated.example.test' not in snapshot['relays']
    assert set(snapshot['relays']) == {HOST_A, HOST_B, HOST_C}
    result = applier.switch(request('dedicated.example.test'))
    assert result['status'] == 'failed' and gluetun.puts == []


@pytest.mark.parametrize('break_tunnel', ['no interface', 'old handshake'])
def test_no_update_until_the_tunnel_answers(tmp_path, break_tunnel):
    # gluetun reports running while it still tries stale servers that don't answer.
    applier, kernel, gluetun = stale(tmp_path)
    if break_tunnel == 'no interface':
        kernel.tunnel = None
    else:
        kernel.age = gluetun_applier.UPDATE_HANDSHAKE_SEC + 10
    applier.update_servers()
    assert gluetun.updates == 0 and applier.update_attempts == 0 and applier.update_state is None
    kernel.tunnel, kernel.age = HOST_A, 1
    applier.update_servers()
    assert gluetun.updates == 1


@pytest.mark.parametrize('endpoint', ['198.51.100.122:51820', '[2001:db8:5::22]:51820'])
def test_the_live_server_is_found_by_any_of_its_addresses(tmp_path, endpoint):
    # gluetun picks any address of the selected server, IPv6 included.
    applier, kernel, _ = make(tmp_path, write=False)
    data = json.loads(servers_json('ivpn'))
    for server in data['ivpn']['servers']:
        if server['hostname'] == HOST_B:
            server['ips'] = [ENDPOINT[HOST_B], '198.51.100.122', '2001:db8:5::22']
    applier.servers_file.write_text(json.dumps(data))
    assert applier.catalog.refresh()
    kernel.tunnel, kernel.endpoint_override = HOST_B, endpoint
    assert applier.server_for(applier.peers()) == HOST_B
    result = applier.inspect()
    assert result['status'] == 'ok' and result['server'] == HOST_B


# Egress check retry ------------------------------------------------------------

@pytest.mark.parametrize('provider, check', [
    ('mullvad', lambda url: 'am.i.mullvad.net' in url),
    ('nordvpn', lambda url: url.endswith('/ips/insights')),
    ('ivpn', lambda url: url in ECHO_URLS[4]),
])
def test_every_check_through_gluetun_is_asked_once_more_when_unanswered(tmp_path, provider, check):
    applier, kernel, _ = make(tmp_path, provider)
    calls = unanswered(applier, kernel, lambda args: args[0] == 'curl' and check(args[-1]))
    start = kernel.now
    result = applier.inspect()
    assert result['status'] == 'ok' and result['egress_tier'] in ('provider', 'tunnel')
    assert kernel.now - start == 10 + EGRESS_RETRY_SEC
    # The tunnel tier stops at the first unanswered echo, then asks both services.
    assert len(calls) == (3 if provider == 'ivpn' else 2)


def test_a_tunnel_tier_answer_that_fails_is_never_asked_again_through_gluetun(tmp_path):
    applier, kernel, _ = make(tmp_path)
    kernel.egress = HOST4
    start = kernel.now
    result = applier.inspect()
    assert result['message'] == 'Tunnel egress did not pass the tunnel checks.' and kernel.now == start

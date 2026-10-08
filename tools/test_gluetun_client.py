"""Offline gluetun v3.41.3 fixtures; no engine, tunnel or control server runs.

Oversized, symlink and special-file fixtures are made in tmp_path so the
repository does not carry a 32 MiB blob or a platform-specific special file.
"""
import copy
from collections import Counter
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from molebridge import gluetun_catalog as catalog
from applier import gluetun

FIXTURES = Path(__file__).with_name('fixtures') / 'gluetun'
KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
OTHER_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE='
NOW = 1000
# gluetun's own servers.json at the pinned release (internal/storage/servers.json
# in its source tree), when a checkout is available: set GLUETUN_SERVERS_JSON.
REFERENCE = Path(os.environ.get('GLUETUN_SERVERS_JSON') or '/nonexistent')


@pytest.fixture
def storage():
    return json.loads((FIXTURES / 'servers.json').read_text())


def write_storage(tmp_path, storage):
    path = tmp_path / 'servers.json'
    path.write_text(json.dumps(storage))
    return path


@pytest.mark.parametrize('provider', catalog.SUPPORTED_PROVIDERS)
def test_providers(provider):
    relays, timestamp = catalog.read_gluetun_snapshot(FIXTURES / 'servers.json', provider, now=NOW)
    assert timestamp == 900
    assert len(relays) == 2
    assert catalog.read_gluetun_catalog(FIXTURES / 'servers.json', provider, now=NOW) == relays
    for server_id, relay in relays.items():
        assert server_id == relay['id']
        assert relay['selection_filter'] == catalog.PROVIDER_SELECTION[provider][1]
        assert relay['public_key'] == KEY
    if provider == 'windscribe':
        assert relays['windscribe-one.example.test']['country'] == ''
    if provider == 'fastestvpn':
        assert relays['fastestvpn-one.example.test']['city'] == ''


def test_servers_a_plain_account_cannot_use_never_reach_the_catalogue():
    nord = catalog.read_gluetun_catalog(FIXTURES / 'servers.json', 'nordvpn', now=NOW)
    # Dedicated IP, Double VPN and obfuscated servers are in the file, not the catalogue.
    assert set(nord) == {'nordvpn-one.example.test', 'nordvpn-two.example.test'}
    surf = catalog.read_gluetun_catalog(FIXTURES / 'servers.json', 'surfshark', now=NOW)
    assert set(surf) == {'zz-one.prod.surfshark.com', 'zz-two-st001.prod.surfshark.com'}


@pytest.mark.parametrize('categories,ok', [
    (['Standard VPN servers'], True), (['P2P', 'Standard VPN servers'], True),
    (['Dedicated IP'], False), (['Standard VPN servers', 'Dedicated IP'], False),
    (['Double VPN'], False), (['Onion Over VPN'], False), (['Standard VPN servers', 'Obfuscated Servers'], False),
    (['P2P'], False), ([], False), (None, False)])
def test_nordvpn_selectability_matches_the_native_rule(categories, ok):
    from molebridge import nordvpn
    assert catalog.selectable('nordvpn', {'categories': categories}) is ok
    # The same groups as the native catalogue, by title.
    assert nordvpn.EXCLUDED_TITLES == {nordvpn.GROUP_TITLES[g] for g in nordvpn.EXCLUDED_GROUPS}


def test_relay_projection():
    relays = catalog.read_gluetun_catalog(FIXTURES / 'servers.json', 'mullvad', now=NOW)
    assert relays['mullvad-one.example.test'] == {
        'id': 'mullvad-one.example.test', 'selection_filter': 'hostnames',
        'hostname': 'mullvad-one.example.test', 'public_key': KEY,
        'ipv4_addr_in': '198.51.100.5', 'ipv4_addrs': ['198.51.100.5', '198.51.100.50'],
        'ipv6_addrs': ['2001:db8::1', '2001:db8::2'],
        'country': 'Example Country', 'city': 'Example City', 'region': 'Example Region',
        'categories': ['Standard', 'Example Category']}


@pytest.mark.parametrize('fixture', ('duplicate.json', 'truncated.json', 'future.json'))
def test_bad_snapshot(fixture):
    with pytest.raises(ValueError):
        catalog.read_gluetun_snapshot(FIXTURES / fixture, 'mullvad', now=NOW)


@pytest.mark.parametrize('field,value', [
    ('vpn', 'openvpn'), ('wgpubkey', OTHER_KEY[:-1]), ('wgpubkey', 4),
    ('hostname', 'UPPER.example.test'), ('hostname', '-bad.example.test'),
    ('hostname', 'bad-.example.test'), ('hostname', 'a..test'),
    ('hostname', 'a' * 64 + '.test'), ('hostname', 'a.' * 126 + 'aa'),
    ('hostname', 'bad.example.test\n'), ('hostname', 'a_test'),
    ('country', 'x' * 257), ('country', '\x00'), ('city', '\x7f'), ('city', '\x85'),
    ('city', 4), ('city', '\u202e'), ('city', '\ud800'),
    ('region', ['Example']), ('categories', 'Standard'),
    ('categories', ['x' * 257]), ('categories', ['\n']), ('categories', [3]),
    ('categories', ['Standard'] * 65), ('ips', ['2001:db8::1']),
    ('ips', '198.51.100.1'), ('ips', [None, 4, '198.51.100.01']),
    ('ips', ['198.51.100.1'] * 65),
])
def test_malformed_entries_are_skipped(tmp_path, storage, field, value):
    storage['mullvad']['servers'] = storage['mullvad']['servers'][:2]
    storage['mullvad']['servers'][0][field] = value
    relays = catalog.read_gluetun_catalog(write_storage(tmp_path, storage), 'mullvad', now=NOW)
    assert list(relays) == ['mullvad-two.example.test']


def test_bad_key_cannot_hide_duplicate(tmp_path, storage):
    first = storage['mullvad']['servers'][0]
    storage['mullvad']['servers'] = [first, {**first, 'wgpubkey': 'invalid'}]
    with pytest.raises(ValueError, match='duplicate'):
        catalog.read_gluetun_catalog(write_storage(tmp_path, storage), 'mullvad', now=NOW)


def test_invalid_uppercase_hostname_cannot_hide_filter_collision(tmp_path, storage):
    first = storage['mullvad']['servers'][0]
    storage['mullvad']['servers'] = [first, {**first, 'hostname': first['hostname'].upper()}]
    with pytest.raises(ValueError, match='^duplicate gluetun server identifier$'):
        catalog.read_gluetun_catalog(write_storage(tmp_path, storage), 'mullvad', now=NOW)


@pytest.mark.parametrize('provider', tuple(catalog.REJECTED_PROVIDERS))
def test_provider_without_exact_selection_rejected(provider):
    with pytest.raises(ValueError) as error:
        catalog.read_gluetun_catalog(FIXTURES / 'servers.json', provider, now=NOW)
    assert str(error.value) == catalog.REJECTED_PROVIDERS[provider]


def test_ambiguous_provider_fixtures(storage):
    airvpn = storage['airvpn']['servers']
    assert len({entry['server_name'] for entry in airvpn}) < len(airvpn)
    assert len({entry['hostname'] for entry in airvpn}) < len(airvpn)
    protonvpn = storage['protonvpn']['servers']
    assert len({entry['server_name'] for entry in protonvpn}) < len(protonvpn)
    assert len({entry['hostname'] for entry in protonvpn}) < len(protonvpn)


@pytest.mark.skipif(not REFERENCE.is_file(), reason='GLUETUN_SERVERS_JSON not set')
@pytest.mark.parametrize('provider', catalog.SUPPORTED_PROVIDERS)
def test_reference_catalogue_ids_select_exactly_one_row(provider):
    # Do not copy reference identities, keys or addresses into fixtures or
    # assertion output. Only booleans/counts below reach pytest diagnostics.
    # Freshness is tested separately; this check isolates the reference IDs.
    relays = catalog.read_gluetun_catalog(REFERENCE, provider, now=2**63 - 1)
    data = json.loads(REFERENCE.read_text())
    field, selection_filter = catalog.PROVIDER_SELECTION[provider]
    entries = [entry for entry in data[provider]['servers'] if entry['vpn'] == 'wireguard']
    field_matches_filter = field == {'hostnames': 'hostname', 'names': 'server_name',
                                     'numbers': 'number'}[selection_filter]
    counts = Counter(entry[field].casefold() for entry in entries)
    all_reference_ids_unique = all(count == 1 for count in counts.values())
    nonempty_catalogue = bool(relays)
    catalogue_ids_unique = len({server_id.casefold() for server_id in relays}) == len(relays)
    ids_select_one_row = all(counts[server_id.casefold()] == 1 for server_id in relays)
    relay_ids_and_filters_match = all(relay['id'] == server_id
                                     and relay['selection_filter'] == selection_filter
                                     for server_id, relay in relays.items())
    assert all_reference_ids_unique
    assert field_matches_filter
    assert nonempty_catalogue
    assert catalogue_ids_unique
    assert ids_select_one_row
    assert relay_ids_and_filters_match


@pytest.mark.parametrize('timestamp', (None, True, '900', 900.0, -1, 1001))
def test_timestamp(tmp_path, storage, timestamp):
    storage['mullvad']['timestamp'] = timestamp
    with pytest.raises(ValueError, match='timestamp'):
        catalog.read_gluetun_catalog(write_storage(tmp_path, storage), 'mullvad', now=NOW)


@pytest.mark.parametrize('data', ([], {}, {'version': True}, {'version': 2},
                                 {'version': 1}, {'version': 1, 'mullvad': []},
                                 {'version': 1, 'mullvad': {'version': 1, 'timestamp': 900, 'servers': []}}))
def test_invalid_structure(tmp_path, data):
    with pytest.raises(ValueError):
        catalog.read_gluetun_catalog(write_storage(tmp_path, data), 'mullvad', now=NOW)


@pytest.mark.parametrize('provider', ('pia', 'private internet access', 'Mullvad', None, []))
def test_unsupported_provider(provider):
    with pytest.raises(ValueError, match='unsupported'):
        catalog.read_gluetun_catalog(FIXTURES / 'servers.json', provider, now=NOW)


@pytest.mark.parametrize('raw', (b'{"version":1,"version":1}', b'\xff',
                               b'{"version":NaN}', b'[' * 2000, b'{} trailing'))
def test_bad_json_is_sanitized(tmp_path, raw):
    path = tmp_path / 'servers.json'
    path.write_bytes(raw)
    with pytest.raises(ValueError, match='^cannot read gluetun catalogue$') as error:
        catalog.read_gluetun_catalog(path, 'mullvad', now=NOW)
    assert error.value.__suppress_context__


@pytest.mark.parametrize('kind', ('oversized', 'symlink', 'fifo', 'directory', 'missing'))
def test_unsafe_catalogue_file(tmp_path, kind):
    path = tmp_path / 'servers.json'
    if kind == 'oversized':
        with path.open('wb') as stream:
            stream.truncate(catalog.MAX_CATALOG_BYTES + 1)
    elif kind == 'symlink':
        path.symlink_to(FIXTURES / 'servers.json')
    elif kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'directory':
        path.mkdir()
    with pytest.raises(ValueError, match='^cannot read gluetun catalogue$'):
        catalog.read_gluetun_catalog(path, 'mullvad', now=NOW)


def test_truncated_read_leaves_previous_snapshot():
    previous = catalog.read_gluetun_snapshot(FIXTURES / 'servers.json', 'mullvad', now=NOW)
    snapshot = previous
    try:
        snapshot = catalog.read_gluetun_snapshot(FIXTURES / 'truncated.json', 'mullvad', now=NOW)
    except ValueError:
        pass
    assert snapshot is previous


@pytest.mark.parametrize('provider', ('nordvpn', 'windscribe'))
def test_shared_key_is_identified_by_endpoint(provider):
    relays = catalog.read_gluetun_catalog(FIXTURES / 'servers.json', provider, now=NOW)
    for server_id, relay in relays.items():
        for endpoint in (relay['ipv4_addr_in'], relay['ipv4_addr_in'] + ':51820'):
            assert catalog.server_for_peer(relays, KEY, endpoint) == server_id
            assert catalog.server_for_peer(relays, OTHER_KEY, endpoint) is None
    assert catalog.server_for_peer(relays, KEY, '192.0.2.1:51820') is None
    ambiguous = copy.deepcopy(relays)
    first, second = ambiguous.values()
    second['ipv4_addr_in'] = first['ipv4_addr_in']
    second['ipv4_addrs'] = [first['ipv4_addr_in']]
    second['public_key'] = OTHER_KEY
    assert catalog.server_for_peer(ambiguous, KEY, first['ipv4_addr_in']) is None


@pytest.mark.parametrize('endpoint', (None, '', 'example.test:51820', '198.51.100.5:0',
                                     '198.51.100.5:65536', '198.51.100.5:x',
                                     '[2001:db8::1]:51820', '198.51.100.5:1\n'))
def test_bad_peer_endpoint(endpoint):
    relays = catalog.read_gluetun_catalog(FIXTURES / 'servers.json', 'mullvad', now=NOW)
    assert catalog.server_for_peer(relays, KEY, endpoint) is None
    assert catalog.server_for_peer(relays, 'invalid', '198.51.100.5') is None


API_KEY = 'AAAAAAAA-example-api-key'


class FakeRun:
    """Capture the temporary header during the call, without running curl."""
    def __init__(self, response='{"status":"running"}', error=None):
        self.response, self.error = response, error
        self.calls, self.headers = [], []

    def __call__(self, args, *, timeout, limit):
        header = Path(args[args.index('-H') + 1][1:])
        assert header.stat().st_mode & 0o7777 == 0o600
        assert header.parent.stat().st_mode & 0o777 == 0o700
        assert timeout == 12
        assert limit == gluetun.MAX_RESPONSE_BYTES
        assert args[:2] == ['curl', '-q']
        assert args[args.index('--noproxy') + 1] == '*'
        assert args[args.index('--proto') + 1] == '=http'
        assert args[args.index('--max-time') + 1] == '10'
        assert args[args.index('--max-filesize') + 1] == str(limit)
        assert args[args.index('--max-redirs') + 1] == '0'
        assert '-L' not in args and '--location' not in args
        assert not any(API_KEY in arg for arg in args)
        self.headers.append((header, header.read_text()))
        self.calls.append(args)
        if self.error:
            raise self.error
        return self.response


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / 'api-key'
    path.write_text(API_KEY + '\n')
    path.chmod(0o600)
    return path


def assert_header_removed(run):
    assert run.headers
    for path, text in run.headers:
        assert text == 'X-API-Key: ' + API_KEY + '\n'
        assert not path.exists()
        assert not path.parent.exists()


@pytest.mark.parametrize('url', ('http://127.0.0.1:8000', 'http://[::1]:8000',
                               'http://127.0.0.1:1', 'http://[::1]:65535'))
def test_loopback_client(key_file, url):
    run = FakeRun()
    client = gluetun.GluetunClient(url, key_file, run=run)
    assert client.vpn_status() == 'running'
    assert run.calls[0][-1] == url + '/v1/vpn/status'
    assert_header_removed(run)


@pytest.mark.parametrize('url', (None, '', 'https://127.0.0.1:8000', 'http://localhost:8000',
                               'http://192.0.2.1:8000', 'http://127.0.0.2:8000',
                               'http://127.0.0.1', 'http://127.0.0.1:0',
                               'http://127.0.0.1:65536', 'http://127.0.0.1:08000',
                               'http://127.0.0.1:8000/', 'http://127.0.0.1:8000?x=1',
                               'http://127.0.0.1:8000#x', 'http://127.0.0.1:8000\n',
                               'http://user@127.0.0.1:8000', 'http://[::ffff:127.0.0.1]:8000',
                               'http://[::1%zone]:8000', 'http://[::1]:8000/path'))
def test_bad_base_url(key_file, url):
    run = FakeRun()
    with pytest.raises(ValueError, match='^invalid gluetun control URL$'):
        gluetun.GluetunClient(url, key_file, run=run)
    assert not run.calls


@pytest.mark.parametrize('mode', (0o600, 0o400))
def test_restrictive_key_mode(key_file, mode):
    key_file.chmod(mode)
    assert gluetun.read_api_key(key_file) == API_KEY


@pytest.mark.parametrize('mode', (0o644, 0o640, 0o604, 0o700, 0o1600))
def test_exposed_key_mode(key_file, mode):
    key_file.chmod(mode)
    with pytest.raises(ValueError, match='^cannot read gluetun API key$'):
        gluetun.read_api_key(key_file)


@pytest.mark.parametrize('mode', (0o2600, 0o4600))
def test_special_key_mode(key_file, monkeypatch, mode):
    # Some filesystems strip these bits on chmod; exercise fstat validation
    # independently of that host policy.
    import stat
    from types import SimpleNamespace
    monkeypatch.setattr(gluetun.os, 'fstat', lambda fd: SimpleNamespace(
        st_mode=stat.S_IFREG | mode, st_size=len(API_KEY)))
    with pytest.raises(ValueError, match='^cannot read gluetun API key$'):
        gluetun.read_api_key(key_file)


@pytest.mark.parametrize('raw', (b'', b'\n', b'\xff', b'key\nother', b'key\r',
                               b'key\x00', b'key\t', b'key\x7f', b'key\x1b',
                               b' key', b'key ', b'x' * (gluetun.MAX_KEY_BYTES + 1)))
def test_bad_key_file(key_file, raw):
    key_file.write_bytes(raw)
    with pytest.raises(ValueError, match='^cannot read gluetun API key$') as error:
        gluetun.read_api_key(key_file)
    assert error.value.__suppress_context__


def test_key_newline(key_file):
    for ending in ('', '\n', '\r\n'):
        key_file.write_text(API_KEY + ending)
        assert gluetun.read_api_key(key_file) == API_KEY


@pytest.mark.parametrize('kind', ('symlink', 'fifo', 'directory', 'missing'))
def test_unsafe_key_file(tmp_path, key_file, kind):
    path = tmp_path / 'unsafe-key'
    if kind == 'symlink':
        path.symlink_to(key_file)
    elif kind == 'fifo':
        os.mkfifo(path, 0o600)
    elif kind == 'directory':
        path.mkdir(mode=0o600)
    with pytest.raises(ValueError, match='^cannot read gluetun API key$'):
        gluetun.read_api_key(path)


@pytest.mark.parametrize('method,path', (('GET', '/v1/vpn/settings'),
                                       ('GET', '/v1/vpn/settings?x=1'),
                                       ('GET', '/v1/openvpn/settings'),
                                       ('PUT', '/v1/vpn/status'),
                                       ('PUT', '/v1/updater/settings'),
                                       ('GET', '/v1/updater/status/../../vpn/settings'),
                                       ('GET', 'http://example.test/'),
                                       ('GET', '/v1/publicip/ip/../vpn/settings')))
def test_settings_and_other_routes_refused(key_file, method, path):
    run = FakeRun()
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(ValueError, match='^gluetun control route refused$'):
        client._request(method, path)
    assert not run.calls and not run.headers


@pytest.mark.parametrize('server_id,selection_filter', (
    ('relay.example.test', 'hostnames'), ('ExampleNode', 'names'), ('EX#26', 'names'),
    ('EX-CORE#2', 'names'), (26, 'numbers')))
@pytest.mark.parametrize('use_relay', (True, False))
def test_exact_selection_body(key_file, server_id, selection_filter, use_relay):
    run = FakeRun('VPN settings updated\r\n\x00\x7f\x85\u202e')
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    relay = {'id': server_id, 'selection_filter': selection_filter,
             'hostname': 'attribute.example.test', 'public_key': KEY}
    if use_relay:
        outcome = client.select_server(relay)
    else:
        outcome = client.select_server(server_id, selection_filter)
    assert outcome == 'VPN settings updated'
    args = run.calls[0]
    assert args[args.index('-X') + 1] == 'PUT'
    assert args[-1] == 'http://127.0.0.1:8000/v1/vpn/settings'
    assert 'Content-Type: application/json' in args
    expected = {
        'provider': {'server_selection': {
            'hostnames': [], 'countries': [], 'regions': [],
            'cities': [], 'names': [], 'numbers': [], 'categories': [], 'isps': [],
            'owned_only': False, 'free_only': False, 'premium_only': False,
            'stream_only': False, 'multi_hop_only': False, 'port_forward_only': False,
            'secure_core_only': False, 'tor_only': False}}}
    expected['provider']['server_selection'][selection_filter] = [server_id]
    assert json.loads(args[args.index('--data-binary') + 1]) == expected
    assert_header_removed(run)


@pytest.mark.parametrize('hostname', (None, 'relay.example.test\n', 'Bad.example.test',
                                    'x' * 254, 'example.test"', 'a..test', '-bad.test'))
def test_selection_rejects_hostname_before_io(key_file, hostname):
    run = FakeRun()
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(ValueError, match='^invalid gluetun server selection$'):
        client.select_server(hostname, 'hostnames')
    assert not run.calls


@pytest.mark.parametrize('server_id,selection_filter', (
    ('relay.example.test', None), ('relay.example.test', 'countries'),
    ('relay.example.test', ['hostnames']), ('relay.example.test', {}),
    ('EX#1\n', 'names'), ('\x00', 'names'), ('x' * 257, 'names'),
    ('', 'names'), ('EX\u202e#1', 'names'), ('EX\ud800#1', 'names'),
    ('26', 'numbers'), (True, 'numbers'), (0, 'numbers'), (65536, 'numbers')))
def test_invalid_id_or_filter_refused(key_file, server_id, selection_filter):
    run = FakeRun()
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(ValueError, match='^invalid gluetun server selection$'):
        client.select_server(server_id, selection_filter)
    assert not run.calls


@pytest.mark.parametrize('relay', ({}, {'hostname': 'relay.example.test'},
                                 {'id': 'relay.example.test', 'selection_filter': 'countries'}))
def test_invalid_relay_refused(key_file, relay):
    run = FakeRun()
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(ValueError, match='^invalid gluetun server selection$'):
        client.select_server(relay)
    assert not run.calls


def test_conflicting_relay_filter_refused(key_file):
    run = FakeRun()
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    relay = {'id': 'relay.example.test', 'selection_filter': 'hostnames'}
    with pytest.raises(ValueError, match='^conflicting gluetun server selection filter$'):
        client.select_server(relay, 'names')
    assert not run.calls


def test_peer_returns_id_instead_of_hostname():
    # The peer resolver is independent of provider selection policy.
    relays = {'ExampleNode': {'id': 'ExampleNode', 'hostname': 'regional.example.test',
                             'public_key': KEY, 'ipv4_addr_in': '198.51.100.1'}}
    assert catalog.server_for_peer(relays, KEY, '198.51.100.1:51820') == 'ExampleNode'


@pytest.mark.parametrize('outcome', ('', '\n\x00', 'x' * (gluetun.MAX_OUTCOME_CHARS + 1)))
def test_invalid_selection_outcome(key_file, outcome):
    run = FakeRun(outcome)
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(ValueError, match='^invalid gluetun selection outcome$'):
        client.select_server('relay.example.test', 'hostnames')
    assert_header_removed(run)


@pytest.mark.parametrize('status', gluetun.VPN_STATUSES)
def test_vpn_statuses(key_file, status):
    run = FakeRun(json.dumps({'status': status}))
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    assert client.vpn_status() == status
    assert_header_removed(run)


@pytest.mark.parametrize('raw', ('{}', '[]', 'null', 'broken input',
                               '{"status":"running","status":"stopped"}',
                               '{"status":true}', '{"status":"unknown"}',
                               '{"status":"RUNNING"}', '{"status":"running\\n"}',
                               '{"status":NaN}', '[' * 2000))
def test_bad_status_response(key_file, raw):
    run = FakeRun(raw)
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(ValueError):
        client.vpn_status()
    assert_header_removed(run)


@pytest.mark.parametrize('address', ('198.51.100.20', '2001:db8::20'))
def test_public_ip(key_file, address):
    run = FakeRun(json.dumps({'public_ip': address, 'city': 'Example City'}))
    client = gluetun.GluetunClient('http://[::1]:8000', key_file, run=run)
    assert client.public_ip() == address
    assert run.calls[0][-1] == 'http://[::1]:8000/v1/publicip/ip'
    assert_header_removed(run)


@pytest.mark.parametrize('value', (None, True, [], 4, '198.51.100.01',
                                 '198.51.100.20:8000', '198.51.100.20\n',
                                 '2001:DB8::20', '2001:db8::20%zone',
                                 '2001:db8::20/64', 'bad', 'x' * 256))
def test_bad_public_ip(key_file, value):
    run = FakeRun(json.dumps({'public_ip': value}))
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(ValueError, match='^invalid gluetun public IP$'):
        client.public_ip()
    assert_header_removed(run)


@pytest.mark.parametrize('response', ('x' * (gluetun.MAX_RESPONSE_BYTES + 1), None, '\ud800'))
def test_invalid_raw_response(key_file, response):
    run = FakeRun(response)
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(RuntimeError, match='^gluetun control request failed$'):
        client.vpn_status()
    assert_header_removed(run)


@pytest.mark.parametrize('error_type', (RuntimeError, OSError, ValueError))
def test_run_failure_is_sanitized_and_header_removed(key_file, error_type):
    run = FakeRun(error=error_type(API_KEY))
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    with pytest.raises(RuntimeError, match='^gluetun control request failed$') as error:
        client.vpn_status()
    assert API_KEY not in str(error.value)
    assert error.value.__suppress_context__
    assert_header_removed(run)


def test_auth_config():
    # tomllib is not needed by the product (which supports Python 3.10).
    try:
        import tomllib
    except ImportError:
        # The fixed output remains verifiable on Python 3.10 without a dependency.
        assert gluetun.gluetun_auth_config('example-role') == (
            '[[roles]]\nname = "example-role"\nauth = "apikey"\napikey = ""\n'
            'routes = ["PUT /v1/vpn/settings", "GET /v1/vpn/status", "GET /v1/publicip/ip", '
            '"GET /v1/updater/status", "PUT /v1/updater/status"]\n')
        return
    config = tomllib.loads(gluetun.gluetun_auth_config('example-role'))
    assert config == {'roles': [{'name': 'example-role', 'auth': 'apikey', 'apikey': '',
                                'routes': ['PUT /v1/vpn/settings', 'GET /v1/vpn/status',
                                           'GET /v1/publicip/ip', 'GET /v1/updater/status',
                                           'PUT /v1/updater/status']}]}


@pytest.mark.parametrize('role', (None, '', 'x' * 65, 'role\n', 'role"', 'role name', '[roles]'))
def test_bad_auth_role(role):
    with pytest.raises(ValueError, match='^invalid gluetun role name$'):
        gluetun.gluetun_auth_config(role)


def test_updater_status_and_start(key_file):
    run = FakeRun('{"status":"completed"}')
    client = gluetun.GluetunClient('http://127.0.0.1:8000', key_file, run=run)
    assert client.updater_status() == 'completed'
    assert run.calls[-1][-1] == 'http://127.0.0.1:8000/v1/updater/status'
    assert run.calls[-1][run.calls[-1].index('-X') + 1] == 'GET'
    run.response = '{"outcome":"running"}\n'
    assert client.start_update() == 'running'
    args = run.calls[-1]
    assert args[args.index('-X') + 1] == 'PUT' and args[-1] == 'http://127.0.0.1:8000/v1/updater/status'
    assert args[args.index('--data-binary') + 1] == '{"status":"running"}'
    for bad in ('{"outcome":""}', '{"outcome":"x\\u0007"}', 'already running', '{"outcome":' + '"x' * 40 + '"}',
                '{"status":"running"}'):
        run.response = bad
        with pytest.raises(ValueError):
            client.start_update()
    run.response = '{"status":"bogus"}'
    with pytest.raises(ValueError):
        client.updater_status()


def test_every_address_of_a_server_identifies_it():
    # gluetun connects to any address of the selected server.
    relays = catalog.read_gluetun_catalog(FIXTURES / 'servers.json', 'mullvad', now=NOW)
    one = 'mullvad-one.example.test'
    for endpoint in ('198.51.100.5:51820', '198.51.100.50:51820', '198.51.100.50'):
        assert catalog.server_for_peer(relays, KEY, endpoint) == one
    # 2001:db8::1 is listed for both Mullvad servers here, 2001:db8::2 for one.
    assert catalog.server_for_peer(relays, KEY, '[2001:db8::2]:51820') == one
    assert catalog.server_for_peer(relays, KEY, '2001:db8::2') == one
    assert catalog.server_for_peer(relays, KEY, '[2001:db8::1]:51820') is None
    assert catalog.server_for_peer(relays, OTHER_KEY, '[2001:db8::2]:51820') is None


@pytest.mark.parametrize('endpoint,address', [
    ('198.51.100.5:51820', '198.51.100.5'), ('198.51.100.5', '198.51.100.5'),
    ('[2001:db8::2]:51820', '2001:db8::2'), ('[2001:DB8::2]:51820', '2001:db8::2'), ('2001:db8::2', '2001:db8::2'),
    ('[2001:db8::2]', '2001:db8::2'), ('[198.51.100.5]:51820', None), ('[2001:db8::2]:0', None),
    ('[2001:db8::2]:65536', None), ('[2001:db8::2]51820', None), ('2001:db8::2]:1', None),
    ('[2001:db8::2%eth0]:1', None), ('198.51.100.05:1', None), ('x' * 65, None), (None, None),
])
def test_endpoint_address(endpoint, address):
    assert catalog.endpoint_address(endpoint) == address


def test_snapshot_entries_keep_every_address():
    relays = catalog.read_gluetun_catalog(FIXTURES / 'servers.json', 'mullvad', now=NOW)
    entry = catalog.validate_entry(catalog.snapshot_entry(relays['mullvad-one.example.test']))
    assert entry['ipv4_addrs'] == ['198.51.100.5', '198.51.100.50']
    for bad in (['198.51.100.50', '198.51.100.5'], [], ['198.51.100.5', '198.51.100.5'], ['198.51.100.5', 'x']):
        assert catalog.validate_entry(dict(entry, ipv4_addrs=bad)) is None


@pytest.mark.skipif(not REFERENCE.is_file(), reason='GLUETUN_SERVERS_JSON not set')
@pytest.mark.parametrize('provider', catalog.SUPPORTED_PROVIDERS)
def test_reference_catalogue_every_endpoint_is_identified_or_ambiguous(provider):
    relays = catalog.read_gluetun_catalog(REFERENCE, provider, now=2**63 - 1)
    owners = Counter(address for relay in relays.values() for address in catalog.relay_addresses(relay))
    checked = multi = 0
    for server_id, relay in relays.items():
        addresses = catalog.relay_addresses(relay)
        multi += len(addresses) > 1
        for address in addresses:
            endpoint = f'[{address}]:51820' if ':' in address else f'{address}:51820'
            expected = server_id if owners[address] == 1 else None
            assert catalog.server_for_peer(relays, relay['public_key'], endpoint) == expected
            checked += 1
    # Only counts reach the diagnostics.
    assert checked >= len(relays)
    if provider in ('surfshark', 'mullvad'):
        assert multi > 0

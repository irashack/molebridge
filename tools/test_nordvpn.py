"""NordVPN catalogue and egress parsing, and the key setup helper, from fixtures
only. Nothing here contacts NordVPN; curl is replaced wherever it would run."""
import copy
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from molebridge import nordvpn
from molebridge.nordvpn import (NORD_ADDRESS, NORD_INSIGHTS_URL, NORD_MAX_CATALOG_BYTES, NORD_PORT,
                                NORD_SERVERS_URL, parse_insights, parse_nord_catalog,
                                server_for_endpoint)
from molebridge.relays import valid_key

FIXTURES = Path(__file__).parent / 'fixtures' / 'nordvpn'
US, DE, UK = 'us9001.nordvpn.com', 'de9002.nordvpn.com', 'uk9003.nordvpn.com'
US_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DE_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE='
PRIVATE_KEY = 'A' * 42 + 'Q='
TOKEN = 'cafe' * 16


def load(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def data():
    return load('nordvpn-servers.json')


def add_group(data, ident, gid):
    data['groups'].append({'id': gid, 'identifier': ident, 'type': {'id': 3, 'identifier': 'legacy_group_category'}})
    return gid


def mutated(data, change):
    """The catalogue with the first (US) server changed by `change(server, data)`."""
    data = copy.deepcopy(data)
    change(data['servers'][0], data)
    return data


def wireguard(server):
    return next(t for t in server['technologies'] if t['id'] == 35)


def only_de(data, change):
    result = parse_nord_catalog(mutated(data, change))
    assert list(result) == [DE]
    return result


# -- catalogue: what is kept ---------------------------------------------------

def test_fixture_keeps_standard_servers_and_drops_dedicated_ip(data):
    result = parse_nord_catalog(data)
    assert list(result) == [US, DE]
    assert result[US] == {
        'hostname': US, 'public_key': US_KEY, 'ipv4_addr_in': '198.51.100.11', 'city': 'Dallas',
        'country': 'United States', 'country_code': 'US', 'location_code': 'us-dallas',
        'load': 12, 'virtual': False}
    assert result[DE]['country_code'] == 'DE' and result[DE]['location_code'] == 'de-berlin'
    assert all(valid_key(r['public_key']) for r in result.values())


def test_shared_location_key_is_kept_for_every_server(data):
    clone = copy.deepcopy(data['servers'][0])
    clone.update(hostname='us9004.nordvpn.com', station='198.51.100.14', id=990004)
    clone['ips'][0]['ip']['ip'] = '198.51.100.14'
    data['servers'].append(clone)
    result = parse_nord_catalog(data)
    assert result['us9004.nordvpn.com']['public_key'] == result[US]['public_key']


def test_ipv6_entries_are_ignored_entirely(data):
    def change(server, _):
        server['ips'].append({'type': 'entry', 'ip': {'ip': '2001:db8::1', 'version': 6}})
        server['ips'].append({'type': 'entry', 'ip': {'ip': 'not even an address', 'version': 6}})
    assert parse_nord_catalog(mutated(data, change))[US]['ipv4_addr_in'] == '198.51.100.11'


def test_non_entry_rows_are_ignored(data):
    def change(server, _):
        server['ips'].append({'type': 'exit', 'ip': {'ip': '198.51.100.99', 'version': 4}})
        server['ips'].append('garbage')
    assert US in parse_nord_catalog(mutated(data, change))


def test_double_vpn_style_hostnames_match(data):
    def change(server, _):
        server['hostname'] = 'uk-nl10.nordvpn.com'
    assert 'uk-nl10.nordvpn.com' in parse_nord_catalog(mutated(data, change))


@pytest.mark.parametrize('load,expected', [(0, 0), (100, 100), (101, None), (-1, None), ('5', None),
                                           (True, None), (5.0, None), (None, None)])
def test_load_is_kept_only_when_well_formed(data, load, expected):
    def change(server, _):
        server['load'] = load
    entry = parse_nord_catalog(mutated(data, change))[US]
    assert entry.get('load') == expected
    assert ('load' in entry) == (expected is not None)


def test_missing_load_is_omitted(data):
    def change(server, _):
        del server['load']
    assert 'load' not in parse_nord_catalog(mutated(data, change))[US]


def test_virtual_location_specification(data):
    def virtual(value):
        def change(server, _):
            server['specifications'].append({'identifier': 'virtual_location', 'values': [{'value': value}]})
        return change
    assert parse_nord_catalog(mutated(data, virtual('true')))[US]['virtual'] is True
    assert parse_nord_catalog(mutated(data, virtual('false')))[US]['virtual'] is False

    def malformed(server, _):
        server['specifications'] = ['x', {'identifier': 'virtual_location', 'values': 'true'}]
    assert parse_nord_catalog(mutated(data, malformed))[US]['virtual'] is False


def test_location_code_is_a_slug(data):
    def change(server, doc):
        doc['locations'][0]['country']['city']['name'] = "St. John's / Newfoundland"
    assert parse_nord_catalog(mutated(data, change))[US]['location_code'] == 'us-st-john-s-newfoundland'


# -- catalogue: what is dropped --------------------------------------------------

def set_status(status):
    def change(server, _):
        server['status'] = status
    return change


def drop_vpn_service(server, _):
    server['service_ids'] = [5]


def drop_wireguard_row(server, _):
    server['technologies'].remove(wireguard(server))


def wireguard_offline(server, _):
    wireguard(server)['status'] = 'offline'


def wireguard_no_status(server, _):
    del wireguard(server)['status']


def key_invalid(server, _):
    wireguard(server)['metadata'][0]['value'] = 'not a key'


def key_wrong_length(server, _):
    wireguard(server)['metadata'][0]['value'] = 'AAAA'


def key_not_canonical(server, _):
    wireguard(server)['metadata'][0]['value'] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB='


def key_not_string(server, _):
    wireguard(server)['metadata'][0]['value'] = 5


def key_twice(server, _):
    wireguard(server)['metadata'].append({'name': 'public_key', 'value': DE_KEY})


def key_missing(server, _):
    wireguard(server)['metadata'] = [{'name': 'other', 'value': US_KEY}]


def metadata_missing(server, _):
    del wireguard(server)['metadata']


def metadata_not_list(server, _):
    wireguard(server)['metadata'] = {'name': 'public_key', 'value': US_KEY}


def wireguard_twice(server, _):
    server['technologies'].append(copy.deepcopy(wireguard(server)))


def no_locations(server, _):
    server['location_ids'] = []


def two_locations(server, _):
    server['location_ids'] = [79, 101]


def unknown_location(server, _):
    server['location_ids'] = [12345]


def location_bool(server, _):
    server['location_ids'] = [True]


def location_string(server, _):
    server['location_ids'] = ['79']


def location_missing(server, _):
    del server['location_ids']


def blank_country_name(_, doc):
    doc['locations'][0]['country']['name'] = ''


def missing_country_name(_, doc):
    del doc['locations'][0]['country']['name']


def lowercase_country_code(_, doc):
    doc['locations'][0]['country']['code'] = 'us'


def long_country_code(_, doc):
    doc['locations'][0]['country']['code'] = 'USA'


def blank_city_name(_, doc):
    doc['locations'][0]['country']['city']['name'] = ''


def missing_city(_, doc):
    del doc['locations'][0]['country']['city']


def city_not_text(_, doc):
    doc['locations'][0]['country']['city']['name'] = 7


def city_too_long(_, doc):
    doc['locations'][0]['country']['city']['name'] = 'x' * 257


def city_control_character(_, doc):
    doc['locations'][0]['country']['city']['name'] = 'Dal\x00las'


def city_newline(_, doc):
    doc['locations'][0]['country']['city']['name'] = 'Dal\nlas'


def city_no_letters(_, doc):
    doc['locations'][0]['country']['city']['name'] = '...'


def duplicate_location_id(_, doc):
    doc['locations'].append(copy.deepcopy(doc['locations'][1]))
    doc['locations'][-1]['id'] = 79


def not_standard(server, _):
    server['group_ids'] = [15, 21]


def group_missing(server, _):
    del server['group_ids']


def excluded_group(identifier):
    def change(server, doc):
        server['group_ids'].append(add_group(doc, identifier, 500))
    return change


def no_entry_ip(server, _):
    server['ips'] = []


def ipv6_only(server, _):
    server['ips'] = [{'type': 'entry', 'ip': {'ip': '2001:db8::1', 'version': 6}}]


def two_v4_entries(server, _):
    server['ips'].append({'type': 'entry', 'ip': {'ip': '198.51.100.12', 'version': 4}})


def entry_ip_invalid(server, _):
    server['ips'][0]['ip']['ip'] = '198.51.100.011'


def entry_version_text(server, _):
    server['ips'][0]['ip']['version'] = '4'


def entry_without_ip(server, _):
    server['ips'][0]['ip'] = 'x'


def ips_not_list(server, _):
    server['ips'] = {}


def station_differs(server, _):
    server['station'] = '198.51.100.12'


def station_missing(server, _):
    del server['station']


def station_not_text(server, _):
    server['station'] = 3


def hostname(value):
    def change(server, _):
        server['hostname'] = value
    return change


DROPPED = {
    'offline': set_status('offline'), 'status missing': set_status(None),
    'no vpn service': drop_vpn_service,
    'no wireguard row': drop_wireguard_row, 'wireguard offline': wireguard_offline,
    'wireguard without status': wireguard_no_status,
    'invalid key': key_invalid, 'short key': key_wrong_length, 'non-canonical key': key_not_canonical,
    'key not text': key_not_string, 'two keys': key_twice, 'no key': key_missing,
    'no metadata': metadata_missing, 'metadata not a list': metadata_not_list,
    'two wireguard rows': wireguard_twice,
    'no location': no_locations, 'two locations': two_locations, 'unknown location': unknown_location,
    'location is a bool': location_bool, 'location is text': location_string,
    'location ids missing': location_missing,
    'blank country': blank_country_name, 'no country name': missing_country_name,
    'lowercase code': lowercase_country_code, 'three letter code': long_country_code,
    'blank city': blank_city_name, 'no city': missing_city, 'city not text': city_not_text,
    'long city': city_too_long, 'control character': city_control_character, 'newline': city_newline,
    'city without letters': city_no_letters, 'duplicate location id': duplicate_location_id,
    'not standard': not_standard, 'no groups': group_missing,
    'dedicated ip': excluded_group('legacy_dedicated_ip'), 'double vpn': excluded_group('legacy_double_vpn'),
    'onion': excluded_group('legacy_onion_over_vpn'), 'obfuscated': excluded_group('legacy_obfuscated_servers'),
    'no entry ip': no_entry_ip, 'ipv6 only': ipv6_only, 'two v4 entries': two_v4_entries,
    'invalid entry ip': entry_ip_invalid, 'version as text': entry_version_text,
    'entry ip not an object': entry_without_ip, 'ips not a list': ips_not_list,
    'station differs': station_differs, 'no station': station_missing, 'station not text': station_not_text,
    'uppercase hostname': hostname('US9001.nordvpn.com'), 'foreign domain': hostname('us9001.example.net'),
    'subdomain': hostname('a.us9001.nordvpn.com'), 'no digits': hostname('us.nordvpn.com'),
    'six digits': hostname('us123456.nordvpn.com'), 'onion hostname': hostname('ch-onion1.nordvpn.com'),
    'trailing newline': hostname('us9001.nordvpn.com\n'), 'hostname not text': hostname(9001),
}


@pytest.mark.parametrize('name', DROPPED)
def test_server_is_dropped(data, name):
    only_de(data, DROPPED[name])


def test_wireguard_technology_is_found_by_identifier_not_by_id(data):
    # Renumber the top-level row and the server's rows together.
    def change(server, doc):
        doc['technologies'][2]['id'] = 77
        wireguard(server)['id'] = 77
        for other in doc['servers'][1:]:
            wireguard(other)['id'] = 77
    assert list(parse_nord_catalog(mutated(data, change))) == [US, DE]


def test_wireguard_row_with_the_wrong_identifier_is_not_wireguard(data):
    data['technologies'][2]['identifier'] = 'openvpn_xor'
    with pytest.raises(ValueError):
        parse_nord_catalog(data)


def test_vpn_service_is_found_by_identifier_not_by_id(data):
    data['services'][0]['identifier'] = 'other'
    with pytest.raises(ValueError):
        parse_nord_catalog(data)


def test_unknown_ids_in_group_ids_are_harmless(data):
    def change(server, _):
        server['group_ids'].append(99999)
    assert US in parse_nord_catalog(mutated(data, change))


def test_dedicated_ip_fixture_server_is_dropped(data):
    assert UK not in parse_nord_catalog(data)


def test_non_object_servers_are_skipped(data):
    data['servers'] += [None, 'x', 5, [], {}]
    assert list(parse_nord_catalog(data)) == [US, DE]


# -- catalogue: errors ---------------------------------------------------------------

def test_duplicate_hostname_raises(data):
    twin = copy.deepcopy(data['servers'][0])
    twin['id'] = 990009
    data['servers'].append(twin)
    with pytest.raises(ValueError, match='duplicate'):
        parse_nord_catalog(data)


def test_duplicate_hostname_of_a_dropped_server_is_not_an_error(data):
    twin = copy.deepcopy(data['servers'][0])
    twin['status'] = 'offline'
    data['servers'].append(twin)
    assert list(parse_nord_catalog(data)) == [US, DE]


def test_empty_result_raises(data):
    data['servers'] = []
    with pytest.raises(ValueError):
        parse_nord_catalog(data)


def test_all_servers_dropped_raises(data):
    for server in data['servers']:
        server['status'] = 'offline'
    with pytest.raises(ValueError):
        parse_nord_catalog(data)


@pytest.mark.parametrize('value', [None, [], 'servers', 5, True])
def test_non_object_document_raises(value):
    with pytest.raises(ValueError):
        parse_nord_catalog(value)


@pytest.mark.parametrize('missing', ['servers', 'groups', 'services', 'locations', 'technologies'])
def test_missing_table_raises(data, missing):
    del data[missing]
    with pytest.raises(ValueError):
        parse_nord_catalog(data)


@pytest.mark.parametrize('table', ['servers', 'groups', 'services', 'locations', 'technologies'])
@pytest.mark.parametrize('value', [{}, None, 'x', 3])
def test_table_of_the_wrong_type_raises(data, table, value):
    data[table] = value
    with pytest.raises(ValueError):
        parse_nord_catalog(data)


def test_oversized_tables_raise(data, monkeypatch):
    monkeypatch.setattr(nordvpn, 'NORD_MAX_SERVERS', 2)
    with pytest.raises(ValueError, match='too large'):
        parse_nord_catalog(data)
    monkeypatch.setattr(nordvpn, 'NORD_MAX_SERVERS', 50000)
    monkeypatch.setattr(nordvpn, 'NORD_MAX_TABLE', 2)
    with pytest.raises(ValueError, match='too large'):
        parse_nord_catalog(data)


def test_malformed_table_rows_are_skipped_not_fatal(data):
    data['groups'] += [None, 'x', {'id': 'a', 'identifier': 'legacy_standard'}, {'id': True, 'identifier': 'x'}]
    data['locations'] += [None, {'id': 5}, {'id': 6, 'country': 'x'}]
    data['services'] += [None, {'id': None}]
    data['technologies'] += [None, {'id': 9, 'identifier': 4}]
    assert list(parse_nord_catalog(data)) == [US, DE]


def test_errors_never_echo_input(data):
    secret = 'SECRET-HOST-VALUE'
    data['servers'][0]['hostname'] = secret
    data['servers'][1]['status'] = secret
    data['servers'][2]['hostname'] = secret
    with pytest.raises(ValueError) as caught:
        parse_nord_catalog(data)
    assert secret not in str(caught.value)


# -- constants --------------------------------------------------------------------

def test_constants():
    assert NORD_SERVERS_URL.startswith('https://api.nordvpn.com/v2/servers?')
    assert 'limit=0' in NORD_SERVERS_URL
    assert 'filters%5Bservers_technologies%5D%5Bidentifier%5D=wireguard_udp' in NORD_SERVERS_URL
    assert '[' not in NORD_SERVERS_URL and ']' not in NORD_SERVERS_URL
    assert NORD_MAX_CATALOG_BYTES == 32 * 1024 * 1024
    assert NORD_ADDRESS == '10.5.0.2/32' and NORD_PORT == 51820
    assert NORD_INSIGHTS_URL == 'https://api.nordvpn.com/v1/helpers/ips/insights'


@pytest.mark.parametrize('name', ['us9001.nordvpn.com', 'uk-nl10.nordvpn.com', 'de1.nordvpn.com',
                                  'ca12345.nordvpn.com'])
def test_hostname_pattern_accepts(name):
    assert nordvpn.NORD_HOSTNAME_RE.fullmatch(name)


@pytest.mark.parametrize('name', ['us.nordvpn.com', 'usa1.nordvpn.com', 'us1.nordvpn.com.evil.test',
                                  'us-1.nordvpn.com', 'US1.nordvpn.com', 'us1.nordvpn.net', ''])
def test_hostname_pattern_rejects(name):
    assert not nordvpn.NORD_HOSTNAME_RE.fullmatch(name)


# -- server_for_endpoint ------------------------------------------------------------

def test_endpoint_identifies_the_server_even_with_shared_keys(data):
    clone = copy.deepcopy(data['servers'][0])
    clone.update(hostname='us9004.nordvpn.com', station='198.51.100.14')
    clone['ips'][0]['ip']['ip'] = '198.51.100.14'
    data['servers'].append(clone)
    relays = parse_nord_catalog(data)
    assert relays[US]['public_key'] == relays['us9004.nordvpn.com']['public_key']
    assert server_for_endpoint(relays, '198.51.100.11:51820') == US
    assert server_for_endpoint(relays, '198.51.100.14:51820') == 'us9004.nordvpn.com'
    assert server_for_endpoint(relays, '198.51.100.22:51820') == DE


def test_unknown_endpoint_or_wrong_port_gives_none(data):
    relays = parse_nord_catalog(data)
    assert server_for_endpoint(relays, '198.51.100.99:51820') is None
    assert server_for_endpoint(relays, '198.51.100.11:51821') is None
    assert server_for_endpoint(relays, '198.51.100.11:1337') is None


@pytest.mark.parametrize('endpoint', ['(none)', '', '198.51.100.11', '198.51.100.11:', ':51820',
                                      '198.51.100.11:051820', '198.51.100.11:51820 ', ' 198.51.100.11:51820',
                                      '198.51.100.11:51820\n', '[2001:db8::1]:51820', '2001:db8::1:51820',
                                      '198.51.100.011:51820', 'us9001.nordvpn.com:51820', None, 5, b'x'])
def test_malformed_endpoint_gives_none(data, endpoint):
    assert server_for_endpoint(parse_nord_catalog(data), endpoint) is None


def test_ambiguous_endpoint_gives_none(data):
    relays = parse_nord_catalog(data)
    relays[DE] = {**relays[DE], 'ipv4_addr_in': relays[US]['ipv4_addr_in']}
    assert server_for_endpoint(relays, '198.51.100.11:51820') is None


def test_endpoint_with_non_dict_relays_gives_none():
    assert server_for_endpoint({}, '198.51.100.11:51820') is None
    assert server_for_endpoint(None, '198.51.100.11:51820') is None
    assert server_for_endpoint({'x': 'y'}, '198.51.100.11:51820') is None


# -- parse_insights -----------------------------------------------------------------

def test_insights_protected():
    assert parse_insights(load('nordvpn-insights-protected.json')) == {
        'egress_ip': '198.51.100.11', 'egress_city': 'Dallas', 'egress_country': 'United States',
        'exit_confirmed': True}


def test_insights_unprotected():
    assert parse_insights(load('nordvpn-insights-unprotected.json')) == {
        'egress_ip': '203.0.113.84', 'egress_city': 'Exampleville', 'egress_country': 'United States',
        'exit_confirmed': False}


def test_insights_unknown_with_mixed_types():
    raw = load('nordvpn-insights-unknown.json')
    assert raw['isp_asn'] == 'Unknown' and raw['longitude'] is False
    assert parse_insights(raw) == {'egress_ip': '198.51.100.7', 'egress_city': None, 'egress_country': None,
                                   'exit_confirmed': False}


@pytest.mark.parametrize('field', ['isp_asn', 'longitude', 'latitude', 'isp', 'state_code', 'zip_code'])
@pytest.mark.parametrize('value', [None, [], {}, 'x' * 1000, '\x00', 1.5, True])
def test_insights_ignores_unused_fields_whatever_their_type(field, value):
    raw = {**load('nordvpn-insights-protected.json'), field: value}
    assert parse_insights(raw)['exit_confirmed'] is True


def test_insights_result_has_only_the_four_fields():
    assert set(parse_insights(load('nordvpn-insights-protected.json'))) == {
        'egress_ip', 'egress_city', 'egress_country', 'exit_confirmed'}


@pytest.mark.parametrize('protected', [1, 0, 'true', 'false', None, [], {}])
def test_insights_protected_must_be_a_bool(protected):
    with pytest.raises(ValueError):
        parse_insights({**load('nordvpn-insights-protected.json'), 'protected': protected})


def test_insights_protected_missing():
    raw = load('nordvpn-insights-protected.json')
    del raw['protected']
    with pytest.raises(ValueError):
        parse_insights(raw)


@pytest.mark.parametrize('address', ['2001:db8::1', '198.51.100.011', '198.51.100', 'example.test', '', None, 5,
                                     '198.51.100.7\n', ' 198.51.100.7'])
def test_insights_ip_must_be_ipv4(address):
    with pytest.raises(ValueError):
        parse_insights({**load('nordvpn-insights-protected.json'), 'ip': address})


def test_insights_ip_missing():
    raw = load('nordvpn-insights-protected.json')
    del raw['ip']
    with pytest.raises(ValueError):
        parse_insights(raw)


@pytest.mark.parametrize('field', ['city', 'country', 'country_code'])
@pytest.mark.parametrize('value', [None, 5, False, [], '', 'x' * 257, 'a\x00b', 'a\nb', 'a\x7fb'])
def test_insights_text_is_checked(field, value):
    with pytest.raises(ValueError):
        parse_insights({**load('nordvpn-insights-protected.json'), field: value})


@pytest.mark.parametrize('field', ['city', 'country', 'country_code'])
def test_insights_text_missing(field):
    raw = load('nordvpn-insights-protected.json')
    del raw[field]
    with pytest.raises(ValueError):
        parse_insights(raw)


def test_insights_text_limit_is_inclusive():
    raw = {**load('nordvpn-insights-protected.json'), 'city': 'x' * 256}
    assert parse_insights(raw)['egress_city'] == 'x' * 256


@pytest.mark.parametrize('value', [None, [], 'x', 5, True])
def test_insights_non_object_raises(value):
    with pytest.raises(ValueError):
        parse_insights(value)


def test_insights_errors_never_echo_input():
    with pytest.raises(ValueError) as caught:
        parse_insights({**load('nordvpn-insights-protected.json'), 'city': 'SECRET\x00VALUE'})
    assert 'SECRET' not in str(caught.value)


# -- tools/nordvpn-key.py -----------------------------------------------------------------

spec = importlib.util.spec_from_file_location('nordvpn_key', ROOT / 'tools' / 'nordvpn-key.py')
nk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nk)

prepare_spec = importlib.util.spec_from_file_location('prepare', ROOT / 'tools' / 'prepare-tunnel-config.py')
prepare = importlib.util.module_from_spec(prepare_spec)
prepare_spec.loader.exec_module(prepare)

CREDENTIALS = json.dumps({'id': 1, 'nordlynx_private_key': PRIVATE_KEY,
                          'username': 'u-EXAMPLE', 'password': 'p-EXAMPLE'}).encode()


class FakeNord:
    """Replaces the HTTP call; records the tokens it was given."""

    def __init__(self, response=CREDENTIALS):
        self.response = response
        self.tokens = []

    def __call__(self, token):
        self.tokens.append(token)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.fixture
def fake(monkeypatch):
    fake = FakeNord()
    monkeypatch.setattr(nk, 'fetch_credentials', fake)
    return fake


def token_file(tmp_path, mode=0o600, text=TOKEN + '\n'):
    path = tmp_path / 'token'
    path.write_text(text)
    path.chmod(mode)
    return path


def run(capsys, *args):
    code = nk.main(['nordvpn-key.py', *map(str, args)])
    out, err = capsys.readouterr()
    return code, out, err


def assert_no_secrets(*streams):
    for text in streams:
        for secret in (TOKEN, PRIVATE_KEY, 'u-EXAMPLE', 'p-EXAMPLE', 'nordlynx_private_key'):
            assert secret not in text


def test_key_tool_writes_the_tunnel_config(tmp_path, fake, capsys):
    out = tmp_path / 'wg_confs' / 'nordvpn.conf'
    code, stdout, stderr = run(capsys, token_file(tmp_path), out)
    assert code == 0 and stderr == ''
    assert stdout == nk.OK_LINE + '\n'
    assert fake.tokens == [TOKEN]
    assert_no_secrets(stdout, stderr)
    text = out.read_text()
    sections = prepare.parse_wireguard_conf(text)
    assert sections['Interface']['PrivateKey'] == PRIVATE_KEY
    assert sections['Interface']['Address'] == '10.5.0.2/32'
    assert sections['Interface']['Table'] == 'off'
    assert sections['Interface']['MTU'] == '1420'
    assert sections['Peer'] == {}
    assert '[Peer]' not in text and 'DNS' not in text and 'Endpoint' not in text
    assert 'ip route replace default dev %i table ' + prepare.EXIT_TABLE in text
    assert 'ip -6' not in text


def test_config_matches_the_mullvad_format_without_the_peer():
    mullvad = prepare.build_tunnel_conf(
        f'[Interface]\nPrivateKey = {PRIVATE_KEY}\nAddress = 192.0.2.2/32\n'
        f'[Peer]\nPublicKey = {US_KEY}\nEndpoint = 198.51.100.10:51820\n')
    nord = nk.build_nord_conf(PRIVATE_KEY, prepare.EXIT_TABLE)
    interface = lambda text: [line for line in text.splitlines()[1:] if line.split(' = ')[0] in (
        'PrivateKey', 'MTU', 'Table', 'PostUp', 'PreDown')]
    assert interface(nord) == interface(mullvad)


@pytest.mark.skipif(not hasattr(os, 'fchmod'), reason='POSIX file permissions required')
def test_output_is_mode_0600_whatever_the_umask(tmp_path, fake, capsys):
    out = tmp_path / 'nordvpn.conf'
    old = os.umask(0)
    try:
        assert run(capsys, token_file(tmp_path), out)[0] == 0
    finally:
        os.umask(old)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_token_file_with_loose_mode_is_refused(tmp_path, fake, capsys):
    out = tmp_path / 'nordvpn.conf'
    for mode in (0o640, 0o604, 0o660, 0o644, 0o666, 0o601):
        code, stdout, stderr = run(capsys, token_file(tmp_path, mode), out)
        assert code == 1 and stdout == ''
        assert '0600' in stderr
        assert_no_secrets(stdout, stderr)
    assert fake.tokens == [] and not out.exists()


@pytest.mark.parametrize('mode', [0o600, 0o400])
def test_token_file_with_strict_mode_is_accepted(tmp_path, fake, capsys, mode):
    assert run(capsys, token_file(tmp_path, mode), tmp_path / 'out.conf')[0] == 0
    assert fake.tokens == [TOKEN]


def test_token_file_that_is_not_a_regular_file_is_refused(tmp_path, fake, capsys):
    target = token_file(tmp_path)
    link = tmp_path / 'link'
    link.symlink_to(target)
    for source in (link, tmp_path, tmp_path / 'missing'):
        code, stdout, stderr = run(capsys, source, tmp_path / 'out.conf')
        assert code == 1 and stdout == ''
        assert_no_secrets(stdout, stderr)
    assert fake.tokens == []


def test_token_from_stdin(tmp_path, fake, capsys, monkeypatch):
    monkeypatch.setattr(sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(TOKEN.encode() + b'\n')))
    out = tmp_path / 'out.conf'
    code, stdout, stderr = run(capsys, '-', out)
    assert code == 0 and fake.tokens == [TOKEN]
    assert_no_secrets(stdout, stderr)
    assert PRIVATE_KEY in out.read_text()


@pytest.mark.parametrize('content', [b'', b'\n', b'has space\n', b'two\nlines\n', b'quo"te', b'back\\slash',
                                     b'\xff\xfe', b'x' * 513, b'tab\there', b'a\x00b'])
def test_bad_token_text_is_refused(tmp_path, fake, capsys, monkeypatch, content):
    monkeypatch.setattr(sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(content)))
    out = tmp_path / 'out.conf'
    code, stdout, stderr = run(capsys, '-', out)
    assert code == 1 and stdout == '' and fake.tokens == [] and not out.exists()
    assert 'error:' in stderr and 'x' * 20 not in stderr


def test_existing_output_is_refused_and_untouched(tmp_path, fake, capsys):
    out = tmp_path / 'nordvpn.conf'
    out.write_text('existing')
    code, stdout, stderr = run(capsys, token_file(tmp_path), out)
    assert code == 1 and stdout == '' and 'exists' in stderr
    assert out.read_text() == 'existing'
    assert fake.tokens == []


def test_dangling_symlink_output_is_refused(tmp_path, fake, capsys):
    out = tmp_path / 'nordvpn.conf'
    out.symlink_to(tmp_path / 'elsewhere')
    assert run(capsys, token_file(tmp_path), out)[0] == 1
    assert not (tmp_path / 'elsewhere').exists() and fake.tokens == []


def test_write_new_never_replaces(tmp_path):
    out = tmp_path / 'nordvpn.conf'
    nk.write_new(out, 'first')
    with pytest.raises(nk.NordKeyError):
        nk.write_new(out, 'second')
    assert out.read_text() == 'first'


@pytest.mark.parametrize('response', [
    b'', b'not json', b'[]', b'{}', b'null',
    json.dumps({'nordlynx_private_key': 'short'}).encode(),
    json.dumps({'nordlynx_private_key': None}).encode(),
    json.dumps({'nordlynx_private_key': 7}).encode(),
    json.dumps({'nordlynx_private_key': PRIVATE_KEY[:-2] + 'R='}).encode(),
    json.dumps({'private_key': PRIVATE_KEY}).encode(),
    b'{"nordlynx_private_key": "' + PRIVATE_KEY.encode() + b'", "nordlynx_private_key": "x"}',
    b'\xff\xfe',
])
def test_unusable_responses_write_nothing(tmp_path, capsys, monkeypatch, response):
    monkeypatch.setattr(nk, 'fetch_credentials', FakeNord(response))
    out = tmp_path / 'out.conf'
    code, stdout, stderr = run(capsys, token_file(tmp_path), out)
    assert code == 1 and stdout == '' and not out.exists()
    assert 'error:' in stderr
    assert_no_secrets(stdout, stderr)


def test_failed_request_writes_nothing_and_prints_a_fixed_line(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(nk, 'fetch_credentials', FakeNord(nk.NordKeyError('the request to NordVPN failed')))
    out = tmp_path / 'out.conf'
    code, stdout, stderr = run(capsys, token_file(tmp_path), out)
    assert (code, stdout, stderr) == (1, '', 'error: the request to NordVPN failed\n')
    assert not out.exists()


def test_unexpected_error_does_not_echo_its_message(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(nk, 'fetch_credentials', FakeNord(ValueError(f'leaked {TOKEN} {PRIVATE_KEY}')))
    code, stdout, stderr = run(capsys, token_file(tmp_path), tmp_path / 'out.conf')
    assert code == 1
    assert_no_secrets(stdout, stderr)


def test_usage_error(capsys):
    for args in ((), ('only-one',), ('a', 'b', 'c')):
        assert run(capsys, *args)[0] == 2


def test_token_is_never_taken_from_the_environment(tmp_path, fake, capsys, monkeypatch):
    monkeypatch.setenv('NORDVPN_TOKEN', TOKEN)
    monkeypatch.setenv('NORD_TOKEN', TOKEN)
    assert run(capsys, tmp_path / 'missing', tmp_path / 'out.conf')[0] == 1
    assert fake.tokens == []


def test_fetch_passes_the_credential_only_in_a_private_file(monkeypatch):
    seen = {}

    def fake_run(args, **kwargs):
        seen['args'] = args
        seen['kwargs'] = kwargs
        config = Path(args[args.index('--config') + 1])
        seen['config'] = config
        seen['mode'] = stat.S_IMODE(config.stat().st_mode)
        seen['text'] = config.read_text()
        return subprocess.CompletedProcess(args, 0, stdout=CREDENTIALS, stderr=b'')

    monkeypatch.setattr(nk.subprocess, 'run', fake_run)
    assert nk.fetch_credentials(TOKEN) == CREDENTIALS
    args = seen['args']
    assert TOKEN not in ' '.join(args)
    assert args[0] == 'curl' and args[1] == '-q'
    assert args[args.index('--proto') + 1] == '=https'
    assert '--max-filesize' in args and '--max-time' in args
    assert args[-1] == 'https://api.nordvpn.com/v1/users/services/credentials'
    assert seen['kwargs']['stdin'] is subprocess.DEVNULL and seen['kwargs']['timeout'] > 0
    assert seen['mode'] == 0o600
    assert seen['text'] == f'user = "token:{TOKEN}"\n'
    assert not seen['config'].exists()


@pytest.mark.parametrize('outcome', [
    subprocess.CompletedProcess([], 22, stdout=b'', stderr=b'curl: (22) ' + TOKEN.encode()),
    subprocess.CompletedProcess([], 0, stdout=b'x' * (nk.RESPONSE_MAX_BYTES + 1), stderr=b''),
    OSError('curl missing ' + TOKEN),
    subprocess.TimeoutExpired('curl', 25),
])
def test_fetch_failure_is_a_fixed_error_and_cleans_up(monkeypatch, outcome):
    paths = []

    def fake_run(args, **kwargs):
        paths.append(Path(args[args.index('--config') + 1]))
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(nk.subprocess, 'run', fake_run)
    with pytest.raises(nk.NordKeyError) as caught:
        nk.fetch_credentials(TOKEN)
    assert str(caught.value) == 'the request to NordVPN failed'
    assert TOKEN not in repr(caught.value)
    assert paths and not paths[0].exists()


def test_script_runs_standalone_and_fails_closed(tmp_path):
    out = tmp_path / 'out.conf'
    done = subprocess.run([sys.executable, str(ROOT / 'tools' / 'nordvpn-key.py'), str(tmp_path / 'missing'), str(out)],
                          capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL, check=False)
    assert done.returncode == 1 and done.stdout == ''
    assert done.stderr == 'error: the token could not be read\n'
    assert not out.exists()

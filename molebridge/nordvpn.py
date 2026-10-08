"""NordVPN catalogue and egress parsing.

NordVPN's server list and its egress check are untrusted input, like Mullvad's
relay list. This module only parses; it fetches nothing and touches no
tunnel. The caller keeps its last good catalogue when a parse raises
ValueError. The applier side is applier/nordvpn.py.

NordLynx server keys belong to a location, not a server, so many servers share
one key. A server is therefore identified by the endpoint address of the live
peer (`server_for_endpoint`), never by its key.
"""
from __future__ import annotations

import re
import unicodedata

from molebridge.validate import decode_json, valid_ipv4, valid_key

# The v2 list, filtered server-side to WireGuard servers. The brackets are
# percent-encoded so curl needs no `-g`. The filtered response is about 8 MB.
NORD_SERVERS_URL = ('https://api.nordvpn.com/v2/servers?limit=0'
                    '&filters%5Bservers_technologies%5D%5Bidentifier%5D=wireguard_udp')
NORD_MAX_CATALOG_BYTES = 32 * 1024 * 1024
# Every NordLynx server shares one tunnel address and one port.
NORD_ADDRESS = '10.5.0.2/32'
NORD_PORT = 51820
NORD_INSIGHTS_URL = 'https://api.nordvpn.com/v1/helpers/ips/insights'

NORD_HOSTNAME_RE = re.compile(r'[a-z]{2}(-[a-z]{2})?[0-9]{1,5}\.nordvpn\.com')
NORD_COUNTRY_CODE_RE = re.compile(r'[A-Z]{2}')
NORD_LOCATION_CODE_RE = re.compile(r'[a-z]{2}-[a-z0-9]+(-[a-z0-9]+)*')
NORD_MAX_SERVERS = 50000
NORD_MAX_TABLE = 10000
TEXT_MAX = 256

WIREGUARD = 'wireguard_udp'
VPN_SERVICE = 'vpn'
# NordVPN's server groups that decide whether an account key can use a
# server: identifier (in NordVPN's API, which the native catalogue reads) ->
# title (which gluetun stores as the server's categories,
# internal/provider/nordvpn/updater/models.go:147-157 at v3.41.3). A server
# must be in the standard group and in none of the excluded ones: dedicated
# IP servers need their own purchase, and the others need other connection
# settings.
GROUP_TITLES = {'legacy_standard': 'Standard VPN servers', 'legacy_dedicated_ip': 'Dedicated IP',
                'legacy_double_vpn': 'Double VPN', 'legacy_onion_over_vpn': 'Onion Over VPN',
                'legacy_obfuscated_servers': 'Obfuscated Servers'}
STANDARD_GROUP = 'legacy_standard'
EXCLUDED_GROUPS = frozenset({'legacy_dedicated_ip', 'legacy_double_vpn',
                             'legacy_onion_over_vpn', 'legacy_obfuscated_servers'})
STANDARD_TITLE = GROUP_TITLES[STANDARD_GROUP]
EXCLUDED_TITLES = frozenset(GROUP_TITLES[group] for group in EXCLUDED_GROUPS)


def selectable_by_titles(titles):
    """The native rule on gluetun's category titles."""
    return STANDARD_TITLE in titles and not set(titles) & EXCLUDED_TITLES
UNKNOWN = 'Unknown'


def is_int(value):
    return type(value) is int


def clean_text(value):
    """Non-empty text of at most 256 characters with no control or surrogate characters."""
    return (isinstance(value, str) and 0 < len(value) <= TEXT_MAX
            and all(unicodedata.category(c) not in ('Cc', 'Cs', 'Zl', 'Zp') for c in value))


def id_map(rows, valid):
    """{id: rows[field]} for well-formed rows. An id that appears twice is
    ambiguous, so it resolves to nothing."""
    result, ambiguous = {}, set()
    for row in rows:
        if not isinstance(row, dict) or not is_int(row.get('id')):
            continue
        value = valid(row)
        if value is None:
            continue
        if row['id'] in result:
            ambiguous.add(row['id'])
        result[row['id']] = value
    for key in ambiguous:
        del result[key]
    return result


def identifier_of(row):
    ident = row.get('identifier')
    return ident if clean_text(ident) else None


def location_of(row):
    country = row.get('country')
    if not isinstance(country, dict):
        return None
    city = country.get('city')
    code = country.get('code')
    if not isinstance(city, dict) or not clean_text(country.get('name')) or not clean_text(city.get('name')):
        return None
    if not isinstance(code, str) or not NORD_COUNTRY_CODE_RE.fullmatch(code):
        return None
    return {'country': country['name'], 'country_code': code, 'city': city['name']}


def int_list(value):
    if not isinstance(value, list) or not all(is_int(v) for v in value):
        return None
    return value


def slug(text):
    return re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')


def entry_address(ips):
    """The server's single IPv4 entry address, or None. IPv6 rows are ignored."""
    if not isinstance(ips, list):
        return None
    found = []
    for row in ips:
        if not isinstance(row, dict) or row.get('type') != 'entry':
            continue
        address = row.get('ip')
        if not isinstance(address, dict) or not is_int(address.get('version')):
            return None
        if address['version'] != 4:
            continue
        if not valid_ipv4(address.get('ip')):
            return None
        found.append(address['ip'])
    return found[0] if len(found) == 1 else None


def wireguard_key(technologies, wireguard_ids):
    """The public key of the server's one online WireGuard technology row."""
    if not isinstance(technologies, list):
        return None
    rows = [t for t in technologies
            if isinstance(t, dict) and is_int(t.get('id')) and t['id'] in wireguard_ids]
    if len(rows) != 1 or rows[0].get('status') != 'online':
        return None
    metadata = rows[0].get('metadata')
    if not isinstance(metadata, list):
        return None
    keys = [m.get('value') for m in metadata if isinstance(m, dict) and m.get('name') == 'public_key']
    return keys[0] if len(keys) == 1 and valid_key(keys[0]) else None


def is_virtual(specifications):
    if not isinstance(specifications, list):
        return False
    for spec in specifications:
        if isinstance(spec, dict) and spec.get('identifier') == 'virtual_location' \
                and isinstance(spec.get('values'), list):
            return any(isinstance(v, dict) and v.get('value') == 'true' for v in spec['values'])
    return False


def parse_server(server, tables):
    if not isinstance(server, dict) or server.get('status') != 'online':
        return None
    host = server.get('hostname')
    if not isinstance(host, str) or not NORD_HOSTNAME_RE.fullmatch(host):
        return None
    groups, services, locations, wireguard_ids = tables
    group_ids, service_ids, location_ids = (int_list(server.get(k))
                                            for k in ('group_ids', 'service_ids', 'location_ids'))
    if group_ids is None or service_ids is None or location_ids is None:
        return None
    if VPN_SERVICE not in {services.get(i) for i in service_ids}:
        return None
    names = {groups.get(i) for i in group_ids}
    if STANDARD_GROUP not in names or names & EXCLUDED_GROUPS:
        return None
    if len(location_ids) != 1 or location_ids[0] not in locations:
        return None
    location = locations[location_ids[0]]
    key = wireguard_key(server.get('technologies'), wireguard_ids)
    address = entry_address(server.get('ips'))
    # The station is what a switch connects to; it must agree with the entry IP.
    if key is None or address is None or server.get('station') != address:
        return None
    code = slug(location['city'])
    if not code:
        return None
    relay = {'hostname': host, 'public_key': key, 'ipv4_addr_in': address,
             'city': location['city'], 'country': location['country'],
             'country_code': location['country_code'],
             'location_code': f"{location['country_code'].lower()}-{code}"}
    load = server.get('load')
    if is_int(load) and 0 <= load <= 100:
        relay['load'] = load
    relay['virtual'] = is_virtual(server.get('specifications'))
    return relay


def parse_nord_catalog(data):
    """{hostname: relay} from the decoded `GET /v2/servers` response.

    Raises ValueError for a malformed document, a duplicate hostname or an
    empty result; the caller then keeps its last good catalogue."""
    if not isinstance(data, dict):
        raise ValueError('catalogue is not an object')
    lists = {k: data.get(k) for k in ('servers', 'groups', 'services', 'locations', 'technologies')}
    if not all(isinstance(v, list) for v in lists.values()):
        raise ValueError('catalogue is missing a list')
    if len(lists['servers']) > NORD_MAX_SERVERS or any(
            len(lists[k]) > NORD_MAX_TABLE for k in ('groups', 'services', 'locations', 'technologies')):
        raise ValueError('catalogue is too large')
    tables = (id_map(lists['groups'], identifier_of),
              id_map(lists['services'], identifier_of),
              id_map(lists['locations'], location_of),
              {i for i, name in id_map(lists['technologies'], identifier_of).items()
               if name == WIREGUARD})
    entries = {}
    for server in lists['servers']:
        relay = parse_server(server, tables)
        if relay:
            if relay['hostname'] in entries:
                raise ValueError('duplicate relay hostname')
            entries[relay['hostname']] = relay
    if not entries:
        raise ValueError('no usable servers')
    return entries


def parse_catalog(raw, *, port_forward_only=False):
    """{hostname: relay} from the raw response body. NordVPN has no port forwarding."""
    return parse_nord_catalog(decode_json(raw))


def validate_entry(entry):
    """A relay as stored in the snapshot (what parse_server produced), or None."""
    if not isinstance(entry, dict):
        return None
    host = entry.get('hostname')
    if not isinstance(host, str) or not NORD_HOSTNAME_RE.fullmatch(host):
        return None
    if not valid_key(entry.get('public_key')) or not valid_ipv4(entry.get('ipv4_addr_in')):
        return None
    if not clean_text(entry.get('city')) or not clean_text(entry.get('country')):
        return None
    if not isinstance(entry.get('country_code'), str) or not NORD_COUNTRY_CODE_RE.fullmatch(entry['country_code']):
        return None
    code = entry.get('location_code')
    if not isinstance(code, str) or len(code) > TEXT_MAX or not NORD_LOCATION_CODE_RE.fullmatch(code):
        return None
    if type(entry.get('virtual')) is not bool:
        return None
    result = {k: entry[k] for k in ('hostname', 'public_key', 'ipv4_addr_in', 'city', 'country',
                                    'country_code', 'location_code')}
    load = entry.get('load')
    if is_int(load) and 0 <= load <= 100:
        result['load'] = load
    result['virtual'] = entry['virtual']
    return result


def chip_label(hostname):
    """Short chip label: 'us9001.nordvpn.com' -> 'us9001'."""
    return hostname.split('.', 1)[0]


def details(info):
    """'virtual location · load 12%' where the catalogue says so."""
    parts = []
    if info.get('virtual') is True:
        parts.append('virtual location')
    if is_int(info.get('load')):
        parts.append(f"load {info['load']}%")
    return ' · '.join(parts)


def server_for_endpoint(relays, endpoint):
    """The hostname of the one relay whose address and port are the live peer
    endpoint (`ip:port`, as `wg show <interface> endpoints` prints it), or None."""
    if not isinstance(relays, dict) or not isinstance(endpoint, str):
        return None
    address, _, port = endpoint.rpartition(':')
    if port != str(NORD_PORT) or not valid_ipv4(address):
        return None
    matches = [host for host, relay in relays.items()
               if isinstance(relay, dict) and relay.get('ipv4_addr_in') == address]
    return matches[0] if len(matches) == 1 and isinstance(matches[0], str) else None


def insight_text(value):
    if value == UNKNOWN:
        return None
    if not clean_text(value):
        raise ValueError('invalid egress text')
    return value


def parse_insights(data):
    """Egress details from the decoded `ips/insights` response.

    NordVPN answers with "Unknown" strings and mistyped numbers for an address
    it has no data on; only the fields used here are checked."""
    if not isinstance(data, dict):
        raise ValueError('egress response is not an object')
    if type(data.get('protected')) is not bool or not valid_ipv4(data.get('ip')):
        raise ValueError('invalid egress response')
    city, country = insight_text(data.get('city')), insight_text(data.get('country'))
    insight_text(data.get('country_code'))  # checked like the others; the panel has no use for it
    return {'egress_ip': data['ip'], 'egress_city': city, 'egress_country': country,
            'exit_confirmed': data['protected']}

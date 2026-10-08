"""PIA's region list: one entry per region, each with the WireGuard servers
the applier may register its key on. PIA returns a server's key only from
that authenticated registration (applier/pia.py). Untrusted input; this
module only parses it."""
from __future__ import annotations

import re

from molebridge.validate import decode_json, valid_ipv4, valid_text

# The first line is the JSON region list; a signature follows it.
PIA_SERVERLIST_URL = 'https://serverlist.piaservers.net/vpninfo/servers/v6'
REGION_RE = re.compile(r'[a-z0-9][a-z0-9_-]{0,47}')
PIA_COUNTRY_RE = re.compile(r'[A-Z]{2}')
# The TLS name each server presents; the applier verifies it against PIA's CA.
PIA_CN_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,62}')
PIA_MAX_SERVERS = 16
# Region names start with a country prefix ("US East"), except where PIA
# writes the whole country ("Morocco"). These prefixes differ from the code.
PIA_NAME_PREFIX = {'GB': 'UK'}
# Countries PIA lists only with a prefixed region name.
PIA_COUNTRY_NAMES = {'AU': 'Australia', 'CA': 'Canada', 'DE': 'Germany', 'ES': 'Spain',
                     'FI': 'Finland', 'FR': 'France', 'GB': 'United Kingdom', 'IL': 'Israel',
                     'IT': 'Italy', 'JP': 'Japan', 'NL': 'Netherlands', 'SE': 'Sweden',
                     'US': 'United States'}


def validate_pia_servers(servers):
    if not isinstance(servers, list) or not 0 < len(servers) <= PIA_MAX_SERVERS:
        return None
    result = []
    for server in servers:
        if not isinstance(server, dict) or not valid_ipv4(server.get('ip')):
            return None
        if not isinstance(server.get('cn'), str) or not PIA_CN_RE.fullmatch(server['cn']):
            return None
        result.append({'ip': server['ip'], 'cn': server['cn']})
    return result


def validate_pia_entry(entry):
    """A PIA region as stored in the snapshot. `ipv4_addr_in` is the latency
    target; switching uses only `servers`."""
    if not isinstance(entry, dict):
        return None
    name = entry.get('hostname')
    if not isinstance(name, str) or not REGION_RE.fullmatch(name):
        return None
    if not all(valid_text(entry.get(k)) for k in ('city', 'country', 'location_code')):
        return None
    if not valid_ipv4(entry.get('ipv4_addr_in')):
        return None
    servers = validate_pia_servers(entry.get('servers'))
    if servers is None or any(type(entry.get(k)) is not bool for k in ('port_forward', 'geo')):
        return None
    return {**{k: entry[k] for k in ('hostname', 'city', 'country', 'location_code', 'ipv4_addr_in',
                                     'port_forward', 'geo')}, 'servers': servers}


def pia_names(regions):
    """(country name, place name) per region id, from PIA's display names."""
    countries = dict(PIA_COUNTRY_NAMES)
    for region in regions:
        code, name = region['country'], region['name']
        if not name.startswith(PIA_NAME_PREFIX.get(code, code) + ' '):
            # An unprefixed name is the country itself; keep the shortest.
            if code not in PIA_COUNTRY_NAMES and len(name) < len(countries.get(code, name + ' ')):
                countries[code] = name
    names = {}
    for region in regions:
        code, name = region['country'], region['name']
        prefix = PIA_NAME_PREFIX.get(code, code) + ' '
        place = name[len(prefix):] if name.startswith(prefix) else name
        names[region['id']] = (countries.get(code, code), place)
    return names


def parse_pia_response(data, *, port_forward_only=False):
    if not isinstance(data, dict) or not isinstance(data.get('regions'), list):
        raise ValueError('missing regions list')
    regions = []
    for region in data['regions']:
        if not isinstance(region, dict) or region.get('offline') is not False:
            continue
        if not isinstance(region.get('id'), str) or not REGION_RE.fullmatch(region['id']):
            continue
        if not isinstance(region.get('country'), str) or not PIA_COUNTRY_RE.fullmatch(region['country']):
            continue
        if not valid_text(region.get('name')) or len(region['name']) > 64:
            continue
        if any(type(region.get(k)) is not bool for k in ('port_forward', 'geo')):
            continue
        if port_forward_only and not region['port_forward']:
            continue
        servers = region.get('servers')
        wg = validate_pia_servers(servers.get('wg')) if isinstance(servers, dict) else None
        if wg is None:
            continue
        meta = validate_pia_servers(servers.get('meta')) if isinstance(servers.get('meta'), list) else None
        regions.append({**region, 'wg': wg, 'meta': meta})
    names = pia_names(regions)
    entries = {}
    for region in regions:
        country, place = names[region['id']]
        entry = validate_pia_entry({
            'hostname': region['id'], 'country': country, 'city': place,
            'location_code': region['country'].lower() + '-' + region['id'],
            # PIA's own tooling measures latency against the region's meta server.
            'ipv4_addr_in': (region['meta'] or region['wg'])[0]['ip'],
            'port_forward': region['port_forward'], 'geo': region['geo'], 'servers': region['wg']})
        if entry:
            if entry['hostname'] in entries:
                raise ValueError('duplicate region id')
            entries[entry['hostname']] = entry
    return entries


def parse_catalog(raw, *, port_forward_only=False):
    # Only the first line is JSON; the signature after it is not parsed.
    first = raw.split('\n', 1)[0] if isinstance(raw, str) else raw
    return parse_pia_response(decode_json(first), port_forward_only=port_forward_only)


def details(info):
    return ' · '.join(label for key, label in (('port_forward', 'port forwarding'),
                                               ('geo', 'virtual location')) if info.get(key) is True)

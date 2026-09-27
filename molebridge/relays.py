"""The applier owns the relay catalogue; the panel can only read its snapshot.

Two providers are supported. A Mullvad catalogue lists relays, each with the
WireGuard key and endpoint a switch applies. A PIA catalogue lists regions,
each with the WireGuard servers the applier may register its key on; PIA
returns a server's key only from that authenticated registration.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from pathlib import Path

from molebridge.state import (CATALOG_MAX_AGE, HOSTNAME_RE, SERVER_NAME_RE,
                              decode_json, now_iso, read_json, recent, write_json_atomic)

MULLVAD_RELAYS_URL = 'https://api.mullvad.net/app/v1/relays'
# The first line is the JSON region list; a signature follows it.
PIA_SERVERLIST_URL = 'https://serverlist.piaservers.net/vpninfo/servers/v6'
CATALOG_URL = {'mullvad': MULLVAD_RELAYS_URL, 'pia': PIA_SERVERLIST_URL}
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
REFRESH_INTERVAL_S = 6 * 60 * 60
# Mullvad-owned hardware; stboot means the relay runs from RAM.
OPTIONAL_FLAGS = ('owned', 'stboot')


def valid_key(value):
    if not isinstance(value, str):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32 and base64.b64encode(raw).decode() == value
    except ValueError:
        return False


def valid_ipv4(value):
    try:
        return isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def valid_text(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and all(ord(c) >= 32 for c in value)


def validate_entry(entry, provider='mullvad'):
    if provider == 'pia':
        return validate_pia_entry(entry)
    if not isinstance(entry, dict):
        return None
    host = entry.get('hostname')
    if not isinstance(host, str) or not HOSTNAME_RE.fullmatch(host):
        return None
    if not valid_key(entry.get('public_key')) or not valid_ipv4(entry.get('ipv4_addr_in')):
        return None
    if not all(valid_text(entry.get(k)) for k in ('city', 'country', 'location_code')):
        return None
    result = {k: entry[k] for k in ('hostname', 'public_key', 'ipv4_addr_in', 'city', 'country', 'location_code')}
    # Optional display attributes: kept only when well formed, never required.
    result.update({k: entry[k] for k in OPTIONAL_FLAGS if type(entry.get(k)) is bool})
    if valid_text(entry.get('provider')) and len(entry['provider']) <= 64:
        result['provider'] = entry['provider']
    return result


def parse_relay_response(data):
    if not isinstance(data, dict) or not isinstance(data.get('locations'), dict):
        raise ValueError('missing locations map')
    wireguard = data.get('wireguard')
    if not isinstance(wireguard, dict) or not isinstance(wireguard.get('relays'), list):
        raise ValueError('missing wireguard relays')
    entries = {}
    for relay in wireguard['relays']:
        if not isinstance(relay, dict) or relay.get('active') is not True:
            continue
        code = relay.get('location')
        loc = data['locations'].get(code) if isinstance(code, str) else None
        if not isinstance(loc, dict):
            continue
        entry = validate_entry({**relay, 'city': loc.get('city'), 'country': loc.get('country'), 'location_code': code})
        if entry:
            if entry['hostname'] in entries:
                raise ValueError('duplicate relay hostname')
            entries[entry['hostname']] = entry
    return entries


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
    if not isinstance(name, str) or not SERVER_NAME_RE['pia'].fullmatch(name):
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
        if not isinstance(region.get('id'), str) or not SERVER_NAME_RE['pia'].fullmatch(region['id']):
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


def parse_catalog(raw, provider='mullvad', *, port_forward_only=False):
    if provider == 'pia':
        # Only the first line is JSON; the signature after it is not parsed.
        first = raw.split('\n', 1)[0] if isinstance(raw, str) else raw
        return parse_pia_response(decode_json(first), port_forward_only=port_forward_only)
    return parse_relay_response(decode_json(raw))


def snapshot_relays(snapshot, provider='mullvad'):
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get('relays'), dict):
        return {}
    # A snapshot written before providers existed is a Mullvad catalogue.
    if snapshot.get('provider', 'mullvad') != provider:
        return {}
    entries = {}
    for host, raw in snapshot['relays'].items():
        entry = validate_entry(raw, provider)
        if entry and host == entry['hostname']:
            entries[host] = entry
    return entries


class RelayCatalog:
    def __init__(self, directory: Path, provider='mullvad', *, port_forward_only=False):
        self.path = directory / 'relays.json'
        self.error_path = directory / 'relay-error.json'
        self.provider = provider
        self.port_forward_only = port_forward_only
        snapshot = read_json(self.path)
        self.snapshot = snapshot if isinstance(snapshot, dict) else {}
        self.relays = snapshot_relays(self.snapshot, provider)
        if self.port_forward_only:
            self.relays = {k: v for k, v in self.relays.items() if v.get('port_forward') is True}

    def usable(self):
        return bool(self.relays) and recent(self.snapshot.get('fetched_at'), CATALOG_MAX_AGE)

    def refresh(self, fetch):
        try:
            entries = parse_catalog(fetch(), self.provider, port_forward_only=self.port_forward_only)
            if not entries:
                raise ValueError('relay list is empty')
            snapshot = {'fetched_at': now_iso(), 'provider': self.provider, 'relays': entries}
            write_json_atomic(self.path, snapshot, public=True)
            self.snapshot, self.relays = snapshot, entries
            write_json_atomic(self.error_path, {}, public=True)
            return True
        except (OSError, ValueError, RuntimeError, UnicodeError, RecursionError):
            # Never log remote data, addresses or exception bodies.
            write_json_atomic(self.error_path, {'message': 'Relay refresh failed; retaining the last good catalogue.',
                                               'checked_at': now_iso()}, public=True)
            return False

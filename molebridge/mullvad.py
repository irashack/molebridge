"""Mullvad's relay list: one entry per relay, each with the WireGuard key and
endpoint a switch applies. Untrusted input; this module only parses it."""
from __future__ import annotations

import re

from molebridge.validate import decode_json, valid_ipv4, valid_key, valid_text

MULLVAD_RELAYS_URL = 'https://api.mullvad.net/app/v1/relays'
HOSTNAME_RE = re.compile(r'[a-z0-9-]{1,40}-wg-[0-9]{3}')
# Mullvad-owned hardware; stboot means the relay runs from RAM.
OPTIONAL_FLAGS = ('owned', 'stboot')


def validate_entry(entry):
    """A relay as stored in the snapshot, or None."""
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


def parse_catalog(raw, *, port_forward_only=False):
    """{hostname: relay} from the raw response body."""
    return parse_relay_response(decode_json(raw))


def chip_label(hostname):
    """Short chip label: 'se-sto-wg-001' -> 'wg-001'."""
    marker = hostname.rfind('-wg-')
    return hostname[marker + 1:] if marker >= 0 else hostname


def details(info):
    """Hosting summary such as 'Example Hosting · rented · RAM-only'."""
    parts = []
    if isinstance(info.get('provider'), str):
        parts.append(str(info['provider']))
    if isinstance(info.get('owned'), bool):
        parts.append('Mullvad-owned' if info['owned'] else 'rented')
    if info.get('stboot') is True:
        parts.append('RAM-only')
    return ' · '.join(parts)

"""The applier owns the relay catalogue; the panel can only read its snapshot."""
from __future__ import annotations

import base64
import ipaddress
from pathlib import Path

from molebridge.state import (CATALOG_MAX_AGE, HOSTNAME_RE,
                              decode_json, now_iso, read_json, recent, write_json_atomic)

MULLVAD_RELAYS_URL = 'https://api.mullvad.net/app/v1/relays'
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


def validate_entry(entry):
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


def snapshot_relays(snapshot):
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get('relays'), dict):
        return {}
    entries = {}
    for host, raw in snapshot['relays'].items():
        entry = validate_entry(raw)
        if entry and host == entry['hostname']:
            entries[host] = entry
    return entries


class RelayCatalog:
    def __init__(self, directory: Path):
        self.path = directory / 'relays.json'
        self.error_path = directory / 'relay-error.json'
        snapshot = read_json(self.path)
        self.snapshot = snapshot if isinstance(snapshot, dict) else {}
        self.relays = snapshot_relays(self.snapshot)

    def usable(self):
        return bool(self.relays) and recent(self.snapshot.get('fetched_at'), CATALOG_MAX_AGE)

    def refresh(self, fetch):
        try:
            entries = parse_relay_response(decode_json(fetch()))
            if not entries:
                raise ValueError('relay list is empty')
            snapshot = {'fetched_at': now_iso(), 'relays': entries}
            write_json_atomic(self.path, snapshot, public=True)
            self.snapshot, self.relays = snapshot, entries
            write_json_atomic(self.error_path, {}, public=True)
            return True
        except (OSError, ValueError, RuntimeError, UnicodeError, RecursionError):
            # Never log remote data, addresses or exception bodies.
            write_json_atomic(self.error_path, {'message': 'Relay refresh failed; retaining the last good catalogue.',
                                               'checked_at': now_iso()}, public=True)
            return False

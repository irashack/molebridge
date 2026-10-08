"""The applier owns the relay catalogue; the panel can only read its snapshot.

Each provider's module parses its own server list (molebridge/mullvad.py,
molebridge/pia.py, molebridge/nordvpn.py); the registry
(molebridge/providers.py) says which. This
module keeps the validated snapshot and the last good one when a refresh
fails. A Mullvad catalogue lists relays, each with the WireGuard key and
endpoint a switch applies. A PIA catalogue lists regions, each with the
WireGuard servers the applier may register its key on. A NordVPN catalogue
lists servers like Mullvad's, but servers in one location share a key.
"""
from __future__ import annotations

from pathlib import Path

from molebridge import providers
from molebridge.state import CATALOG_MAX_AGE, now_iso, read_json, recent, write_json_atomic
from molebridge.validate import decode_json, valid_ipv4, valid_key, valid_text  # noqa: F401 - re-exported
# Compatibility names for code and tests written before the registry.
from molebridge.mullvad import MULLVAD_RELAYS_URL, OPTIONAL_FLAGS, parse_relay_response  # noqa: F401
from molebridge.pia import (PIA_CN_RE, PIA_COUNTRY_NAMES, PIA_COUNTRY_RE, PIA_MAX_SERVERS,  # noqa: F401
                            PIA_NAME_PREFIX, PIA_SERVERLIST_URL, parse_pia_response, pia_names,
                            validate_pia_entry, validate_pia_servers)

CATALOG_URL = {p.id: p.catalog_url for p in providers.REGISTRY.values()}
REFRESH_INTERVAL_S = 6 * 60 * 60


def snapshot_limit(provider):
    """The provider's snapshot size limit, shared by the writer and both readers."""
    spec = providers.REGISTRY.get(provider)
    return spec.snapshot_max_bytes if spec else providers.DEFAULT_CATALOG_BYTES


def read_snapshot(path: Path, provider='mullvad'):
    return read_json(path, snapshot_limit(provider))


def snapshot_too_large(entries, limit):
    """True when the entries alone provably serialize past `limit`: every key
    and text value costs at least its length plus quotes and punctuation.
    Stops counting as soon as the bound passes the limit."""
    total = 0
    for name, entry in entries.items():
        total += len(name) + 4
        for key, value in entry.items():
            total += len(key) + 4 + (len(value) if isinstance(value, str) else 1)
        if total > limit:
            return True
    return False


def validate_entry(entry, provider='mullvad'):
    return providers.get(provider).validate_entry(entry)


def parse_catalog(raw, provider='mullvad', *, port_forward_only=False):
    return providers.get(provider).parse_catalog(raw, port_forward_only=port_forward_only)


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
        snapshot = read_snapshot(self.path, provider)
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
            # A snapshot too large to be read back would leave the panel, and
            # a restarted applier, with no catalogue: keep the last good one.
            # Refused early when the entries alone are provably too large, and
            # otherwise while encoding, before the output passes the limit.
            limit = snapshot_limit(self.provider)
            if snapshot_too_large(entries, limit):
                raise ValueError('relay snapshot exceeds its size limit')
            snapshot = {'fetched_at': now_iso(), 'provider': self.provider, 'relays': entries}
            write_json_atomic(self.path, snapshot, public=True, max_bytes=limit)
            self.snapshot, self.relays = snapshot, entries
            write_json_atomic(self.error_path, {}, public=True)
            return True
        except (OSError, ValueError, RuntimeError, UnicodeError, RecursionError):
            # Never log remote data, addresses or exception bodies.
            write_json_atomic(self.error_path, {'message': 'Relay refresh failed; retaining the last good catalogue.',
                                               'checked_at': now_iso()}, public=True)
            return False

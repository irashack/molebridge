"""Read gluetun v3.41.3's single-file catalogue without changing a snapshot.

The parser is separate from file I/O so a later storage format can have its
own reader. Callers retain their last good snapshot on ValueError. `now` is
Unix time in seconds; the returned timestamp belongs to the provider data,
not to the time Molebridge read the file.
"""
from __future__ import annotations

import ipaddress
import math
import os
import re
import stat
import unicodedata

from molebridge import nordvpn
from molebridge.validate import decode_json, valid_key

MAX_CATALOG_BYTES = 32 * 1024 * 1024
MAX_IPS = 64
MAX_CATEGORIES = 64
DNS_NAME_RE = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
                         r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*')
SERVER_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._#/-]{0,255}')
# internal/constants/providers/providers.go:8-36. PIA's spaced key belongs
# to its OpenVPN storage; it is not a built-in WireGuard provider in this release.
PROVIDER_KEYS = {name: name for name in ('airvpn', 'custom', 'fastestvpn', 'ivpn',
                                      'mullvad', 'nordvpn', 'protonvpn', 'surfshark', 'windscribe')}
# (storage ID field, ServerSelection JSON filter). Paths below are relative
# to the gluetun v3.41.3 reference tree. storage/filter.go:116-120 maps
# server_name -> names and hostname -> hostnames; :129-138 compares case
# insensitively. These IDs must be unique across ALL WireGuard rows, even
# rows Molebridge cannot use: otherwise gluetun could pick a discarded row.
#
# AirVPN's public name generates TWO rows (IPv4 and IPv6) and its hostnames
# are regional: provider/airvpn/updater/servers.go:49-68. Neither single
# filter is exact across its 510 rows. ProtonVPN names logical servers and
# hostnames physical servers: provider/protonvpn/updater/servers.go:51-96,
# updater/iptoserver.go:22-40. Both fields repeat across its 800 rows; even
# name+hostname repeats. Custom bypasses storage/filter.go:20-21 entirely.
PROVIDER_SELECTION = {
    'airvpn': (None, None),
    'custom': (None, None),
    'fastestvpn': ('hostname', 'hostnames'),  # provider/fastestvpn/updater/hosttoserver.go:70-75
    'ivpn': ('hostname', 'hostnames'),        # provider/ivpn/updater/servers.go:89-94
    'mullvad': ('hostname', 'hostnames'),     # provider/mullvad/updater/hosttoserver.go:72
    'nordvpn': ('hostname', 'hostnames'),     # provider/nordvpn/updater/servers.go:85
    'protonvpn': (None, None),
    'surfshark': ('hostname', 'hostnames'),   # provider/surfshark/updater/hosttoserver.go:49-68
    'windscribe': ('hostname', 'hostnames'),  # provider/windscribe/updater/servers.go:45,57-63
}
SUPPORTED_PROVIDERS = tuple(name for name, (field, _) in PROVIDER_SELECTION.items() if field)
REJECTED_PROVIDERS = {
    'airvpn': 'gluetun provider has no unique single-filter server identifier',
    'custom': 'gluetun custom provider does not support catalogue server selection',
    'protonvpn': 'gluetun provider has no unique single-filter server identifier',
}


# Servers an ordinary account key can use. gluetun lists every server its
# updater finds, including ones a plain subscription can't connect to:
# - NordVPN: dedicated-IP, Double VPN, Onion Over VPN and obfuscated servers,
#   told apart by their categories; the same rule as the native catalogue
#   (molebridge/nordvpn.py).
# - Surfshark: gluetun fetches its generic, double (multi-hop), static and
#   obfuscated clusters into one list (internal/provider/surfshark/updater/
#   api.go:56 at v3.41.3) with nothing marking the kind. Only the generic
#   (`xx-yyy.prod.surfshark.com`) and static-IP (`xx-yyy-st001...`) names,
#   which every subscription can use, are kept; the v3.41.3 data has only
#   these two shapes among its WireGuard servers (142 and 36).
# Mullvad, IVPN, Windscribe and FastestVPN carry no such classes in gluetun's
# WireGuard data (no categories, free, premium or multihop fields).
SURFSHARK_SELECTABLE_RE = re.compile(r'[a-z]{2}-[a-z]{2,4}(-st[0-9]{3})?\.prod\.surfshark\.com')


def selectable(provider, entry):
    if provider == 'nordvpn':
        categories = entry.get('categories')
        return isinstance(categories, list) and nordvpn.selectable_by_titles(categories)
    if provider == 'surfshark':
        return bool(SURFSHARK_SELECTABLE_RE.fullmatch(entry.get('hostname', '')))
    return True


def valid_hostname(value):
    return isinstance(value, str) and len(value) <= 253 and bool(DNS_NAME_RE.fullmatch(value))


def valid_server_id(value, selection_filter):
    """Validate an exact ID filter, including its JSON value type."""
    if selection_filter == 'hostnames':
        return valid_hostname(value)
    if selection_filter == 'names':
        return isinstance(value, str) and bool(SERVER_ID_RE.fullmatch(value))
    if selection_filter == 'numbers':
        return type(value) is int and 0 < value <= 65535
    return False


def valid_text(value):
    return (isinstance(value, str) and len(value) <= 256
            and all(unicodedata.category(c) not in ('Cc', 'Cf', 'Cs') for c in value))


def _relay(entry):
    key = entry.get('wgpubkey')
    if not isinstance(key, str) or len(key) != 44 or not valid_key(key):
        return None
    # These fields have omitempty in internal/models/server.go:16-18.
    country, city = entry.get('country', ''), entry.get('city', '')
    if not valid_text(country) or not valid_text(city):
        return None
    ips = entry.get('ips')
    if not isinstance(ips, list) or not 0 < len(ips) <= MAX_IPS:
        return None
    ipv4, ipv6 = [], []
    for value in ips:
        if not isinstance(value, str) or len(value) > 45 or '%' in value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        found = ipv4 if address.version == 4 else ipv6
        if str(address) not in found:
            found.append(str(address))
    if not ipv4:
        return None
    # gluetun makes a connection candidate of every address of a selected
    # server and picks one at random (internal/provider/utils/connection.go:
    # 50-75), so every address is kept for identifying the live peer.
    # ipv4_addr_in, the first, is the latency probe's target.
    relay = {'hostname': entry['hostname'], 'public_key': entry['wgpubkey'],
             'ipv4_addr_in': ipv4[0], 'ipv4_addrs': ipv4, 'ipv6_addrs': ipv6, 'city': city, 'country': country}
    if 'region' in entry:
        if not valid_text(entry['region']):
            return None
        relay['region'] = entry['region']
    if 'categories' in entry:
        categories = entry['categories']
        if (not isinstance(categories, list) or len(categories) > MAX_CATEGORIES
                or not all(valid_text(value) for value in categories)):
            return None
        relay['categories'] = list(categories)
    return relay


def parse_gluetun_catalog(data, provider, *, now):
    """Validate the v3.41.3 storage object; return (relays, provider timestamp)."""
    if not isinstance(provider, str) or provider not in PROVIDER_KEYS:
        raise ValueError('unsupported gluetun provider')
    if provider in REJECTED_PROVIDERS:
        raise ValueError(REJECTED_PROVIDERS[provider])
    id_field, selection_filter = PROVIDER_SELECTION[provider]
    if (type(now) not in (int, float) or now < 0
            or (type(now) is float and not math.isfinite(now))):
        raise ValueError('invalid catalogue clock')
    if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != 1:
        raise ValueError('invalid gluetun catalogue format')
    block = data.get(PROVIDER_KEYS[provider])
    if (not isinstance(block, dict) or type(block.get('version')) is not int
            or not 0 <= block['version'] <= 65535 or not isinstance(block.get('servers'), list)):
        raise ValueError('invalid gluetun provider block')
    timestamp = block.get('timestamp')
    if type(timestamp) is not int or not 0 <= timestamp <= now:
        raise ValueError('invalid gluetun catalogue timestamp')
    relays, seen = {}, set()
    for entry in block['servers']:
        if not isinstance(entry, dict) or entry.get('vpn') != 'wireguard':
            continue
        server_id = entry.get(id_field)
        # Count candidates before checking credentials, endpoint families or
        # hostname syntax. An uppercase or otherwise unusable row can still
        # match the same case-insensitive gluetun filter as a usable row.
        if isinstance(server_id, str) and len(server_id) <= 256:
            token = server_id.casefold()
        elif type(server_id) is int and selection_filter == 'numbers':
            token = server_id
        else:
            continue
        if token in seen:
            raise ValueError('duplicate gluetun server identifier')
        seen.add(token)
        if (not valid_server_id(server_id, selection_filter)
                or not valid_hostname(entry.get('hostname'))):
            continue
        relay = _relay(entry)
        if relay is not None and selectable(provider, entry):
            relays[server_id] = {**relay, 'id': server_id, 'selection_filter': selection_filter}
    if not relays:
        raise ValueError('gluetun catalogue is empty')
    return relays, timestamp


def read_gluetun_snapshot(path, provider, *, now):
    """Read (relays, timestamp), refusing incomplete writes and unsafe files."""
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CATALOG_BYTES:
                raise ValueError('invalid gluetun catalogue file')
            raw = stream.read(MAX_CATALOG_BYTES + 1)
        if len(raw) > MAX_CATALOG_BYTES:
            raise ValueError('gluetun catalogue exceeds limit')
        data = decode_json(raw.decode('utf-8', errors='strict'))
    except (OSError, ValueError, UnicodeError, RecursionError):
        # JSON and OS exception bodies can contain untrusted data or paths.
        raise ValueError('cannot read gluetun catalogue') from None
    return parse_gluetun_catalog(data, provider, now=now)


def read_gluetun_catalog(path, provider, *, now):
    return read_gluetun_snapshot(path, provider, now=now)[0]


def endpoint_address(endpoint):
    """The canonical address of a WireGuard endpoint as `wg show endpoints`
    prints it (`198.51.100.1:51820`, `[2001:db8::1]:51820`) or a bare
    address, or None."""
    if not isinstance(endpoint, str) or not 0 < len(endpoint) <= 64:
        return None
    if endpoint.startswith('['):
        address, separator, rest = endpoint[1:].partition(']')
        if not separator or (rest and not re.fullmatch(r':[0-9]{1,5}', rest)):
            return None
        port = rest[1:]
    elif endpoint.count(':') == 1:
        address, _, port = endpoint.partition(':')
        if not re.fullmatch(r'[0-9]{1,5}', port):
            return None
    else:
        address, port = endpoint, ''
    if (port and not 0 < int(port) < 65536) or '%' in address:
        return None
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if str(parsed) != address.lower() or (endpoint.startswith('[') and parsed.version != 6):
        return None
    return str(parsed)


def relay_addresses(relay):
    return set(relay.get('ipv4_addrs') or [relay['ipv4_addr_in']]) | set(relay.get('ipv6_addrs') or [])


def server_for_peer(relays, public_key, endpoint):
    """Resolve the live endpoint, IPv4 or IPv6, against every address of every
    server, then confirm the key.

    A key alone is insufficient: providers may share it across many servers.
    An address listed for more than one server stays unknown even if only one
    of them has the key.
    """
    if not isinstance(public_key, str) or len(public_key) != 44 or not valid_key(public_key):
        return None
    address = endpoint_address(endpoint)
    if address is None:
        return None
    matches = [relay for relay in relays.values() if address in relay_addresses(relay)]
    if len(matches) != 1 or matches[0]['public_key'] != public_key:
        return None
    return matches[0]['id']


# The gluetun backend's registry entries (molebridge/providers.py) and the
# snapshot the applier publishes from this reader. Every supported provider
# selects by hostname (PROVIDER_SELECTION), so a snapshot entry is keyed by
# its hostname, like Mullvad's.
LABELS = {'fastestvpn': 'FastestVPN', 'ivpn': 'IVPN', 'mullvad': 'Mullvad', 'nordvpn': 'NordVPN',
          'surfshark': 'Surfshark', 'windscribe': 'Windscribe'}
if set(LABELS) != set(SUPPORTED_PROVIDERS) or any(
        PROVIDER_SELECTION[name] != ('hostname', 'hostnames') for name in SUPPORTED_PROVIDERS):
    raise RuntimeError('every supported gluetun provider needs a label and hostname selection')
# A hostname of at most 253 characters, as a pattern the panel's script can
# use too (no \Z).
SERVER_NAME_RE = re.compile(r'(?=.{1,253}$)' + DNS_NAME_RE.pattern)
# gluetun's data for a provider is dated when it last changed. Older than
# this, the panel and the doctor call it stale.
DATA_STALE_SEC = 30 * 24 * 60 * 60
SNAPSHOT_KEYS = {'id', 'hostname', 'public_key', 'ipv4_addr_in', 'ipv4_addrs', 'ipv6_addrs', 'city', 'country', 'region',
                 'categories', 'selection_filter'}


def snapshot_entry(relay):
    """A reader relay as the applier publishes it. gluetun's Windscribe data
    names the country in `region` and has no `country`; the panel groups by
    country, so such an entry takes its region as its country."""
    entry = dict(relay)
    if not entry.get('country') and entry.get('region'):
        entry['country'] = entry.pop('region')
    return entry


def _canonical(value, version):
    try:
        address = ipaddress.ip_address(value) if isinstance(value, str) and len(value) <= 45 else None
    except ValueError:
        return False
    return address is not None and address.version == version and str(address) == value


def validate_entry(entry):
    """A snapshot entry re-read from disk, or None."""
    if not isinstance(entry, dict) or set(entry) - SNAPSHOT_KEYS:
        return None
    if entry.get('selection_filter') != 'hostnames' or entry.get('id') != entry.get('hostname'):
        return None
    key = entry.get('public_key')
    if not valid_hostname(entry.get('hostname')) or not isinstance(key, str) or len(key) != 44 or not valid_key(key):
        return None
    if not _canonical(entry.get('ipv4_addr_in'), 4):
        return None
    if 'ipv4_addrs' in entry:
        v4 = entry['ipv4_addrs']
        if (not isinstance(v4, list) or not 0 < len(v4) <= MAX_IPS or v4[0] != entry['ipv4_addr_in']
                or not all(_canonical(value, 4) for value in v4) or len(set(v4)) != len(v4)):
            return None
    addresses = entry.get('ipv6_addrs')
    if (not isinstance(addresses, list) or len(addresses) > MAX_IPS
            or not all(_canonical(value, 6) for value in addresses)):
        return None
    if not valid_text(entry.get('city')) or not valid_text(entry.get('country')):
        return None
    if 'region' in entry and not valid_text(entry['region']):
        return None
    categories = entry.get('categories', [])
    if (not isinstance(categories, list) or len(categories) > MAX_CATEGORIES
            or not all(valid_text(value) for value in categories)):
        return None
    return dict(entry)


def parse_unavailable(raw, *, port_forward_only=False):
    """Registry placeholder: with gluetun the applier reads gluetun's own
    server list from disk and never downloads one."""
    raise ValueError('gluetun server lists are read from gluetun, not downloaded')


def chip_label(hostname):
    return hostname.split('.', 1)[0]


def details(info):
    parts = [info.get('region')] + list(info.get('categories') or [])
    return ' · '.join(str(part) for part in parts if isinstance(part, str) and part)

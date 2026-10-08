"""The provider registry: everything Molebridge knows per VPN provider, in one
place. The applier, the panel, the host doctor and the setup helpers read it;
nothing else keeps a per-provider table.

Each provider's own module (molebridge/mullvad.py, pia.py, nordvpn.py) parses
its server list. The applier subclass named here applies a selection and
confirms egress. Adding a provider means a module, an applier class and an
entry below; docs/providers.md#adding-a-provider lists what each must do.

The gluetun backend adds one entry per provider gluetun can select exactly
(molebridge/gluetun_catalog.py), with the id `gluetun-<gluetun's provider
id>`: gluetun owns that tunnel and its server list, and the applier talks to
gluetun's control server. Native entries are unaffected.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Callable, Dict, Mapping, Pattern, Tuple

from molebridge import gluetun_catalog, mullvad, nordvpn, pia

# Egress tiers, strongest first. "provider": the provider's own endpoint says
# the request arrived over its VPN. "tunnel": independent IP echo services
# through the tunnel agree on an address that is not the host's own, and it
# matches the selected server where the catalogue lists exit addresses.
TIERS = ('provider', 'tunnel')
DEFAULT_CATALOG_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    # A selectable name: a relay hostname or a region id.
    server_name_re: Pattern
    catalog_url: str
    # parse_catalog(raw text, *, port_forward_only=False) -> {name: entry};
    # raises ValueError so the last good catalogue is kept.
    parse_catalog: Callable
    # validate_entry(entry) -> entry or None, for snapshot entries re-read from disk.
    validate_entry: Callable
    # 'module:Class' of the applier subclass; imported only by the applier.
    applier: str
    # One tunnel address valid on every server, set before any switch (and
    # present in the tunnel config), or an address assigned per server.
    address_before_switch: bool
    # The strongest egress confirmation the provider supports; see TIERS.
    egress_tier: str
    # Whether the tunnel can carry IPv6. Without it, forwarded IPv6 always
    # hits the exit table's unreachable fallback.
    ipv6: bool
    catalog_max_bytes: int = DEFAULT_CATALOG_BYTES
    catalog_timeout_s: int = 20
    # The validated snapshot (state/applier/relays.json): the applier refuses
    # to write a larger one, keeping the last good catalogue, and the applier
    # and panel refuse to read one.
    snapshot_max_bytes: int = DEFAULT_CATALOG_BYTES
    # Account files the applier reads, relative to the checkout (mode 0600).
    secret_files: Tuple[str, ...] = ()
    # Panel presentation: 'tree' (country, city, server) or 'regions' (a flat list).
    layout: str = 'tree'
    # Catalogue attribute -> filter label; offered only when it narrows the list.
    filters: Mapping[str, str] = field(default_factory=dict)
    # (attribute, badge text, title) shown on a server when the attribute is true.
    badges: Tuple[Tuple[str, str, str], ...] = ()
    # (dark, light) browser chrome colour for the provider style.
    theme_colors: Tuple[str, str] = ('#232638', '#eff1f5')
    # The short name on a server's button, and a one-line summary of the server.
    chip_label: Callable[[str], str] = lambda hostname: hostname  # noqa: E731
    details: Callable[[dict], str] = lambda info: ''  # noqa: E731
    # 'native': Molebridge's own WireGuard container (compose.yaml). 'gluetun':
    # gluetun owns the tunnel (compose.gluetun.yaml), as `gluetun_provider`.
    backend: str = 'native'
    gluetun_provider: str = ''
    # Shown with the label in the panel, e.g. 'via gluetun'.
    note: str = ''
    # The native provider whose typed egress check this entry reuses, or ''
    # for the tunnel checks alone.
    egress_check: str = ''
    # The panel styles an entry as this provider (its CSS data-provider);
    # empty means its own id.
    style: str = ''

    @property
    def css_id(self):
        return self.style or self.id

    def valid_server_name(self, value):
        return isinstance(value, str) and bool(self.server_name_re.fullmatch(value))

    def applier_class(self):
        module, _, name = self.applier.partition(':')
        return getattr(importlib.import_module(module), name)


REGISTRY: Dict[str, Provider] = {p.id: p for p in (
    Provider(
        id='mullvad', label='Mullvad', server_name_re=mullvad.HOSTNAME_RE,
        catalog_url=mullvad.MULLVAD_RELAYS_URL, parse_catalog=mullvad.parse_catalog,
        validate_entry=mullvad.validate_entry, applier='applier.apply:Applier',
        address_before_switch=True, egress_tier='provider', ipv6=True,
        filters={'owned': 'Mullvad-owned', 'stboot': 'RAM-only'},
        theme_colors=('#192e45', '#e9eef3'), chip_label=mullvad.chip_label, details=mullvad.details),
    Provider(
        id='pia', label='PIA', server_name_re=pia.REGION_RE,
        catalog_url=pia.PIA_SERVERLIST_URL, parse_catalog=pia.parse_catalog,
        validate_entry=pia.validate_pia_entry, applier='applier.pia:PiaApplier',
        address_before_switch=False, egress_tier='provider', ipv6=False,
        secret_files=('secrets/pia/username', 'secrets/pia/password'),
        layout='regions', filters={'port_forward': 'Port forwarding'},
        badges=(('port_forward', 'PF', 'Port forwarding'), ('geo', 'virtual', 'Virtual location')),
        theme_colors=('#1c1e22', '#f2f4f5'), details=pia.details),
    Provider(
        id='nordvpn', label='NordVPN', server_name_re=nordvpn.NORD_HOSTNAME_RE,
        catalog_url=nordvpn.NORD_SERVERS_URL, parse_catalog=nordvpn.parse_catalog,
        validate_entry=nordvpn.validate_entry, applier='applier.nordvpn:NordApplier',
        address_before_switch=True, egress_tier='provider', ipv6=False,
        catalog_max_bytes=nordvpn.NORD_MAX_CATALOG_BYTES, catalog_timeout_s=60,
        # About 1.5 MB in 2026; long location names, escaped, can inflate it.
        snapshot_max_bytes=16 * 1024 * 1024,
        badges=(('virtual', 'virtual', 'Virtual location'),),
        theme_colors=('#161b26', '#eef2f8'), chip_label=nordvpn.chip_label, details=nordvpn.details),
)}
# Native styling and checks carry over to the same provider through gluetun.
_NATIVE = dict(REGISTRY)
for _name in gluetun_catalog.SUPPORTED_PROVIDERS:
    _native = _NATIVE.get(_name)
    REGISTRY[f'gluetun-{_name}'] = Provider(
        id=f'gluetun-{_name}', label=gluetun_catalog.LABELS[_name], server_name_re=gluetun_catalog.SERVER_NAME_RE,
        catalog_url='', parse_catalog=gluetun_catalog.parse_unavailable,
        validate_entry=gluetun_catalog.validate_entry,
        applier=f'applier.gluetun_applier:Gluetun{_name.capitalize()}Applier',
        # gluetun sets its own tunnel address; a switch may leave the
        # interface without one while gluetun restarts its tunnel.
        address_before_switch=False,
        egress_tier='provider' if _name in ('mullvad', 'nordvpn') else 'tunnel',
        ipv6=_native.ipv6 if _native else False,
        catalog_max_bytes=gluetun_catalog.MAX_CATALOG_BYTES, snapshot_max_bytes=16 * 1024 * 1024,
        secret_files=('secrets/gluetun/api_key',),
        badges=(), theme_colors=_native.theme_colors if _native else ('#232638', '#eff1f5'),
        chip_label=gluetun_catalog.chip_label, details=gluetun_catalog.details,
        backend='gluetun', gluetun_provider=_name, note='via gluetun',
        egress_check=_name if _name in ('mullvad', 'nordvpn') else '',
        style=_name if _native else 'gluetun')
del _NATIVE, _name, _native
PROVIDERS = tuple(REGISTRY)


def get(provider_id) -> Provider:
    try:
        return REGISTRY[provider_id]
    except (KeyError, TypeError):
        raise ValueError('PROVIDER must be one of: ' + ', '.join(PROVIDERS)) from None


def from_env(env) -> Provider:
    return get(env.get('PROVIDER', '') or 'mullvad')

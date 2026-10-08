"""The provider registry: one entry per provider, and every consumer reads it."""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from applier import apply as applier_module
from applier.apply import Applier
from molebridge import providers, relays, state
from molebridge.routing import RoutingConfig

CONFIG = RoutingConfig('192.0.2.0/24', '2001:db8:1::/64')


def test_registry_ids_and_lookup():
    assert providers.PROVIDERS == tuple(providers.REGISTRY)
    assert providers.PROVIDERS[:2] == ('mullvad', 'pia')
    for key, spec in providers.REGISTRY.items():
        assert spec.id == key
        if spec.backend == 'native':
            assert re.fullmatch(r'[a-z][a-z0-9]{0,15}', key)
        else:
            assert spec.backend == 'gluetun' and key == 'gluetun-' + spec.gluetun_provider
        assert providers.get(key) is spec
    assert providers.from_env({}).id == 'mullvad'
    assert providers.from_env({'PROVIDER': ''}).id == 'mullvad'
    for bad in ('examplevpn', 'Mullvad', None, ['pia']):
        with pytest.raises(ValueError, match='PROVIDER must be one of'):
            providers.get(bad)


@pytest.mark.parametrize('provider', providers.PROVIDERS)
def test_every_entry_is_complete(provider):
    spec = providers.get(provider)
    assert spec.label and spec.egress_tier in providers.TIERS and spec.layout in ('tree', 'regions')
    if spec.backend == 'native':
        assert spec.catalog_url.startswith('https://')
    else:
        # The gluetun backend reads gluetun's own list and downloads nothing.
        assert spec.catalog_url == '' and spec.note == 'via gluetun'
        with pytest.raises(ValueError):
            spec.parse_catalog('{}')
    assert spec.catalog_max_bytes > 0 and spec.catalog_timeout_s > 0
    assert all(not path.startswith('/') and '..' not in path for path in spec.secret_files)
    cls = spec.applier_class()
    assert issubclass(cls, Applier) and cls.provider == provider
    assert set(key for key, _, _ in spec.badges) | set(spec.filters) <= {'owned', 'stboot', 'port_forward', 'geo',
                                                                       'virtual'}
    assert all(re.fullmatch(r'#[0-9a-f]{6}', color) for color in spec.theme_colors)


def test_mullvad_and_pia_keep_their_settings():
    mullvad, pia = providers.get('mullvad'), providers.get('pia')
    assert (mullvad.label, mullvad.address_before_switch, mullvad.ipv6, mullvad.layout) == ('Mullvad', True, True, 'tree')
    assert (pia.label, pia.address_before_switch, pia.ipv6, pia.layout) == ('PIA', False, False, 'regions')
    assert mullvad.catalog_url == 'https://api.mullvad.net/app/v1/relays'
    assert pia.catalog_url == 'https://serverlist.piaservers.net/vpninfo/servers/v6'
    assert mullvad.catalog_max_bytes == pia.catalog_max_bytes == 10 * 1024 * 1024
    assert mullvad.catalog_timeout_s == pia.catalog_timeout_s == 20
    assert mullvad.egress_tier == pia.egress_tier == 'provider'
    assert pia.secret_files == ('secrets/pia/username', 'secrets/pia/password') and mullvad.secret_files == ()
    assert mullvad.chip_label('se-sto-wg-001') == 'wg-001'


def test_compatibility_names_follow_the_registry():
    assert state.PROVIDERS == providers.PROVIDERS
    assert state.PROVIDER_LABEL == {p.id: p.label for p in providers.REGISTRY.values()}
    assert state.SERVER_NAME_RE == {p.id: p.server_name_re for p in providers.REGISTRY.values()}
    assert state.HOSTNAME_RE is providers.get('mullvad').server_name_re
    assert relays.CATALOG_URL == {p.id: p.catalog_url for p in providers.REGISTRY.values()}
    assert state.provider_from_env({'PROVIDER': 'pia'}) == 'pia'
    assert state.valid_server_name('se-sto-wg-001') and not state.valid_server_name('ex_example')
    assert state.valid_server_name('ex_example', 'pia') and not state.valid_server_name('../x', 'pia')


NATIVE = tuple(p for p in providers.PROVIDERS if providers.get(p).backend == 'native')


@pytest.mark.parametrize('provider', NATIVE)
def test_catalogue_fetch_takes_url_cap_and_timeout_from_the_registry(tmp_path, provider):
    spec = providers.get(provider)
    calls = []

    class Probe(spec.applier_class()):
        def __init__(self):
            self.port_forward = False
            Applier.__init__(self, tmp_path, CONFIG, run=lambda args, **kw: calls.append((args, kw)) or 'x\n200')

    assert Probe().fetch_catalog() == 'x'
    args, limits = calls[0]
    assert args[-1] == spec.catalog_url
    assert args[args.index('--max-filesize') + 1] == str(spec.catalog_max_bytes)
    assert args[args.index('--max-time') + 1] == str(spec.catalog_timeout_s)
    assert limits == {'timeout': spec.catalog_timeout_s + 2, 'limit': spec.catalog_max_bytes + 4}


@pytest.mark.parametrize('provider', providers.PROVIDERS)
def test_applier_address_model_comes_from_the_registry(tmp_path, provider):
    spec = providers.get(provider)
    cls = spec.applier_class()
    # No subclass keeps its own copy.
    assert isinstance(getattr(cls, 'address_before_switch'), property)
    instance = cls.__new__(cls)
    assert instance.address_before_switch is spec.address_before_switch


def test_applier_main_builds_each_providers_class(monkeypatch, tmp_path):
    built = []
    for provider in providers.PROVIDERS:
        cls = providers.get(provider).applier_class()
        monkeypatch.setattr(cls, 'from_env', classmethod(lambda c, *a, **kw: built.append(c.provider) or None),
                            raising=False)
    monkeypatch.setattr(applier_module, 'Applier', lambda *a, **kw: built.append('mullvad') or None)
    monkeypatch.setattr(sys, 'argv', ['applier', '--healthcheck'])
    monkeypatch.setenv('OVERLAY_CIDR', CONFIG.overlay)
    monkeypatch.setenv('STATE_DIR', str(tmp_path))
    for provider in providers.PROVIDERS:
        monkeypatch.setenv('PROVIDER', provider)
        with pytest.raises(AttributeError):
            applier_module.main()
    assert built == list(providers.PROVIDERS)


def test_unknown_provider_stops_the_applier(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['applier'])
    monkeypatch.setenv('OVERLAY_CIDR', CONFIG.overlay)
    monkeypatch.setenv('PROVIDER', 'examplevpn')
    assert applier_module.main() == 1
    assert capsys.readouterr().out == 'applier: invalid configuration or unavailable state\n'


def test_routing_init_knows_every_provider():
    script = (ROOT / 'routing' / '10-exit-routing').read_text()
    cases = script[script.index('case "$PROVIDER" in'):]
    cases = cases[:cases.index('esac')]
    for provider in NATIVE:
        assert re.search(rf'^\s+{provider}\)', cases, re.M), provider


@pytest.mark.parametrize('provider', providers.PROVIDERS)
def test_snapshot_of_another_provider_is_ignored(provider):
    other = next(p for p in providers.PROVIDERS if p != provider)
    snapshot = {'fetched_at': state.now_iso(), 'provider': other, 'relays': {'x': {'hostname': 'x'}}}
    assert relays.snapshot_relays(snapshot, provider) == {}
    assert relays.snapshot_relays(json.loads(json.dumps({**snapshot, 'provider': provider})), provider) == {}


def test_nordvpn_entry_is_mullvad_shaped_ipv4_only_with_its_own_cap():
    from molebridge import nordvpn
    spec = providers.get('nordvpn')
    assert (spec.label, spec.address_before_switch, spec.ipv6, spec.layout) == ('NordVPN', True, False, 'tree')
    assert spec.egress_tier == 'provider' and spec.secret_files == ()
    assert spec.catalog_url == nordvpn.NORD_SERVERS_URL
    assert spec.catalog_max_bytes == nordvpn.NORD_MAX_CATALOG_BYTES == 32 * 1024 * 1024
    assert spec.catalog_timeout_s == 60
    assert spec.parse_catalog is nordvpn.parse_catalog and spec.validate_entry is nordvpn.validate_entry
    assert spec.valid_server_name('us9001.nordvpn.com') and spec.valid_server_name('uk-nl10.nordvpn.com')
    assert not spec.valid_server_name('se-sto-wg-001') and not spec.valid_server_name('us9001')
    assert spec.chip_label('us9001.nordvpn.com') == 'us9001'
    # Only this provider's download cap grew.
    assert {p.catalog_max_bytes for p in providers.REGISTRY.values()
            if p.id != 'nordvpn' and p.backend == 'native'} == {state.MAX_CATALOG_BYTES}


def test_snapshot_limits_come_from_the_registry():
    assert relays.snapshot_limit('mullvad') == relays.snapshot_limit('pia') == state.MAX_CATALOG_BYTES
    assert relays.snapshot_limit('nordvpn') == 16 * 1024 * 1024
    assert relays.snapshot_limit('examplevpn') == state.MAX_CATALOG_BYTES
    for spec in providers.REGISTRY.values():
        assert relays.snapshot_limit(spec.id) == spec.snapshot_max_bytes


def test_write_with_a_limit_refuses_before_touching_the_old_file(tmp_path):
    path = tmp_path / 'relays.json'
    state.write_json_atomic(path, {'old': True}, public=True)
    before = path.read_bytes()
    with pytest.raises(ValueError, match='size limit'):
        state.write_json_atomic(path, {'x': 'y' * 100}, public=True, max_bytes=50)
    assert path.read_bytes() == before and sorted(p.name for p in tmp_path.iterdir()) == ['relays.json']
    state.write_json_atomic(path, {'x': 'y'}, public=True, max_bytes=50)
    assert json.loads(path.read_text()) == {'x': 'y'}


@pytest.mark.parametrize('provider', providers.PROVIDERS)
def test_oversized_snapshot_keeps_the_last_good_catalogue(tmp_path, monkeypatch, provider):
    good = {'fetched_at': state.now_iso(), 'provider': provider, 'relays': {}}
    state.write_json_atomic(tmp_path / 'relays.json', good, public=True)
    before = (tmp_path / 'relays.json').read_bytes()
    catalog = relays.RelayCatalog(tmp_path, provider)
    spec = providers.get(provider)
    big = {f'name{i}': {'hostname': f'name{i}'} for i in range(200)}
    monkeypatch.setitem(providers.REGISTRY, provider,
                        __import__('dataclasses').replace(spec, parse_catalog=lambda raw, **kw: big,
                                                          snapshot_max_bytes=1000))
    assert catalog.refresh(lambda: 'x') is False
    assert (tmp_path / 'relays.json').read_bytes() == before
    assert state.read_json(tmp_path / 'relay-error.json')['message'] == \
        'Relay refresh failed; retaining the last good catalogue.'


def test_readers_and_writer_agree_on_the_limit(tmp_path):
    """A snapshot the writer accepts, the applier and the panel can read back."""
    path = tmp_path / 'relays.json'
    payload = {'fetched_at': state.now_iso(), 'provider': 'nordvpn', 'relays': {}, 'pad': 'x' * (12 * 1024 * 1024)}
    state.write_json_atomic(path, payload, public=True, max_bytes=relays.snapshot_limit('nordvpn'))
    assert relays.read_snapshot(path, 'nordvpn') == payload
    assert relays.read_snapshot(path, 'mullvad') is None
    sys.path.insert(0, str(ROOT / 'panel'))
    import app as panel_app
    assert panel_app.read_snapshot is relays.read_snapshot


# -- bounded memory for oversized snapshots ---------------------------------------

LONG = 'é' * 250  # 1,500 bytes once JSON-escaped


def big_entries(count):
    """NordVPN-shaped entries sharing one long text, so building them is cheap
    while serializing them is not (about 3 kB each)."""
    return {f'us{i}.nordvpn.com': {'hostname': f'us{i}.nordvpn.com', 'city': LONG, 'country': LONG,
                                   'country_code': 'US', 'location_code': 'us-x', 'virtual': False}
            for i in range(count)}


def traced_peak(action):
    import tracemalloc
    tracemalloc.start()
    try:
        action()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_encoding_stops_at_the_limit_with_bounded_memory(tmp_path):
    path = tmp_path / 'relays.json'
    state.write_json_atomic(path, {'last': 'good'}, public=True)
    before = path.read_bytes()
    # About 150 MB serialized; the limit is NordVPN's 16 MiB.
    snapshot = {'fetched_at': state.now_iso(), 'provider': 'nordvpn', 'relays': big_entries(50000)}

    def write():
        with pytest.raises(ValueError, match='size limit'):
            state.write_json_atomic(path, snapshot, public=True, max_bytes=relays.snapshot_limit('nordvpn'))
    assert traced_peak(write) < 4 * 1024 * 1024
    assert path.read_bytes() == before and [p.name for p in tmp_path.iterdir()] == ['relays.json']


def test_streamed_output_is_what_json_dump_writes(tmp_path):
    obj = {'fetched_at': state.now_iso(), 'relays': {'a': {'city': LONG, 'n': 1.5, 'b': True, 'x': None}}}
    path = tmp_path / 'out.json'
    state.write_json_atomic(path, obj, max_bytes=10 ** 6)
    assert path.read_text() == json.dumps(obj, allow_nan=False)
    with pytest.raises(ValueError):
        state.write_json_atomic(path, {'x': float('nan')})
    assert path.read_text() == json.dumps(obj, allow_nan=False)


@pytest.mark.parametrize('count', [50000, 5800])
def test_oversized_nordvpn_refresh_keeps_last_good_with_bounded_memory(tmp_path, monkeypatch, count):
    """50,000 entries fail the early bound; 5,800 pass it (about 9 MB of text
    counted once) but serialize past 16 MiB, so the encoder stops them."""
    good = {'fetched_at': state.now_iso(), 'provider': 'nordvpn', 'relays': {}}
    state.write_json_atomic(tmp_path / 'relays.json', good, public=True)
    before = (tmp_path / 'relays.json').read_bytes()
    entries = big_entries(count)
    assert relays.snapshot_too_large(entries, relays.snapshot_limit('nordvpn')) is (count == 50000)
    spec = providers.get('nordvpn')
    monkeypatch.setitem(providers.REGISTRY, 'nordvpn',
                        __import__('dataclasses').replace(spec, parse_catalog=lambda raw, **kw: entries))
    catalog = relays.RelayCatalog(tmp_path, 'nordvpn')
    outcome = []
    assert traced_peak(lambda: outcome.append(catalog.refresh(lambda: 'x'))) < 4 * 1024 * 1024
    assert outcome == [False] and catalog.relays == {}
    assert (tmp_path / 'relays.json').read_bytes() == before
    assert state.read_json(tmp_path / 'relay-error.json')['message'] == \
        'Relay refresh failed; retaining the last good catalogue.'
    assert sorted(p.name for p in tmp_path.iterdir()) == ['relay-error.json', 'relays.json']


def test_early_bound_never_refuses_what_fits():
    entries = big_entries(100)
    snapshot = {'fetched_at': state.now_iso(), 'provider': 'nordvpn', 'relays': entries}
    size = len(json.dumps(snapshot))
    assert not relays.snapshot_too_large(entries, size)
    assert relays.snapshot_too_large(entries, 100 * 260)

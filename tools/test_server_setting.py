"""Configuration authority against fakes only; no live host or provider."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from applier.apply import Applier, REFRESH_SEC, SERVER_REPORT_CHARS
from molebridge import providers
from molebridge.routing import RoutingConfig
from molebridge.state import desired_request, now_iso, write_json_atomic
from test_runtime import CONFIG, ENTRY, HOST, Kernel
from test_gluetun_applier import HOST_A, HOST_B, HOST_C, make as gluetun_make, request
from test_nordvpn_applier import CONFIG as NORD_CONFIG, NordKernel, catalogue
from test_pia import CONFIG as PIA_CONFIG, PiaKernel, REGION, PASSWORD, entry


NAMES = {'mullvad': HOST, 'pia': REGION, 'nordvpn': 'us9001.nordvpn.com',
         **{spec.id: HOST_B for spec in providers.REGISTRY.values() if spec.backend == 'gluetun'}}


@pytest.mark.parametrize('provider', NAMES)
def test_server_from_env_uses_desired_name_validation(tmp_path, provider):
    spec = providers.get(provider)
    config = RoutingConfig.from_env({'OVERLAY_CIDR': '192.0.2.0/24',
                                    'TUNNEL_BACKEND': 'gluetun' if spec.backend == 'gluetun' else 'wireguard',
                                    'EXIT_IF': 'wg0' if spec.backend == 'gluetun' else 'exitvpn'})
    key_file = tmp_path / 'api-key'
    key_file.write_text('0' * 32)
    key_file.chmod(0o600)
    for server in [NAMES[provider], '', '--bad', NAMES[provider] + '\n', 'bad name', '<script>', 'x' * 4096]:
        app = spec.applier_class().from_env(tmp_path, config, {'SERVER': server, 'GLUETUN_API_KEY_FILE': str(key_file)})
        assert app.configured_server == server
        assert (app.configured_request() is not None) == (desired_request(
            {'server': server, 'requested_at': now_iso()}, provider) is not None)
        assert app.publish('unknown', 'Starting.')['configured_server'] == (server[:SERVER_REPORT_CHARS] or None)


def native(tmp_path, provider, server):
    if provider == 'mullvad':
        kernel, config, relays = Kernel(), CONFIG, {HOST: ENTRY}
    elif provider == 'nordvpn':
        kernel, config, relays = NordKernel(), NORD_CONFIG, catalogue()
    else:
        kernel, config, relays = PiaKernel(), PIA_CONFIG, {REGION: entry()}
    write_json_atomic(tmp_path / 'applier' / 'relays.json',
                      {'provider': provider, 'fetched_at': now_iso(), 'relays': relays})
    kwargs = {}
    if provider == 'pia':
        secrets_dir = tmp_path / 'secrets'
        secrets_dir.mkdir()
        (secrets_dir / 'username').write_text('p0000000')
        (secrets_dir / 'password').write_text(PASSWORD)
        kwargs['secrets_dir'] = secrets_dir
    app = providers.get(provider).applier_class()(tmp_path, config, server=server, **kwargs,
            run=kernel.run, clock=lambda: kernel.now, sleep=kernel.sleep)
    app.next_catalog = float('inf')
    return app, kernel


@pytest.mark.parametrize('provider', ['mullvad', 'pia', 'nordvpn'])
@pytest.mark.parametrize('desired_kind', ['valid', 'malformed', 'missing', 'symlink'])
def test_native_request_path_never_reads_desired(tmp_path, monkeypatch, provider, desired_kind):
    app, kernel = native(tmp_path, provider, NAMES[provider])
    app.desired_path.parent.mkdir(exist_ok=True)
    if desired_kind == 'valid':
        write_json_atomic(app.desired_path, {'server': {'mullvad': 'zz-zzz-wg-999', 'pia': 'ex_absent', 'nordvpn': 'us9999.nordvpn.com'}[provider], 'requested_at': now_iso()})
    elif desired_kind == 'malformed':
        app.desired_path.write_text('{broken')
    elif desired_kind == 'symlink':
        app.desired_path.symlink_to(tmp_path / 'missing')
    # Assert no filesystem read/stat of the request path, even if malformed.
    import applier.apply as module
    original = module.read_json
    def read(path, *args):
        assert path != app.desired_path
        return original(path, *args)
    monkeypatch.setattr(module, 'read_json', read)
    original_exists = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda path: pytest.fail('desired path stat') if path == app.desired_path else original_exists(path))
    result = app.tick()
    assert result['status'] == 'ok', result['message']
    assert result['server'] == NAMES[provider]
    assert result['requested_server'] == NAMES[provider]
    assert result['configured_server'] == NAMES[provider]


@pytest.mark.parametrize('provider', [p for p in NAMES if p != 'gluetun-surfshark'])
@pytest.mark.parametrize('server,kind', [('--bad\n"', 'Invalid'), ('absent.example.test', 'Unknown')])
def test_bad_configuration_has_quoted_failure_and_no_fallback(tmp_path, provider, server, kind):
    # Native names have narrower syntax than gluetun hostnames.
    if kind == 'Unknown':
        server = {'mullvad': 'zz-zzz-wg-999', 'pia': 'ex_absent',
                  'nordvpn': 'us9999.nordvpn.com'}.get(provider, server)
    if provider.startswith('gluetun-'):
        app, kernel, control = gluetun_make(tmp_path, provider.removeprefix('gluetun-'), server=server)
        app.update_threshold = None
    else:
        app, kernel = native(tmp_path, provider, server)
        control = None
    write_json_atomic(app.desired_path, request(NAMES[provider]))
    result = app.tick()
    assert result['status'] == 'failed'
    assert result['message'].startswith(f'{kind} SERVER {json.dumps(server)};')
    assert app.inspect()['status'] == 'failed'
    if control:
        assert control.puts == []
    else:
        assert not any(call[:2] == ['wg', 'set'] for call in kernel.calls)


@pytest.mark.parametrize('provider', [p.removeprefix('gluetun-') for p in NAMES if p.startswith('gluetun-') and p != 'gluetun-surfshark'])
def test_gluetun_restore_and_request_use_server_not_saved_or_panel(tmp_path, monkeypatch, provider):
    app, kernel, control = gluetun_make(tmp_path, provider, server=HOST_B)
    app.save_selection(desired=HOST_C, last_put=HOST_A, last_successful=HOST_C)
    write_json_atomic(app.desired_path, request(HOST_C))
    import applier.gluetun_applier as module
    original = module.read_json
    def read(path, *args):
        assert path != app.desired_path
        return original(path, *args)
    monkeypatch.setattr(module, 'read_json', read)
    assert app.restore() == HOST_B
    assert control.puts == [HOST_B]
    # Let gluetun complete its fake reconnect, then use the normal request path.
    app.update_threshold = None
    result = app.tick()
    assert result['status'] == 'ok', result['message']
    assert result['server'] == HOST_B
    kernel.tunnel = HOST_A
    kernel.now += 91
    assert app.restore() == HOST_B
    assert control.puts[-1] == HOST_B


def test_configuration_retries_failed_apply_and_reconverges(tmp_path):
    app, kernel = native(tmp_path, 'mullvad', HOST)
    kernel.fail_set = True
    failed = app.tick()
    assert failed['status'] == 'failed'
    assert 'configured SERVER will retry automatically.' in failed['message']
    kernel.fail_set = False
    kernel.now += REFRESH_SEC
    assert app.tick()['status'] == 'ok'
    # A recreated interface has no peer; the configuration remains authoritative.
    kernel.keys = []
    assert app.tick()['status'] == 'ok'


def test_configuration_waits_for_fresh_catalogue_then_validates(tmp_path):
    app, kernel = native(tmp_path, 'mullvad', HOST)
    app.catalog.snapshot['fetched_at'] = '2000-01-01T00:00:00Z'
    result = app.tick()
    assert result['status'] == 'failed'
    assert app.pending and not kernel.mutations
    app.catalog.snapshot['fetched_at'] = now_iso()
    assert app.tick()['status'] == 'ok'


@pytest.mark.parametrize('status,reported,actual,expected', [
    ('ok', HOST, HOST, 0), ('failed', HOST, HOST, 1),
    ('ok', None, HOST, 1), ('ok', HOST, 'zz-zzz-wg-999', 1),
    ('failed', '--bad', HOST, 1), ('failed', 'zz-zzz-wg-999', HOST, 1),
])
def test_configured_health_requires_success_on_server(tmp_path, monkeypatch, status, reported, actual, expected):
    import applier.apply as module
    app, kernel = native(tmp_path, 'mullvad', HOST)
    write_json_atomic(app.result_path, app.publish(status, 'Example status.',
                      configured_server=reported, server=actual))
    monkeypatch.setattr(module, 'Applier', lambda *args, **kwargs: app)
    monkeypatch.setattr(sys, 'argv', ['applier', '--healthcheck'])
    monkeypatch.setenv('OVERLAY_CIDR', CONFIG.overlay)
    assert module.main() == expected


def test_configured_inspection_cannot_mark_a_different_server_healthy(tmp_path, monkeypatch):
    app, kernel = native(tmp_path, 'mullvad', HOST)
    monkeypatch.setattr(app, 'server_for', lambda _keys: 'zz-zzz-wg-999')
    res = app.inspect()
    assert res['status'] == 'failed'
    assert res['message'] == 'The configured SERVER is not the current server; waiting for convergence.'


def test_compose_passes_server_only_to_applier():
    import yaml
    root = Path(__file__).resolve().parents[1]
    for name in ['compose.yaml', 'compose.pia.yaml', 'compose.nordvpn.yaml', 'compose.gluetun.yaml']:
        compose = yaml.safe_load((root / name).read_text())
        assert compose['services']['applier']['environment']['SERVER'] == '${SERVER:-}'
        assert all('SERVER' not in service.get('environment', {})
                   for key, service in compose['services'].items() if key != 'applier')


def test_invalid_unicode_setting_keeps_status_bounded_and_readable(tmp_path):
    from molebridge.state import read_json, configured_server
    app, _ = native(tmp_path, 'mullvad', '😀' * 4096)
    result = app.tick()
    assert result['status'] == 'failed'
    assert app.result_path.stat().st_size <= 16384
    assert configured_server(read_json(app.result_path, 16384))

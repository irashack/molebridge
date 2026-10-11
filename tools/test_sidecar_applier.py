"""The sidecar kind in the applier (EXIT_KIND=sidecar): an ordinary gluetun
other containers share, with no routing contract and no NetBird. Fakes
only; tools/test_sidecar_tools.py covers the host-side doctor."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from applier import apply as apply_module
from molebridge import providers
from molebridge.routing import RoutingConfig
from molebridge.state import read_json, write_json_atomic
from molebridge.verdict import ExitConfig, Target, assess
from test_gluetun_applier import HOST_A, HOST_B, FakeGluetun, Kernel, request, servers_json

SIDECAR = RoutingConfig.from_env({'EXIT_KIND': 'sidecar', 'TUNNEL_BACKEND': 'gluetun', 'EXIT_IF': 'wg0'})


def make(tmp_path, provider='nordvpn'):
    kernel = Kernel()
    servers = tmp_path / 'gluetun-servers' / 'servers.json'
    servers.parent.mkdir(exist_ok=True)
    servers.write_text(servers_json(provider))
    gluetun = FakeGluetun(kernel)
    cls = providers.get(f'gluetun-{provider}').applier_class()

    def no_marked(*args):
        raise AssertionError('a sidecar never measures off the tunnel')
    applier = cls(tmp_path, SIDECAR, client=gluetun, servers_file=servers, run=kernel.run,
                  clock=lambda: kernel.now, sleep=kernel.sleep, fetch_marked=no_marked)
    applier.catalog.refresh()
    applier.update_threshold = None
    return applier, kernel, gluetun


def verdict(applier, result):
    return assess(ExitConfig(applier.provider, 'sidecar'), result,
                  Target.for_panel(result, read_json(applier.desired_path), applier.provider))


@pytest.mark.parametrize('env', [
    {'EXIT_KIND': 'sidecar', 'TUNNEL_BACKEND': 'wireguard'},
    {'EXIT_KIND': 'sidecar'},
    {'EXIT_KIND': 'sidecar', 'TUNNEL_BACKEND': 'gluetun', 'EXIT_IF': 'wg-0'},
    {'EXIT_KIND': 'exit', 'TUNNEL_BACKEND': 'gluetun', 'OVERLAY_CIDR': '192.0.2.0/24'},
])
def test_configuration_refusals(env):
    with pytest.raises(ValueError):
        RoutingConfig.from_env(env)


def test_a_sidecar_needs_a_gluetun_provider(tmp_path, monkeypatch, capsys):
    with pytest.raises(ValueError):
        ExitConfig('nordvpn', 'sidecar')
    monkeypatch.setenv('EXIT_KIND', 'sidecar')
    monkeypatch.setenv('TUNNEL_BACKEND', 'gluetun')
    monkeypatch.setenv('PROVIDER', 'nordvpn')
    monkeypatch.setenv('STATE_DIR', str(tmp_path))
    monkeypatch.setattr(sys, 'argv', ['applier'])
    assert apply_module.main() == 1
    assert 'invalid configuration' in capsys.readouterr().out


def test_a_provider_tier_sidecar_switches_and_verifies_without_the_contract(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    write_json_atomic(applier.desired_path, request(HOST_B))
    result = applier.tick()
    assert result['status'] == 'ok' and result['server'] == HOST_B and gluetun.puts == [HOST_B]
    assert result['kind'] == 'sidecar' and result['backend'] == 'gluetun'
    checks = result['checks']
    assert {checks[n]['state'] for n in ('routing', 'netbird', 'owner_record')} == {'n/a'}
    assert checks['traffic_protection'] == {'state': 'not-checked', 'by': "gluetun's firewall"}
    assert checks['app_attachment'] == {'state': 'not-checked', 'by': 'the host doctor'}
    assert checks['egress']['tier'] == 'provider'
    found = verdict(applier, result)
    assert found.state == 'ok' and found.checks['traffic_protection'] == 'not-checked'
    # Nothing of the routing contract is read or written.
    assert not any(c[0] == 'ip' and 'rule' in c for c in kernel.calls)
    assert not any(c[0] in ('nft', 'cat') for c in kernel.calls)


def test_a_tunnel_tier_sidecar_is_switched_never_verified_and_never_reapplied(tmp_path):
    applier, kernel, gluetun = make(tmp_path, 'ivpn')
    write_json_atomic(applier.desired_path, request(HOST_B))
    result = applier.tick()
    assert gluetun.puts == [HOST_B] and result['server'] == HOST_B
    egress = result['checks']['egress']
    assert egress['state'] == 'fail' and egress['reason'] == 'host-address-not-measurable'
    assert result['message'] == "Switched; the egress couldn't be compared with this host's address."
    assert result['selection']['outcome'] == 'applied-unverified'
    assert result['selection']['next_action'] == 'recheck'
    found = verdict(applier, result)
    assert found.state == 'unknown' and found.label == 'switched, egress unverified'
    for _ in range(60):
        kernel.now += 60
        applier.tick()
    assert gluetun.puts == [HOST_B]
    assert applier.selection['last_applied'] == HOST_B and applier.selection['last_successful'] is None


def test_a_tunnel_tier_sidecar_restores_the_last_applied_server(tmp_path):
    applier, kernel, gluetun = make(tmp_path, 'ivpn')
    applier.save_selection(last_put=HOST_B, last_applied=HOST_B)
    kernel.tunnel = HOST_A  # gluetun restarted on its environment's server
    result = applier.tick()
    assert gluetun.puts == [HOST_B] and result['selection']['source'] == 'restore'


def test_a_drifted_tunnel_tier_sidecar_is_still_put_back(tmp_path):
    applier, kernel, gluetun = make(tmp_path, 'ivpn')
    write_json_atomic(applier.desired_path, request(HOST_B))
    applier.tick()
    kernel.tunnel = HOST_A
    kernel.now += 91
    applier.tick()
    assert gluetun.puts == [HOST_B, HOST_B]


def test_health_and_doctor_are_kind_aware(tmp_path):
    applier, kernel, gluetun = make(tmp_path)
    write_json_atomic(applier.desired_path, request(HOST_B))
    applier.tick()
    assert applier.healthy()
    gluetun.status = None
    assert not applier.healthy()
    gluetun.status = 'running'
    checks = applier.doctor_checks()
    assert 'routing protection' not in checks and 'NetBird kernel WireGuard and kernel firewall' not in checks
    assert checks["gluetun's control server answers with the API key"]
    assert list(checks)[-1] == 'verified NordVPN egress' and all(checks.values())

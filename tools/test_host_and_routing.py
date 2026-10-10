import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('host_tools', ROOT / 'tools' / 'molebridge.py')
host_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_tools)


def test_recovery_rebuilds_and_recreates_all_namespace_users(monkeypatch, tmp_path):
    calls = []
    host = host_tools.Host(tmp_path, run=lambda args, **kw: calls.append(args) or '')
    monkeypatch.setattr(host, 'config', lambda: {})
    monkeypatch.setattr(host, 'check_files', lambda _: None)
    monkeypatch.setattr(host, 'check_volume', lambda _: None)
    monkeypatch.setattr(host, 'doctor', lambda: calls.append(['doctor']))
    host.recover()
    assert calls[0] == ['docker', 'compose', 'build', 'wireguard', 'applier']
    assert calls[1] == ['docker', 'compose', 'stop', 'netbird', 'applier']
    assert calls[2][-4:] == ['wireguard', 'netbird', 'applier', 'control-panel']
    assert '--force-recreate' in calls[2] and '--wait' in calls[2]
    assert calls[3][-2:] == ['applier.apply', '--doctor']
    assert calls[4] == ['doctor']
    assert all('down' not in c and '-v' not in c and 'volume' not in c for c in calls)


def test_recovery_of_the_gluetun_backend_recreates_its_namespace_users(monkeypatch, tmp_path):
    calls = []
    host = host_tools.Host(tmp_path, run=lambda args, **kw: calls.append(args) or '')
    monkeypatch.setattr(host, 'config', lambda: {'services': {'gluetun': {}}})
    monkeypatch.setattr(host, 'check_files', lambda _: None)
    monkeypatch.setattr(host, 'check_volume', lambda _: None)
    monkeypatch.setattr(host, 'doctor', lambda: calls.append(['doctor']))
    host.recover()
    assert calls[0] == ['docker', 'compose', 'build', 'guard', 'applier']
    assert calls[1] == ['docker', 'compose', 'stop', 'netbird', 'applier', 'guard']
    assert calls[2][-5:] == ['gluetun', 'guard', 'netbird', 'applier', 'control-panel']
    assert '--force-recreate' in calls[2] and calls[-1] == ['doctor']
    assert all('down' not in c and '-v' not in c and 'volume' not in c for c in calls)


def test_failed_build_leaves_live_containers_alone(monkeypatch, tmp_path):
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        raise host_tools.CheckError('build failed')
    host = host_tools.Host(tmp_path, run=run)
    monkeypatch.setattr(host, 'config', lambda: {})
    monkeypatch.setattr(host, 'check_files', lambda _: None)
    monkeypatch.setattr(host, 'check_volume', lambda _: None)
    with pytest.raises(host_tools.CheckError):
        host.recover()
    assert calls == [['docker', 'compose', 'build', 'wireguard', 'applier']]


def test_missing_volume_refuses_reenrollment(tmp_path):
    def fail(*args, **kwargs):
        raise host_tools.CheckError('absent')
    host = host_tools.Host(tmp_path, run=fail)
    with pytest.raises(host_tools.CheckError, match='will not enroll'):
        host.check_volume({'volumes': {'netbird-data': {'name': 'example_netbird-data'}}})


def test_doctor_detects_dead_namespace(tmp_path):
    values = iter(['net:[1]', 'net:[2]', 'net:[2]'])
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: next(values))
    with pytest.raises(host_tools.CheckError, match='namespace'):
        host.namespace_checks()


def test_compose_trust_boundary():
    yaml = pytest.importorskip('yaml')
    compose = yaml.safe_load((ROOT / 'compose.yaml').read_text())
    panel = compose['services']['control-panel']
    assert panel['cap_drop'] == ['ALL'] and 'cap_add' not in panel
    assert './state/applier:/state/applier:ro' in panel['volumes']
    assert './state/panel:/state/panel' in panel['volumes']
    applier = compose['services']['applier']
    assert './state/panel:/state/panel:ro' in applier['volumes']
    assert all('tunnel' not in v and '/config' not in v for v in applier['volumes'])
    assert applier['network_mode'] == 'service:wireguard'
    assert applier['read_only']
    netbird = compose['services']['netbird']
    assert netbird['environment']['NB_INTERFACE_NAME'] == applier['environment']['OVERLAY_IF']
    assert netbird['entrypoint'] == ['/bin/sh', '/usr/local/bin/molebridge-wait-for-guards',
                                     '/usr/local/bin/netbird-entrypoint.sh']
    assert './routing/wait-for-guards:/usr/local/bin/molebridge-wait-for-guards:ro' in netbird['volumes']
    wireguard = compose['services']['wireguard']
    assert wireguard['sysctls']['net.ipv4.icmp_errors_use_inbound_ifaddr'] == '1'


def test_compose_sets_the_required_netbird_settings():
    yaml = pytest.importorskip('yaml')
    compose = yaml.safe_load((ROOT / 'compose.yaml').read_text())
    netbird = compose['services']['netbird']['environment']
    assert netbird['NB_DISABLE_USERSPACE_ROUTING'] == 'true'
    assert not set(host_tools.NETBIRD_MUST_BE_OFF) & set(netbird)
    pia = yaml.safe_load((ROOT / 'compose.pia.yaml').read_text())
    assert 'environment' not in pia['services'].get('netbird', {})


def test_compose_avoids_engine_specific_runtime_settings():
    """Settings Docker accepts silently but a rootless Podman host rejects, or
    honors differently, once the same file runs there."""
    yaml = pytest.importorskip('yaml')
    compose = yaml.safe_load((ROOT / 'compose.yaml').read_text())
    for name, service in compose['services'].items():
        logging = service['logging']
        assert logging['driver'] == 'json-file', name
        assert set(logging['options']) == {'max-size'}, name
    # Docker grants NET_RAW implicitly; NetBird needs it to bring the overlay up.
    assert compose['services']['netbird']['cap_add'] == ['NET_ADMIN', 'NET_RAW']
    # The panel's user must be separable from PUID/PGID for remapped engines.
    assert compose['services']['control-panel']['user'] == '${PANEL_USER:-1000:1000}'


TUNNEL_CONF = """[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 203.0.113.1/32, 2001:db8:3::1/128
MTU = 1420
Table = off
PostUp = ip route replace default dev %i table 51821; ip -6 route replace default dev %i table 51821
PreDown = ip route del default dev %i table 51821; ip -6 route del default dev %i table 51821
"""


def compose_config(**changes):
    config = {
        'services': {
            'wireguard': {'environment': {'OVERLAY_CIDR': '192.0.2.0/24', 'EXIT_TABLE': '51821', 'EXIT_IF': 'mullvad'},
                          'sysctls': {'net.ipv4.ip_forward': '1', 'net.ipv4.icmp_errors_use_inbound_ifaddr': '1'}},
            'control-panel': {'cap_drop': ['ALL'], 'volumes': [
                {'target': '/state/applier', 'read_only': True}, {'target': '/state/panel'}]},
            'applier': {'volumes': [{'target': '/state/applier'}]},
            'netbird': {'environment': {'NB_INTERFACE_NAME': 'wt0', 'NB_DISABLE_USERSPACE_ROUTING': 'true'}},
        },
        'volumes': {'netbird-data': {'name': 'example_netbird-data'}},
    }
    config['services']['wireguard'].update(changes)
    return config


def test_doctor_requires_the_return_path_sysctl(tmp_path):
    (tmp_path / '.env').write_text('')
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(compose_config()))
    assert host.config()['services']['wireguard']['sysctls']
    for sysctls in ({}, {'net.ipv4.icmp_errors_use_inbound_ifaddr': '0'}):
        host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(compose_config(sysctls=sysctls)))
        with pytest.raises(host_tools.CheckError, match='icmp_errors_use_inbound_ifaddr'):
            host.config()


@pytest.mark.parametrize('changes,message', [
    ({'NB_DISABLE_USERSPACE_ROUTING': 'false'}, 'NB_DISABLE_USERSPACE_ROUTING=true'),
    ({'NB_DISABLE_USERSPACE_ROUTING': None}, 'NB_DISABLE_USERSPACE_ROUTING=true'),
    ({'NB_FORCE_USERSPACE_FIREWALL': 'true'}, 'sets NB_FORCE_USERSPACE_FIREWALL'),
    ({'NB_FORCE_USERSPACE_ROUTER': '1'}, 'sets NB_FORCE_USERSPACE_ROUTER'),
    ({'NB_USE_NETSTACK_MODE': 'true'}, 'sets NB_USE_NETSTACK_MODE'),
    ({'NB_USE_NETSTACK_MODE': 'TRUE', 'NB_WG_KERNEL_DISABLED': '1'}, None),
    ({'NB_CONFIG': '/var/lib/netbird/peer.json'}, 'sets NB_CONFIG'),
    ({'WT_CONFIG': ''}, 'sets WT_CONFIG'),
    ({'NB_PROFILE': 'alternate'}, 'sets NB_PROFILE'),
    ({'NB_FOREGROUND_MODE': 'true'}, "sets NB_FOREGROUND_MODE; Molebridge supports only NetBird's daemon mode"),
    ({'WT_FOREGROUND_MODE': '1'}, 'sets WT_FOREGROUND_MODE'),
    ({'NB_FOREGROUND_MODE': 'false'}, None),
    ({'WT_INTERFACE_NAME': 'wt1'}, 'WT_INTERFACE_NAME'),
    ({'WT_INTERFACE_NAME': 'wt0'}, None),
    ({'NB_WG_KERNEL_DISABLED': 'true'}, 'sets NB_WG_KERNEL_DISABLED'),
    ({'NB_ENABLE_ROSENPASS': 'True'}, 'sets NB_ENABLE_ROSENPASS'),
    ({'WT_ENABLE_ROSENPASS': 't'}, 'sets WT_ENABLE_ROSENPASS'),
    ({'NB_ENABLE_ROSENPASS': 'false', 'NB_FORCE_USERSPACE_FIREWALL': '0'}, None),
])
def test_doctor_refuses_unsupported_netbird_settings(tmp_path, changes, message):
    (tmp_path / '.env').write_text('')
    config = compose_config()
    env = config['services']['netbird']['environment']
    for key, value in changes.items():
        if value is None:
            env.pop(key)
        else:
            env[key] = value
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(config))
    if message is None:
        host.config()
    else:
        with pytest.raises(host_tools.CheckError, match=message):
            host.config()


@pytest.mark.parametrize('output,message', [
    ('NetBird gate: configuration accepted\nexit=0\n', None),
    ('NetBird gate: refusing to start NetBird: Rosenpass is enabled in a stored NetBird profile '
     '(RosenpassEnabled) (see docs/troubleshooting.md)\nexit=1\n', 'Rosenpass is enabled'),
    ('NetBird gate: refusing to start NetBird: NB_CONFIG is set; x\nexit=1\n', 'NB_CONFIG is set'),
    ('something else\nexit=1\n', 'did not accept'),
    ('NetBird gate: configuration accepted\nexit=1\n', 'did not accept'),
    ('', 'did not accept'),
])
def test_doctor_runs_the_gate_configuration_checks(tmp_path, output, message):
    calls = []
    host = host_tools.Host(tmp_path, run=lambda args, **kw: calls.append(args) or output)
    if message is None:
        host.netbird_config_check()
    else:
        with pytest.raises(host_tools.CheckError, match=message) as excinfo:
            host.netbird_config_check()
        assert 'something else' not in str(excinfo.value)
    assert calls[0][:5] == ['docker', 'compose', 'exec', '-T', 'netbird']
    assert '/usr/local/bin/molebridge-wait-for-guards --check-config' in calls[0][-1]


BLACKLIST_OUTPUT = """  "IFaceBlackList": [
    "docker0",
    "veth",
    "lo",
    "mullvad"
  ],
"""


def test_doctor_reads_only_the_ice_blacklist_field(tmp_path):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return BLACKLIST_OUTPUT
    host = host_tools.Host(tmp_path, run=run)
    host.ice_blacklist_check(compose_config())
    assert calls[0][:5] == ['docker', 'compose', 'exec', '-T', 'netbird']
    script = calls[0][-1]
    assert 'IFaceBlackList' in script and 'default.json' in script
    assert 'cat ' not in script and 'PrivateKey' not in script


@pytest.mark.parametrize('output,message', [
    (BLACKLIST_OUTPUT.replace('"lo",\n    "mullvad"', '"lo"'), 'not in the NetBird ICE interface blacklist'),
    ('  "IFaceBlackList": [],\n', 'not in the NetBird ICE interface blacklist'),
    ('  "IFaceBlackList": null,\n', 'not in the NetBird ICE interface blacklist'),
    ('', 'no interface blacklist'),
    ('  "WgPort": 51820,\n', 'no interface blacklist'),
])
def test_doctor_fails_clearly_without_the_exit_interface_blacklisted(tmp_path, output, message):
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: output)
    with pytest.raises(host_tools.CheckError, match=message) as excinfo:
        host.ice_blacklist_check(compose_config())
    # Diagnostics name the fix, never the other blacklist entries or the file.
    assert 'docker0' not in str(excinfo.value) and 'veth' not in str(excinfo.value)
    assert '--extra-iface-blacklist mullvad' in str(excinfo.value) or 'blacklist field' in str(excinfo.value)


def test_doctor_fails_when_the_peer_configuration_is_unavailable(tmp_path):
    def fail(*args, **kwargs):
        raise host_tools.CheckError('exec failed')
    host = host_tools.Host(tmp_path, run=fail)
    with pytest.raises(host_tools.CheckError, match='Unable to read'):
        host.ice_blacklist_check(compose_config())


def test_doctor_checks_the_blacklist_before_trusting_applier_state(monkeypatch, tmp_path):
    order = []
    host = host_tools.Host(tmp_path, run=lambda args, **kw: order.append(args) or '')
    monkeypatch.setattr(host, 'config', lambda: compose_config())
    monkeypatch.setattr(host, 'check_files', lambda _: None)
    monkeypatch.setattr(host, 'check_volume', lambda _: None)
    monkeypatch.setattr(host, 'namespace_checks', lambda owner: order.append(['namespace', owner]))
    monkeypatch.setattr(host, 'ice_blacklist_check', lambda _: order.append(['blacklist']))
    monkeypatch.setattr(host, 'netbird_config_check', lambda: order.append(['rosenpass']))
    host.doctor()
    assert order[:3] == [['namespace', 'wireguard'], ['blacklist'], ['rosenpass']]
    assert order[3][-2:] == ['applier.apply', '--doctor']


def test_compose_blacklists_the_exit_interface_at_first_enrollment():
    yaml = pytest.importorskip('yaml')
    compose = yaml.safe_load((ROOT / 'compose.yaml').read_text())
    netbird = compose['services']['netbird']['environment']
    wireguard = compose['services']['wireguard']['environment']
    assert netbird['NB_EXTRA_IFACE_BLACKLIST'] == wireguard['EXIT_IF'] == '${EXIT_IF:-mullvad}'


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
@pytest.mark.parametrize('text,message', [
    (TUNNEL_CONF, None),
    (TUNNEL_CONF.replace('; ip -6 route replace default dev %i table 51821', ''), 'every address family'),
    (TUNNEL_CONF.replace('; ip -6 route del default dev %i table 51821', ''), 'every address family'),
    (TUNNEL_CONF.replace(', 2001:db8:3::1/128', ''), None),
    (TUNNEL_CONF.replace('203.0.113.1/32', '203.0.113.1/32, 203.0.113.2/32'), 'exactly one IPv4'),
    (TUNNEL_CONF.replace('Address = 203.0.113.1/32, 2001:db8:3::1/128', 'Address = 2001:db8:3::1/128'), 'exactly one IPv4'),
    (TUNNEL_CONF.replace('203.0.113.1/32', 'not-an-address'), 'invalid Address'),
])
def test_doctor_checks_both_route_hooks_and_one_address_per_family(tmp_path, text, message):
    path = tmp_path / 'tunnel' / 'wg_confs' / 'mullvad.conf'
    path.parent.mkdir(parents=True)
    path.write_text(text)
    path.chmod(0o600)
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: '')
    if message is None:
        host.check_files(compose_config())
    else:
        with pytest.raises(host_tools.CheckError, match=message):
            host.check_files(compose_config())


def shell():
    if os.name == 'nt':
        path = Path('C:/Program Files/Git/bin/sh.exe')
        return str(path) if path.exists() else None
    return shutil.which('sh')


def posix_path(path):
    text = path.as_posix()
    return '/' + text[0].lower() + text[2:] if os.name == 'nt' else text


def routing_run(tmp_path, fault='', **env_changes):
    if not shell():
        pytest.skip('POSIX shell unavailable')
    binary = tmp_path / 'ip'
    binary.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$LOGFILE"
case "$*" in *"rule show"*) [ -z "$RULES_SHOWN" ] || printf '%s\\n' "$RULES_SHOWN"; exit 0 ;; esac
case "$*" in *"rule del"*) exit 1 ;; esac
if [ -n "$INJECT_FAULT" ]; then
    case "$*" in *"$INJECT_FAULT"*) exit 1 ;; esac
fi
exit 0
''', newline='\n')
    binary.chmod(0o755)
    log = tmp_path / 'commands'
    ready = tmp_path / 'ready'
    conf = tmp_path / 'mullvad.conf'
    conf.write_text(env_changes.pop('conf_text', TUNNEL_CONF))
    tunnel_conf = env_changes.pop('TUNNEL_CONF', posix_path(conf))
    env = dict(os.environ, OVERLAY_CIDR='192.0.2.0/24', OVERLAY6_CIDR='2001:db8:1::/64',
               OVERLAY_IF='wt0', EXIT_IF='mullvad', EXIT_TABLE='51821', TUNNEL_CONF=tunnel_conf,
               FAKE_BIN=posix_path(tmp_path), SCRIPT=posix_path(ROOT / 'routing' / '10-exit-routing'),
               LOGFILE=posix_path(log), ROUTING_READY_FILE=posix_path(ready), INJECT_FAULT=fault,
               RULES_SHOWN=env_changes.pop('rules_shown', ''), **env_changes)
    result = subprocess.run([shell(), '-c', 'PATH="$FAKE_BIN:$PATH"; export PATH; sh "$SCRIPT"'],
                            env=env, capture_output=True, text=True, timeout=10)
    return result, log.read_text().splitlines() if log.exists() else [], ready


def test_routing_initialization_blocks_before_replacing_rules(tmp_path):
    result, calls, ready = routing_run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert ready.exists()
    for family, address, protocol in (('-4', '203.0.113.1', 'icmp'),
                                      ('-6', '2001:db8:3::1', 'ipv6-icmp')):
        guard = calls.index(f'{family} rule add iif wt0 unreachable priority 80')
        fallback = calls.index(f'{family} route replace unreachable default metric 4096 table 51821')
        deleting = calls.index(f'{family} rule del priority 90')
        stale = calls.index(f'{family} rule del priority 94')
        return_path = calls.index(
            f'{family} rule add from {address} ipproto {protocol} lookup 51821 priority 94')
        final = calls.index(f'{family} rule add iif wt0 unreachable priority 97')
        unblock = calls.index(f'{family} rule del iif wt0 unreachable priority 80')
        assert guard < fallback < deleting < stale < return_path < final < unblock
        # The local-delivery rule goes in before the kernel's rule 0 comes out,
        # and both happen before anything else changes.
        local = calls.index(f'{family} rule add not iif wt0 lookup local priority 1')
        kernel_rule = calls.index(f'{family} rule del priority 0')
        assert local < kernel_rule < guard
    assert '-4 rule add iif mullvad to 192.0.2.0/24 lookup main priority 90' in calls
    assert 'AAAAAAAA' not in result.stdout + result.stderr


@pytest.mark.parametrize('detached', ['', '[detached] '])
def test_routing_rerun_keeps_the_local_delivery_rule(tmp_path, detached):
    result, calls, ready = routing_run(tmp_path, rules_shown=f'1:\tnot from all iif wt0 {detached}lookup local')
    assert result.returncode == 0, result.stderr
    assert not any('lookup local' in call for call in calls)
    assert '-4 rule del priority 0' in calls and '-6 rule del priority 0' in calls


@pytest.mark.parametrize('shown', ['0:\tfrom all lookup local', '1:\tnot from all iif wt1 lookup local',
                                   '1:\tnot from all iif wt0 fwmark 0x1 lookup local'])
def test_routing_installs_the_exact_local_delivery_rule(tmp_path, shown):
    result, calls, ready = routing_run(tmp_path, rules_shown=shown)
    assert result.returncode == 0, result.stderr
    assert '-4 rule add not iif wt0 lookup local priority 1' in calls


def test_failed_local_delivery_rule_keeps_the_kernel_rule(tmp_path):
    result, calls, ready = routing_run(tmp_path, fault='-4 rule add not iif wt0 lookup local')
    assert result.returncode != 0 and not ready.exists()
    assert not any('rule del priority 0' in call for call in calls)


def test_ipv4_only_tunnel_gets_no_ipv6_return_path_rule(tmp_path):
    result, calls, ready = routing_run(tmp_path, conf_text=TUNNEL_CONF.replace(', 2001:db8:3::1/128', ''))
    assert result.returncode == 0, result.stderr
    assert ready.exists()
    assert '-4 rule add from 203.0.113.1 ipproto icmp lookup 51821 priority 94' in calls
    assert not any('-6 rule add from' in call for call in calls)


@pytest.mark.parametrize('conf_text', [
    TUNNEL_CONF.replace('Address = 203.0.113.1/32, 2001:db8:3::1/128', 'Address = 2001:db8:3::1/128'),
    TUNNEL_CONF.replace('203.0.113.1/32', '203.0.113.1/32, 203.0.113.2/32'),
    TUNNEL_CONF.replace('2001:db8:3::1/128', '2001:db8:3::1/128, 2001:db8:3::2/128'),
    TUNNEL_CONF.replace('203.0.113.1/32', '203.0.113.256/32'),
    TUNNEL_CONF.replace('2001:db8:3::1/128', '2001:db8:3::g/128'),
    TUNNEL_CONF.replace('Address = 203.0.113.1/32, 2001:db8:3::1/128\n', ''),
])
def test_unsupported_tunnel_addresses_stop_routing_init(tmp_path, conf_text):
    result, calls, ready = routing_run(tmp_path, conf_text=conf_text)
    assert result.returncode != 0
    assert '10-exit-routing:' in result.stderr and 'AAAAAAAA' not in result.stdout + result.stderr
    assert not ready.exists() and not any('rule add' in call for call in calls)


def test_missing_tunnel_config_stops_routing_init(tmp_path):
    result, calls, ready = routing_run(tmp_path, TUNNEL_CONF=posix_path(tmp_path / 'absent.conf'))
    assert result.returncode != 0
    assert 'tunnel configuration is missing' in result.stderr
    assert not ready.exists() and not calls


def test_failed_routing_init_leaves_guard_and_never_marks_ready(tmp_path):
    result, calls, ready = routing_run(tmp_path, fault='-6 rule add iif wt0 lookup')
    assert result.returncode != 0
    assert not ready.exists()
    assert not any('rule del iif wt0 unreachable priority 80' in call for call in calls)


@pytest.mark.parametrize('setting,value', [('EXIT_TABLE', '254'), ('OVERLAY_CIDR', '0.0.0.0/0'),
                                        ('OVERLAY_CIDR', '192.0.2.5/24'), ('OVERLAY_IF', '../bad')])
def test_bad_config_makes_no_routing_changes(tmp_path, setting, value):
    # Pass overridden variables through a copied environment to avoid kwargs duplication.
    if not shell():
        pytest.skip('POSIX shell unavailable')
    conf = tmp_path / 'mullvad.conf'
    conf.write_text(TUNNEL_CONF)
    env = dict(os.environ, OVERLAY_CIDR='192.0.2.0/24', EXIT_TABLE='51821', TUNNEL_CONF=posix_path(conf),
               ROUTING_READY_FILE=posix_path(tmp_path / 'ready'))
    env[setting] = value
    result = subprocess.run([shell(), posix_path(ROOT / 'routing' / '10-exit-routing')],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert '10-exit-routing:' in result.stderr


BOOT = '00000000-0000-4000-8000-000000000001'
LOCAL_GUARD = '1:\tnot from all iif mesh0 lookup local'
TERMINAL = '97: from all iif mesh0 [detached] unreachable'
GUARDS = LOCAL_GUARD + '\n' + TERMINAL


def gate_run(tmp_path, rule4, rule6, *, interface='mesh0', advance=False, check_only=False, **env_changes):
    if not shell():
        pytest.skip('POSIX shell unavailable')
    for family, value in ((4, rule4), (6, rule6)):
        (tmp_path / f'rules-{family}').write_text(value)
    (tmp_path / 'state').mkdir(exist_ok=True)
    # The rest of the native contract (routing/contract-rules), for an
    # addressless config (no 94/98) and an IPv4 overlay only; the tests vary
    # rules 1 and 97 and anything else in rules-4 and rules-6.
    contract = f'95:\tfrom all iif {interface} lookup 51821\n96:\tfrom all oif mullvad lookup 51821\n'
    (tmp_path / 'native-4').write_text('90:\tfrom all to 192.0.2.0/24 iif mullvad lookup main\n' + contract)
    (tmp_path / 'native-6').write_text(contract)
    # The exit's owner record, live at the fake clock, in the fake namespace.
    (tmp_path / 'boot').write_text(BOOT + '\n')
    (tmp_path / 'uptime').write_text('1000.00 1.00\n')
    (tmp_path / 'owner').write_text(f'molebridge-exit 1 {BOOT} 1000 5:4026531992 0a0a - - applier 0 -\n')
    binaries = {
        'ip': '''#!/bin/sh
case "$*" in
    *"route show table"*) echo 'unreachable default metric 4096' ;;
    *"rule show"*) cat "$GATE_DIR/rules${1}"; echo; cat "$GATE_DIR/native${1}" ;;
    *) exit 1 ;;
esac
''',
        'stat': '#!/bin/sh\necho 5:4026531992\n',
        'setsid': '#!/bin/sh\nexec "$@"\n',
        'sleep': '''#!/bin/sh
if [ "$ADVANCE" != 1 ]; then exit 42; fi
if [ ! -f "$GATE_DIR/first-wait" ]; then
    touch "$GATE_DIR/first-wait"
    printf '%s\\n' '1:	not from all iif mesh0 [detached] lookup local' \\
        '97: from all iif mesh0 [detached] unreachable' > "$GATE_DIR/rules-4"
else
    touch "$GATE_DIR/second-wait"
    printf '%s\\n' '1:	not from all iif mesh0 [detached] lookup local' \\
        '97: from all iif mesh0 [detached] unreachable' > "$GATE_DIR/rules-6"
fi
''',
    }
    for name, source in binaries.items():
        binary = tmp_path / name
        binary.write_text(source, newline='\n')
        binary.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('NB_', 'WT_'))}
    env.update(GATE_DIR=posix_path(tmp_path), NB_INTERFACE_NAME=interface, NB_DISABLE_USERSPACE_ROUTING='true',
               NB_STATE_DIR=posix_path(tmp_path / 'state'), ADVANCE=str(int(advance)),
               SCRIPT=posix_path(ROOT / 'routing' / 'wait-for-guards'), OVERLAY_CIDR='192.0.2.0/24',
               EXIT_IF='mullvad', EXIT_TABLE='51821', CONTRACT_RULES=posix_path(ROOT / 'routing' / 'contract-rules'),
               OWNER_RECORD=posix_path(tmp_path / 'owner'), MOLEBRIDGE_BOOT_ID_FILE=posix_path(tmp_path / 'boot'),
               MOLEBRIDGE_UPTIME_FILE=posix_path(tmp_path / 'uptime'))
    for key, value in env_changes.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    command = ('sh "$SCRIPT" --check-config' if check_only
               else 'sh "$SCRIPT" sh -c \'touch "$GATE_DIR/started"\'')
    return subprocess.run([shell(), '-c', 'PATH="$GATE_DIR:$PATH"; export PATH; ' + command],
                          env=env, capture_output=True, text=True, timeout=5)


@pytest.mark.parametrize('rule', [
    '', '97: from all iif wt0 unreachable', '97: from 192.0.2.2 iif mesh0 unreachable',
    '97: from all iif mesh0 lookup 51821', '197: from all iif mesh0 unreachable',
    '97: from all iif mesh0 unreachable suppress_prefixlength 0',
])
@pytest.mark.parametrize('family', [4, 6])
def test_netbird_gate_refuses_missing_wrong_or_narrowed_guards(tmp_path, rule, family):
    valid = LOCAL_GUARD + '\n97: from all iif mesh0 unreachable'
    rule = LOCAL_GUARD + '\n' + rule
    result = gate_run(tmp_path, rule if family == 4 else valid, rule if family == 6 else valid)
    assert result.returncode != 0
    assert not (tmp_path / 'started').exists()


def test_netbird_gate_waits_for_both_families_before_starting(tmp_path):
    result = gate_run(tmp_path, '', '', advance=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'first-wait').exists() and (tmp_path / 'second-wait').exists()
    assert (tmp_path / 'started').exists()


@pytest.mark.parametrize('detached', ['', '[detached] '])
def test_netbird_gate_accepts_exact_guards_before_overlay_exists(tmp_path, detached):
    rule = f'1:\tnot from all iif mesh0 {detached}lookup local\n97: from all iif mesh0 {detached}unreachable'
    assert gate_run(tmp_path, rule, rule).returncode == 0
    assert (tmp_path / 'started').exists()


@pytest.mark.parametrize('rules', [
    TERMINAL,                                                       # rule 1 missing
    '0:\tfrom all lookup local\n' + GUARDS,                         # kernel rule 0 still present
    '1:\tfrom all iif mesh0 lookup local\n' + TERMINAL,              # not inverted
    '1:\tnot from all iif wt0 lookup local\n' + TERMINAL,            # inverted for another interface
    '1:\tnot from all iif mesh0 fwmark 0x1 lookup local\n' + TERMINAL,  # narrowed inversion
    '2:\tnot from all iif mesh0 lookup local\n' + TERMINAL,          # wrong priority
    '1:\tnot from all iif mesh0 lookup main\n' + TERMINAL,
    GUARDS + '\n32765:\tfrom all lookup local',                     # a later catch-all local rule
    GUARDS + '\n200:\tfrom all iif mesh0 lookup local',
    GUARDS + '\n200:\tnot from all iif lo lookup local',
])
@pytest.mark.parametrize('family', [4, 6])
def test_netbird_gate_requires_the_local_delivery_guard(tmp_path, rules, family):
    result = gate_run(tmp_path, rules if family == 4 else GUARDS, rules if family == 6 else GUARDS)
    # 42 is the fake sleep's exit: the gate reached its wait loop and kept waiting.
    assert result.returncode == 42, result.stderr
    assert not (tmp_path / 'started').exists()


@pytest.mark.parametrize('extra', ['200:\tfrom all iif lo lookup local',
                                   '200:\tnot from all iif mesh0 lookup local',
                                   '32766:\tfrom all lookup main'])
def test_netbird_gate_accepts_local_rules_that_cannot_match_the_overlay(tmp_path, extra):
    rules = GUARDS + '\n' + extra
    assert gate_run(tmp_path, rules, rules).returncode == 0
    assert (tmp_path / 'started').exists()


@pytest.mark.parametrize('name,value', [
    ('NB_FORCE_USERSPACE_FIREWALL', 'true'), ('NB_FORCE_USERSPACE_FIREWALL', '1'),
    ('NB_FORCE_USERSPACE_ROUTER', 'True'), ('NB_USE_NETSTACK_MODE', 'true'),
    ('NB_CONFIG', '/var/lib/netbird/peer.json'), ('NB_CONFIG', ''), ('WT_CONFIG', '/etc/netbird/config.json'),
    ('NB_PROFILE', 'alternate'), ('WT_PROFILE', ''),
    ('NB_FOREGROUND_MODE', 'true'), ('NB_FOREGROUND_MODE', '1'), ('WT_FOREGROUND_MODE', 'T'),
    ('NB_INTERFACE_NAME', ''), ('WT_INTERFACE_NAME', 'wt0'),
    ('NB_WG_KERNEL_DISABLED', 'true'), ('NB_ENABLE_ROSENPASS', 'true'), ('NB_ENABLE_ROSENPASS', 't'),
    ('WT_ENABLE_ROSENPASS', 'TRUE'), ('NB_DISABLE_USERSPACE_ROUTING', 'false'),
    ('NB_DISABLE_USERSPACE_ROUTING', ''), ('NB_DISABLE_USERSPACE_ROUTING', 'yes'),
])
def test_netbird_gate_refuses_unsupported_netbird_settings(tmp_path, name, value):
    result = gate_run(tmp_path, GUARDS, GUARDS, **{name: value})
    assert result.returncode == 1
    assert not (tmp_path / 'started').exists()
    assert 'NetBird gate: refusing to start NetBird: ' + name in result.stderr
    assert 'docs/troubleshooting.md' in result.stderr


@pytest.mark.parametrize('name,value', [
    ('NB_FORCE_USERSPACE_FIREWALL', 'false'), ('NB_FORCE_USERSPACE_ROUTER', '0'),
    ('NB_USE_NETSTACK_MODE', ''), ('NB_ENABLE_ROSENPASS', 'false'), ('NB_ROSENPASS_PERMISSIVE', 'true'),
    ('NB_DISABLE_USERSPACE_ROUTING', '1'),
    # NetBird turns these two on only for the exact value "true".
    ('NB_USE_NETSTACK_MODE', 'TRUE'), ('NB_USE_NETSTACK_MODE', '1'), ('NB_WG_KERNEL_DISABLED', '1'),
    ('NB_WG_KERNEL_DISABLED', 'True'),
    ('NB_FOREGROUND_MODE', 'false'), ('WT_FOREGROUND_MODE', '0'), ('WT_INTERFACE_NAME', 'mesh0'),
])
def test_netbird_gate_accepts_settings_that_keep_kernel_mode(tmp_path, name, value):
    assert gate_run(tmp_path, GUARDS, GUARDS, **{name: value}).returncode == 0
    assert (tmp_path / 'started').exists()


KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
PROFILE = ('{\n    "PrivateKey": "' + KEY + '",\n    "WgIface": "mesh0",\n'
           '    "RosenpassEnabled": %s,\n    "RosenpassPermissive": false\n}\n')


def write_profile(tmp_path, text, path='default.json'):
    profile = tmp_path / 'state' / path
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_bytes(text.encode() if isinstance(text, str) else text)
    return profile


def profile_verdict(tmp_path, text, *, interface='mesh0', path='default.json'):
    write_profile(tmp_path, text, path)
    rules = GUARDS.replace('mesh0', interface)
    result = gate_run(tmp_path, rules, rules, interface=interface)
    # The profile holds the peer's key; nothing of it may reach the log.
    assert KEY[:8] not in result.stdout + result.stderr
    return result


@pytest.mark.parametrize('text', [
    PROFILE % 'true',
    '{"PrivateKey": "' + KEY + '", "WgIface": "mesh0", "RosenpassEnabled":\n  true}',
    '{"WgIface":"mesh0",\n"RosenpassEnabled"\n:\ttrue\n}',
    '{"WgIface": "mesh0", "rosenpassenabled": true}',            # Go matches field names in any ASCII case
    '{"WgIface": "mesh0", "ROSENPASSENABLED": true}',
    '{"WgIface": "mesh0", "Rosenpass\\u0045nabled": true}',      # an escape that decodes to ASCII
    '{"WgIface": "mesh0", "RosenpassEnabled": null}',            # null counts as on
    '{"WgIface": "mesh0", "RosenpassEnabled": 0}',
    '{"WgIface": "mesh0", "RosenpassEnabled": "false"}',
])
def test_netbird_gate_reads_rosenpass_as_go_does(tmp_path, text):
    result = profile_verdict(tmp_path, text)
    assert result.returncode == 1 and not (tmp_path / 'started').exists()
    assert 'Rosenpass is enabled in a stored NetBird profile' in result.stderr


@pytest.mark.parametrize('text', [
    '{"WgIface": "mesh0", "RosenpassEnabled": false, "rosenpassEnabled": true}',
    '{"WgIface": "mesh0", "wgiface": "mesh0"}',
    '{"WgIface": "mesh0", "WGIFACE": "wt0"}',
])
def test_netbird_gate_refuses_a_repeated_checked_field(tmp_path, text):
    result = profile_verdict(tmp_path, text)
    assert result.returncode == 1 and 'repeats WgIface or RosenpassEnabled' in result.stderr


@pytest.mark.parametrize('text', [
    '{"WgIface": "mesh0", "R\u00f6senpassEnabled": true}',            # a non-ASCII field name
    '{"WgIface": "mesh0", "Ro\u017fenpassEnabled": true}',            # long s, which Go folds to s
    '{"WgIface": "mesh0", "\\u212aey": 1}',                           # Kelvin sign, as an escape
    '{"WgIface": "mesh0", "Wg\\tIface": "wt0"}',
])
def test_netbird_gate_refuses_root_field_names_outside_ascii(tmp_path, text):
    result = profile_verdict(tmp_path, text)
    assert result.returncode == 1 and 'field name outside printable ASCII' in result.stderr


@pytest.mark.parametrize('text', [
    '["WgIface", "mesh0"]', '"mesh0"', '', '   ', 'null',
    '{"WgIface": "mesh0"', '{"WgIface": "mesh0"} {}', '{"WgIface": "mesh0"}x',
    '{"WgIface": "mesh0",}', '{"WgIface" "mesh0"}', "{'WgIface': 'mesh0'}",
    '{"WgIface": "mesh0", "Port": 01}', '{"WgIface": "mesh0", "Port": 1.}', '{"WgIface": "mesh0", "Port": -}',
    '{"WgIface": "mesh0", "Port": 1e}', '{"WgIface": "mesh0", "On": tru}', '{"WgIface": "mesh0", "On": truex}',
    '{"WgIface": "mesh0", "Name": "a\\qb"}', '{"WgIface": "mesh0", "Name": "\\u00g0"}',
    '{"WgIface": "mesh0", "Name": "tab\there"}',                     # raw control character in a string
    '{"WgIface": "mesh0", "List": [1, 2,]}', '{"WgIface": "mesh0", "List": [1 2]}',
    '{"WgIface": "mesh0", "Obj": {"a": 1]}', b'{"WgIface": "mesh0", "Name": "a\x00b"}',
])
def test_netbird_gate_refuses_malformed_json(tmp_path, text):
    result = profile_verdict(tmp_path, text)
    assert result.returncode == 1 and 'is not a valid JSON object' in result.stderr


@pytest.mark.skipif(os.name != 'posix' or os.geteuid() == 0, reason='needs an unreadable file')
def test_netbird_gate_refuses_an_unreadable_profile(tmp_path):
    write_profile(tmp_path, PROFILE % 'false').chmod(0)
    result = gate_run(tmp_path, GUARDS, GUARDS)
    assert result.returncode == 1 and 'cannot read the stored NetBird profile' in result.stderr


@pytest.mark.parametrize('text,interface', [
    ('{"WgIface": "wt0"}', 'mesh0'),
    ('{"PrivateKey": "' + KEY + '"}', 'mesh0'),                     # absent: NetBird uses wt0
    ('{"WgIface": ""}', 'mesh0'),                                   # empty: NetBird uses wt0
    ('{"WgIface": null}', 'mesh0'),
    ('{"WgIface": 5}', 'mesh0'),
    ('{"WgIface": ["mesh0"]}', 'mesh0'),
    ('{"WgIface": "mesh00"}', 'mesh0'),
    ('{"WgIface": "mesh\\u0030 "}', 'mesh0'),
    ('{"WgIface": "mesh0", "Extra": {"WgIface": "mesh0"}}', 'wt0'),
    ('{"Extra": {"WgIface": "mesh0"}, "RosenpassEnabled": false}', 'mesh0'),  # nested: not the field
    ('{"Wg Iface": "mesh0", "RosenpassEnabled": false}', 'mesh0'),           # another field
    ('{"List": [{"WgIface": "mesh0"}]}', 'mesh0'),
    ('{"WgIface": "mesh0"}', 'wt0'),
])
def test_netbird_gate_refuses_a_profile_for_another_interface(tmp_path, text, interface):
    result = profile_verdict(tmp_path, text, interface=interface)
    assert result.returncode == 1 and not (tmp_path / 'started').exists()
    assert 'uses a WireGuard interface other than ' + interface in result.stderr


@pytest.mark.parametrize('text,interface', [
    ('{"PrivateKey": "' + KEY + '"}', 'wt0'),
    ('{"WgIface": ""}', 'wt0'),
    ('{"wgiface": "mesh0", "RosenpassEnabled": false}', 'mesh0'),
    ('{"WgIface": "mesh\\u0030"}', 'mesh0'),
    ('{\n  "WgIface":\n    "wt0",\n  "SSHKey": "-----BEGIN-----\\nAAAA\\n-----END-----\\n"\n}', 'wt0'),
    # Escapes, Unicode and nesting in unrelated fields are fine.
    ('{"Name": "R\\u0026D \\u00e9t\\u00e9 \\ud83d\\ude00 \\"q\\" \\\\ \\/", "WgIface": "mesh0"}', 'mesh0'),
    ('{"Name": "caf\u00e9", "WgIface": "mesh0", "ManagementURL": {"Scheme": "https", "Host": "example.net"}}', 'mesh0'),
    ('{"WgIface": "mesh0", "Nested": {"RosenpassEnabled": true, "WgIface": "wt0", "WgIface": "x"}}', 'mesh0'),
    ('{"WgIface": "mesh0", "Numbers": [0, -1, 2.5, 1e3, -0.5E-2, 10], "Flags": [true, false, null], "Empty": {}, "None": []}', 'mesh0'),
    ('{"WgIface": "mesh0", "RosenpassEnabled": false}', 'mesh0'),
])
def test_netbird_gate_accepts_a_profile_for_the_guarded_interface(tmp_path, text, interface):
    result = profile_verdict(tmp_path, text, interface=interface)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'started').exists()


@pytest.mark.parametrize('state', [
    '{"name": "alternate", "username": ""}',
    '{"name": "alternate", "username": "root"}',
    '{"Name": "alternate"}',                                          # Go matches "name" in any case
    '{"name": "default", "NAME": "alternate"}',
    '{"name": null}',
    '{"name": 1}',
    '{"name": "def\\u0061ult2"}',
    'not json',
    '[]',
])
def test_netbird_gate_supports_only_the_default_profile(tmp_path, state):
    write_profile(tmp_path, PROFILE % 'false')
    write_profile(tmp_path, state, 'active_profile.json')
    result = gate_run(tmp_path, GUARDS, GUARDS)
    assert result.returncode == 1 and not (tmp_path / 'started').exists()
    assert 'active NetBird profile' in result.stderr


@pytest.mark.parametrize('state', ['{"name": "default", "username": ""}', '{"name": "default", "username": "root"}',
                                   '{"name": ""}', '{}', '{"username": "root"}', '{"name": "def\\u0061ult"}'])
def test_netbird_gate_accepts_the_default_active_profile(tmp_path, state):
    write_profile(tmp_path, PROFILE % 'false')
    write_profile(tmp_path, state, 'active_profile.json')
    assert gate_run(tmp_path, GUARDS, GUARDS).returncode == 0


def test_netbird_gate_reads_only_the_files_netbird_loads_at_start(tmp_path):
    # Other profiles and state files cannot be loaded at start while the
    # active profile is the default one.
    write_profile(tmp_path, PROFILE % 'false')
    write_profile(tmp_path, '{"WgIface": "wt0", "RosenpassEnabled": true}', 'root/0123456789abcdef.json')
    write_profile(tmp_path, '{"email": "user@example.net"}', 'root/0123456789abcdef.state.json')
    write_profile(tmp_path, 'not json', 'state.json')
    write_profile(tmp_path, '{"name": "default", "username": "root"}', 'active_profile.json')
    assert gate_run(tmp_path, GUARDS, GUARDS).returncode == 0


@pytest.mark.parametrize('legacy', ['/etc/netbird/config.json', '/etc/wiretrustee/config.json'])
def test_netbird_gate_checks_the_legacy_files_netbird_migrates(tmp_path, legacy):
    # The legacy paths are absolute; check a copy of the gate that names a
    # temporary file instead.
    local = tmp_path / 'legacy.json'
    script = tmp_path / 'gate-copy'
    script.write_text((ROOT / 'routing' / 'wait-for-guards').read_text().replace(legacy, posix_path(local)))
    local.write_text('{"WgIface": "mesh0", "RosenpassEnabled": true}')
    result = gate_run(tmp_path, GUARDS, GUARDS, SCRIPT=posix_path(script))
    assert result.returncode == 1 and 'Rosenpass is enabled' in result.stderr
    local.write_text('{"WgIface": "wt0"}')
    result = gate_run(tmp_path, GUARDS, GUARDS, SCRIPT=posix_path(script))
    assert result.returncode == 1 and 'other than mesh0' in result.stderr
    local.write_text('{"WgIface": "mesh0"}')
    assert gate_run(tmp_path, GUARDS, GUARDS, SCRIPT=posix_path(script)).returncode == 0


def test_netbird_gate_check_mode_runs_only_the_configuration_checks(tmp_path):
    # No routing guards exist; check mode must not wait for them.
    write_profile(tmp_path, PROFILE % 'false')
    result = gate_run(tmp_path, '', '', check_only=True)
    assert result.returncode == 0 and result.stdout.strip() == 'NetBird gate: configuration accepted'
    write_profile(tmp_path, PROFILE % 'true')
    result = gate_run(tmp_path, '', '', check_only=True)
    assert result.returncode == 1 and 'Rosenpass is enabled' in result.stderr


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
@pytest.mark.parametrize('extra,secrets,message', [
    ('', True, None),
    ('', False, 'secrets/pia/username'),
    ('Address = 10.0.0.2/32\n', True, 'no Address or Peer'),
    ('[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n', True, 'no Address or Peer'),
])
def test_doctor_accepts_an_addressless_pia_config_with_its_login(tmp_path, extra, secrets, message):
    spec = importlib.util.spec_from_file_location('prepare', ROOT / 'tools' / 'prepare-tunnel-config.py')
    prepare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare)
    path = tmp_path / 'tunnel' / 'wg_confs' / 'pia.conf'
    path.parent.mkdir(parents=True)
    path.write_text(prepare.build_pia_conf(prepare.new_private_key()) + extra)
    path.chmod(0o600)
    if secrets:
        (tmp_path / 'secrets' / 'pia').mkdir(parents=True)
        for name in ('username', 'password'):
            (tmp_path / 'secrets' / 'pia' / name).write_text('x')
            (tmp_path / 'secrets' / 'pia' / name).chmod(0o600)
    config = compose_config()
    config['services']['wireguard']['environment'].update(EXIT_IF='pia', PROVIDER='pia')
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: '')
    if message is None:
        host.check_files(config)
    else:
        with pytest.raises(host_tools.CheckError, match=message):
            host.check_files(config)


APPLIER_SETTLING = 'PASS recent applier check\nPASS routing protection\nFAIL verified Mullvad egress\n'
APPLIER_OK = 'PASS recent applier check\nPASS routing protection\nPASS verified Mullvad egress\n'


def test_recover_waits_for_the_applier_to_verify_the_exit(monkeypatch, tmp_path, capsys):
    """Right after a recreation the applier has no verified result yet (with
    gluetun it may first put the last verified server back); recover waits
    for it instead of failing with a bare 'Command failed'."""
    answers = [(1, APPLIER_SETTLING)] * 3 + [(0, APPLIER_OK)]
    calls, now = [], [0.0]

    def run(args, **kwargs):
        calls.append(args)
        if args[-1] == '--doctor':
            assert kwargs.get('allow_failure') is True
            return answers.pop(0) if answers else (0, APPLIER_OK)
        return ''
    host = host_tools.Host(tmp_path, run=run, sleep=lambda s: now.__setitem__(0, now[0] + s), clock=lambda: now[0])
    monkeypatch.setattr(host, 'config', lambda: {})
    monkeypatch.setattr(host, 'check_files', lambda _: None)
    monkeypatch.setattr(host, 'check_volume', lambda _: None)
    monkeypatch.setattr(host, 'namespace_checks', lambda owner: None)
    monkeypatch.setattr(host, 'ice_blacklist_check', lambda _: None)
    monkeypatch.setattr(host, 'netbird_config_check', lambda: None)
    host.recover()
    assert now[0] == 3 * host_tools.SETTLE_POLL_SEC
    assert 'PASS configuration' in capsys.readouterr().out


def test_recover_names_the_check_that_never_passed(monkeypatch, tmp_path):
    now = [0.0]

    def run(args, **kwargs):
        if args[-1] == '--doctor':
            return (1, APPLIER_SETTLING + 'unexpected text 198.51.100.1\n')
        return ''
    host = host_tools.Host(tmp_path, run=run, sleep=lambda s: now.__setitem__(0, now[0] + s), clock=lambda: now[0])
    for name in ('config', 'netbird_config_check'):
        monkeypatch.setattr(host, name, lambda: {})
    for name in ('check_files', 'check_volume', 'namespace_checks', 'ice_blacklist_check'):
        monkeypatch.setattr(host, name, lambda _: None)
    with pytest.raises(host_tools.CheckError) as error:
        host.recover()
    assert str(error.value) == 'The applier reports: verified Mullvad egress (docs/troubleshooting.md).'
    assert host_tools.SETTLE_SEC <= now[0] <= host_tools.SETTLE_SEC + host_tools.SETTLE_POLL_SEC


def test_recover_names_the_compose_step_that_failed(monkeypatch, tmp_path):
    def run(args, **kwargs):
        if 'up' in args:
            raise host_tools.CheckError('Command failed; check Docker/Compose locally. Expanded output was withheld.')
        return ''
    host = host_tools.Host(tmp_path, run=run)
    monkeypatch.setattr(host, 'config', lambda: {})
    monkeypatch.setattr(host, 'check_files', lambda _: None)
    monkeypatch.setattr(host, 'check_volume', lambda _: None)
    with pytest.raises(host_tools.CheckError, match='^Recreating the containers .* failed: Command failed'):
        host.recover()


def test_applier_checks_report_a_dead_applier(tmp_path):
    host = host_tools.Host(tmp_path, run=lambda args, **kw: (1, ''))
    assert host.applier_checks() == [(False, 'the applier check itself (is the applier container running?)')]

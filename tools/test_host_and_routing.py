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
    assert calls[3] == ['doctor']
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
            'wireguard': {'environment': {'OVERLAY_CIDR': '192.0.2.0/24', 'EXIT_TABLE': '51821'},
                          'sysctls': {'net.ipv4.ip_forward': '1', 'net.ipv4.icmp_errors_use_inbound_ifaddr': '1'}},
            'control-panel': {'cap_drop': ['ALL'], 'volumes': [
                {'target': '/state/applier', 'read_only': True}, {'target': '/state/panel'}]},
            'applier': {'volumes': [{'target': '/state/applier'}]},
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
               **env_changes)
    result = subprocess.run([shell(), '-c', 'PATH="$FAKE_BIN:$PATH"; export PATH; sh "$SCRIPT"'],
                            env=env, capture_output=True, text=True, timeout=10)
    return result, log.read_text().splitlines() if log.exists() else [], ready


def test_routing_initialization_blocks_before_replacing_rules(tmp_path):
    result, calls, ready = routing_run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert ready.exists()
    for family, address in (('-4', '203.0.113.1'), ('-6', '2001:db8:3::1')):
        guard = calls.index(f'{family} rule add iif wt0 unreachable priority 80')
        fallback = calls.index(f'{family} route replace unreachable default metric 4096 table 51821')
        deleting = calls.index(f'{family} rule del priority 90')
        stale = calls.index(f'{family} rule del priority 94')
        return_path = calls.index(f'{family} rule add from {address} lookup 51821 priority 94')
        final = calls.index(f'{family} rule add iif wt0 unreachable priority 97')
        unblock = calls.index(f'{family} rule del iif wt0 unreachable priority 80')
        assert guard < fallback < deleting < stale < return_path < final < unblock
    assert '-4 rule add iif mullvad to 192.0.2.0/24 lookup main priority 90' in calls
    assert 'AAAAAAAA' not in result.stdout + result.stderr


def test_ipv4_only_tunnel_gets_no_ipv6_return_path_rule(tmp_path):
    result, calls, ready = routing_run(tmp_path, conf_text=TUNNEL_CONF.replace(', 2001:db8:3::1/128', ''))
    assert result.returncode == 0, result.stderr
    assert ready.exists()
    assert '-4 rule add from 203.0.113.1 lookup 51821 priority 94' in calls
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


def gate_run(tmp_path, rule4, rule6, *, interface='mesh0', advance=False):
    if not shell():
        pytest.skip('POSIX shell unavailable')
    for family, value in ((4, rule4), (6, rule6)):
        (tmp_path / f'rules-{family}').write_text(value)
    binaries = {
        'ip': '#!/bin/sh\ncat "$GATE_DIR/rules${1}"\n',
        'sleep': '''#!/bin/sh
if [ "$ADVANCE" != 1 ]; then exit 42; fi
if [ ! -f "$GATE_DIR/first-wait" ]; then
    touch "$GATE_DIR/first-wait"
    printf '%s\\n' '97: from all iif mesh0 [detached] unreachable' > "$GATE_DIR/rules-4"
else
    touch "$GATE_DIR/second-wait"
    printf '%s\\n' '97: from all iif mesh0 [detached] unreachable' > "$GATE_DIR/rules-6"
fi
''',
    }
    for name, source in binaries.items():
        binary = tmp_path / name
        binary.write_text(source, newline='\n')
        binary.chmod(0o755)
    env = dict(os.environ, GATE_DIR=posix_path(tmp_path), NB_INTERFACE_NAME=interface,
               ADVANCE=str(int(advance)), SCRIPT=posix_path(ROOT / 'routing' / 'wait-for-guards'))
    return subprocess.run([shell(), '-c',
                           'PATH="$GATE_DIR:$PATH"; export PATH; sh "$SCRIPT" sh -c \'touch "$GATE_DIR/started"\''],
                          env=env, capture_output=True, text=True, timeout=5)


@pytest.mark.parametrize('rule', [
    '', '97: from all iif wt0 unreachable', '97: from 192.0.2.2 iif mesh0 unreachable',
    '97: from all iif mesh0 lookup 51821', '197: from all iif mesh0 unreachable',
    '97: from all iif mesh0 unreachable suppress_prefixlength 0',
])
@pytest.mark.parametrize('family', [4, 6])
def test_netbird_gate_refuses_missing_wrong_or_narrowed_guards(tmp_path, rule, family):
    valid = '97: from all iif mesh0 unreachable'
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
    rule = f'97: from all iif mesh0 {detached}unreachable'
    assert gate_run(tmp_path, rule, rule).returncode == 0
    assert (tmp_path / 'started').exists()

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
    env = dict(os.environ, OVERLAY_CIDR='192.0.2.0/24', OVERLAY6_CIDR='2001:db8:1::/64',
               OVERLAY_IF='wt0', EXIT_IF='mullvad', EXIT_TABLE='51821',
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
    for family in ('-4', '-6'):
        guard = calls.index(f'{family} rule add iif wt0 unreachable priority 80')
        fallback = calls.index(f'{family} route replace unreachable default metric 4096 table 51821')
        deleting = calls.index(f'{family} rule del priority 90')
        final = calls.index(f'{family} rule add iif wt0 unreachable priority 97')
        unblock = calls.index(f'{family} rule del iif wt0 unreachable priority 80')
        assert guard < fallback < deleting < final < unblock
    assert '-4 rule add iif mullvad to 192.0.2.0/24 lookup main priority 90' in calls


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
    env = dict(os.environ, OVERLAY_CIDR='192.0.2.0/24', EXIT_TABLE='51821',
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

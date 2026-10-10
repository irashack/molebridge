"""The routing image's tunnel-config grammar (routing/molebridge-exit,
--check-config): what the generators write is accepted, anything else is
refused before any network change, and no message carries conf text."""
import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load('prepare', ROOT / 'tools' / 'prepare-tunnel-config.py')
nordkey = load('nordkey', ROOT / 'tools' / 'nordvpn-key.py')

# Fictitious values: all-zero keys and documentation addresses.
KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
SENTINEL = 'SENTINELq7Zk'
DOWNLOADED = f"""[Interface]
PrivateKey = {KEY}
Address = 203.0.113.2/32,2001:db8:3::2/128
DNS = 203.0.113.9

[Peer]
PublicKey = {KEY}
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 198.51.100.10:51820
"""
MULLVAD = prepare.build_tunnel_conf(DOWNLOADED)
MULLVAD4 = prepare.build_tunnel_conf(DOWNLOADED.replace(',2001:db8:3::2/128', ''))
PIA = prepare.build_pia_conf(KEY)
NORDVPN = nordkey.build_nord_conf(KEY)


def check(tmp_path, text, provider='mullvad', **env_changes):
    (tmp_path / f'{provider}.conf').write_text(text)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('MOLEBRIDGE_', 'OVERLAY', 'EXIT_'))}
    env.update(MOLEBRIDGE_LIB=str(ROOT / 'routing'), TUNNEL_CONF_DIR=str(tmp_path), OVERLAY_CIDR='192.0.2.0/24',
               EXIT_IF=provider, PROVIDER=provider, ROUTING_READY_FILE=str(tmp_path / 'ready'))
    env.update(env_changes)
    result = subprocess.run(['sh', str(ROOT / 'routing' / 'molebridge-exit'), '--check-config'], env=env,
                            capture_output=True, text=True, timeout=20)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.parametrize('provider,text', [('mullvad', MULLVAD), ('mullvad', MULLVAD4), ('pia', PIA),
                                           ('nordvpn', NORDVPN)])
def test_generated_configs_are_accepted(tmp_path, provider, text):
    code, output = check(tmp_path, text, provider)
    assert code == 0 and 'configuration accepted' in output, output
    assert KEY not in output


def test_check_config_names_families_not_addresses(tmp_path):
    code, output = check(tmp_path, MULLVAD)
    assert 'an IPv4 address and an IPv6 address' in output
    assert '203.0.113.2' not in output and '2001:db8:3' not in output


@pytest.mark.parametrize('spelling', ['2001:db8:3:0:0:0:0:2', '2001:DB8:3::2',
                                      '2001:0db8:0003:0000:0000:0000:0000:0002'])
def test_valid_ipv6_spellings_are_accepted(tmp_path, spelling):
    code, output = check(tmp_path, MULLVAD.replace('2001:db8:3::2', spelling))
    assert code == 0, output


@pytest.mark.parametrize('provider,text,message', [
    ('mullvad', MULLVAD.replace('Table = off', 'Table = auto'), 'Table on line'),
    ('mullvad', MULLVAD.replace('MTU = 1420', 'MTU = 9000'), 'MTU on line'),
    ('mullvad', MULLVAD.replace('MTU = 1420', 'MTU = 01420'), 'MTU on line'),
    ('mullvad', MULLVAD.replace('MTU = 1420\n', ''), 'MTU is missing'),
    ('mullvad', MULLVAD.replace('MTU = 1420', 'MTU = 1420\nDNS = 203.0.113.9'), 'unsupported field on line'),
    ('mullvad', MULLVAD.replace('MTU = 1420', 'MTU = 1420\nSaveConfig = true'), 'unsupported field on line'),
    ('mullvad', MULLVAD.replace('MTU = 1420', 'MTU = 1420\nPreUp = true'), 'unsupported field on line'),
    ('mullvad', MULLVAD.replace('MTU = 1420', 'MTU = 1420\nPostDown = true'), 'unsupported field on line'),
    ('mullvad', MULLVAD.replace('MTU = 1420', 'MTU = 1420\nFwMark = 0x1'), 'unsupported field on line'),
    ('mullvad', MULLVAD.replace('MTU = 1420', 'MTU = 1420\nMTU = 1420'), 'MTU appears more than once'),
    ('mullvad', MULLVAD + '\n[Interface]\n', '[Interface] on line'),
    ('mullvad', MULLVAD + '\n[Peer]\n', '[Peer] on line'),
    ('mullvad', MULLVAD.replace('table 51821', 'table 51822'), 'PostUp on line'),
    ('mullvad', MULLVAD.replace('; ip -6 route replace default dev %i table 51821', ''), 'PostUp on line'),
    ('mullvad', MULLVAD4.replace('route del default', 'route flush'), 'PreDown on line'),
    ('mullvad', MULLVAD.replace('203.0.113.2/32', '203.0.113.2/24'), 'Address on line'),
    ('mullvad', MULLVAD.replace('203.0.113.2/32', '203.0.113.2/32, 203.0.113.3/32'), 'Address on line'),
    ('mullvad', MULLVAD.replace('203.0.113.2/32', '203.0.113.02/32'), 'Address on line'),
    ('mullvad', MULLVAD.replace('203.0.113.2/32', '203.0.113.256/32'), 'Address on line'),
    ('mullvad', MULLVAD.replace('2001:db8:3::2', '2001:db8::3::2'), 'Address on line'),
    ('mullvad', MULLVAD.replace('2001:db8:3::2', '2001:db8:3::2:3:4:5:6:7'), 'Address on line'),
    ('mullvad', MULLVAD.replace('2001:db8:3::2', '::ffff:203.0.113.9'), 'Address on line'),
    ('mullvad', MULLVAD.replace('Address = 203.0.113.2/32, ', 'Address = '), 'Address on line'),
    ('mullvad', MULLVAD.replace('198.51.100.10:51820', 'se-sto-wg-001.example.net:51820'), 'Endpoint on line'),
    ('mullvad', MULLVAD.replace('198.51.100.10:51820', '198.51.100.10:0'), 'Endpoint on line'),
    ('mullvad', MULLVAD.replace('198.51.100.10:51820', '198.51.100.10'), 'Endpoint on line'),
    ('mullvad', MULLVAD.replace('0.0.0.0/0, ::/0', '0.0.0.0/1, ::/0'), 'AllowedIPs on line'),
    ('mullvad', MULLVAD4.replace('0.0.0.0/0', '0.0.0.0/0, ::/0'), 'AllowedIPs on line'),
    ('mullvad', MULLVAD.replace('PersistentKeepalive = 25', 'PersistentKeepalive = 0'), 'PersistentKeepalive on line'),
    ('mullvad', MULLVAD.replace(f'PrivateKey = {KEY}', 'PrivateKey = AAAA='), 'PrivateKey on line'),
    ('mullvad', MULLVAD.replace(f'PrivateKey = {KEY}', f'PrivateKey = {KEY[:42]}B='), 'PrivateKey on line'),
    ('mullvad', MULLVAD.split('[Peer]')[0], '[Peer] is missing'),
    ('pia', PIA.replace('MTU = 1420', 'MTU = 1420\nAddress = 203.0.113.8/32'), 'not supported for PIA'),
    ('pia', PIA + '\n[Peer]\n', '[Peer]'),
    ('nordvpn', NORDVPN.replace('Address = 10.5.0.2/32', 'Address = 10.5.0.2/32, 2001:db8:3::6/128'), 'Address on line'),
    ('nordvpn', NORDVPN.replace('Address = 10.5.0.2/32\n', ''), 'Address is missing'),
])
def test_unsupported_configs_are_refused_with_fixed_messages(tmp_path, provider, text, message):
    code, output = check(tmp_path, text, provider)
    assert code == 1 and message in output, output
    assert 'regenerate it with' in output


def sentinel_variants():
    # The sentinel as a field name, a bare line, every field's value, a
    # section header, inside a hook, and as a key that looks right.
    yield MULLVAD.replace('MTU = 1420', f'MTU = 1420\n{SENTINEL} = x')
    yield MULLVAD.replace('MTU = 1420', f'MTU = 1420\n{SENTINEL}')
    yield MULLVAD.replace('[Interface]', f'[{SENTINEL}]')
    yield MULLVAD.replace('table 51821; ip -6', f'table 51821; {SENTINEL}; ip -6')
    for field in ('PrivateKey', 'Address', 'MTU', 'Table', 'PostUp', 'PreDown', 'PublicKey', 'Endpoint',
                  'AllowedIPs', 'PersistentKeepalive'):
        lines = [f'{field} = {SENTINEL}' if line.startswith(field + ' =') else line for line in MULLVAD.splitlines()]
        yield '\n'.join(lines) + '\n'


@pytest.mark.parametrize('text', list(sentinel_variants()))
def test_no_message_carries_conf_text(tmp_path, text):
    code, output = check(tmp_path, text)
    assert code == 1
    assert SENTINEL not in output and KEY not in output


@pytest.mark.parametrize('kind', ['nul', 'cr', 'large', 'symlink', 'missing'])
def test_unreadable_or_odd_files_are_refused(tmp_path, kind):
    path = tmp_path / 'mullvad.conf'
    if kind == 'nul':
        code, output = check(tmp_path, MULLVAD.replace('MTU', 'M\0TU'))
    elif kind == 'cr':
        code, output = check(tmp_path, MULLVAD.replace('\n', '\r\n'))
    elif kind == 'large':
        code, output = check(tmp_path, MULLVAD + '#' * 5000 + '\n')
    else:
        (tmp_path / 'real.conf').write_text(MULLVAD)
        if kind == 'symlink':
            path.symlink_to(tmp_path / 'real.conf')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('MOLEBRIDGE_', 'OVERLAY', 'EXIT_'))}
        env.update(MOLEBRIDGE_LIB=str(ROOT / 'routing'), TUNNEL_CONF_DIR=str(tmp_path), OVERLAY_CIDR='192.0.2.0/24')
        result = subprocess.run(['sh', str(ROOT / 'routing' / 'molebridge-exit'), '--check-config'], env=env,
                                capture_output=True, text=True, timeout=20)
        code, output = result.returncode, result.stdout + result.stderr
    assert code == 1, output


@pytest.mark.parametrize('name,value', [('ROUTING_RECONCILE_INTERVAL', '1'), ('ROUTING_RECONCILE_INTERVAL', '3'),
                                        ('ROUTING_RECONCILE_INTERVAL', '62'), ('ROUTING_RECONCILE_INTERVAL', '02'),
                                        ('PROVIDER', 'other'), ('OVERLAY_CIDR', '192.0.2.1/24'),
                                        ('EXIT_TABLE', '254'), ('TUNNEL_BACKEND', 'other')])
def test_bad_settings_are_refused(tmp_path, name, value):
    code, output = check(tmp_path, MULLVAD, **{name: value})
    assert code == 1 and 'molebridge-exit' in output or '10-exit-routing' in output


@pytest.mark.parametrize('address', ['203.0.113.2/24', '203.0.113.2/32,203.0.113.3/32', '203.0.113.2/32,2001:db8:3::5/64',
                                     '203.0.113.2/32,2001:db8:3::5/128,2001:db8:3::6/128'])
def test_the_generator_refuses_what_the_image_would(address):
    # D26: a regenerated config always passes the image's grammar.
    with pytest.raises(prepare.ConfigError):
        prepare.build_tunnel_conf(DOWNLOADED.replace('203.0.113.2/32,2001:db8:3::2/128', address))


@pytest.mark.parametrize('address', ['203.0.113.2', '203.0.113.2/32', '203.0.113.2/32,2001:db8:3::5', '2001:db8:3::5/128,203.0.113.2/32'])
def test_whatever_the_generator_accepts_the_image_accepts(tmp_path, address):
    text = prepare.build_tunnel_conf(DOWNLOADED.replace('203.0.113.2/32,2001:db8:3::2/128', address))
    code, output = check(tmp_path, text)
    assert code == 0, output

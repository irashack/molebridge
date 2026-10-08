#!/usr/bin/env python3
"""Host-side doctor and explicit recovery. Never mounted in the panel."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from molebridge.routing import RoutingConfig


class CheckError(Exception):
    pass


# Go's strconv.ParseBool true values.
TRUE_VALUES = {'1', 't', 'T', 'TRUE', 'true', 'True'}
# The NetBird settings routing/wait-for-guards refuses, each with the values
# NetBird itself reads as on: ParseBool for most, the exact "true" for the
# netstack and kernel-module switches.
NETBIRD_MUST_BE_OFF = {'NB_FORCE_USERSPACE_FIREWALL': TRUE_VALUES, 'NB_FORCE_USERSPACE_ROUTER': TRUE_VALUES,
                       'NB_USE_NETSTACK_MODE': {'true'}, 'NB_WG_KERNEL_DISABLED': {'true'},
                       'NB_ENABLE_ROSENPASS': TRUE_VALUES, 'WT_ENABLE_ROSENPASS': TRUE_VALUES}
# Molebridge supports only NetBird's daemon mode.
NETBIRD_DAEMON_ONLY = ('NB_FOREGROUND_MODE', 'WT_FOREGROUND_MODE')
# Unsupported in any value: Molebridge supports only NetBird's default profile.
NETBIRD_UNSUPPORTED = ('NB_CONFIG', 'WT_CONFIG', 'NB_PROFILE', 'WT_PROFILE')
GATE_REFUSAL = 'NetBird gate: refusing to start NetBird: '


def tunnel_families(text):
    """Address families of the tunnel config, requiring one address per family.

    The routing init script and the applier both assume a single tunnel
    address per family for the return-path rule."""
    addresses = []
    for line in re.findall(r'^\s*Address\s*=\s*(.+)$', text, re.M):
        addresses.extend(a.strip() for a in line.split(',') if a.strip())
    try:
        versions = [ipaddress.ip_interface(a).version for a in addresses]
    except ValueError:
        raise CheckError('Tunnel configuration has an invalid Address.') from None
    if versions.count(4) != 1 or versions.count(6) > 1:
        raise CheckError('Tunnel configuration needs exactly one IPv4 Address and at most one IPv6 Address.')
    return set(versions)


def execute(args, *, cwd, timeout=30):
    """Capture errors instead of exposing expanded Compose secrets in output."""
    try:
        result = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError('Command unavailable or timed out; check Docker/Compose.') from exc
    if result.returncode:
        raise CheckError('Command failed; check Docker/Compose locally. Expanded output was withheld.')
    return result.stdout


class Host:
    def __init__(self, root=ROOT, run=execute):
        self.root, self.run = Path(root), run

    def compose(self, *args, timeout=30):
        return self.run(['docker', 'compose', *args], cwd=self.root, timeout=timeout)

    def config(self):
        if not (self.root / '.env').is_file():
            raise CheckError('Missing .env; follow docs/setup.md.')
        try:
            data = json.loads(self.compose('config', '--format', 'json'))
            RoutingConfig.from_env(data['services']['wireguard']['environment'])
            sysctls = data['services']['wireguard'].get('sysctls') or {}
            if str(sysctls.get('net.ipv4.icmp_errors_use_inbound_ifaddr')) != '1':
                raise CheckError('The wireguard service must set net.ipv4.icmp_errors_use_inbound_ifaddr=1 (compose.yaml).')
            panel = data['services']['control-panel']
            mounts = {v['target']: v for v in panel['volumes']}
            if not mounts['/state/applier'].get('read_only'):
                raise CheckError('The panel must mount applier state read-only.')
            if mounts['/state/panel'].get('read_only'):
                raise CheckError('The panel request directory must be writable.')
            if panel.get('cap_drop') != ['ALL'] or panel.get('cap_add'):
                raise CheckError('The panel must have no capabilities.')
            if any(v['target'].startswith('/config') for v in data['services']['applier']['volumes']):
                raise CheckError('The applier must not mount the tunnel configuration.')
            netbird = data['services']['netbird'].get('environment') or {}
            if str(netbird.get('NB_DISABLE_USERSPACE_ROUTING')) not in TRUE_VALUES:
                raise CheckError('The netbird service must set NB_DISABLE_USERSPACE_ROUTING=true (compose.yaml).')
            for name, values in NETBIRD_MUST_BE_OFF.items():
                if str(netbird.get(name)) in values:
                    raise CheckError(f'The netbird service sets {name}; Molebridge needs kernel WireGuard, '
                                     f"NetBird's kernel firewall and no Rosenpass (docs/troubleshooting.md).")
            for name in NETBIRD_DAEMON_ONLY:
                if str(netbird.get(name)) in TRUE_VALUES:
                    raise CheckError(f'The netbird service sets {name}; Molebridge supports only '
                                     f"NetBird's daemon mode (docs/troubleshooting.md).")
            if 'WT_INTERFACE_NAME' in netbird and netbird['WT_INTERFACE_NAME'] != netbird.get('NB_INTERFACE_NAME', 'wt0'):
                raise CheckError('The netbird service sets WT_INTERFACE_NAME to another interface than '
                                 'NB_INTERFACE_NAME (docs/troubleshooting.md).')
            for name in NETBIRD_UNSUPPORTED:
                if name in netbird:
                    raise CheckError(f'The netbird service sets {name}; Molebridge supports only '
                                     f"NetBird's default profile (docs/troubleshooting.md).")
            return data
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckError('Invalid Compose or routing configuration.') from exc

    def check_files(self, config):
        exit_if = config['services']['wireguard']['environment'].get('EXIT_IF', 'mullvad')
        provider = config['services']['wireguard']['environment'].get('PROVIDER', 'mullvad')
        if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}', exit_if):
            raise CheckError('Invalid EXIT_IF.')
        for relative in (f'tunnel/wg_confs/{exit_if}.conf',):
            path = self.root / relative
            if path.is_symlink() or not path.is_file():
                raise CheckError('Missing or symlinked tunnel configuration.')
            if os.name == 'posix' and stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise CheckError('Tunnel configuration must have mode 0600.')
            # Never include the content in an exception, log or subprocess argv.
            text = path.read_text(encoding='utf-8')
            expected = config['services']['wireguard']['environment']['EXIT_TABLE']
            if not re.search(r'^Table\s*=\s*off\s*$', text, re.M):
                raise CheckError('Tunnel configuration must use Table = off.')
            if provider == 'pia':
                # PIA assigns the address per registration; the config has none.
                if re.search(r'^\s*Address\s*=', text, re.M) or re.search(r'^\s*\[Peer\]', text, re.M):
                    raise CheckError('A PIA tunnel configuration has no Address or Peer; regenerate it with --pia.')
                families = set()
            else:
                families = tunnel_families(text)
            for key, action in (('PostUp', 'replace'), ('PreDown', 'del')):
                match = re.search(r'^' + key + r'\s*=\s*(.+)$', text, re.M)
                for flag in ('', '-6 ') if 6 in families else ('',):
                    route = rf'ip {flag}route {action} default dev %i table {re.escape(str(expected))}(?:\s*;|\s*$)'
                    if not match or not re.search(route, match[1]):
                        raise CheckError('Tunnel configuration and EXIT_TABLE do not match for every address family; regenerate the config.')
        secrets = ['secrets/netbird.env', 'secrets/applier.env']
        if provider == 'pia':
            for relative in ('secrets/pia/username', 'secrets/pia/password'):
                if not (self.root / relative).is_file():
                    raise CheckError('PIA needs secrets/pia/username and secrets/pia/password (docs/providers.md).')
            secrets += ['secrets/pia/username', 'secrets/pia/password']
        for relative in secrets:
            path = self.root / relative
            if path.exists() and (path.is_symlink() or (os.name == 'posix' and stat.S_IMODE(path.stat().st_mode) != 0o600)):
                raise CheckError('Secret files must be regular files with mode 0600.')

    def check_volume(self, config):
        name = config['volumes']['netbird-data']['name']
        try:
            self.run(['docker', 'volume', 'inspect', name, '--format', '{{.Name}}'], cwd=self.root, timeout=10)
        except CheckError as exc:
            raise CheckError('Existing NetBird identity volume not found. Check COMPOSE_PROJECT_NAME; recovery will not enroll a new peer.') from exc

    def namespace_checks(self):
        namespaces = [self.compose('exec', '-T', service, 'readlink', '/proc/self/ns/net').strip()
                      for service in ('wireguard', 'netbird', 'applier')]
        if not namespaces[0] or len(set(namespaces)) != 1:
            raise CheckError('Containers do not share the current network namespace; run recover.')

    def ice_blacklist_check(self, config):
        """The exit interface must be in the peer's stored ICE interface blacklist.

        No `netbird` command prints that setting, so read the one field from the
        peer profile inside the container. The profile also holds the peer's
        private key: only the blacklist array leaves the container, and none of
        it is printed here."""
        exit_if = config['services']['wireguard']['environment'].get('EXIT_IF', 'mullvad')
        script = ("awk '/\"IFaceBlackList\"/ {p=1} p {print} p && /\\]|null/ {exit}' "
                  '/var/lib/netbird/default.json')
        try:
            output = self.compose('exec', '-T', 'netbird', 'sh', '-c', script)
        except CheckError:
            raise CheckError('Unable to read the NetBird peer configuration; is the netbird container running?') from None
        if '"IFaceBlackList"' not in output:
            raise CheckError('NetBird peer configuration has no interface blacklist field; check the profile file name for this NetBird version.')
        entries = re.findall(r'"([^"]*)"', output)[1:]
        if exit_if not in entries:
            raise CheckError(f'The exit interface {exit_if} is not in the NetBird ICE interface blacklist; '
                             f'run docker compose exec netbird netbird down, then docker compose exec netbird '
                             f'netbird up --extra-iface-blacklist {exit_if} (docs/setup.md).')

    def netbird_config_check(self):
        """Run the NetBird gate's configuration checks inside the netbird
        container, where they see its environment and stored profiles. The
        same code refuses to launch NetBird. Only the gate's own refusal line
        is shown; the profiles also hold the peer's private key, and the gate
        prints nothing from them."""
        script = 'sh /usr/local/bin/molebridge-wait-for-guards --check-config 2>&1; echo "exit=$?"'
        try:
            lines = self.compose('exec', '-T', 'netbird', 'sh', '-c', script).strip().splitlines()
        except CheckError:
            raise CheckError('Unable to check the NetBird configuration; is the netbird container running?') from None
        if lines[-1:] == ['exit=0'] and 'NetBird gate: configuration accepted' in lines:
            return
        refusal = next((line for line in lines if line.startswith(GATE_REFUSAL)
                        and len(line) <= 300 and line.isprintable()), None)
        raise CheckError(refusal or 'The NetBird gate did not accept the configuration (docs/troubleshooting.md).')

    def doctor(self):
        config = self.config()
        self.check_files(config)
        self.check_volume(config)
        self.namespace_checks()
        self.ice_blacklist_check(config)
        self.netbird_config_check()
        # This command deliberately prints only fixed check labels, no addresses.
        self.compose('exec', '-T', 'applier', 'python', '-m', 'applier.apply', '--doctor', timeout=30)
        print('PASS configuration, permissions, identity volume, namespace, ICE blacklist, NetBird settings '
              'and profiles, NetBird kernel mode, routing and recent provider check')
        print('Client DNS, IPv6 and failure drills still require docs/verification.md.')

    def recover(self):
        config = self.config()
        self.check_files(config)
        self.check_volume(config)
        print('Building the routing and applier images before interrupting the existing exit.', flush=True)
        self.compose('build', 'wireguard', 'applier', timeout=600)
        print('Recreating the exit namespace and its dependents; clients will be interrupted.', flush=True)
        self.compose('stop', 'netbird', 'applier', timeout=60)
        self.compose('up', '-d', '--force-recreate', '--wait', '--wait-timeout', '180',
                     'wireguard', 'netbird', 'applier', 'control-panel', timeout=240)
        self.doctor()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('doctor', 'recover'))
    args = parser.parse_args(argv)
    try:
        getattr(Host(), args.action)()
    except (CheckError, OSError, ValueError):
        # Show the fixed CheckError messages, never OS exception text containing
        # potentially sensitive paths or expanded Compose values.
        exc = sys.exc_info()[1]
        print(f'FAIL {exc}' if isinstance(exc, CheckError) else 'FAIL unable to inspect local configuration.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

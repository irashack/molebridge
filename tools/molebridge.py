#!/usr/bin/env python3
"""Host-side doctor and explicit recovery. Never mounted in the panel."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from molebridge import providers
from molebridge.routing import RoutingConfig, render_post_rules
from applier.gluetun import default_role_allowed, gluetun_auth_file, valid_auth_file


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


# The settings the gluetun backend's host-side commands read, with the
# defaults compose.gluetun.yaml gives them. OVERLAY_CIDR has none.
GLUETUN_DEFAULTS = {'OVERLAY_CIDR': '', 'OVERLAY6_CIDR': '', 'OVERLAY_IF': 'wt0', 'EXIT_IF': 'wg0',
                    'EXIT_TABLE': '51821', 'HOST_IF': 'eth0', 'HOST_TABLE': '51822',
                    'CONTROL_MARK': '0x1bd00', 'NB_WIREGUARD_PORT': '51820'}


def read_env_file(path, names):
    """The named settings from a Compose .env file: `KEY=value` lines,
    optionally after `export`, with optional single or double quotes and, for
    unquoted values, a comment after whitespace and `#`. A missing file reads
    as empty. A value that needs interpolation (`$`) is refused rather than
    guessed at."""
    found = {}
    try:
        text = Path(path).read_text(encoding='utf-8')
    except FileNotFoundError:
        return found
    except (OSError, UnicodeError) as exc:
        raise CheckError('Unable to read .env.') from exc
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('export '):
            line = line[len('export '):].lstrip()
        key, separator, value = line.partition('=')
        key = key.strip()
        if not separator or key not in names:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
            value = value[1:-1]
        else:
            value = re.split(r'\s+#', value, maxsplit=1)[0].strip()
        if '$' in value:
            raise CheckError(f'{key} in .env uses interpolation; write the value itself.')
        found[key] = value
    return found


def execute(args, *, cwd, timeout=30, allow_failure=False):
    """Capture errors instead of exposing expanded Compose secrets in output.
    With allow_failure, return (exit status, output) instead of raising on a
    non-zero status; only for commands whose output is known to be safe."""
    try:
        result = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError('Command unavailable or timed out; check Docker/Compose.') from exc
    if allow_failure:
        return result.returncode, result.stdout
    if result.returncode:
        raise CheckError('Command failed; check Docker/Compose locally. Expanded output was withheld.')
    return result.stdout


# The applier's --doctor prints one fixed label per check (applier/apply.py,
# doctor_checks); only lines of that shape are shown.
APPLIER_CHECK_LINE = re.compile(r"(PASS|FAIL) [A-Za-z0-9 ',./-]{1,100}")
# recover waits this long for the applier to verify the recreated exit: with
# gluetun it may first put the last verified server back, about 20 s, up to
# its 90 s switch timeout.
SETTLE_SEC = 180
SETTLE_POLL_SEC = 5


class Host:
    def __init__(self, root=ROOT, run=execute, *, sleep=time.sleep, clock=time.monotonic):
        self.root, self.run, self.sleep, self.clock = Path(root), run, sleep, clock

    def compose(self, *args, timeout=30, step=None):
        try:
            return self.run(['docker', 'compose', *args], cwd=self.root, timeout=timeout)
        except CheckError as exc:
            if step is None:
                raise
            raise CheckError(f'{step} failed: {exc}') from None

    def applier_checks(self):
        """The applier's own checks as [(passed, label)], from its --doctor.
        Fixed labels only; any other output is dropped."""
        result = self.run(['docker', 'compose', 'exec', '-T', 'applier', 'python', '-m', 'applier.apply',
                           '--doctor'], cwd=self.root, timeout=30, allow_failure=True)
        status, output = result if isinstance(result, tuple) else (0, result)
        checks = [(line[:4] == 'PASS', line[5:]) for line in output.splitlines()
                  if APPLIER_CHECK_LINE.fullmatch(line)]
        if status and all(passed for passed, _ in checks):
            checks.append((False, 'the applier check itself (is the applier container running?)'))
        return checks

    def compose_config(self):
        if not (self.root / '.env').is_file():
            raise CheckError('Missing .env; follow docs/setup.md.')
        try:
            data = json.loads(self.compose('config', '--format', 'json'))
        except ValueError as exc:
            raise CheckError('Invalid Compose or routing configuration.') from exc
        if not isinstance(data, dict) or not isinstance(data.get('services'), dict):
            raise CheckError('Invalid Compose or routing configuration.')
        return data

    @staticmethod
    def owner(config):
        """The service that owns the namespace: wireguard, or gluetun with
        compose.gluetun.yaml."""
        return 'gluetun' if 'gluetun' in (config.get('services') or {}) else 'wireguard'

    @staticmethod
    def routing_env(config):
        """The routing settings: the wireguard service's, or the guard's."""
        services = config['services']
        return services['guard' if 'gluetun' in services else 'wireguard']['environment']

    def config(self):
        data = self.compose_config()
        try:
            services = data['services']
            if self.owner(data) == 'gluetun':
                self.gluetun_compose_checks(services)
            else:
                RoutingConfig.from_env(services['wireguard']['environment'])
                sysctls = services['wireguard'].get('sysctls') or {}
                if str(sysctls.get('net.ipv4.icmp_errors_use_inbound_ifaddr')) != '1':
                    raise CheckError('The wireguard service must set net.ipv4.icmp_errors_use_inbound_ifaddr=1 (compose.yaml).')
                if any(v['target'].startswith('/config') for v in services['applier']['volumes']):
                    raise CheckError('The applier must not mount the tunnel configuration.')
            panel = services['control-panel']
            mounts = {v['target']: v for v in panel['volumes']}
            if not mounts['/state/applier'].get('read_only'):
                raise CheckError('The panel must mount applier state read-only.')
            if mounts['/state/panel'].get('read_only'):
                raise CheckError('The panel request directory must be writable.')
            if panel.get('cap_drop') != ['ALL'] or panel.get('cap_add'):
                raise CheckError('The panel must have no capabilities.')
            if any('secrets' in Path(str(v.get('source', ''))).parts for v in panel['volumes']):
                raise CheckError('The panel must not mount any secret.')
            netbird = services['netbird'].get('environment') or {}
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

    def gluetun_compose_checks(self, services):
        """compose.gluetun.yaml's own invariants, on the resolved file."""
        routing = RoutingConfig.from_env(services['guard']['environment'])
        if not routing.gluetun:
            raise CheckError('The guard service must set TUNNEL_BACKEND=gluetun (compose.gluetun.yaml).')
        gluetun = services['gluetun']
        sysctls = gluetun.get('sysctls') or {}
        if str(sysctls.get('net.ipv4.icmp_errors_use_inbound_ifaddr')) != '1':
            raise CheckError('The gluetun service must set net.ipv4.icmp_errors_use_inbound_ifaddr=1 '
                             '(compose.gluetun.yaml).')
        if gluetun.get('entrypoint') != ['/bin/sh', '/usr/local/bin/molebridge-gluetun-preflight', '/gluetun-entrypoint']:
            raise CheckError("The gluetun service must start through Molebridge's role-file check (compose.gluetun.yaml).")
        if not default_role_allowed((gluetun.get('environment') or {}).get('HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE')):
            raise CheckError('The gluetun service must not set a default control-server role '
                             '(HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE); the role file alone decides.')
        if gluetun.get('ports'):
            raise CheckError('The gluetun service must publish no port; its control server stays in the namespace.')
        targets = {v['target'] for v in gluetun['volumes']}
        if not {'/gluetun/auth/config.toml', '/iptables/post-rules.txt'} <= targets:
            raise CheckError("The gluetun service must mount its role file and post-rules (compose.gluetun.yaml).")
        applier = services['applier']
        env = applier.get('environment') or {}
        provider = providers.get(env.get('PROVIDER'))
        if provider.backend != 'gluetun' or provider.gluetun_provider != (gluetun.get('environment') or {}).get(
                'VPN_SERVICE_PROVIDER'):
            raise CheckError("The applier's PROVIDER must be gluetun-<GLUETUN_PROVIDER> (compose.gluetun.yaml).")
        if RoutingConfig.from_env(env) != routing:
            raise CheckError('The applier and the guard must use the same routing settings (compose.gluetun.yaml).')
        for volume in applier['volumes']:
            source = Path(str(volume.get('source', '')))
            if source.name in ('wireguard_private_key', 'auth.toml') or volume['target'].startswith('/config'):
                raise CheckError("The applier must not mount the tunnel key or gluetun's role file.")
            if volume['target'] != '/state/applier' and not volume.get('read_only'):
                raise CheckError('The applier must mount everything but its state read-only.')

    def check_files(self, config):
        if self.owner(config) == 'gluetun':
            return self.check_gluetun_files()
        exit_if = config['services']['wireguard']['environment'].get('EXIT_IF', 'mullvad')
        try:
            spec = providers.get(config['services']['wireguard']['environment'].get('PROVIDER') or 'mullvad')
        except ValueError as exc:
            raise CheckError(str(exc)) from None
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
            if not spec.address_before_switch:
                # PIA assigns the address per registration; the config has none.
                if re.search(r'^\s*Address\s*=', text, re.M) or re.search(r'^\s*\[Peer\]', text, re.M):
                    raise CheckError(f'A {spec.label} tunnel configuration has no Address or Peer; regenerate it with --pia.')
                families = set()
            else:
                families = tunnel_families(text)
                if 6 in families and not spec.ipv6:
                    raise CheckError(f'{spec.label} tunnels carry no IPv6; remove the IPv6 Address.')
            for key, action in (('PostUp', 'replace'), ('PreDown', 'del')):
                match = re.search(r'^' + key + r'\s*=\s*(.+)$', text, re.M)
                for flag in ('', '-6 ') if 6 in families else ('',):
                    route = rf'ip {flag}route {action} default dev %i table {re.escape(str(expected))}(?:\s*;|\s*$)'
                    if not match or not re.search(route, match[1]):
                        raise CheckError('Tunnel configuration and EXIT_TABLE do not match for every address family; regenerate the config.')
        secrets = ['secrets/netbird.env', 'secrets/applier.env']
        for relative in spec.secret_files:
            if not (self.root / relative).is_file():
                raise CheckError(f'{spec.label} needs {" and ".join(spec.secret_files)} (docs/providers.md).')
        secrets += list(spec.secret_files)
        for relative in secrets:
            path = self.root / relative
            if path.exists() and (path.is_symlink() or (os.name == 'posix' and stat.S_IMODE(path.stat().st_mode) != 0o600)):
                raise CheckError('Secret files must be regular files with mode 0600.')

    def check_gluetun_files(self):
        for relative in ('secrets/gluetun/wireguard_private_key', 'secrets/gluetun/auth.toml',
                         'secrets/gluetun/api_key'):
            path = self.root / relative
            if path.is_symlink() or not path.is_file():
                raise CheckError(f'Missing {relative}; see docs/configuration.md#gluetun-backend.')
            if os.name == 'posix' and stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise CheckError('Secret files must be regular files with mode 0600.')
        try:
            auth = (self.root / 'secrets' / 'gluetun' / 'auth.toml').read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            auth = None
        # Never shown: the file holds the API key.
        if not valid_auth_file(auth):
            raise CheckError('secrets/gluetun/auth.toml is not the role file Molebridge generates; '
                             'run python3 tools/molebridge.py gluetun-auth --rotate.')
        post_rules = self.root / 'tunnel' / 'gluetun' / 'post-rules.txt'
        if post_rules.is_symlink() or not post_rules.is_file():
            raise CheckError('Missing tunnel/gluetun/post-rules.txt; run python3 tools/molebridge.py gluetun-post-rules.')
        for relative in ('secrets/netbird.env', 'secrets/applier.env'):
            path = self.root / relative
            if path.exists() and (path.is_symlink() or (os.name == 'posix' and stat.S_IMODE(path.stat().st_mode) != 0o600)):
                raise CheckError('Secret files must be regular files with mode 0600.')

    def gluetun_auth(self, *, rotate=False):
        """Write gluetun's role file and the applier's copy of its key, both
        mode 0600, from one key generated here. The key is never printed."""
        directory = self.root / 'secrets' / 'gluetun'
        key_path, auth_path = directory / 'api_key', directory / 'auth.toml'
        present = [p.exists() or p.is_symlink() for p in (key_path, auth_path)]
        if all(present) and not rotate:
            return False
        if any(present) and not rotate:
            raise CheckError('Only one of secrets/gluetun/api_key and auth.toml exists; '
                             'run gluetun-auth --rotate to write both again.')
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink() or any(p.is_symlink() for p in (key_path, auth_path)):
            raise CheckError('secrets/gluetun and its files must not be symlinks.')
        key = secrets.token_urlsafe(32)
        for path, text in ((key_path, key + '\n'), (auth_path, gluetun_auth_file(key))):
            temporary = path.with_name('.' + path.name + '.tmp')
            if temporary.exists() or temporary.is_symlink():
                temporary.unlink()
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='ascii') as stream:
                stream.write(text)
            os.replace(temporary, path)
        return True

    def check_volume(self, config):
        name = config['volumes']['netbird-data']['name']
        try:
            self.run(['docker', 'volume', 'inspect', name, '--format', '{{.Name}}'], cwd=self.root, timeout=10)
        except CheckError as exc:
            raise CheckError('Existing NetBird identity volume not found. Check COMPOSE_PROJECT_NAME; recovery will not enroll a new peer.') from exc

    def namespace_checks(self, owner='wireguard'):
        members = ('gluetun', 'guard', 'netbird', 'applier') if owner == 'gluetun' else ('wireguard', 'netbird', 'applier')
        namespaces = [self.compose('exec', '-T', service, 'readlink', '/proc/self/ns/net').strip()
                      for service in members]
        if not namespaces[0] or len(set(namespaces)) != 1:
            raise CheckError('Containers do not share the current network namespace; run recover.')

    def ice_blacklist_check(self, config):
        """The exit interface must be in the peer's stored ICE interface blacklist.

        No `netbird` command prints that setting, so read the one field from the
        peer profile inside the container. The profile also holds the peer's
        private key: only the blacklist array leaves the container, and none of
        it is printed here."""
        exit_if = self.routing_env(config).get('EXIT_IF', 'mullvad')
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
        self.namespace_checks(self.owner(config))
        self.ice_blacklist_check(config)
        self.netbird_config_check()
        # The applier prints only fixed check labels, no addresses.
        failed = [label for passed, label in self.applier_checks() if not passed]
        if failed:
            raise CheckError('The applier reports: ' + '; '.join(failed) + ' (docs/troubleshooting.md).')
        print('PASS configuration, permissions, identity volume, namespace, ICE blacklist, NetBird settings '
              'and profiles, NetBird kernel mode, routing and recent provider check')
        print('Client DNS, IPv6 and failure drills still require docs/verification.md.')

    def gluetun_settings(self):
        """The gluetun backend's settings as Compose resolves them, without
        running Compose, so the same command works with Docker and
        podman-compose: the process environment first, then .env, then the
        defaults compose.gluetun.yaml uses."""
        values = dict(GLUETUN_DEFAULTS)
        values.update(read_env_file(self.root / '.env', GLUETUN_DEFAULTS))
        values.update({k: os.environ[k] for k in GLUETUN_DEFAULTS if k in os.environ})
        return values

    def gluetun_post_rules(self, *, ipv6=True):
        """Write gluetun's post-rules file from the guard's validated settings."""
        settings = self.gluetun_settings()
        try:
            config = RoutingConfig.from_env(dict(settings, TUNNEL_BACKEND='gluetun'))
            port = settings['NB_WIREGUARD_PORT']
            if not re.fullmatch(r'[1-9][0-9]{0,4}', port):
                raise ValueError('NB_WIREGUARD_PORT')
            text = render_post_rules(config, int(port), ipv6=ipv6)
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckError('Invalid gluetun routing settings; check OVERLAY_CIDR, CONTROL_MARK, HOST_IF, EXIT_IF, '
                             'EXIT_TABLE, HOST_TABLE and NB_WIREGUARD_PORT in .env (docs/configuration.md).') from exc
        path = self.root / 'tunnel' / 'gluetun' / 'post-rules.txt'
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or path.parent.is_symlink() or (path.exists() and not path.is_file()):
            raise CheckError('tunnel/gluetun/post-rules.txt must be a regular file; remove what is there.')
        temporary = path.with_name('.post-rules.txt.tmp')
        temporary.write_text(text, encoding='utf-8')
        temporary.chmod(0o644)
        os.replace(temporary, path)
        return path

    def recover(self):
        config = self.config()
        self.check_files(config)
        self.check_volume(config)
        owner = self.owner(config)
        built = ('guard', 'applier') if owner == 'gluetun' else ('wireguard', 'applier')
        dependents = ('netbird', 'applier', 'guard') if owner == 'gluetun' else ('netbird', 'applier')
        order = ('gluetun', 'guard', 'netbird', 'applier') if owner == 'gluetun' else ('wireguard', 'netbird', 'applier')
        print('Building the routing and applier images before interrupting the existing exit.', flush=True)
        self.compose('build', *built, timeout=600, step='Building the images')
        print('Recreating the exit namespace and its dependents; clients will be interrupted.', flush=True)
        self.compose('stop', *dependents, timeout=60, step='Stopping ' + ', '.join(dependents))
        self.compose('up', '-d', '--force-recreate', '--wait', '--wait-timeout', '180',
                     *order, 'control-panel', timeout=240,
                     step='Recreating the containers (a container did not become healthy within 180 s; '
                          'see docker compose ps)')
        self.wait_for_applier()
        self.doctor()

    def wait_for_applier(self):
        """Give the recreated applier time to verify the exit: right after a
        recreation it has no verified result yet, and with gluetun it may
        first put the last verified server back. Bounded by SETTLE_SEC; the
        doctor afterwards names any check still failing."""
        print(f'Waiting up to {SETTLE_SEC} s for the applier to verify the exit.', flush=True)
        deadline = self.clock() + SETTLE_SEC
        while True:
            try:
                if all(passed for passed, _ in self.applier_checks()):
                    return True
            except CheckError:
                pass
            if self.clock() >= deadline:
                return False
            self.sleep(SETTLE_POLL_SEC)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('doctor', 'recover', 'gluetun-post-rules', 'gluetun-auth'))
    parser.add_argument('--ipv4-only', action='store_true',
                        help='gluetun-post-rules: leave out ip6tables lines, for a host where gluetun finds no ip6tables')
    parser.add_argument('--rotate', action='store_true',
                        help='gluetun-auth: replace an existing key and role file')
    args = parser.parse_args(argv)
    try:
        if args.action == 'gluetun-post-rules':
            path = Host().gluetun_post_rules(ipv6=not args.ipv4_only)
            print(f'Wrote {path.relative_to(ROOT)}; recreate gluetun to apply it.')
        elif args.action == 'gluetun-auth':
            if Host().gluetun_auth(rotate=args.rotate):
                print('Wrote secrets/gluetun/auth.toml and secrets/gluetun/api_key (mode 0600, key not shown); '
                      'recreate gluetun and the applier to use them.')
            else:
                print('secrets/gluetun/auth.toml and api_key already exist; --rotate replaces them.')
        else:
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

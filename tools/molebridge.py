#!/usr/bin/env python3
"""Host-side doctor and explicit recovery. Never mounted in the panel."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from collections import namedtuple
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
APPLIER_CHECK_LINE = re.compile(r"(PASS|FAIL) [A-Za-z0-9 ',./_-]{1,100}")
# recover waits this long for the applier to verify the recreated exit: with
# gluetun it may first put the last verified server back, about 20 s, up to
# its 90 s switch timeout.
SETTLE_SEC = 180
SETTLE_POLL_SEC = 5


# The Compose command of each supported engine.
COMPOSE = {'docker': ('docker', 'compose'), 'podman': ('podman-compose',)}
# The two exit kinds, from the applier's EXIT_KIND: the NetBird exit
# (compose.yaml or compose.gluetun.yaml) and the gluetun sidecar
# (compose.sidecar.yaml).
KINDS = ('overlay', 'sidecar')
# compose.sidecar.yaml copies SIDECAR_APPS into this label on the applier, so
# the doctor reads it from the configuration Compose resolves.
SIDECAR_APPS_LABEL = 'io.molebridge.sidecar-apps'
SIDECAR_SERVICES = ('gluetun', 'applier', 'control-panel')
SERVICE_NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}')
# A container name or ID, and an image reference, given on the command line.
CONTAINER_NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}')
IMAGE_REF = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.:/@-]{0,254}')
CONTAINER_ID = re.compile(r'[0-9a-f]{64}')
NAMESPACE_ID = re.compile(r'net:\[[0-9]{1,20}\]')
PREFLIGHT_ENTRYPOINT = ['/bin/sh', '/usr/local/bin/molebridge-gluetun-preflight', '/gluetun-entrypoint']
CONTROL_ADDRESS, CONTROL_PORT = '127.0.0.1:8000', 8000
# The namespace probe: the routing image routing/Dockerfile builds, tagged
# here by the doctor. Only its readlink is used, so any build of it will do.
PROBE_IMAGE = 'localhost/molebridge-netns-probe:local'
# What the doctor needs from a container's inspect output.
Member = namedtuple('Member', 'id started network_mode control_published')


def detect_engine(environ=None, which=shutil.which):
    """docker or podman: MOLEBRIDGE_ENGINE when set, otherwise Docker when its
    CLI is installed, otherwise podman-compose when it is."""
    environ = os.environ if environ is None else environ
    chosen = environ.get('MOLEBRIDGE_ENGINE', '')
    if chosen:
        if chosen not in COMPOSE:
            raise CheckError('MOLEBRIDGE_ENGINE must be docker or podman.')
        return chosen
    if not which('docker') and which('podman-compose') and which('podman'):
        return 'podman'
    return 'docker'


def port_targets(entry):
    """The container ports a Compose `ports` entry publishes, in the long form
    Docker resolves or the short form podman-compose prints."""
    if isinstance(entry, dict):
        spec = str(entry.get('target', ''))
    else:
        spec = str(entry).partition('/')[0].rsplit(':', 1)[-1]
    low, _, high = spec.partition('-')
    if not low.isdigit() or (high and not high.isdigit()):
        raise ValueError('port')
    return range(int(low), int(high or low) + 1)


def long_volume(entry):
    """A short-form volume (`source:target[:options]`, as podman-compose
    prints it) in the long form Docker resolves."""
    if isinstance(entry, dict):
        return entry
    parts = str(entry).split(':')
    if len(parts) == 1:
        return {'type': 'volume', 'target': parts[0]}
    kind = 'bind' if parts[0].startswith(('.', '/', '~')) else 'volume'
    volume = {'type': kind, 'source': parts[0], 'target': parts[1]}
    if len(parts) > 2 and 'ro' in parts[2].split(','):
        volume['read_only'] = True
    return volume


def as_dict(value):
    """Compose's list form of environment or labels (`KEY=value`) as a dict."""
    if isinstance(value, list):
        return dict(str(item).partition('=')[::2] for item in value)
    return value


def control_published(info):
    """Whether the engine publishes the control server's port on the host."""
    for ports in ((info.get('HostConfig') or {}).get('PortBindings'), (info.get('NetworkSettings') or {}).get('Ports')):
        if isinstance(ports, dict) and any(str(key).partition('/')[0] == str(CONTROL_PORT) and value
                                           for key, value in ports.items()):
            return True
    return False


class Host:
    def __init__(self, root=ROOT, run=execute, *, sleep=time.sleep, clock=time.monotonic, engine='docker'):
        self.root, self.run, self.sleep, self.clock = Path(root), run, sleep, clock
        if engine not in COMPOSE:
            raise CheckError('The engine must be docker or podman.')
        self.engine = engine
        # The configuration config() last resolved; the engine checks name
        # containers from it.
        self.loaded = None
        # recover sets this: the doctor then returns the applier's failing
        # `verified ...` checks instead of failing on them.
        self.accept_unverified = False
        # Without Compose (container_doctor): the applier's container, the
        # probe image named on the command line, and the advice that replaces
        # `run recover`.
        self.applier_container = None
        self.probe_ref = None
        self.remedy = 'run recover'

    def compose(self, *args, timeout=30, step=None):
        try:
            return self.run([*COMPOSE[self.engine], *args], cwd=self.root, timeout=timeout)
        except CheckError as exc:
            if step is None:
                raise
            raise CheckError(f'{step} failed: {exc}') from None

    def applier_checks(self):
        """The applier's own checks as [(passed, label)], from its --doctor.
        Fixed labels only; any other output is dropped."""
        if self.applier_container:
            target = [self.engine, 'exec', self.applier_container]
        else:
            target = [*COMPOSE[self.engine], 'exec', '-T', 'applier']
        result = self.run([*target, 'python', '-m', 'applier.apply', '--doctor'],
                          cwd=self.root, timeout=30, allow_failure=True)
        status, output = result if isinstance(result, tuple) else (0, result)
        checks = [(line[:4] == 'PASS', line[5:]) for line in output.splitlines()
                  if APPLIER_CHECK_LINE.fullmatch(line)]
        if status and all(passed for passed, _ in checks):
            checks.append((False, 'the applier check itself (is the applier container running?)'))
        return checks

    def compose_config(self):
        if not (self.root / '.env').is_file():
            raise CheckError('Missing .env; follow docs/setup.md.')
        if self.engine == 'podman':
            return self.podman_config()
        try:
            data = json.loads(self.compose('config', '--format', 'json'))
        except ValueError as exc:
            raise CheckError('Invalid Compose or routing configuration.') from exc
        if not isinstance(data, dict) or not isinstance(data.get('services'), dict):
            raise CheckError('Invalid Compose or routing configuration.')
        return data

    def podman_config(self):
        """podman-compose's resolved configuration, which it prints only as
        YAML, in the shape `docker compose config --format json` gives: long
        volumes and environment and labels as mappings."""
        try:
            import yaml
        except ImportError:
            raise CheckError('Reading the podman-compose configuration needs PyYAML (python3-yaml), '
                             'which podman-compose itself uses.') from None
        try:
            data = yaml.safe_load(self.compose('config'))
            for service in data['services'].values():
                for key in ('environment', 'labels'):
                    if key in service:
                        service[key] = as_dict(service[key])
                if 'volumes' in service:
                    service['volumes'] = [long_volume(v) for v in service['volumes']]
        except (yaml.YAMLError, AttributeError, KeyError, TypeError) as exc:
            raise CheckError('Invalid Compose or routing configuration.') from exc
        return data

    def project(self, config):
        """The Compose project name. Docker resolves it into the
        configuration; podman-compose takes COMPOSE_PROJECT_NAME from the
        environment or .env, then the file's name, then the directory's."""
        if self.engine == 'docker' and config.get('name'):
            return config['name']
        return (os.environ.get('COMPOSE_PROJECT_NAME')
                or read_env_file(self.root / '.env', {'COMPOSE_PROJECT_NAME'}).get('COMPOSE_PROJECT_NAME')
                or config.get('name') or self.root.name)

    @staticmethod
    def kind(config):
        """The exit kind: the applier's EXIT_KIND, overlay when unset."""
        services = config.get('services') if isinstance(config, dict) else None
        applier = services.get('applier') if isinstance(services, dict) else None
        env = applier.get('environment') if isinstance(applier, dict) else None
        value = env.get('EXIT_KIND') if isinstance(env, dict) else None
        if value in (None, ''):
            return 'overlay'
        if value not in KINDS:
            raise CheckError('EXIT_KIND must be overlay or sidecar.')
        return value

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
        self.loaded = data
        try:
            services = data['services']
            if self.kind(data) == 'sidecar':
                self.sidecar_compose_checks(services)
                self.sidecar_apps(data)
                self.panel_checks(services)
                return data
            if self.owner(data) == 'gluetun':
                self.gluetun_compose_checks(services)
            else:
                RoutingConfig.from_env(services['wireguard']['environment'])
                sysctls = services['wireguard'].get('sysctls') or {}
                if str(sysctls.get('net.ipv4.icmp_errors_use_inbound_ifaddr')) != '1':
                    raise CheckError('The wireguard service must set net.ipv4.icmp_errors_use_inbound_ifaddr=1 (compose.yaml).')
                if any(v['target'].startswith('/config') for v in services['applier']['volumes']):
                    raise CheckError('The applier must not mount the tunnel configuration.')
            self.panel_checks(services)
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

    @staticmethod
    def panel_checks(services):
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

    def sidecar_compose_checks(self, services):
        """compose.sidecar.yaml's own invariants, on the resolved file."""
        if {'wireguard', 'guard', 'netbird'} & set(services):
            raise CheckError('The sidecar has no NetBird or routing service; use compose.sidecar.yaml on its own.')
        gluetun, applier = services['gluetun'], services['applier']
        genv, env = gluetun.get('environment') or {}, applier.get('environment') or {}
        if env.get('TUNNEL_BACKEND') != 'gluetun':
            raise CheckError('The sidecar applier must set TUNNEL_BACKEND=gluetun (compose.sidecar.yaml).')
        try:
            provider = providers.get(env.get('PROVIDER'))
        except ValueError:
            provider = None
        if provider is None or provider.backend != 'gluetun' or provider.gluetun_provider != genv.get(
                'VPN_SERVICE_PROVIDER'):
            raise CheckError("The applier's PROVIDER must be gluetun-<GLUETUN_PROVIDER> (compose.sidecar.yaml).")
        if applier.get('network_mode') != 'service:gluetun':
            raise CheckError('The applier must use network_mode: service:gluetun (compose.sidecar.yaml).')
        if (applier.get('cap_drop') != ['ALL'] or not applier.get('read_only')
                or set(applier.get('cap_add') or ()) - {'NET_ADMIN', 'NET_RAW', 'DAC_OVERRIDE'}):
            raise CheckError('The applier must drop every capability but the three compose.sidecar.yaml adds, '
                             'and run read-only.')
        if gluetun.get('entrypoint') != PREFLIGHT_ENTRYPOINT:
            raise CheckError("The gluetun service must start through Molebridge's role-file check (compose.sidecar.yaml).")
        if not default_role_allowed(genv.get('HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE')):
            raise CheckError('The gluetun service must not set a default control-server role '
                             '(HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE); the role file alone decides.')
        if genv.get('HTTP_CONTROL_SERVER_ADDRESS') != CONTROL_ADDRESS:
            raise CheckError(f'The gluetun control server must listen on {CONTROL_ADDRESS} only '
                             '(HTTP_CONTROL_SERVER_ADDRESS, compose.sidecar.yaml).')
        if any(CONTROL_PORT in port_targets(port) for port in gluetun.get('ports') or ()):
            raise CheckError(f'The gluetun service must not publish port {CONTROL_PORT}; '
                             'its control server stays in the namespace.')
        volumes = gluetun.get('volumes') or []
        targets = {v['target'] for v in volumes}
        names = {Path(str(v.get('source', ''))).name for v in volumes}
        if '/gluetun/auth/config.toml' not in targets:
            raise CheckError('The gluetun service must mount its role file (compose.sidecar.yaml).')
        if '/iptables/post-rules.txt' in targets or 'post-rules.txt' in names:
            raise CheckError("The sidecar's gluetun must not mount the overlay's post-rules; "
                             "they are safe only behind the overlay's guard.")
        if 'api_key' in names:
            raise CheckError('The gluetun service must not mount the API key; only the applier does.')
        key = False
        for volume in applier.get('volumes') or []:
            source = Path(str(volume.get('source', '')))
            if source.name in ('wireguard_private_key', 'auth.toml') or volume['target'].startswith('/config'):
                raise CheckError("The applier must not mount the tunnel key or gluetun's role file.")
            if volume['target'] != '/state/applier' and not volume.get('read_only'):
                raise CheckError('The applier must mount everything but its state read-only.')
            key = key or source.name == 'api_key'
        if not key:
            raise CheckError('The applier must mount secrets/gluetun/api_key read-only (compose.sidecar.yaml).')

    @staticmethod
    def sidecar_apps(config):
        """SIDECAR_APPS: the Compose services of the applications in
        gluetun's namespace. Every service that joins gluetun must be listed,
        so recover recreates it with gluetun."""
        services = config['services']
        labels = as_dict(services['applier'].get('labels')) or {}
        raw = labels.get(SIDECAR_APPS_LABEL) if isinstance(labels, dict) else None
        names = [name.strip() for name in str(raw or '').split(',') if name.strip()]
        if not names:
            raise CheckError('No applications declared: set SIDECAR_APPS in .env to the Compose services that use '
                             'the tunnel (docs/gluetun-sidecar.md).')
        for name in names:
            if not SERVICE_NAME.fullmatch(name) or name in SIDECAR_SERVICES or names.count(name) > 1:
                raise CheckError('SIDECAR_APPS must list distinct Compose services of your applications, '
                                 'comma-separated (docs/gluetun-sidecar.md).')
            if not isinstance(services.get(name), dict):
                raise CheckError(f'SIDECAR_APPS names {name}, which is not a service in the Compose configuration.')
            if services[name].get('network_mode') != 'service:gluetun':
                raise CheckError(f'The {name} service must use network_mode: service:gluetun.')
        for name, service in services.items():
            if (name != 'applier' and name not in names and isinstance(service, dict)
                    and service.get('network_mode') == 'service:gluetun'):
                raise CheckError(f"The {name} service joins gluetun's namespace but isn't in SIDECAR_APPS; "
                                 'add it, so recover recreates it with gluetun.')
        return names

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
                # Any spelling counts: wg-quick reads field names in any case.
                if re.search(r'^\s*Address\s*=', text, re.M | re.I) or re.search(r'^\s*\[Peer\]', text, re.M | re.I):
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
        self.check_gluetun_secrets('docs/configuration.md#gluetun-backend')
        post_rules = self.root / 'tunnel' / 'gluetun' / 'post-rules.txt'
        if post_rules.is_symlink() or not post_rules.is_file():
            raise CheckError('Missing tunnel/gluetun/post-rules.txt; run python3 tools/molebridge.py gluetun-post-rules.')

    def check_sidecar_files(self):
        """The sidecar's secrets; it has no post-rules."""
        self.check_gluetun_secrets('docs/gluetun-sidecar.md')

    def check_gluetun_secrets(self, guide):
        for relative in ('secrets/gluetun/wireguard_private_key', 'secrets/gluetun/auth.toml',
                         'secrets/gluetun/api_key'):
            path = self.root / relative
            if path.is_symlink() or not path.is_file():
                raise CheckError(f'Missing {relative}; see {guide}.')
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
        if self.engine == 'podman':
            # podman-compose doesn't resolve volume names: <project>_<volume>.
            volume = config['volumes']['netbird-data'] or {}
            name = volume.get('name') or f'{self.project(config)}_netbird-data'
        else:
            name = config['volumes']['netbird-data']['name']
        try:
            self.run([self.engine, 'volume', 'inspect', name, '--format', '{{.Name}}'], cwd=self.root, timeout=10)
        except CheckError as exc:
            raise CheckError('Existing NetBird identity volume not found. Check COMPOSE_PROJECT_NAME; recovery will not enroll a new peer.') from exc

    def namespace_checks(self, owner='wireguard'):
        members = ('gluetun', 'guard', 'netbird', 'applier') if owner == 'gluetun' else ('wireguard', 'netbird', 'applier')
        if self.loaded is not None:
            # The engine's record first, from the configuration doctor and
            # recover load: every member is attached to the owner's current
            # container.
            self.membership(self.loaded, owner, members[1:])
        namespaces = [self.compose('exec', '-T', service, 'readlink', '/proc/self/ns/net').strip()
                      for service in members]
        if not namespaces[0] or len(set(namespaces)) != 1:
            raise CheckError('Containers do not share the current network namespace; run recover.')

    def container_ref(self, config, service):
        """The service's container: its container_name, or the one container
        Compose's labels give it."""
        entry = config['services'].get(service)
        if not isinstance(entry, dict):
            raise CheckError(f'The Compose configuration has no {service} service.')
        name = entry.get('container_name')
        if isinstance(name, str) and name:
            return name
        try:
            output = self.run([self.engine, 'ps', '-a', '-q', '--no-trunc',
                               '--filter', f'label=com.docker.compose.project={self.project(config)}',
                               '--filter', f'label=com.docker.compose.service={service}'],
                              cwd=self.root, timeout=15)
        except CheckError:
            raise CheckError(f'Unable to list the {service} container; check {self.engine}.') from None
        found = output.split()
        if not found:
            raise CheckError(f'The {service} container is missing; {self.remedy}.')
        if len(found) > 1:
            raise CheckError(f'More than one {service} container exists; {self.remedy}.')
        return found[0]

    def inspect_container(self, config, service):
        """The fields the doctor needs from the engine's inspect output, for
        a running container; never the output itself, which holds the
        container's environment."""
        reference = self.container_ref(config, service)
        try:
            output = self.run([self.engine, 'inspect', '--type', 'container', reference], cwd=self.root, timeout=15)
        except CheckError:
            raise CheckError(f'The {service} container is missing or cannot be inspected; {self.remedy}.') from None
        try:
            data = json.loads(output)
            if not isinstance(data, list) or len(data) != 1:
                raise ValueError('inspect')
            info = data[0]
            state, host = info['State'], info['HostConfig']
            member = Member(info['Id'], state['StartedAt'], host['NetworkMode'], control_published(info))
            if not CONTAINER_ID.fullmatch(member.id) or not all(isinstance(v, str) for v in member[1:3]):
                raise ValueError('inspect')
            running = state['Running'] is True
        except (ValueError, KeyError, TypeError, AttributeError):
            raise CheckError(f"The {service} container's inspect output was not understood; "
                             f'is it a {self.engine} container?') from None
        if not running:
            raise CheckError(f'The {service} container is not running; {self.remedy}.')
        return member

    def membership(self, config, owner, members):
        """{service: Member} for the owner and its members, each running and
        attached by the engine to the owner's current container. The control
        server's port must not be published on a gluetun owner."""
        lead = self.inspect_container(config, owner)
        if owner == 'gluetun' and lead.control_published:
            raise CheckError(f'The gluetun container publishes port {CONTROL_PORT}; '
                             'its control server must stay in the namespace.')
        snapshot = {owner: lead}
        for service in members:
            member = self.inspect_container(config, service)
            if member.network_mode != 'container:' + lead.id:
                raise CheckError(f"The {service} container is not attached to {owner}'s current container; "
                                 f'{self.remedy}.')
            snapshot[service] = member
        return snapshot

    def build_probe_image(self):
        """Build the routing image from this checkout as the namespace probe."""
        try:
            self.run([self.engine, 'build', '--tag', PROBE_IMAGE, '--file', str(ROOT / 'routing' / 'Dockerfile'),
                      str(ROOT)], cwd=self.root, timeout=600)
        except CheckError as exc:
            raise CheckError(f'Building the namespace probe image failed: {exc}') from None

    def probe_image(self):
        """The namespace probe's image: the one named with --probe-image when
        the engine has it, otherwise PROBE_IMAGE, built once when missing."""
        if self.probe_ref:
            try:
                self.run([self.engine, 'image', 'inspect', '--format', '{{.Id}}', self.probe_ref],
                         cwd=self.root, timeout=15)
                return self.probe_ref
            except CheckError:
                pass
        try:
            self.run([self.engine, 'image', 'inspect', '--format', '{{.Id}}', PROBE_IMAGE], cwd=self.root, timeout=15)
        except CheckError:
            self.build_probe_image()
        return PROBE_IMAGE

    def namespace_of(self, image, container_id, service):
        """The network namespace the engine joins for this container now, read
        by a throwaway probe that needs nothing from the container's image:
        joined by the resolved ID, no capabilities, read-only."""
        try:
            output = self.run([self.engine, 'run', '--rm', '--pull', 'never', '--network', f'container:{container_id}',
                               '--entrypoint', 'readlink', '--cap-drop', 'ALL', '--read-only',
                               '--security-opt', 'no-new-privileges', image, '/proc/self/ns/net'],
                              cwd=self.root, timeout=60)
        except CheckError:
            raise CheckError(f'The namespace probe could not join the {service} container; {self.remedy}.') from None
        namespace = output.strip()
        if not NAMESPACE_ID.fullmatch(namespace):
            raise CheckError('The namespace probe printed no namespace; recover rebuilds it.')
        return namespace

    def sidecar_namespace_checks(self, config):
        """The applier and every declared application share gluetun's
        current namespace: the engine attaches each to gluetun's current
        container, and a probe joined to each finds the same namespace as one
        joined to gluetun. A container ID survives a restart that changes the
        namespace, so the probe is the proof. Nothing may restart meanwhile."""
        self.namespace_identity(config, ('applier', *self.sidecar_apps(config)))

    def namespace_identity(self, config, members):
        image = self.probe_image()
        before = self.membership(config, 'gluetun', members)
        namespaces = {service: self.namespace_of(image, member.id, service) for service, member in before.items()}
        after = self.membership(config, 'gluetun', members)
        if any(after[service][:2] != before[service][:2] for service in before):
            raise CheckError('A container restarted or was replaced during the check; run doctor again.')
        for service in members:
            if namespaces[service] != namespaces['gluetun']:
                raise CheckError(f"The {service} container is not in gluetun's current network namespace; "
                                 f'{self.remedy}.')

    def container_doctor(self, gluetun, applier, apps, probe_image=None):
        """The sidecar doctor without Compose, as under Quadlet: the engine
        membership, the identity probe and the applier's own checks, for
        containers named on the command line. There is no configuration to
        read, so the configuration and the secret files aren't checked."""
        apps = [name.strip() for name in (apps or '').split(',') if name.strip()]
        if not apps:
            raise CheckError('No applications declared: name the application containers with --apps '
                             '(docs/gluetun-sidecar.md).')
        names = [gluetun, applier, *apps]
        if not all(isinstance(name, str) and CONTAINER_NAME.fullmatch(name) for name in names):
            raise CheckError('--gluetun, --applier and --apps take container names or IDs (docs/gluetun-sidecar.md).')
        if len(set(names)) != len(names) or {'gluetun', 'applier'} & set(apps):
            raise CheckError('--gluetun, --applier and --apps must name distinct containers.')
        if probe_image is not None and not IMAGE_REF.fullmatch(probe_image):
            raise CheckError('--probe-image takes an image reference.')
        self.applier_container, self.probe_ref = applier, probe_image
        self.remedy = 'restart gluetun, the applier and every application together'
        config = {'services': {'gluetun': {'container_name': gluetun}, 'applier': {'container_name': applier},
                               **{app: {'container_name': app} for app in apps}}}
        self.namespace_identity(config, ('applier', *apps))
        failed = [label for passed, label in self.applier_checks() if not passed]
        if failed:
            raise CheckError('The applier reports: ' + '; '.join(failed) + ' (docs/troubleshooting.md).')
        print('PASS namespace membership of the applier and every named application, unpublished control server, '
              "the applier's checks and recent provider check")
        print("Without Compose the configuration and secret files aren't checked; traffic protection is gluetun's "
              "firewall, which Molebridge doesn't check (docs/gluetun-sidecar.md).")
        return []

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
        """Every check, or CheckError. Returns the applier's failing
        `verified ...` checks, which only recover accepts."""
        config = self.config()
        sidecar = self.kind(config) == 'sidecar'
        if sidecar:
            self.check_sidecar_files()
            self.sidecar_namespace_checks(config)
        else:
            self.check_files(config)
            self.check_volume(config)
            self.namespace_checks(self.owner(config))
            self.ice_blacklist_check(config)
            self.netbird_config_check()
        # The applier prints only fixed check labels, no addresses.
        failed = [label for passed, label in self.applier_checks() if not passed]
        unverified = bool(failed) and all(label.startswith('verified ') for label in failed)
        if failed and not (self.accept_unverified and unverified):
            raise CheckError('The applier reports: ' + '; '.join(failed) + ' (docs/troubleshooting.md).')
        if sidecar:
            print('PASS configuration, permissions, namespace membership of the applier and every declared '
                  'application, unpublished control server' + ('' if failed else ' and recent provider check'))
            print("Traffic protection is gluetun's firewall, which Molebridge doesn't check; "
                  "check your applications' egress and DNS (docs/gluetun-sidecar.md).")
        else:
            print('PASS configuration, permissions, identity volume, namespace, ICE blacklist, NetBird settings '
                  'and profiles, NetBird kernel mode, routing' + ('' if failed else ' and recent provider check'))
            print('Client DNS, IPv6 and failure drills still require docs/verification.md.')
        return failed

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

    def wait_args(self):
        # podman-compose has no --wait; the applier wait that follows covers it.
        return ('--wait', '--wait-timeout', '180') if self.engine == 'docker' else ()

    def recover(self):
        """Recreate the namespace owner and everything in its namespace, then
        wait for the doctor. 0: recovered and verified; 3: recovered and
        operational, not verified; a CheckError (exit status 1): failed."""
        config = self.config()
        if self.kind(config) == 'sidecar':
            return self.recover_sidecar(config)
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
        self.compose('up', '-d', '--force-recreate', *self.wait_args(),
                     *order, 'control-panel', timeout=240, step=self.recreate_step())
        return self.settle()

    def recreate_step(self):
        if self.engine == 'podman':
            return 'Recreating the containers (see podman ps)'
        return 'Recreating the containers (a container did not become healthy within 180 s; see docker compose ps)'

    def recover_sidecar(self, config):
        """gluetun, the applier and every declared application, recreated
        together: a new gluetun container is a new namespace."""
        self.check_sidecar_files()
        apps = self.sidecar_apps(config)
        print('Building the applier and namespace probe images before interrupting the applications.', flush=True)
        self.compose('build', 'applier', timeout=600, step='Building the images')
        self.build_probe_image()
        print('Recreating gluetun, the applier and every declared application together; '
              "the applications' connections will be interrupted.", flush=True)
        self.compose('stop', 'applier', *apps, timeout=120, step='Stopping the applier and the applications')
        self.compose('up', '-d', '--force-recreate', *self.wait_args(), 'gluetun', 'applier', *apps,
                     timeout=240, step=self.recreate_step())
        # A tunnel-tier provider is never verified in a sidecar: its egress
        # can't be compared with this host's address there.
        return self.settle(verify=self.egress_tier(config) != 'tunnel', sidecar=True)

    @staticmethod
    def egress_tier(config):
        services = config.get('services') or {}
        env = (services.get('applier') or {}).get('environment') or {}
        try:
            return providers.get(env.get('PROVIDER')).egress_tier
        except ValueError:
            return 'provider'

    def settle(self, *, verify=True, sidecar=False):
        """Wait for the applier, then run the doctor, accepting only a missing
        verification: 0 verified, 3 operational and unverified."""
        self.wait_for_applier(verify=verify)
        self.accept_unverified = True
        try:
            unverified = self.doctor()
        finally:
            self.accept_unverified = False
        if not unverified:
            return 0
        print('UNVERIFIED Recovered and operational, but not verified: ' + '; '.join(unverified) + '.')
        if sidecar and not verify:
            print("A sidecar with a tunnel-tier provider is never verified: its egress can't be compared with "
                  "this host's address (docs/gluetun-sidecar.md).")
        else:
            print('See docs/troubleshooting.md.')
        return 3

    def wait_for_applier(self, *, verify=True):
        """Give the recreated applier time to verify the exit: right after a
        recreation it has no verified result yet, and with gluetun it may
        first put the last verified server back. Bounded by SETTLE_SEC; the
        doctor afterwards names any check still failing. Without verify, the
        `verified ...` check is not waited for."""
        if verify:
            print(f'Waiting up to {SETTLE_SEC} s for the applier to verify the exit.', flush=True)
        else:
            print(f"Waiting up to {SETTLE_SEC} s for the applier's checks; this exit can't be verified.", flush=True)
        deadline = self.clock() + SETTLE_SEC
        while True:
            try:
                if all(passed for passed, label in self.applier_checks() if verify or not label.startswith('verified ')):
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
    parser.add_argument('--engine', choices=tuple(COMPOSE),
                        help='doctor and recover: docker (docker compose) or podman (podman-compose); by default '
                             'MOLEBRIDGE_ENGINE, else docker when installed, else podman')
    without = parser.add_argument_group('doctor without Compose (a sidecar run by Quadlet or by hand)')
    without.add_argument('--kind', choices=('sidecar',), help='the exit kind; only sidecar has this mode')
    without.add_argument('--gluetun', metavar='CONTAINER', help="gluetun's container name or ID")
    without.add_argument('--applier', metavar='CONTAINER', help="the applier's container name or ID")
    without.add_argument('--apps', metavar='C1,C2', help="the applications' containers, comma-separated")
    without.add_argument('--probe-image', metavar='IMAGE',
                         help='an image with readlink for the namespace probe, such as the routing or applier '
                              "image; by default the routing image, built from this checkout")
    args = parser.parse_args(argv)
    standalone = (args.kind, args.gluetun, args.applier, args.apps, args.probe_image)
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
        elif any(value is not None for value in standalone):
            if args.action != 'doctor' or args.kind != 'sidecar' or not (args.gluetun and args.applier):
                raise CheckError('Without Compose only the sidecar doctor runs: doctor --kind sidecar --gluetun '
                                 '<container> --applier <container> --apps <containers> (docs/gluetun-sidecar.md).')
            Host(engine=args.engine or detect_engine()).container_doctor(
                args.gluetun, args.applier, args.apps, args.probe_image)
        else:
            status = getattr(Host(engine=args.engine or detect_engine()), args.action)()
            if args.action == 'recover' and isinstance(status, int):
                # 0 recovered and verified, 3 recovered and operational but
                # not verified; failures end below with 1.
                return status
    except (CheckError, OSError, ValueError):
        # Show the fixed CheckError messages, never OS exception text containing
        # potentially sensitive paths or expanded Compose values.
        exc = sys.exc_info()[1]
        print(f'FAIL {exc}' if isinstance(exc, CheckError) else 'FAIL unable to inspect local configuration.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

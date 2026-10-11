"""tools/molebridge.py for the gluetun sidecar (EXIT_KIND=sidecar): kind
detection, configuration refusals, engine-based namespace membership on
Docker and Podman inspect output, the identity probe, and recover's exit
status. The engine is a fake; tools/check-sidecar-doctor.py runs the same
code against Docker."""
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('host_tools_sidecar', ROOT / 'tools' / 'molebridge.py')
host_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_tools)

PROBE = host_tools.PROBE_IMAGE
# Present in every container's environment; it must never reach a message.
SENTINEL = 'sentinel-Zx9k' + 'q' * 20
APPS = ('example-app',)


def cid(n):
    return f'{n:064x}'


def resolved_sidecar_config(root, apps=APPS, provider='nordvpn'):
    """compose.sidecar.yaml as `docker compose config --format json` resolves
    it: the parts the host tool checks."""
    def bind(source, target, read_only=True):
        return {'type': 'bind', 'source': str(root / source), 'target': target, 'read_only': read_only}
    services = {
        'gluetun': {'container_name': 'molebridge-sidecar-gluetun',
                    'entrypoint': list(host_tools.PREFLIGHT_ENTRYPOINT),
                    'environment': {'VPN_SERVICE_PROVIDER': provider, 'HTTP_CONTROL_SERVER_ADDRESS': '127.0.0.1:8000',
                                    'HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH': '/gluetun/auth/config.toml'},
                    'volumes': [{'type': 'volume', 'source': 'gluetun-data', 'target': '/gluetun'},
                                {'type': 'volume', 'source': 'gluetun-servers', 'target': '/gluetun/servers'},
                                bind('routing/gluetun-preflight', '/usr/local/bin/molebridge-gluetun-preflight'),
                                bind('secrets/gluetun/wireguard_private_key', '/run/secrets/wireguard_private_key'),
                                bind('secrets/gluetun/auth.toml', '/gluetun/auth/config.toml')]},
        'applier': {'container_name': 'molebridge-sidecar-applier', 'network_mode': 'service:gluetun',
                    'cap_drop': ['ALL'], 'cap_add': ['NET_ADMIN', 'NET_RAW', 'DAC_OVERRIDE'], 'read_only': True,
                    'labels': {host_tools.SIDECAR_APPS_LABEL: ','.join(apps)},
                    'environment': {'EXIT_KIND': 'sidecar', 'TUNNEL_BACKEND': 'gluetun',
                                    'PROVIDER': f'gluetun-{provider}', 'EXIT_IF': 'wg0'},
                    'volumes': [bind('state/panel', '/state/panel'),
                                bind('state/applier', '/state/applier', False),
                                {'type': 'volume', 'source': 'gluetun-servers', 'target': '/gluetun-servers',
                                 'read_only': True},
                                bind('secrets/gluetun/api_key', '/run/secrets/gluetun/api_key')]},
        'control-panel': {'container_name': 'molebridge-sidecar-control-panel', 'cap_drop': ['ALL'],
                          'environment': {'EXIT_KIND': 'sidecar', 'PROVIDER': f'gluetun-{provider}'},
                          'volumes': [bind('state/panel', '/state/panel', False),
                                      bind('state/applier', '/state/applier')]},
    }
    for app in apps:
        services[app] = {'network_mode': 'service:gluetun'}
    return {'name': 'molebridge-sidecar', 'services': services}


# Inspect output, trimmed to realistic fields. Docker 29 (as `docker inspect`
# printed it for compose-created containers) and Podman 5 differ: Podman
# names have no leading slash, its times carry the local offset, its State has
# OciVersion and ConmonPid, its owner on a podman-compose network reports
# "bridge", and it lists the namespace owner under Dependencies. Both report a
# joined container's HostConfig.NetworkMode as container:<full owner ID>.

def docker_inspect(c):
    return {
        'Id': c['id'], 'Created': '2026-10-11T06:05:02.700000000Z', 'Path': 'sleep', 'Args': ['2147483647'],
        'State': {'Status': 'running' if c['running'] else 'exited', 'Running': c['running'], 'Paused': False,
                  'Restarting': False, 'OOMKilled': False, 'Dead': False, 'Pid': 4242 if c['running'] else 0,
                  'ExitCode': 0, 'Error': '', 'StartedAt': c['started'], 'FinishedAt': '0001-01-01T00:00:00Z'},
        'Image': 'sha256:' + 'a' * 64, 'Name': '/' + c['name'], 'RestartCount': 0,
        'HostConfig': {'NetworkMode': c['mode'], 'PortBindings': c['ports'],
                       'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0}},
        'Config': {'Env': [f'GLUETUN_SECRET={SENTINEL}'],
                   'Labels': {'com.docker.compose.project': 'molebridge-sidecar',
                              'com.docker.compose.service': c['service']}},
        'NetworkSettings': {'Ports': c['ports'], 'SandboxKey': ''},
    }


def podman_time(docker_time):
    # Podman prints its local offset, e.g. 2026-10-11T08:05:03.227322297+02:00.
    return docker_time.replace('T06:', 'T08:').replace('Z', '+02:00')


def podman_inspect(c):
    return {
        'Id': c['id'], 'Created': podman_time('2026-10-11T06:05:02.700000000Z'), 'Path': 'sleep',
        'Args': ['2147483647'],
        'State': {'OciVersion': '1.2.0', 'Status': 'running' if c['running'] else 'exited', 'Running': c['running'],
                  'Paused': False, 'Restarting': False, 'OOMKilled': False, 'Dead': False,
                  'Pid': 4242 if c['running'] else 0, 'ConmonPid': 4240, 'ExitCode': 0, 'Error': '',
                  'StartedAt': podman_time(c['started']), 'FinishedAt': '0001-01-01T00:00:00Z',
                  'CheckpointedAt': '0001-01-01T00:00:00Z', 'RestoredAt': '0001-01-01T00:00:00Z'},
        'Image': 'a' * 64, 'ImageName': 'docker.io/library/busybox:1.37.0', 'Name': c['name'], 'Pod': '',
        'Namespace': '', 'Dependencies': [c['mode'].partition(':')[2]] if c['mode'].startswith('container:') else [],
        'HostConfig': {'NetworkMode': 'bridge' if c['service'] == 'gluetun' else c['mode'],
                       'PortBindings': c['ports'], 'CgroupMode': 'private'},
        'Config': {'Env': [f'GLUETUN_SECRET={SENTINEL}'],
                   'Labels': {'io.podman.compose.project': 'molebridge-sidecar',
                              'com.docker.compose.project': 'molebridge-sidecar',
                              'com.docker.compose.service': c['service']}},
        'NetworkSettings': {'EndpointID': '', 'Gateway': '', 'IPAddress': '', 'Ports': c['ports'], 'SandboxKey': ''},
    }


APPLIER_OK = 'PASS recent applier check\nPASS fresh relay catalogue\nPASS verified NordVPN egress\n'
APPLIER_UNVERIFIED = 'PASS recent applier check\nPASS fresh relay catalogue\nFAIL verified IVPN egress\n'


class Engine:
    """A container engine with one namespace owner (gluetun) and members
    joined to it. Each container records its own namespace, as the kernel
    does: a member keeps the namespace it joined until it is recreated."""

    def __init__(self, root, engine='docker', apps=APPS, config=None):
        self.engine, self.calls, self.count, self.namespaces = engine, [], 10, 100
        self.config = config or resolved_sidecar_config(root, apps)
        self.containers = {}
        self.applier_output = [(0, APPLIER_OK)]
        self.fail = {}
        self.on_probe = None
        for service in ('gluetun', 'applier', *apps):
            self.create(service)

    def create(self, service):
        self.count += 1
        if service == 'gluetun':
            self.namespaces += 1
            namespace, mode = self.namespaces, 'molebridge-sidecar_default'
        else:
            owner = self.containers['gluetun']
            namespace, mode = owner['ns'], 'container:' + owner['id']
        name = self.config['services'][service].get('container_name') or f'molebridge-sidecar-{service}-1'
        self.containers[service] = {'service': service, 'name': name, 'id': cid(self.count), 'running': True,
                                    'started': f'2026-10-11T06:05:{self.count:02d}.000000000Z',
                                    'mode': mode, 'ns': namespace, 'ports': {}}

    def restart_owner(self):
        """`restart` of gluetun: the same ID, a new namespace and start time;
        its members keep the old namespace."""
        owner = self.containers['gluetun']
        self.namespaces += 1
        owner['ns'] = self.namespaces
        owner['started'] = owner['started'].replace(':05:', ':06:')

    def find(self, reference):
        for c in self.containers.values():
            if reference in (c['id'], c['name']):
                return c
        return None

    def inspect_json(self, c):
        return json.dumps([(docker_inspect if self.engine == 'docker' else podman_inspect)(c)])

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        compose = list(host_tools.COMPOSE[self.engine])
        for word, error in self.fail.items():
            if word in args:
                raise host_tools.CheckError(error)
        if args[:len(compose)] == compose:
            rest = args[len(compose):]
            if rest[0] == 'config':
                if self.engine == 'docker':
                    return json.dumps(self.config)
                yaml = pytest.importorskip('yaml')
                return yaml.safe_dump(self.config)
            if rest[0] == 'exec':
                if rest[2] != 'applier':
                    # Application images may have no shell or readlink.
                    raise host_tools.CheckError('Command failed; check Docker/Compose locally.')
                status, output = self.applier_output.pop(0) if len(self.applier_output) > 1 else self.applier_output[0]
                return (status, output) if kwargs.get('allow_failure') else output
            if rest[0] == 'up':
                for service in [a for a in rest if a in self.containers]:
                    self.create(service)
            return ''
        if args[:2] == [self.engine, 'exec']:
            # Without Compose: `<engine> exec <applier container> python ...`.
            if args[2] != self.containers['applier']['name']:
                raise host_tools.CheckError('Command failed; check Docker/Compose locally.')
            status, output = self.applier_output.pop(0) if len(self.applier_output) > 1 else self.applier_output[0]
            return (status, output) if kwargs.get('allow_failure') else output
        if args[:2] == [self.engine, 'ps']:
            service = args[-1].rpartition('=')[2]
            c = self.containers.get(service)
            return (c['id'] + '\n') if c else ''
        if args[:2] == [self.engine, 'inspect']:
            c = self.find(args[-1])
            if c is None:
                raise host_tools.CheckError('Command failed; check Docker/Compose locally. Expanded output was withheld.')
            return self.inspect_json(c)
        if args[:3] == [self.engine, 'image', 'inspect'] or args[:2] == [self.engine, 'build']:
            return ''
        if args[:2] == [self.engine, 'run']:
            target = args[args.index('--network') + 1].partition(':')[2]
            c = self.find(target)
            if self.on_probe:
                self.on_probe(c)
            if c is None or not c['running']:
                raise host_tools.CheckError('Command failed; check Docker/Compose locally. Expanded output was withheld.')
            return f'net:[40265{c["ns"]:05d}]\n'
        raise AssertionError(f'unexpected command {args}')


def host_for(tmp_path, engine, **kwargs):
    (tmp_path / '.env').write_text('')
    fake = Engine(tmp_path, engine, **kwargs)
    clock = [0.0]
    host = host_tools.Host(tmp_path, run=fake, engine=engine, sleep=lambda s: clock.__setitem__(0, clock[0] + s),
                           clock=lambda: clock[0])
    return host, fake, clock


def write_secrets(root):
    host_tools.Host(root, run=lambda *a, **kw: '').gluetun_auth()
    key = root / 'secrets' / 'gluetun' / 'wireguard_private_key'
    key.write_text('x\n')
    key.chmod(0o600)


def probes(fake):
    return [c for c in fake.calls if c[1] == 'run']


# Kind detection

@pytest.mark.parametrize('config,kind', [
    ({}, 'overlay'),
    ({'services': {'applier': {'environment': {}}}}, 'overlay'),
    ({'services': {'applier': {'environment': {'EXIT_KIND': ''}}}}, 'overlay'),
    ({'services': {'applier': {'environment': {'EXIT_KIND': 'overlay'}}}}, 'overlay'),
    ({'services': {'applier': {'environment': {'EXIT_KIND': 'sidecar'}}}}, 'sidecar'),
])
def test_kind_is_read_from_the_applier(config, kind):
    assert host_tools.Host.kind(config) == kind


@pytest.mark.parametrize('value', ['Sidecar', 'exit', 'sidecar '])
def test_an_unknown_kind_is_refused(value):
    with pytest.raises(host_tools.CheckError, match='EXIT_KIND must be overlay or sidecar'):
        host_tools.Host.kind({'services': {'applier': {'environment': {'EXIT_KIND': value}}}})


def test_the_sidecar_compose_file_is_recognised(tmp_path):
    host, _, _ = host_for(tmp_path, 'docker')
    config = host.config()
    assert host.kind(config) == 'sidecar' and host.sidecar_apps(config) == ['example-app']


def test_engine_detection():
    assert host_tools.detect_engine({}, which=lambda name: '/usr/bin/' + name) == 'docker'
    assert host_tools.detect_engine({}, which=lambda name: None if name == 'docker' else '/usr/bin/' + name) == 'podman'
    assert host_tools.detect_engine({}, which=lambda name: None) == 'docker'
    assert host_tools.detect_engine({'MOLEBRIDGE_ENGINE': 'podman'}, which=lambda name: '/x') == 'podman'
    with pytest.raises(host_tools.CheckError, match='MOLEBRIDGE_ENGINE'):
        host_tools.detect_engine({'MOLEBRIDGE_ENGINE': 'nerdctl'})


# The compose file itself

def test_sidecar_compose_file():
    yaml = pytest.importorskip('yaml')
    compose = yaml.safe_load((ROOT / 'compose.sidecar.yaml').read_text())
    services = compose['services']
    assert set(services) == {'gluetun', 'applier', 'example-app', 'control-panel'}
    gluetun = services['gluetun']
    overlay = yaml.safe_load((ROOT / 'compose.gluetun.yaml').read_text())['services']['gluetun']
    assert gluetun['image'] == overlay['image']
    assert gluetun['entrypoint'] == host_tools.PREFLIGHT_ENTRYPOINT == overlay['entrypoint']
    assert './routing/gluetun-preflight:/usr/local/bin/molebridge-gluetun-preflight:ro' in gluetun['volumes']
    env = gluetun['environment']
    assert env['HTTP_CONTROL_SERVER_ADDRESS'] == '127.0.0.1:8000' and 'ports' not in gluetun
    assert env['WIREGUARD_IMPLEMENTATION'] == 'kernelspace' and env['VPN_INTERFACE'] == '${EXIT_IF:-wg0}'
    binds = {v['target']: v for v in gluetun['volumes'] if isinstance(v, dict)}
    # The role file only in gluetun, the key only in the applier, no post-rules.
    assert set(binds) == {'/gluetun/auth/config.toml', '/run/secrets/wireguard_private_key'}
    assert '/iptables/post-rules.txt' not in str(gluetun) and 'post-rules' not in str(services)
    for bind in binds.values():
        assert bind['read_only'] is True and bind['bind'] == {'create_host_path': False}
    applier = services['applier']
    assert applier['network_mode'] == 'service:gluetun' and applier['read_only'] is True
    assert applier['cap_drop'] == ['ALL'] and applier['cap_add'] == ['NET_ADMIN', 'NET_RAW', 'DAC_OVERRIDE']
    assert applier['security_opt'] == ['no-new-privileges:true']
    assert applier['healthcheck']['test'] == ['CMD', 'python', '-m', 'applier.apply', '--healthcheck']
    aenv = applier['environment']
    assert aenv['EXIT_KIND'] == 'sidecar' and aenv['TUNNEL_BACKEND'] == 'gluetun'
    assert aenv['PROVIDER'].startswith('gluetun-${GLUETUN_PROVIDER')
    assert aenv['GLUETUN_CONTROL_URL'] == 'http://127.0.0.1:8000'
    for name in ('EXIT_IF', 'SERVER', 'GLUETUN_API_KEY_FILE', 'GLUETUN_SERVERS_FILE', 'GLUETUN_UPDATER_PERIOD',
                 'GATUS_URL', 'GATUS_ENDPOINT'):
        assert name in aenv, name
    assert not set(aenv) & {'OVERLAY_CIDR', 'CONTROL_MARK', 'HOST_TABLE'}
    applier_binds = {v['target']: v for v in applier['volumes'] if isinstance(v, dict)}
    assert set(applier_binds) == {'/run/secrets/gluetun/api_key'}
    assert applier_binds['/run/secrets/gluetun/api_key']['read_only'] is True
    assert not any('auth.toml' in str(v) or 'wireguard_private_key' in str(v) for v in applier['volumes'])
    assert applier['labels'] == {host_tools.SIDECAR_APPS_LABEL: '${SIDECAR_APPS:-}'}
    app = services['example-app']
    assert app['network_mode'] == 'service:gluetun' and app['image'].count('@sha256:') == 1
    assert app['profiles'] == ['example']
    panel = services['control-panel']
    assert panel['environment']['EXIT_KIND'] == 'sidecar' and panel['environment']['PROVIDER'] == aenv['PROVIDER']
    assert panel['cap_drop'] == ['ALL'] and 'cap_add' not in panel
    assert panel['ports'] == ['127.0.0.1:${PANEL_PORT:-8095}:8080']
    assert not any('secrets' in str(v) for v in panel['volumes'])
    assert not {'netbird', 'guard', 'wireguard'} & set(services)
    example = (ROOT / '.env.sidecar.example').read_text()
    assert 'SIDECAR_APPS=example-app\n' in example and 'COMPOSE_FILE=compose.sidecar.yaml\n' in example
    assert 'COMPOSE_PROFILES=example\n' in example


# Configuration refusals

def _break(config, change):
    change(config['services'])
    return config


@pytest.mark.parametrize('change,message', [
    (lambda s: s['applier']['environment'].update(TUNNEL_BACKEND='wireguard'), 'TUNNEL_BACKEND=gluetun'),
    (lambda s: s['applier']['environment'].update(PROVIDER='nordvpn'), 'gluetun-<GLUETUN_PROVIDER>'),
    (lambda s: s['applier']['environment'].update(PROVIDER='gluetun-ivpn'), 'gluetun-<GLUETUN_PROVIDER>'),
    (lambda s: s['applier']['environment'].pop('PROVIDER'), 'gluetun-<GLUETUN_PROVIDER>'),
    (lambda s: s['applier'].update(network_mode='host'), 'network_mode: service:gluetun'),
    (lambda s: s['applier']['cap_add'].append('SYS_ADMIN'), 'drop every capability'),
    (lambda s: s['applier'].pop('read_only'), 'read-only'),
    (lambda s: s['applier']['volumes'].append({'type': 'bind', 'source': '/x/secrets/gluetun/auth.toml',
                                               'target': '/auth.toml', 'read_only': True}), 'role file'),
    (lambda s: s['applier']['volumes'][3].update(read_only=False), 'read-only'),
    (lambda s: s['applier']['volumes'].pop(3), 'api_key read-only'),
    (lambda s: s['gluetun'].pop('entrypoint'), "role-file check"),
    (lambda s: s['gluetun']['environment'].update(HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE='{"auth":"none"}'),
     'default control-server role'),
    (lambda s: s['gluetun']['environment'].update(HTTP_CONTROL_SERVER_ADDRESS=':8000'), '127.0.0.1:8000 only'),
    (lambda s: s['gluetun'].update(ports=[{'target': 8000, 'published': '8000', 'host_ip': '127.0.0.1'}]),
     'must not publish port 8000'),
    (lambda s: s['gluetun'].update(ports=['7990-8010:7990-8010']), 'must not publish port 8000'),
    (lambda s: s['gluetun']['volumes'].pop(4), 'mount its role file'),
    (lambda s: s['gluetun']['volumes'].append({'type': 'bind', 'source': '/x/tunnel/gluetun/post-rules.txt',
                                               'target': '/iptables/post-rules.txt', 'read_only': True}),
     "must not mount the overlay's post-rules"),
    (lambda s: s['gluetun']['volumes'].append({'type': 'bind', 'source': '/x/secrets/gluetun/api_key',
                                               'target': '/key', 'read_only': True}), 'must not mount the API key'),
    (lambda s: s['control-panel']['volumes'].append({'type': 'bind', 'source': '/x/secrets/gluetun/api_key',
                                                     'target': '/key', 'read_only': True}), 'must not mount any secret'),
    (lambda s: s.update(netbird={'environment': {}}), 'no NetBird or routing service'),
])
def test_doctor_refuses_a_broken_sidecar_compose_file(tmp_path, change, message):
    (tmp_path / '.env').write_text('')
    config = _break(resolved_sidecar_config(tmp_path), change)
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(config))
    with pytest.raises(host_tools.CheckError, match=message):
        host.config()


@pytest.mark.parametrize('apps,message', [
    ('', 'No applications declared'),
    (' , ', 'No applications declared'),
    ('example-app,example-app', 'distinct Compose services'),
    ('gluetun', 'distinct Compose services'),
    ('applier', 'distinct Compose services'),
    ('bad name', 'distinct Compose services'),
    ('missing-app', 'missing-app, which is not a service'),
])
def test_sidecar_apps_must_name_the_applications(tmp_path, apps, message):
    (tmp_path / '.env').write_text('')
    config = resolved_sidecar_config(tmp_path)
    config['services']['applier']['labels'][host_tools.SIDECAR_APPS_LABEL] = apps
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(config))
    with pytest.raises(host_tools.CheckError, match=message):
        host.config()


def test_no_label_means_no_applications_declared(tmp_path):
    (tmp_path / '.env').write_text('')
    config = resolved_sidecar_config(tmp_path)
    config['services']['applier'].pop('labels')
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(config))
    with pytest.raises(host_tools.CheckError, match='^No applications declared'):
        host.config()


def test_every_service_in_gluetuns_namespace_must_be_declared(tmp_path):
    (tmp_path / '.env').write_text('')
    config = resolved_sidecar_config(tmp_path, apps=('example-app', 'other'))
    config['services']['applier']['labels'][host_tools.SIDECAR_APPS_LABEL] = 'example-app'
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: json.dumps(config))
    with pytest.raises(host_tools.CheckError, match="other service joins gluetun's namespace but isn't in SIDECAR_APPS"):
        host.config()
    config['services']['other']['network_mode'] = 'host'
    config['services']['applier']['labels'][host_tools.SIDECAR_APPS_LABEL] = 'example-app,other'
    with pytest.raises(host_tools.CheckError, match='other service must use network_mode: service:gluetun'):
        host.config()


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
def test_sidecar_files_need_no_post_rules(tmp_path):
    host = host_tools.Host(tmp_path, run=lambda *a, **kw: '')
    with pytest.raises(host_tools.CheckError, match='docs/gluetun-sidecar.md'):
        host.check_sidecar_files()
    write_secrets(tmp_path)
    host.check_sidecar_files()
    assert not (tmp_path / 'tunnel').exists()


# Engine-based membership and the identity probe, on Docker and Podman

@pytest.mark.parametrize('engine', ['docker', 'podman'])
def test_attached_containers_pass(tmp_path, engine):
    # shell-less stands for an application image with no shell or readlink,
    # found by Compose's labels rather than a container_name.
    host, fake, _ = host_for(tmp_path, engine, apps=('example-app', 'shell-less'))
    host.sidecar_namespace_checks(host.config())
    gluetun = fake.containers['gluetun']['id']
    # One probe joined to gluetun, then one to each member, by resolved ID.
    joined = [c[c.index('--network') + 1] for c in probes(fake)]
    assert joined == ['container:' + fake.containers[s]['id'] for s in ('gluetun', 'applier', 'example-app',
                                                                         'shell-less')]
    assert probes(fake)[0] == [engine, 'run', '--rm', '--pull', 'never', '--network', f'container:{gluetun}',
                               '--entrypoint', 'readlink', '--cap-drop', 'ALL', '--read-only',
                               '--security-opt', 'no-new-privileges', PROBE, '/proc/self/ns/net']
    # Inspected before and after the probes, by name or by Compose's labels.
    inspected = [c[-1] for c in fake.calls if c[1] == 'inspect']
    assert inspected.count('molebridge-sidecar-gluetun') == 2 and inspected.count(fake.containers['shell-less']['id']) == 2
    assert [engine, 'ps', '-a', '-q', '--no-trunc', '--filter', 'label=com.docker.compose.project=molebridge-sidecar',
            '--filter', 'label=com.docker.compose.service=shell-less'] in fake.calls
    # Nothing runs inside the applications: an image without a shell or
    # readlink passes the same way.
    assert not any('exec' in c for c in fake.calls)


def test_the_podman_configuration_is_read_from_its_yaml(tmp_path):
    pytest.importorskip('yaml')
    host, fake, _ = host_for(tmp_path, 'podman')
    # podman-compose prints short volumes and list-form labels and environment.
    services = fake.config['services']
    services['applier']['volumes'] = ['./state/panel:/state/panel:ro', './state/applier:/state/applier',
                                      'gluetun-servers:/gluetun-servers:ro',
                                      './secrets/gluetun/api_key:/run/secrets/gluetun/api_key:ro']
    services['applier']['labels'] = [f'{host_tools.SIDECAR_APPS_LABEL}=example-app']
    services['applier']['environment'] = [f'{k}={v}' for k, v in services['applier']['environment'].items()]
    services['gluetun']['ports'] = ['127.0.0.1:8080:8080']
    config = host.config()
    assert fake.calls[0] == ['podman-compose', 'config']
    assert host.kind(config) == 'sidecar' and host.sidecar_apps(config) == ['example-app']
    assert config['services']['applier']['volumes'][3] == {
        'type': 'bind', 'source': './secrets/gluetun/api_key', 'target': '/run/secrets/gluetun/api_key',
        'read_only': True}
    services['gluetun']['ports'] = ['127.0.0.1:8000:8000/tcp']
    with pytest.raises(host_tools.CheckError, match='must not publish port 8000'):
        host.config()


@pytest.mark.parametrize('engine', ['docker', 'podman'])
def test_a_same_id_gluetun_restart_leaves_an_application_behind(tmp_path, engine):
    host, fake, _ = host_for(tmp_path, engine)
    config = host.config()
    host.sidecar_namespace_checks(config)
    before = fake.containers['gluetun']['id']
    fake.restart_owner()
    # The engine's record still matches: same ID, every member still points at it.
    assert fake.containers['gluetun']['id'] == before
    assert fake.containers['example-app']['mode'] == 'container:' + before
    with pytest.raises(host_tools.CheckError,
                       match="^The applier container is not in gluetun's current network namespace; run recover.$"):
        host.sidecar_namespace_checks(config)


def test_an_application_left_behind_alone_is_named(tmp_path):
    host, fake, _ = host_for(tmp_path, 'docker')
    fake.restart_owner()
    fake.containers['applier']['ns'] = fake.containers['gluetun']['ns']
    with pytest.raises(host_tools.CheckError, match="^The example-app container is not in gluetun's current"):
        host.sidecar_namespace_checks(host.config())


@pytest.mark.parametrize('engine', ['docker', 'podman'])
@pytest.mark.parametrize('field', ['started', 'id'])
def test_a_restart_during_the_probes_fails(tmp_path, engine, field):
    host, fake, _ = host_for(tmp_path, engine)
    config = host.config()

    def restart(container):
        if container and container['service'] == 'example-app':
            if field == 'started':
                container['started'] = container['started'].replace(':05:', ':07:')
            else:
                fake.create('example-app')
    fake.on_probe = restart
    # Its probe still ran in the namespace it had; the second reading catches it.
    with pytest.raises(host_tools.CheckError, match='^A container restarted or was replaced during the check'):
        host.sidecar_namespace_checks(config)


@pytest.mark.parametrize('engine', ['docker', 'podman'])
@pytest.mark.parametrize('fault,message', [
    (lambda f: f.containers['example-app'].update(mode='container:' + cid(999)),
     "^The example-app container is not attached to gluetun's current container; run recover.$"),
    (lambda f: f.containers['applier'].update(mode='molebridge-sidecar_default'),
     "^The applier container is not attached to gluetun's current container"),
    (lambda f: f.containers['example-app'].update(running=False), '^The example-app container is not running'),
    (lambda f: f.containers['gluetun'].update(running=False), '^The gluetun container is not running'),
    (lambda f: f.containers.pop('example-app'), '^The example-app container is missing; run recover.$'),
    (lambda f: f.containers.pop('applier'), '^The applier container is missing or cannot be inspected'),
    (lambda f: f.containers['gluetun'].update(ports={'8000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]}),
     '^The gluetun container publishes port 8000'),
])
def test_membership_failures(tmp_path, engine, fault, message):
    host, fake, _ = host_for(tmp_path, engine)
    config = host.config()
    fault(fake)
    with pytest.raises(host_tools.CheckError, match=message) as error:
        host.sidecar_namespace_checks(config)
    assert SENTINEL not in str(error.value)


def test_other_published_ports_are_fine(tmp_path):
    host, fake, _ = host_for(tmp_path, 'docker')
    fake.containers['gluetun']['ports'] = {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8080'}],
                                           '8000/tcp': None}
    host.sidecar_namespace_checks(host.config())


@pytest.mark.parametrize('output', ['not json', '[]', '[{"Id": "abc"}]', json.dumps([{'Id': cid(1), 'State': {}}])])
def test_uninspectable_containers_fail(tmp_path, output):
    host, fake, _ = host_for(tmp_path, 'docker')
    config = host.config()
    fake.inspect_json = lambda c: output
    with pytest.raises(host_tools.CheckError, match="^The gluetun container's inspect output was not understood"):
        host.sidecar_namespace_checks(config)


@pytest.mark.parametrize('found,message', [(0, 'is missing'), (2, 'More than one')])
def test_label_lookup_needs_exactly_one_container(tmp_path, found, message):
    host, fake, _ = host_for(tmp_path, 'docker')
    fake.config['services']['example-app'].pop('container_name', None)
    original = fake.__call__

    def run(args, **kwargs):
        if args[:2] == ['docker', 'ps']:
            fake.calls.append(list(args))
            return ''.join(cid(500 + n) + '\n' for n in range(found))
        return original(args, **kwargs)
    host.run = run
    with pytest.raises(host_tools.CheckError, match=message):
        host.sidecar_namespace_checks(host.config())


def test_a_probe_that_cannot_join_or_prints_nonsense_fails(tmp_path):
    host, fake, _ = host_for(tmp_path, 'docker')
    config = host.config()
    fake.fail['run'] = 'Command failed; check Docker/Compose locally. Expanded output was withheld.'
    with pytest.raises(host_tools.CheckError, match='^The namespace probe could not join the gluetun container'):
        host.sidecar_namespace_checks(config)
    fake.fail.clear()
    host.run = lambda args, **kw: 'sh: readlink: not found\n' if args[1] == 'run' else fake(args, **kw)
    with pytest.raises(host_tools.CheckError, match='printed no namespace'):
        host.sidecar_namespace_checks(config)


def test_the_probe_image_is_built_from_the_routing_dockerfile_when_missing(tmp_path):
    host, fake, _ = host_for(tmp_path, 'docker')
    original = fake.__call__

    def run(args, **kwargs):
        if args[:2] == ['docker', 'image']:
            fake.calls.append(list(args))
            raise host_tools.CheckError('absent')
        return original(args, **kwargs)
    host.run = run
    host.sidecar_namespace_checks(host.config())
    build = [c for c in fake.calls if c[1] == 'build']
    assert build == [['docker', 'build', '--tag', PROBE, '--file', str(ROOT / 'routing' / 'Dockerfile'), str(ROOT)]]


# The doctor

@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
@pytest.mark.parametrize('engine', ['docker', 'podman'])
def test_sidecar_doctor_passes_and_says_what_it_does_not_check(tmp_path, engine, capsys):
    host, fake, _ = host_for(tmp_path, engine)
    write_secrets(tmp_path)
    assert host.doctor() == []
    out = capsys.readouterr().out
    assert out.startswith('PASS configuration, permissions, namespace membership')
    assert "Traffic protection is gluetun's firewall, which Molebridge doesn't check" in out
    # No NetBird, routing or identity-volume checks in a sidecar.
    assert not any('netbird' in c or 'volume' in c for c in fake.calls)
    assert fake.calls[-1] == [*host_tools.COMPOSE[engine], 'exec', '-T', 'applier', 'python', '-m', 'applier.apply',
                              '--doctor']


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
def test_sidecar_doctor_fails_on_an_unverified_exit(tmp_path):
    host, fake, _ = host_for(tmp_path, 'docker', config=resolved_sidecar_config(Path('/x'), provider='ivpn'))
    write_secrets(tmp_path)
    fake.applier_output = [(1, APPLIER_UNVERIFIED)]
    with pytest.raises(host_tools.CheckError, match='^The applier reports: verified IVPN egress'):
        host.doctor()


# Recovery

def recovery_host(tmp_path, engine='docker', provider='nordvpn'):
    host, fake, clock = host_for(tmp_path, engine)
    fake.config = resolved_sidecar_config(tmp_path, provider=provider)
    write_secrets(tmp_path)
    return host, fake, clock


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
@pytest.mark.parametrize('engine', ['docker', 'podman'])
def test_sidecar_recovery_recreates_gluetun_with_every_member(tmp_path, engine, capsys):
    host, fake, clock = recovery_host(tmp_path, engine)
    fake.restart_owner()
    old = {s: c['id'] for s, c in fake.containers.items()}
    assert host.recover() == 0
    compose = list(host_tools.COMPOSE[engine])
    lifecycle = [c[len(compose):] for c in fake.calls if c[:len(compose)] == compose and c[len(compose)] != 'exec'
                 and c[len(compose)] != 'config']
    wait = ['--wait', '--wait-timeout', '180'] if engine == 'docker' else []
    assert lifecycle == [['build', 'applier'], ['stop', 'applier', 'example-app'],
                         ['up', '-d', '--force-recreate', *wait, 'gluetun', 'applier', 'example-app']]
    assert [engine, 'build', '--tag', PROBE, '--file', str(ROOT / 'routing' / 'Dockerfile'), str(ROOT)] in fake.calls
    assert all(fake.containers[s]['id'] != old[s] for s in old)
    assert all('down' not in c and '-v' not in c and 'rm' not in c for c in fake.calls)
    assert clock[0] == 0
    assert 'PASS configuration' in capsys.readouterr().out


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
def test_recovery_of_a_provider_tier_sidecar_waits_for_verification(tmp_path, capsys):
    host, fake, clock = recovery_host(tmp_path)
    fake.applier_output = [(1, APPLIER_UNVERIFIED.replace('IVPN', 'NordVPN'))] * 3 + [(0, APPLIER_OK)]
    assert host.recover() == 0
    assert clock[0] == 3 * host_tools.SETTLE_POLL_SEC


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
def test_a_provider_tier_sidecar_that_never_verifies_ends_at_3(tmp_path, capsys):
    host, fake, clock = recovery_host(tmp_path)
    fake.applier_output = [(1, APPLIER_UNVERIFIED.replace('IVPN', 'NordVPN'))]
    assert host.recover() == 3
    assert host_tools.SETTLE_SEC <= clock[0] <= host_tools.SETTLE_SEC + host_tools.SETTLE_POLL_SEC
    out = capsys.readouterr().out
    assert 'UNVERIFIED Recovered and operational, but not verified: verified NordVPN egress.' in out


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
@pytest.mark.parametrize('provider', ['ivpn', 'fastestvpn', 'surfshark', 'windscribe'])
def test_a_tunnel_tier_sidecar_ends_at_3_without_waiting_for_verification(tmp_path, provider, capsys):
    host, fake, clock = recovery_host(tmp_path, provider=provider)
    # The applier's first answer comes before its first check; then
    # everything but verification passes, which never comes.
    fake.applier_output = [(1, 'FAIL recent applier check\nPASS fresh relay catalogue\nFAIL verified X egress\n'),
                           (1, APPLIER_UNVERIFIED)]
    assert host.recover() == 3
    assert clock[0] == host_tools.SETTLE_POLL_SEC
    out = capsys.readouterr().out
    assert "can't be verified" in out and 'A sidecar with a tunnel-tier provider is never verified' in out


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
def test_a_tunnel_tier_sidecar_still_waits_for_its_other_checks(tmp_path):
    host, fake, clock = recovery_host(tmp_path, provider='ivpn')
    fake.applier_output = [(1, 'FAIL recent applier check\nFAIL verified IVPN egress\n')]
    with pytest.raises(host_tools.CheckError, match='^The applier reports: recent applier check; verified IVPN egress'):
        host.recover()
    assert clock[0] >= host_tools.SETTLE_SEC


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
def test_recovery_that_leaves_an_application_behind_fails(tmp_path):
    host, fake, _ = recovery_host(tmp_path)
    original = fake.create

    def forgetful(service):
        # The application isn't recreated: it keeps the old namespace.
        if service != 'example-app':
            original(service)
    fake.create = forgetful
    with pytest.raises(host_tools.CheckError, match="example-app container is not attached to gluetun's current"):
        host.recover()


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
def test_recover_exit_status(tmp_path, monkeypatch, capsys):
    original = host_tools.Host

    def run_main(prepare, provider='nordvpn'):
        host, fake, _ = recovery_host(tmp_path, provider=provider)
        prepare(fake)
        monkeypatch.setattr(host_tools, 'Host', lambda *a, **kw: original(*a, **kw) if a else host)
        try:
            return host_tools.main(['recover', '--engine', 'docker'])
        finally:
            monkeypatch.setattr(host_tools, 'Host', original)
    assert run_main(lambda f: None) == 0
    assert run_main(lambda f: f.applier_output.__setitem__(0, (1, APPLIER_UNVERIFIED)), provider='ivpn') == 3
    assert run_main(lambda f: f.fail.__setitem__('up', 'Command failed; check Docker/Compose locally.')) == 1
    err = capsys.readouterr().err
    assert err.startswith('FAIL Recreating the containers') and SENTINEL not in err
    assert run_main(lambda f: f.applier_output.__setitem__(0, (1, 'FAIL fresh relay catalogue\n'))) == 1


@pytest.mark.skipif(os.name != 'posix', reason='mode 0600 files')
def test_a_failed_build_leaves_the_sidecar_running(tmp_path):
    host, fake, _ = recovery_host(tmp_path)
    fake.fail['build'] = 'Command failed; check Docker/Compose locally. Expanded output was withheld.'
    with pytest.raises(host_tools.CheckError, match='^Building the images failed'):
        host.recover()
    assert not any('stop' in c or 'up' in c for c in fake.calls)


# The overlay kind keeps its readlink comparison and gains the engine check.

def overlay_config():
    return {'name': 'molebridge', 'services': {
        'wireguard': {'container_name': 'molebridge-wireguard'},
        'netbird': {'container_name': 'molebridge-netbird', 'network_mode': 'service:wireguard'},
        'applier': {'container_name': 'molebridge-applier', 'network_mode': 'service:wireguard'},
    }}


@pytest.mark.parametrize('engine', ['docker', 'podman'])
def test_overlay_namespace_check_adds_the_engine_record(tmp_path, engine):
    containers = {'molebridge-wireguard': {'id': cid(1), 'service': 'wireguard', 'mode': 'molebridge_default'},
                  'molebridge-netbird': {'id': cid(2), 'service': 'netbird', 'mode': 'container:' + cid(1)},
                  'molebridge-applier': {'id': cid(3), 'service': 'applier', 'mode': 'container:' + cid(1)}}
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[1] == 'inspect':
            c = dict(containers[args[-1]], name=args[-1], running=True, started='2026-10-11T06:05:01.0Z', ports={})
            return json.dumps([(docker_inspect if engine == 'docker' else podman_inspect)(c)])
        return 'net:[4026531840]\n'
    host = host_tools.Host(tmp_path, run=run, engine=engine)
    host.loaded = overlay_config()
    host.namespace_checks('wireguard')
    assert [c[-1] for c in calls if c[1] == 'inspect'] == list(containers)
    assert [c[-3:] for c in calls if 'readlink' in c] == [[s, 'readlink', '/proc/self/ns/net']
                                                          for s in ('wireguard', 'netbird', 'applier')]
    containers['molebridge-netbird']['mode'] = 'container:' + cid(9)
    with pytest.raises(host_tools.CheckError, match="^The netbird container is not attached to wireguard's current"):
        host.namespace_checks('wireguard')


def test_overlay_recovery_on_podman_has_no_wait(tmp_path, monkeypatch):
    calls = []
    host = host_tools.Host(tmp_path, run=lambda args, **kw: calls.append(args) or '', engine='podman')
    monkeypatch.setattr(host, 'config', lambda: {})
    monkeypatch.setattr(host, 'check_files', lambda _: None)
    monkeypatch.setattr(host, 'check_volume', lambda _: None)
    monkeypatch.setattr(host, 'doctor', lambda: [])
    assert host.recover() == 0
    assert calls[0] == ['podman-compose', 'build', 'wireguard', 'applier']
    assert calls[2] == ['podman-compose', 'up', '-d', '--force-recreate', 'wireguard', 'netbird', 'applier',
                        'control-panel']


def test_overlay_volume_name_under_podman(tmp_path):
    calls = []
    (tmp_path / '.env').write_text('COMPOSE_PROJECT_NAME=exit-a\n')
    host = host_tools.Host(tmp_path, run=lambda args, **kw: calls.append(args) or '', engine='podman')
    host.check_volume({'name': 'molebridge', 'volumes': {'netbird-data': None}})
    assert calls == [['podman', 'volume', 'inspect', 'exit-a_netbird-data', '--format', '{{.Name}}']]


def test_port_targets():
    assert list(host_tools.port_targets('127.0.0.1:8095:8080')) == [8080]
    assert list(host_tools.port_targets('[::1]:8000:8000/udp')) == [8000]
    assert list(host_tools.port_targets('8000')) == [8000]
    assert 8000 in host_tools.port_targets('7990-8010:7990-8010')
    assert list(host_tools.port_targets({'target': 8000, 'published': '18000'})) == [8000]
    with pytest.raises(ValueError):
        host_tools.port_targets('${PORT}')


# The doctor without Compose (a sidecar run by Quadlet): containers named on
# the command line, Podman-shaped inspect output.

QUADLET_APPS = ('downloader', 'indexer')


def quadlet_engine(tmp_path, engine='podman'):
    config = resolved_sidecar_config(tmp_path, apps=QUADLET_APPS)
    config['services']['gluetun']['container_name'] = 'systemd-gluetun'
    config['services']['applier']['container_name'] = 'systemd-switchyard-applier'
    for app in QUADLET_APPS:
        config['services'][app]['container_name'] = app
    fake = Engine(tmp_path, engine, apps=QUADLET_APPS, config=config)
    host = host_tools.Host(tmp_path, run=fake, engine=engine)
    return host, fake


def quadlet_doctor(host, probe_image=None):
    return host.container_doctor('systemd-gluetun', 'systemd-switchyard-applier', 'downloader,indexer',
                                 probe_image)


@pytest.mark.parametrize('engine', ['podman', 'docker'])
def test_the_doctor_without_compose_passes(tmp_path, engine, capsys):
    host, fake = quadlet_engine(tmp_path, engine)
    assert quadlet_doctor(host) == []
    gluetun = fake.containers['gluetun']['id']
    assert probes(fake)[0] == [engine, 'run', '--rm', '--pull', 'never', '--network', f'container:{gluetun}',
                               '--entrypoint', 'readlink', '--cap-drop', 'ALL', '--read-only',
                               '--security-opt', 'no-new-privileges', PROBE, '/proc/self/ns/net']
    assert [c[c.index('--network') + 1] for c in probes(fake)] == [
        'container:' + fake.containers[s]['id'] for s in ('gluetun', 'applier', *QUADLET_APPS)]
    # Inspected by name, twice each, and no Compose at all.
    inspected = [c[-1] for c in fake.calls if c[1] == 'inspect']
    assert sorted(set(inspected)) == sorted(['systemd-gluetun', 'systemd-switchyard-applier', *QUADLET_APPS])
    assert all(inspected.count(name) == 2 for name in set(inspected))
    assert not any(c[0] in ('podman-compose',) or c[:2] == ['docker', 'compose'] for c in fake.calls)
    assert fake.calls[-1] == [engine, 'exec', 'systemd-switchyard-applier', 'python', '-m', 'applier.apply',
                              '--doctor']
    out = capsys.readouterr().out
    assert out.startswith('PASS namespace membership of the applier and every named application')
    assert "configuration and secret files aren't checked" in out


def test_the_doctor_without_compose_from_the_command_line(tmp_path, monkeypatch, capsys):
    host, fake = quadlet_engine(tmp_path)
    original = host_tools.Host
    seen = {}

    def make(*args, **kwargs):
        seen.update(kwargs)
        return host
    monkeypatch.setattr(host_tools, 'Host', make)
    argv = ['doctor', '--kind', 'sidecar', '--engine', 'podman', '--gluetun', 'systemd-gluetun',
            '--applier', 'systemd-switchyard-applier', '--apps', 'downloader,indexer']
    assert host_tools.main(argv) == 0 and seen == {'engine': 'podman'}
    assert capsys.readouterr().out.startswith('PASS namespace membership')
    fake.restart_owner()
    assert host_tools.main(argv) == 1
    err = capsys.readouterr().err
    assert err == ("FAIL The applier container is not in gluetun's current network namespace; "
                   'restart gluetun, the applier and every application together.\n')
    monkeypatch.setattr(host_tools, 'Host', original)


@pytest.mark.parametrize('argv', [
    ['doctor', '--gluetun', 'g', '--applier', 'a', '--apps', 'x'],
    ['doctor', '--kind', 'sidecar', '--applier', 'a', '--apps', 'x'],
    ['doctor', '--kind', 'sidecar'],
    ['recover', '--kind', 'sidecar', '--gluetun', 'g', '--applier', 'a', '--apps', 'x'],
    ['doctor', '--probe-image', 'localhost/x:1'],
])
def test_the_doctor_without_compose_needs_its_containers(argv, capsys):
    assert host_tools.main([*argv, '--engine', 'podman']) == 1
    assert capsys.readouterr().err.startswith('FAIL Without Compose only the sidecar doctor runs')


@pytest.mark.parametrize('gluetun,applier,apps,message', [
    ('g', 'a', '', '^No applications declared: name the application containers with --apps'),
    ('g', 'a', ' , ', '^No applications declared'),
    ('g', 'a', 'x;id', 'take container names or IDs'),
    ('-g', 'a', 'x', 'take container names or IDs'),
    ('g', 'a', 'x,x', 'distinct containers'),
    ('g', 'a', 'g', 'distinct containers'),
    ('g', 'a', 'applier', 'distinct containers'),
])
def test_the_doctor_without_compose_refuses_bad_arguments(tmp_path, gluetun, applier, apps, message):
    calls = []
    host = host_tools.Host(tmp_path, run=lambda args, **kw: calls.append(args) or '', engine='podman')
    with pytest.raises(host_tools.CheckError, match=message):
        host.container_doctor(gluetun, applier, apps)
    assert calls == []


@pytest.mark.parametrize('fault,message', [
    (lambda f: f.restart_owner(), "^The applier container is not in gluetun's current network"),
    (lambda f: f.containers['indexer'].update(mode='container:' + cid(999)),
     "^The indexer container is not attached to gluetun's current container; restart gluetun, the applier and "
     'every application together.$'),
    (lambda f: f.containers['downloader'].update(running=False), '^The downloader container is not running'),
    (lambda f: f.containers.pop('indexer'), '^The indexer container is missing or cannot be inspected'),
    (lambda f: f.containers['gluetun'].update(ports={'8000/tcp': [{'HostIp': '', 'HostPort': '8000'}]}),
     '^The gluetun container publishes port 8000'),
    (lambda f: f.__setattr__('applier_output', [(1, APPLIER_UNVERIFIED.replace(
        'egress', 'egress - host-address-not-measurable, app_attachment-failed'))]),
     '^The applier reports: verified IVPN egress - host-address-not-measurable, app_attachment-failed'),
])
def test_the_doctor_without_compose_fails(tmp_path, fault, message):
    host, fake = quadlet_engine(tmp_path)
    fault(fake)
    with pytest.raises(host_tools.CheckError, match=message) as error:
        quadlet_doctor(host)
    assert SENTINEL not in str(error.value)


def test_the_doctor_without_compose_catches_a_restart_during_the_probes(tmp_path):
    host, fake = quadlet_engine(tmp_path)

    def restart(container):
        if container and container['service'] == 'indexer':
            container['started'] = container['started'].replace(':05:', ':07:')
    fake.on_probe = restart
    with pytest.raises(host_tools.CheckError, match='^A container restarted or was replaced during the check'):
        quadlet_doctor(host)


def test_the_probe_image_can_be_named(tmp_path):
    host, fake = quadlet_engine(tmp_path)
    quadlet_doctor(host, 'localhost/molebridge-wireguard:0.7.0')
    assert {c[c.index('--security-opt') + 2] for c in probes(fake)} == {'localhost/molebridge-wireguard:0.7.0'}
    assert not any(c[1] == 'build' for c in fake.calls)

    # A named image the engine doesn't have: the routing image from this checkout.
    host, fake = quadlet_engine(tmp_path)
    original = fake.__call__

    def run(args, **kwargs):
        if args[:3] == ['podman', 'image', 'inspect']:
            fake.calls.append(list(args))
            raise host_tools.CheckError('absent')
        return original(args, **kwargs)
    host.run = run
    quadlet_doctor(host, 'localhost/absent:1')
    assert {c[c.index('--security-opt') + 2] for c in probes(fake)} == {PROBE}
    assert [c for c in fake.calls if c[1] == 'build'] == [
        ['podman', 'build', '--tag', PROBE, '--file', str(ROOT / 'routing' / 'Dockerfile'), str(ROOT)]]
    with pytest.raises(host_tools.CheckError, match='image reference'):
        quadlet_doctor(host, 'bad image')


def test_applier_lines_with_reason_codes_are_read():
    for line in ('FAIL verified IVPN egress - host-address-not-measurable',
                 'FAIL verified NordVPN egress - egress-failed, app_attachment-failed, rejected'):
        assert host_tools.APPLIER_CHECK_LINE.fullmatch(line)

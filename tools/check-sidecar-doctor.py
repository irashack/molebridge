#!/usr/bin/env python3
"""The sidecar doctor's namespace checks and recovery against Docker, with a
stand-in namespace owner: a pinned busybox in gluetun's place, an applier
and an application that only sleep, and an application image with no shell
(pause). It runs tools/molebridge.py's own code, with the engine for real:

1. attachment: every member is in the owner's namespace (pass);
2. a same-ID restart of the owner (`docker restart`) leaves the members in
   the old namespace while the engine still records them as attached to the
   owner's ID: the doctor must fail;
3. recover recreates the owner and every member together: exit status 0
   and the check passes again; with a tunnel-tier provider, 3.

gluetun, the real applier's checks and the configuration checks are not part
of this; tools/test_sidecar_tools.py covers them. Builds the namespace probe
image from routing/Dockerfile. Needs Docker with Compose and network access
for the pinned images; removes its own project afterwards.

    python3 tools/check-sidecar-doctor.py
"""
import importlib.util
import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('host_tools', ROOT / 'tools' / 'molebridge.py')
host_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_tools)

BUSYBOX = ('docker.io/library/busybox:1.37.0@sha256:'
           'bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e')
# No shell, no readlink: only /pause.
PAUSE = 'registry.k8s.io/pause:3.10@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a'


def compose_file(project):
    sleeper = {'image': BUSYBOX, 'init': True, 'command': ['sleep', '2147483647']}
    member = dict(sleeper, network_mode='service:gluetun', depends_on={'gluetun': {'condition': 'service_started'}})
    return {'name': project, 'services': {
        'gluetun': dict(sleeper, container_name=f'{project}-gluetun'),
        'applier': dict(member, container_name=f'{project}-applier',
                        labels={host_tools.SIDECAR_APPS_LABEL: 'app,shell-less'},
                        environment={'EXIT_KIND': 'sidecar', 'TUNNEL_BACKEND': 'gluetun',
                                     'PROVIDER': 'gluetun-nordvpn'}),
        # Found through Compose's labels: no container_name.
        'app': member,
        'shell-less': {'image': PAUSE, 'network_mode': 'service:gluetun',
                       'depends_on': {'gluetun': {'condition': 'service_started'}}},
    }}


class StandIn(host_tools.Host):
    """The doctor and recover for the stand-in: the namespace checks and the
    Compose life cycle are tools/molebridge.py's own; the parts that need
    gluetun and the real applier are replaced."""
    tier = 'provider'

    def config(self):
        data = self.compose_config()
        self.loaded = data
        self.sidecar_apps(data)
        return data

    def check_sidecar_files(self):
        pass

    def applier_checks(self):
        # The stand-in applier "verifies" a provider-tier exit only.
        return [(True, 'recent applier check'), (self.tier == 'provider', 'verified stand-in egress')]

    def egress_tier(self, config):
        return self.tier


def expect_failure(host, config, message):
    try:
        host.sidecar_namespace_checks(config)
    except host_tools.CheckError as exc:
        if message not in str(exc):
            raise SystemExit(f'FAIL unexpected doctor failure: {exc}') from None
        return str(exc)
    raise SystemExit('FAIL the doctor passed a member left in the old namespace')


def main():
    project = 'mb-sidecar-check-' + secrets.token_hex(3)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'compose.yaml').write_text(json.dumps(compose_file(project), indent=2))
        (root / '.env').write_text('')
        host = StandIn(root, engine='docker')
        try:
            host.compose('up', '-d', '--wait', '--wait-timeout', '120', timeout=300, step='Starting the stand-in')
            config = host.config()

            host.sidecar_namespace_checks(config)
            print('PASS attachment: the applier and both applications share the owner\'s namespace')

            owner = host.inspect_container(config, 'gluetun')
            subprocess.run(['docker', 'restart', '--time', '1', owner.id], check=True, capture_output=True, timeout=60)
            restarted = host.inspect_container(config, 'gluetun')
            if restarted.id != owner.id or restarted.started == owner.started:
                raise SystemExit('FAIL docker restart did not keep the owner\'s ID with a new start')
            for service in ('applier', 'app', 'shell-less'):
                if host.inspect_container(config, service).network_mode != 'container:' + owner.id:
                    raise SystemExit('FAIL the engine no longer records the members as attached to the owner')
            message = expect_failure(host, config, "is not in gluetun's current network namespace")
            print(f'PASS same-ID owner restart: the doctor fails ({message})')

            status = host.recover()
            if status != 0:
                raise SystemExit(f'FAIL recover exited {status}, expected 0')
            config = host.config()
            if host.inspect_container(config, 'gluetun').id == owner.id:
                raise SystemExit('FAIL recover did not recreate the owner')
            host.sidecar_namespace_checks(config)
            print('PASS recovery: recreated together, exit status 0, and the doctor passes')

            host.tier = 'tunnel'
            status = host.recover()
            if status != 3:
                raise SystemExit(f'FAIL recover of a tunnel-tier stand-in exited {status}, expected 3')
            host.sidecar_namespace_checks(host.config())
            print('PASS recovery of a tunnel-tier stand-in: exit status 3 at once, and the doctor passes')
        except host_tools.CheckError as exc:
            raise SystemExit(f'FAIL {exc}') from None
        finally:
            subprocess.run(['docker', 'compose', 'down', '--timeout', '1', '--remove-orphans'], cwd=root,
                           capture_output=True, timeout=120, check=False)


if __name__ == '__main__':
    sys.exit(main())

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).parent / 'prepare-tunnel-config.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)

# Fictitious values: all-zero and all-one 32-byte keys, documentation addresses.
PRIVATE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
PUBLIC = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='

DOWNLOADED = f"""
[Interface]
# Device: Example Device
PrivateKey = {PRIVATE}
Address = 10.64.0.2/32,fc00:bbbb:bbbb:bb01::1:2/128
DNS = 10.64.0.1

[Peer]
PublicKey = {PUBLIC}
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 198.51.100.10:51820
"""


class PrepareTunnelConfigTests(unittest.TestCase):
    def test_rewrites_for_policy_routing(self):
        out = prepare.build_tunnel_conf(DOWNLOADED, table='51821')
        self.assertIn('Table = off', out)
        self.assertIn('MTU = 1420', out)
        self.assertNotIn('DNS', out)
        self.assertIn('ip route replace default dev %i table 51821; ip -6 route replace default dev %i table 51821', out)
        self.assertIn('Endpoint = 198.51.100.10:51820', out)
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', out)

    def test_ipv4_only_config_omits_ipv6_routes(self):
        out = prepare.build_tunnel_conf(DOWNLOADED.replace(',fc00:bbbb:bbbb:bb01::1:2/128', ''))
        self.assertNotIn('ip -6', out)
        self.assertIn('AllowedIPs = 0.0.0.0/0\n', out)

    def test_rejects_bad_key_and_endpoint(self):
        with self.assertRaises(prepare.ConfigError):
            prepare.build_tunnel_conf(DOWNLOADED.replace(PRIVATE, 'not-a-key'))
        with self.assertRaises(prepare.ConfigError):
            prepare.build_tunnel_conf(DOWNLOADED.replace('198.51.100.10:51820', 'se-sto-wg-001:51820'))

    def test_writes_mode_0600_without_printing_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'download.conf'
            src.write_text(DOWNLOADED)
            dest = Path(tmp) / 'wg_confs' / 'mullvad.conf'
            self.assertEqual(prepare.main(['prepare', str(src), str(dest)]), 0)
            self.assertEqual(stat.S_IMODE(os.stat(dest).st_mode), 0o600)
            self.assertIn(PRIVATE, dest.read_text())


if __name__ == '__main__':
    unittest.main()

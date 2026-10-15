"""受控隧道承载选择，不把业务数据报回显误作数据报承载证据。"""
import tempfile
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from macos_parallel import Tunnel, native_parallel
from macos_tunnel import client_config, native


class TransportTests(unittest.TestCase):
    def test_tunnel_constructor_uses_requested_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            with patch('macos_parallel.client_config',return_value='受控配置') as config,patch('macos_parallel.subprocess.Popen'):
                Tunnel(SimpleNamespace(openvpn='/openvpn',transport='udp'),folder,folder,0,{'port':12345},set())
            config.assert_called_once_with(folder/'0','udp')

    def configuration(self, transport):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            for name,kind in (('ca.crt','CERTIFICATE'),('client.crt','CERTIFICATE'),('client.key','PRIVATE KEY')):
                (folder/name).write_text(f'-----BEGIN {kind}-----\nYQ==\n-----END {kind}-----\n')
            return client_config(folder,transport)

    def test_udp_uses_explicit_ipv4_carrier(self):
        value=self.configuration('udp')
        self.assertIn('\nproto udp4\n',value)
        self.assertNotIn('tcp-client',value)
        self.assertIn('route-noexec',value)
        self.assertIn('script-security 1',value)

    def test_tcp_preserves_existing_carrier(self):
        self.assertIn('\nproto tcp-client\n',self.configuration('tcp'))

    def test_invalid_transport_rejected_before_reading_credentials(self):
        with self.assertRaises(ValueError):
            client_config(Path('/nonexistent'),'udp\nscript-security 3')

    def test_single_native_transport_mismatch_precedes_network_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            (folder/'endpoint.json').write_text(json.dumps({'port':12345,'transport':'tcp'}))
            options=SimpleNamespace(bundle=str(folder),transport='udp',openvpn='/openvpn')
            with patch('macos_tunnel.preflight',return_value={'status':'passed'}),patch('macos_tunnel.baseline') as baseline:
                with self.assertRaisesRegex(RuntimeError,'承载'):
                    native(options)
            baseline.assert_not_called()

    def test_parallel_native_transport_mismatch_precedes_network_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            (folder/'endpoints.json').write_text(json.dumps([
                {'port':12345+i,'transport':'tcp','identity':str(i)*32} for i in range(3)]))
            options=SimpleNamespace(bundle=str(folder),transport='udp',case='parallel',openvpn='/openvpn')
            with patch('macos_parallel.preflight',return_value={'status':'passed'}),patch('macos_parallel.baseline') as baseline:
                with self.assertRaisesRegex(RuntimeError,'参数'):
                    native_parallel(options)
            baseline.assert_not_called()


if __name__=='__main__':unittest.main()

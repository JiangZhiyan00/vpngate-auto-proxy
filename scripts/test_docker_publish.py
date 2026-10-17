import unittest
from unittest.mock import patch
import prepare_docker_publish
from prepare_docker_publish import validate_release


class ReleaseTests(unittest.TestCase):
    def test_dirty_source_is_rejected_before_freezing_or_building(self):
        with patch('sys.argv', ['prepare_docker_publish.py', '--tag', 'v1.0.0', '--image', 'example/proxy']), \
                patch.object(prepare_docker_publish.subprocess, 'check_output', return_value=' M src/service.rs\n'), \
                patch.object(prepare_docker_publish, 'build_inputs') as freeze, \
                patch.object(prepare_docker_publish, 'run') as run:
            with self.assertRaises(RuntimeError):
                prepare_docker_publish.main()
            freeze.assert_not_called()
            run.assert_not_called()

    def test_host_installer_and_policy_are_frozen_inputs(self):
        frozen = prepare_docker_publish.build_inputs()
        for name in ('scripts/host-init.py', 'scripts/package_host_init.py', 'deploy/apparmor/vpngate-auto-proxy'):
            self.assertRegex(frozen[name], r'^[0-9a-f]{64}$')

    def test_program_bytes_select_actual_vap_product(self):
        with patch.object(prepare_docker_publish.subprocess, 'check_output', return_value=b'product') as command:
            self.assertEqual(prepare_docker_publish.program_bytes('example/proxy:v1.0.0'), b'product')
        self.assertEqual(command.call_args.args[0][-1], '/usr/local/bin/vap')

    def test_hub_repository_preserves_legal_names(self):
        for image in ['example/proxy.test', 'example/proxy_test', 'team-name/proxy-name',
                      'team_name/proxy', 'localhost-team/proxy', 'ghcr/proxy']:
            with self.subTest(image=image):
                self.assertEqual(validate_release('v12.34.56', image), image + ':v12.34.56')

    def test_registry_domains_and_explicit_hosts_are_rejected(self):
        for image in ['ghcr.io/proxy', 'localhost/proxy', 'docker.io/proxy',
                      'index.docker.io/proxy', 'registry.example/proxy', '127.0.0.1/proxy',
                      'localhost:5000/proxy', 'example:5000/proxy', 'docker.io/example/proxy',
                      'https://docker.io/example/proxy']:
            with self.subTest(image=image), self.assertRaises(ValueError):
                validate_release('v1.0.0', image)

    def test_invalid_repository_names_are_rejected(self):
        for image in ['', '/proxy', 'example/', 'example//proxy', 'example/Proxy',
                      '-example/proxy', 'example-/proxy', 'example/.proxy', 'example/proxy-',
                      'example/proxy:latest', 'example/proxy@sha256:' + 'a' * 64,
                      'example/proxy\n', ' example/proxy', 'example/proxy;id']:
            with self.subTest(image=image), self.assertRaises(ValueError):
                validate_release('v1.0.0', image)

    def test_invalid_target_fails_before_build_or_source_freezing(self):
        for image in ['ghcr.io/proxy', 'localhost/proxy']:
            with self.subTest(image=image), patch('sys.argv', ['prepare_docker_publish.py',
                    '--tag', 'v1.0.0', '--image', image]), \
                    patch.object(prepare_docker_publish, 'build_inputs') as freeze, \
                    patch.object(prepare_docker_publish.Path, 'mkdir',
                                 side_effect=AssertionError('非法目标不得创建输出目录')) as mkdir, \
                    patch.object(prepare_docker_publish, 'run') as run:
                with self.assertRaises(ValueError):
                    prepare_docker_publish.main()
                freeze.assert_not_called()
                mkdir.assert_not_called()
                run.assert_not_called()

    def test_stable_version_and_repository(self):
        self.assertEqual(validate_release('v1.0.0', 'example/vpngate-auto-proxy'),
                         'example/vpngate-auto-proxy:v1.0.0')
        for tag in ['1.0.0', 'v01.0.0', 'v1.0', 'v1.0.0-rc1', 'v1.0.0\n', 'v1.0.0;id']:
            with self.assertRaises(ValueError):
                validate_release(tag, 'example/vpngate-auto-proxy')
        for image in ['Example/proxy', 'example', 'example/proxy:latest', 'example/proxy;id', 'example/proxy\n']:
            with self.assertRaises(ValueError):
                validate_release('v1.0.0', image)


class TimezoneEvidenceTests(unittest.TestCase):
    def test_nanosecond_log_offsets_follow_named_zone(self):
        from validate_docker import validate_event_timezone
        validate_event_timezone([{"timestamp": "2026-07-15T08:00:00.123456789-04:00"},
                                 {"timestamp": "2026-01-15T07:00:00.123456789-05:00"}], "America/New_York")
        for events in [[], [{"timestamp": "2026-07-15T20:00:00.123456789+08:00"}]]:
            with self.assertRaises(RuntimeError):
                validate_event_timezone(events, "America/New_York")

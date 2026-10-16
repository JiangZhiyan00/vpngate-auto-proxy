"""防漏证据判定必须同时满足正对照、零丢包及无负向标记。"""
import unittest
import sys
import struct
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import Mock

from macos_fault import CaptureValidationError, inspect_capture, wait_capture_marker


class CaptureReadinessTests(unittest.TestCase):
    def test_header_only_capture_blocks_fault_phase(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "capture.pcap"
            path.write_bytes(b"header-only")
            with self.assertRaisesRegex(RuntimeError, "正对照.*未被抓包记录"):
                wait_capture_marker(Mock(poll=Mock(return_value=None)), path, "control", timeout=0.02)

    def test_waits_until_both_protocol_markers_arrive(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "capture.pcap"
            path.write_bytes(b"control-tcp")
            timer = threading.Timer(0.02, lambda: path.write_bytes(b"control-tcp control-udp"))
            timer.start()
            try:
                wait_capture_marker(Mock(poll=Mock(return_value=None)), path, "control", timeout=1)
            finally:
                timer.join()

    def test_early_capture_exit_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(RuntimeError, "提前退出"):
                wait_capture_marker(Mock(poll=Mock(return_value=0)), Path(folder) / "missing", "control")


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.positive = "positive-control"
        self.negative = ["scoped-before", "scoped-after"]
        self.header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 262144, 0)
        self.content = self.capture([b"positive-control-tcp", b"positive-control-udp"])
        self.stats = "2 packets captured\n0 packets dropped by kernel\n"

    def capture(self, packets):
        return self.header + b"".join(struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet for packet in packets)

    def test_both_positive_controls_and_no_negative_marker(self):
        self.assertTrue(all(inspect_capture(self.content, self.stats, self.positive, self.negative).values()))

    def test_header_only_zero_packets_is_not_a_pass(self):
        with self.assertRaises(CaptureValidationError) as caught:
            inspect_capture(self.header, "0 packets captured\n0 packets dropped by kernel", self.positive, self.negative)
        self.assertFalse(caught.exception.checks["capture_positive_tcp"])
        self.assertFalse(caught.exception.checks["capture_positive_udp"])

    def test_missing_tcp_or_udp_control_rejected(self):
        for protocol in (b"tcp", b"udp"):
            with self.assertRaises(CaptureValidationError) as caught:
                inspect_capture(self.content.replace(b"positive-control-" + protocol, b"missing".ljust(20, b"-")),
                                self.stats, self.positive, self.negative)
            self.assertFalse(caught.exception.checks["capture_positive_" + protocol.decode()])
            self.assertTrue(caught.exception.checks["no_scoped_management_payload"])

    def test_scoped_payload_rejected_before_or_after_deletion(self):
        for marker in self.negative:
            with self.assertRaises(CaptureValidationError) as caught:
                inspect_capture(self.capture([b"positive-control-tcp", b"positive-control-udp" + marker.encode()]),
                                self.stats, self.positive, self.negative)
            self.assertFalse(caught.exception.checks["no_scoped_management_payload"])
            self.assertTrue(caught.exception.checks["capture_positive_tcp"])
            self.assertTrue(caught.exception.checks["capture_positive_udp"])

    def test_dropped_or_missing_statistics_rejected(self):
        for statistics in ("", "1 packets dropped by kernel"):
            with self.assertRaises(RuntimeError):
                inspect_capture(self.content, statistics, self.positive, self.negative)

    def test_empty_or_unknown_capture_format_rejected(self):
        for content in (b"", self.content[4:]):
            with self.assertRaises(RuntimeError):
                inspect_capture(content, self.stats, self.positive, self.negative)

    def test_incomplete_capture_or_statistics_mismatch_rejected(self):
        for content, stats in ((self.content[:-1], self.stats), (self.content, "3 packets captured\n0 packets dropped by kernel")):
            with self.assertRaises(RuntimeError):
                inspect_capture(content, stats, self.positive, self.negative)


@unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的实验私有目录")
class DiagnosticTests(unittest.TestCase):
    setUp = CaptureTests.setUp
    capture = CaptureTests.capture
    def diagnose(self, negative_packet=False, ownership=False):
        module_spec = importlib.util.spec_from_file_location("diagnose", Path(__file__).with_name("diagnose-macos-fault.py"))
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        positive, negative = "a" * 40, ["b" * 40, "c" * 40]
        packets = [(positive + "-tcp").encode(), (positive + "-udp").encode()]
        if negative_packet:
            packets.append((negative[0] + "-udp").encode())
        with tempfile.TemporaryDirectory(prefix="vap-parallel-", dir="/private/tmp") as name:
            folder = Path(name)
            (folder / "management.pcap").write_bytes(self.capture(packets))
            (folder / "capture.log").write_text(f"{len(packets)} packets captured\n0 packets dropped by kernel\n")
            if ownership:
                (folder / "fault-markers.json").write_text(json.dumps({"positive": positive, "negative": negative}))
            before = {f.name: f.read_bytes() for f in folder.iterdir()}
            result = module.diagnose(folder)
            self.assertEqual(before, {f.name: f.read_bytes() for f in folder.iterdir()})
            return result

    def test_legacy_diagnostic_is_read_only_and_reports_missing_ownership(self):
        report = self.diagnose()
        self.assertFalse(report["marker_ownership_available"])
        self.assertEqual(len(report["marker_groups"]), 1)
        self.assertEqual(report["marker_groups"][0]["tcp_packets"], 1)
        self.assertEqual(report["marker_groups"][0]["udp_packets"], 1)
        self.assertNotIn("a" * 40, json.dumps(report))
        self.assertNotIn("checks", report)

    def test_saved_ownership_identifies_actual_leak(self):
        report = self.diagnose(negative_packet=True, ownership=True)
        self.assertTrue(report["marker_ownership_available"])
        self.assertFalse(report["checks"]["no_scoped_management_payload"])

    def test_saved_ownership_identifies_success(self):
        report = self.diagnose(ownership=True)
        self.assertTrue(all(report["checks"].values()))


if __name__ == "__main__":
    unittest.main()

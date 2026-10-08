"""Tests for displaying and appending detection alerts."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from alerts.alert_manager import AlertManager


class AlertManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.log_file = Path(self.temp_directory.name) / "logs" / "nids.log"
        self.manager = AlertManager(log_file=self.log_file)
        self.detection = {
            "detected": True,
            "type": "TCP_SYN",
            "severity": "LOW",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 50000,
            "destination_port": 443,
            "message": "TCP SYN traffic detected",
        }

    def test_valid_detection_is_displayed_and_logged(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            saved = self.manager.handle_detection(self.detection, event_id="packet-1")

        content = self.log_file.read_text(encoding="utf-8")
        self.assertTrue(saved)
        self.assertIn("[DETECTION ALERT]", output.getvalue())
        self.assertIn("Detection Type   : TCP_SYN", content)
        self.assertIn("Timestamp        :", content)
        self.assertEqual(self.manager.total_detections, 1)
        self.assertEqual(self.manager.severity_counts["LOW"], 1)

    def test_normal_result_does_not_create_alert(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            saved = self.manager.handle_detection({"detected": False, "type": "NORMAL"})

        self.assertFalse(saved)
        self.assertEqual(output.getvalue(), "")
        self.assertFalse(self.log_file.exists())

    def test_missing_fields_use_na(self):
        with contextlib.redirect_stdout(io.StringIO()):
            saved = self.manager.handle_detection({"detected": True})

        content = self.log_file.read_text(encoding="utf-8")
        self.assertTrue(saved)
        self.assertIn("Source IP        : N/A", content)
        self.assertIn("Source Port      : N/A", content)
        self.assertIn("Message          : N/A", content)

    def test_multiple_alerts_append_to_same_file(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(
                self.manager.handle_detection(self.detection, event_id="packet-1")
            )
            self.assertTrue(
                self.manager.handle_detection(self.detection, event_id="packet-2")
            )

        content = self.log_file.read_text(encoding="utf-8")
        self.assertEqual(content.count("[DETECTION ALERT]"), 2)

    def test_duplicate_event_id_is_not_counted_or_logged_twice(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            first_result = self.manager.handle_detection(self.detection, event_id="same")
            duplicate_result = self.manager.handle_detection(
                self.detection, event_id="same"
            )

        content = self.log_file.read_text(encoding="utf-8")
        self.assertTrue(first_result)
        self.assertFalse(duplicate_result)
        self.assertEqual(content.count("[DETECTION ALERT]"), 1)
        self.assertEqual(output.getvalue().count("[DETECTION ALERT]"), 1)
        self.assertEqual(self.manager.total_detections, 1)

    def test_severity_and_detection_type_counters(self):
        results = [
            {**self.detection, "severity": "LOW", "type": "MONITORED_PORT"},
            {**self.detection, "severity": "MEDIUM", "type": "POSSIBLE_PORT_SCAN"},
            {**self.detection, "severity": "HIGH", "type": "POSSIBLE_DOS"},
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            for index, result in enumerate(results):
                self.manager.handle_detection(result, event_id=f"event-{index}")

        self.assertEqual(self.manager.total_detections, 3)
        self.assertEqual(
            self.manager.severity_counts, {"LOW": 1, "MEDIUM": 1, "HIGH": 1}
        )
        self.assertEqual(self.manager.port_scan_detections, 1)
        self.assertEqual(self.manager.dos_detections, 1)

    def test_packet_counter_and_session_summary(self):
        self.manager.record_packet()
        self.manager.record_packet()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.manager.print_summary()

        summary = output.getvalue()
        self.assertEqual(self.manager.packets_processed, 2)
        self.assertIn("Monitoring Status : Stopped", summary)
        self.assertIn("Packets Processed : 2", summary)
        self.assertIn(f"Log File          : {self.log_file}", summary)

    def test_log_directory_is_created_automatically(self):
        self.assertFalse(self.log_file.parent.exists())

        with contextlib.redirect_stdout(io.StringIO()):
            saved = self.manager.handle_detection(self.detection)

        self.assertTrue(saved)
        self.assertTrue(self.log_file.is_file())

    def test_invalid_result_reports_clear_error(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            saved = self.manager.handle_detection({"type": "TCP_SYN"})

        self.assertFalse(saved)
        self.assertIn("Alert error:", output.getvalue())
        self.assertFalse(self.log_file.exists())


if __name__ == "__main__":
    unittest.main()

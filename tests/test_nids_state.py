"""Tests for shared, thread-safe NIDS session state."""

import unittest
from concurrent.futures import ThreadPoolExecutor

from core.nids_state import NidsState


class NidsStateTests(unittest.TestCase):
    def setUp(self):
        self.state = NidsState()
        self.detection = {
            "detected": True,
            "type": "POSSIBLE_DOS",
            "severity": "HIGH",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 50000,
            "destination_port": 443,
            "message": "Possible high-rate traffic indicator.",
        }

    def test_initial_state(self):
        self.assertEqual(self.state.get_status(), "stopped")
        self.assertEqual(
            self.state.get_statistics(),
            {
                "packets": 0,
                "detections": 0,
                "low": 0,
                "medium": 0,
                "high": 0,
                "port_scans": 0,
                "dos_alerts": 0,
            },
        )
        self.assertEqual(self.state.get_recent_alerts(), [])

    def test_status_only_accepts_running_or_stopped(self):
        self.state.set_status("running")
        self.assertEqual(self.state.get_status(), "running")

        with self.assertRaises(ValueError):
            self.state.set_status("unknown")

    def test_packet_counter_increments(self):
        self.state.record_packet()
        self.state.record_packet()

        self.assertEqual(self.state.get_statistics()["packets"], 2)

    def test_logged_detection_counter_only_counts_successful_log_writes(self):
        self.state.record_logged_detection()

        self.assertEqual(self.state.get_logged_detection_count(), 1)

    def test_detection_and_severity_counters_increment(self):
        self.state.record_detection(
            {**self.detection, "severity": "LOW", "type": "MONITORED_PORT"},
            "2026-01-01T00:00:00+00:00",
        )
        self.state.record_detection(
            {**self.detection, "severity": "MEDIUM", "type": "POSSIBLE_PORT_SCAN"},
            "2026-01-01T00:00:01+00:00",
        )
        self.state.record_detection(
            self.detection,
            "2026-01-01T00:00:02+00:00",
        )

        self.assertEqual(
            self.state.get_statistics(),
            {
                "packets": 0,
                "detections": 3,
                "low": 1,
                "medium": 1,
                "high": 1,
                "port_scans": 1,
                "dos_alerts": 1,
            },
        )

    def test_alert_storage_is_newest_first(self):
        self.state.record_detection(
            self.detection, "2026-01-01T00:00:00+00:00", event_id="first"
        )
        self.state.record_detection(
            self.detection, "2026-01-01T00:00:01+00:00", event_id="second"
        )

        alerts = self.state.get_recent_alerts()
        self.assertEqual(alerts[0]["timestamp"], "2026-01-01T00:00:01+00:00")
        self.assertEqual(alerts[1]["timestamp"], "2026-01-01T00:00:00+00:00")

    def test_recent_alert_limit_discards_oldest_entries(self):
        state = NidsState(recent_alert_limit=3)
        for index in range(5):
            state.record_detection(
                self.detection,
                f"2026-01-01T00:00:0{index}+00:00",
                event_id=index,
            )

        alerts = state.get_recent_alerts()
        self.assertEqual(len(alerts), 3)
        self.assertEqual(alerts[0]["timestamp"], "2026-01-01T00:00:04+00:00")
        self.assertEqual(alerts[-1]["timestamp"], "2026-01-01T00:00:02+00:00")

    def test_duplicate_event_id_is_counted_once(self):
        timestamp = "2026-01-01T00:00:00+00:00"

        first = self.state.record_detection(self.detection, timestamp, event_id="same")
        duplicate = self.state.record_detection(self.detection, timestamp, event_id="same")

        self.assertTrue(first)
        self.assertFalse(duplicate)
        self.assertEqual(self.state.get_statistics()["detections"], 1)
        self.assertEqual(len(self.state.get_recent_alerts()), 1)

    def test_concurrent_packet_updates_are_thread_safe(self):
        packet_count = 2000
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(lambda _: self.state.record_packet(), range(packet_count)))

        self.assertEqual(self.state.get_statistics()["packets"], packet_count)


if __name__ == "__main__":
    unittest.main()

"""Tests for per-source packet-rate and port-scan behavior analysis."""

import unittest

from detection.behavior_analyzer import BehaviorAnalyzer


def packet_info(source_ip="192.0.2.10", protocol="UDP", destination_port=None, flags=None):
    """Build structured input resembling the packet analyzer's output."""
    return {
        "source_ip": source_ip,
        "destination_ip": "198.51.100.20",
        "protocol": protocol,
        "source_port": 50000,
        "destination_port": destination_port,
        "tcp_flags": flags,
    }


class BehaviorAnalyzerTests(unittest.TestCase):
    def test_normal_rate_below_threshold(self):
        analyzer = BehaviorAnalyzer(dos_packet_threshold=3, enabled=True)

        results = [
            analyzer.analyze(packet_info(), now=timestamp)
            for timestamp in (0, 1, 2)
        ]

        self.assertTrue(all(not result for result in results))

    def test_rate_exactly_at_threshold_does_not_trigger(self):
        analyzer = BehaviorAnalyzer(dos_packet_threshold=3, enabled=True)

        for timestamp in (0, 1, 2):
            results = analyzer.analyze(packet_info(), now=timestamp)

        self.assertEqual(results, [])
        self.assertEqual(len(analyzer._packet_times["192.0.2.10"]), 3)

    def test_rate_above_threshold_triggers_possible_dos(self):
        analyzer = BehaviorAnalyzer(dos_packet_threshold=3, enabled=True)

        for timestamp in (0, 1, 2):
            analyzer.analyze(packet_info(), now=timestamp)
        results = analyzer.analyze(packet_info(), now=3)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "POSSIBLE_DOS")
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertEqual(results[0]["packet_count"], 4)
        self.assertEqual(results[0]["time_window"], 10)
        self.assertIn("not proof", results[0]["message"])

    def test_source_addresses_are_counted_independently(self):
        analyzer = BehaviorAnalyzer(dos_packet_threshold=2, enabled=True)

        analyzer.analyze(packet_info("192.0.2.10"), now=0)
        analyzer.analyze(packet_info("192.0.2.20"), now=1)
        analyzer.analyze(packet_info("192.0.2.10"), now=2)
        results = analyzer.analyze(packet_info("192.0.2.10"), now=3)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["source_ip"], "192.0.2.10")
        self.assertEqual(len(analyzer._packet_times["192.0.2.20"]), 1)

    def test_packets_outside_window_are_not_counted(self):
        analyzer = BehaviorAnalyzer(
            dos_packet_threshold=2,
            dos_time_window=5,
            enabled=True,
        )

        analyzer.analyze(packet_info(), now=0)
        analyzer.analyze(packet_info(), now=1)
        results = analyzer.analyze(packet_info(), now=6)

        self.assertEqual(results, [])
        self.assertEqual(len(analyzer._packet_times["192.0.2.10"]), 2)

    def test_expired_source_state_is_cleaned(self):
        analyzer = BehaviorAnalyzer(
            dos_packet_threshold=100,
            dos_time_window=5,
            enabled=True,
        )

        analyzer.analyze(packet_info("192.0.2.10"), now=0)
        analyzer.analyze(packet_info("192.0.2.20"), now=10)

        self.assertNotIn("192.0.2.10", analyzer._packet_times)

    def test_dos_cooldown_suppresses_repeated_alerts(self):
        analyzer = BehaviorAnalyzer(
            dos_packet_threshold=1,
            dos_time_window=20,
            dos_alert_cooldown=5,
            enabled=True,
        )

        self.assertEqual(analyzer.analyze(packet_info(), now=0), [])
        first_alert = analyzer.analyze(packet_info(), now=1)
        repeated = analyzer.analyze(packet_info(), now=2)
        after_cooldown = analyzer.analyze(packet_info(), now=6)

        self.assertEqual(first_alert[0]["type"], "POSSIBLE_DOS")
        self.assertEqual(repeated, [])
        self.assertEqual(after_cooldown[0]["type"], "POSSIBLE_DOS")

    def test_port_scan_detection_is_preserved(self):
        analyzer = BehaviorAnalyzer(
            dos_packet_threshold=100,
            port_scan_threshold=2,
            enabled=True,
        )

        results = []
        for timestamp, port in enumerate((22, 80, 443)):
            results.extend(
                analyzer.analyze(
                    packet_info(protocol="TCP", destination_port=port, flags="S"),
                    now=timestamp,
                )
            )

        self.assertEqual([result["type"] for result in results], ["POSSIBLE_PORT_SCAN"])
        self.assertEqual(results[0]["source_ip"], "192.0.2.10")

    def test_dos_and_port_scan_tracking_are_independent(self):
        flood_analyzer = BehaviorAnalyzer(
            dos_packet_threshold=1,
            dos_time_window=10,
            port_scan_threshold=100,
            enabled=True,
        )
        flood_analyzer.analyze(packet_info(), now=0)
        dos_results = flood_analyzer.analyze(packet_info(), now=1)
        self.assertEqual([result["type"] for result in dos_results], ["POSSIBLE_DOS"])
        self.assertFalse(flood_analyzer._scan_ports)

        scan_analyzer = BehaviorAnalyzer(
            dos_packet_threshold=100,
            port_scan_threshold=1,
            enabled=True,
        )
        scan_analyzer.analyze(
            packet_info(protocol="TCP", destination_port=22, flags="S"), now=0
        )
        scan_results = scan_analyzer.analyze(
            packet_info(protocol="TCP", destination_port=80, flags="S"), now=1
        )
        self.assertEqual(
            [result["type"] for result in scan_results], ["POSSIBLE_PORT_SCAN"]
        )
        self.assertNotIn("192.0.2.10", scan_analyzer._dos_last_alert)


if __name__ == "__main__":
    unittest.main()

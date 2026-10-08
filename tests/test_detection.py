"""Tests for the basic rule-based detection indicators."""

import unittest

from scapy.all import ICMP, IP, TCP, UDP

from analysis.packet_analyzer import analyze_packet
from detection.rules import DetectionEngine


class DetectionEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine(
            monitored_ports=[22, 53],
            destination_port_threshold=1024,
            enabled=True,
        )

    def test_normal_tcp_packet(self):
        packet = IP() / TCP(sport=50000, dport=1000, flags="A")
        result = self.engine.analyze(analyze_packet(packet))

        self.assertFalse(result["detected"])
        self.assertEqual(result["type"], "NORMAL")
        self.assertEqual(result["severity"], "NONE")

    def test_tcp_syn_packet(self):
        packet = IP() / TCP(sport=50000, dport=9000, flags="S")
        result = self.engine.analyze(analyze_packet(packet))

        self.assertTrue(result["detected"])
        self.assertEqual(result["type"], "TCP_SYN")
        self.assertEqual(result["severity"], "LOW")

    def test_udp_packet_to_monitored_port(self):
        packet = IP() / UDP(sport=50000, dport=53)
        result = self.engine.analyze(analyze_packet(packet))

        self.assertEqual(result["type"], "MONITORED_PORT")
        self.assertEqual(result["destination_port"], 53)

    def test_icmp_packet(self):
        packet = IP() / ICMP()
        result = self.engine.analyze(analyze_packet(packet))

        self.assertEqual(result["type"], "ICMP_TRAFFIC")
        self.assertEqual(result["severity"], "LOW")

    def test_high_destination_port(self):
        packet = IP() / UDP(sport=50000, dport=50000)
        result = self.engine.analyze(analyze_packet(packet))

        self.assertEqual(result["type"], "HIGH_PORT_TRAFFIC")

    def test_missing_port_information(self):
        packet_info = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "protocol": "TCP",
            "source_port": None,
            "destination_port": None,
            "tcp_flags": None,
        }
        result = self.engine.analyze(packet_info)

        self.assertFalse(result["detected"])
        self.assertEqual(result["type"], "NORMAL")
        self.assertIsNone(result["destination_port"])


if __name__ == "__main__":
    unittest.main()

"""Tests for extracting basic details from Scapy packets."""

import unittest

from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

from analysis.packet_analyzer import analyze_packet


class PacketAnalyzerTests(unittest.TestCase):
    def test_tcp_packet(self):
        packet = IP(src="192.0.2.1", dst="198.51.100.2", ttl=64) / TCP(
            sport=12345, dport=80, flags="S"
        )

        result = analyze_packet(packet)

        self.assertEqual(result["source_ip"], "192.0.2.1")
        self.assertEqual(result["destination_ip"], "198.51.100.2")
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["source_port"], 12345)
        self.assertEqual(result["destination_port"], 80)
        self.assertEqual(result["ttl"], 64)
        self.assertEqual(result["tcp_flags"], "S")

    def test_udp_packet(self):
        packet = IP() / UDP(sport=53000, dport=53)

        result = analyze_packet(packet)

        self.assertEqual(result["protocol"], "UDP")
        self.assertEqual(result["source_port"], 53000)
        self.assertEqual(result["destination_port"], 53)

    def test_icmp_packet(self):
        packet = IP() / ICMP(type=8, code=0)

        result = analyze_packet(packet)

        self.assertEqual(result["protocol"], "ICMP")
        self.assertEqual(result["icmp_type"], 8)
        self.assertEqual(result["icmp_code"], 0)
        self.assertIsNone(result["source_port"])

    def test_non_ip_packet(self):
        packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / Raw(
            load=b"test"
        )

        result = analyze_packet(packet)

        self.assertEqual(result["protocol"], "Non-IP")
        self.assertIsNone(result["source_ip"])
        self.assertIsNone(result["destination_ip"])
        self.assertIsNone(result["ttl"])

    def test_other_ip_protocol(self):
        packet = IP(proto=47)

        result = analyze_packet(packet)

        self.assertEqual(result["protocol"], "Other IP (47)")
        self.assertIsNone(result["source_port"])
        self.assertIsNone(result["destination_port"])


if __name__ == "__main__":
    unittest.main()

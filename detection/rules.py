"""Basic, rule-based indicators for analyzed network packets."""

from config.settings import (
    DETECTION_ENABLED,
    DESTINATION_PORT_THRESHOLD,
    MONITORED_PORTS,
)


class DetectionEngine:
    """Check analyzed packet details against simple configurable rules."""

    def __init__(
        self,
        monitored_ports=None,
        destination_port_threshold=None,
        enabled=None,
    ):
        self.monitored_ports = (
            set(MONITORED_PORTS) if monitored_ports is None else set(monitored_ports)
        )
        self.destination_port_threshold = (
            DESTINATION_PORT_THRESHOLD
            if destination_port_threshold is None
            else destination_port_threshold
        )
        self.enabled = DETECTION_ENABLED if enabled is None else enabled

    def analyze(self, packet_info):
        """Return one structured indicator result for an analyzed packet.

        These rules identify traffic for review; they do not determine that an
        attack has occurred. If multiple rules match, the first matching rule
        in the checks below is returned.
        """
        result = {
            "detected": False,
            "type": "NORMAL",
            "severity": "NONE",
            "message": "No suspicious rule matched",
            "source_ip": packet_info.get("source_ip"),
            "destination_ip": packet_info.get("destination_ip"),
            "source_port": packet_info.get("source_port"),
            "destination_port": packet_info.get("destination_port"),
        }

        if not self.enabled:
            return result

        protocol = packet_info.get("protocol")
        destination_port = packet_info.get("destination_port")
        tcp_flags = packet_info.get("tcp_flags")

        if protocol == "ICMP":
            return self._make_detection(result, "ICMP_TRAFFIC", "ICMP traffic detected")

        if protocol == "TCP" and tcp_flags is not None and "S" in str(tcp_flags):
            return self._make_detection(result, "TCP_SYN", "TCP SYN traffic detected")

        if destination_port in self.monitored_ports:
            return self._make_detection(
                result,
                "MONITORED_PORT",
                "Traffic detected on a monitored destination port",
            )

        try:
            is_high_port = (
                destination_port is not None
                and int(destination_port) > self.destination_port_threshold
            )
        except (TypeError, ValueError):
            is_high_port = False

        if is_high_port:
            return self._make_detection(
                result,
                "HIGH_PORT_TRAFFIC",
                "Traffic detected on a high destination port",
            )

        return result

    @staticmethod
    def _make_detection(result, detection_type, message):
        """Mark a result as a low-severity traffic indicator."""
        result.update(
            {
                "detected": True,
                "type": detection_type,
                "severity": "LOW",
                "message": message,
            }
        )
        return result


def display_detection(result):
    """Print a detection indicator without producing output for normal traffic."""
    if not result["detected"]:
        return

    print("\n[DETECTION]")
    print(f"Type     : {result['type']}")
    print(f"Severity : {result['severity']}")
    print(f"Source   : {result['source_ip'] or 'N/A'}")
    print(f"Target   : {result['destination_ip'] or 'N/A'}")
    if result["destination_port"] is not None:
        print(f"Port     : {result['destination_port']}")
    print(f"Message  : {result['message']}")

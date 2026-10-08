"""Track per-source traffic rates for basic behavioral indicators."""

from collections import defaultdict, deque
from time import monotonic

from config.settings import (
    DETECTION_ENABLED,
    DOS_ALERT_COOLDOWN,
    DOS_PACKET_THRESHOLD,
    DOS_TIME_WINDOW,
    PORT_SCAN_ALERT_COOLDOWN,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW,
)


class BehaviorAnalyzer:
    """Detect possible high packet rates and TCP port scans per source IP."""

    def __init__(
        self,
        dos_packet_threshold=None,
        dos_time_window=None,
        dos_alert_cooldown=None,
        port_scan_threshold=None,
        port_scan_time_window=None,
        port_scan_alert_cooldown=None,
        enabled=None,
    ):
        self.dos_packet_threshold = (
            DOS_PACKET_THRESHOLD
            if dos_packet_threshold is None
            else dos_packet_threshold
        )
        self.dos_time_window = DOS_TIME_WINDOW if dos_time_window is None else dos_time_window
        self.dos_alert_cooldown = (
            DOS_ALERT_COOLDOWN
            if dos_alert_cooldown is None
            else dos_alert_cooldown
        )
        self.port_scan_threshold = (
            PORT_SCAN_THRESHOLD
            if port_scan_threshold is None
            else port_scan_threshold
        )
        self.port_scan_time_window = (
            PORT_SCAN_TIME_WINDOW
            if port_scan_time_window is None
            else port_scan_time_window
        )
        self.port_scan_alert_cooldown = (
            PORT_SCAN_ALERT_COOLDOWN
            if port_scan_alert_cooldown is None
            else port_scan_alert_cooldown
        )
        self.enabled = DETECTION_ENABLED if enabled is None else enabled

        # Keep port scan and packet-rate state separate.
        self._packet_times = defaultdict(deque)
        self._scan_ports = defaultdict(deque)
        self._dos_last_alert = {}
        self._port_scan_last_alert = {}

    def analyze(self, packet_info, now=None):
        """Return zero or more behavioral indicators for one analyzed packet.

        ``now`` is an optional monotonic timestamp, useful for deterministic
        tests. Production callers can omit it.
        """
        if not self.enabled or not isinstance(packet_info, dict):
            return []

        source_ip = packet_info.get("source_ip")
        if not source_ip:
            return []

        current_time = monotonic() if now is None else now
        self._clean_expired_state(current_time)
        results = []

        packet_times = self._packet_times[source_ip]
        packet_times.append(current_time)
        packet_count = len(packet_times)

        if (
            packet_count > self.dos_packet_threshold
            and self._cooldown_finished(
                self._dos_last_alert, source_ip, current_time, self.dos_alert_cooldown
            )
        ):
            self._dos_last_alert[source_ip] = current_time
            results.append(
                self._make_result(
                    packet_info,
                    detection_type="POSSIBLE_DOS",
                    severity="HIGH",
                    message=(
                        "Possible high-rate traffic indicator from source IP "
                        f"({packet_count} packets in {self.dos_time_window} seconds); "
                        "this is not proof of a DoS attack."
                    ),
                    packet_count=packet_count,
                    time_window=self.dos_time_window,
                )
            )

        destination_port = packet_info.get("destination_port")
        if (
            packet_info.get("protocol") == "TCP"
            and packet_info.get("tcp_flags") is not None
            and "S" in str(packet_info["tcp_flags"])
            and destination_port is not None
        ):
            scan_ports = self._scan_ports[source_ip]
            scan_ports.append((current_time, destination_port))
            unique_port_count = len({port for _, port in scan_ports})

            if (
                unique_port_count > self.port_scan_threshold
                and self._cooldown_finished(
                    self._port_scan_last_alert,
                    source_ip,
                    current_time,
                    self.port_scan_alert_cooldown,
                )
            ):
                self._port_scan_last_alert[source_ip] = current_time
                results.append(
                    self._make_result(
                        packet_info,
                        detection_type="POSSIBLE_PORT_SCAN",
                        severity="MEDIUM",
                        message=(
                            f"Possible port-scan indicator: {unique_port_count} "
                            f"distinct TCP destination ports in "
                            f"{self.port_scan_time_window} seconds; "
                            "this is not proof of malicious activity."
                        ),
                        packet_count=packet_count,
                        time_window=self.port_scan_time_window,
                    )
                )

        return results

    def _clean_expired_state(self, current_time):
        """Remove old timestamps and cooldown entries across all sources."""
        self._remove_expired_queues(
            self._packet_times, current_time - self.dos_time_window
        )
        self._remove_expired_queues(
            self._scan_ports, current_time - self.port_scan_time_window
        )
        self._remove_expired_cooldowns(
            self._dos_last_alert, current_time, self.dos_alert_cooldown
        )
        self._remove_expired_cooldowns(
            self._port_scan_last_alert,
            current_time,
            self.port_scan_alert_cooldown,
        )

    @staticmethod
    def _remove_expired_queues(queues, cutoff):
        """Discard observations older than the relevant time-window cutoff."""
        for source_ip in list(queues):
            observations = queues[source_ip]
            while observations:
                observation = observations[0]
                observed_at = observation[0] if isinstance(observation, tuple) else observation
                if observed_at >= cutoff:
                    break
                observations.popleft()
            if not observations:
                del queues[source_ip]

    @staticmethod
    def _remove_expired_cooldowns(last_alerts, current_time, cooldown):
        for source_ip, alert_time in list(last_alerts.items()):
            if current_time - alert_time >= cooldown:
                del last_alerts[source_ip]

    @staticmethod
    def _cooldown_finished(last_alerts, source_ip, current_time, cooldown):
        last_alert_time = last_alerts.get(source_ip)
        return last_alert_time is None or current_time - last_alert_time >= cooldown

    @staticmethod
    def _make_result(
        packet_info,
        detection_type,
        severity,
        message,
        packet_count,
        time_window,
    ):
        return {
            "detected": True,
            "type": detection_type,
            "severity": severity,
            "message": message,
            "source_ip": packet_info.get("source_ip"),
            "destination_ip": packet_info.get("destination_ip"),
            "source_port": packet_info.get("source_port"),
            "destination_port": packet_info.get("destination_port"),
            "packet_count": packet_count,
            "time_window": time_window,
        }

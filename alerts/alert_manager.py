"""Display and append detection indicators to the configured log file."""

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from core.nids_state import NidsState
from config.settings import LOG_FILE


class AlertManager:
    """Format detection results and save them without changing detection logic."""

    def __init__(self, log_file=None, recent_alert_limit=20, state=None):
        self.log_file = Path(LOG_FILE if log_file is None else log_file)
        self.state = state or NidsState(recent_alert_limit=recent_alert_limit)

    def record_packet(self):
        """Count one packet processed during this monitoring session."""
        self.state.record_packet()

    def handle_detection(self, detection_result, event_id=None):
        """Display and append a detected result; ignore normal results.

        Callers may provide a unique event ID to make repeated delivery of the
        same detection idempotent. Distinct packets should have distinct IDs.
        Returns True when an alert was written, or False when the result is
        normal, invalid, or is a duplicate.
        """
        if not isinstance(detection_result, Mapping):
            print("Alert error: detection result must be a dictionary-like object.")
            return False

        if not isinstance(detection_result.get("detected"), bool):
            print("Alert error: detection result must include a boolean 'detected' field.")
            return False

        if not detection_result["detected"]:
            return False

        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        event = self._format_event(timestamp, detection_result)

        if not self.state.record_detection(detection_result, timestamp, event_id):
            return False

        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file.open("a", encoding="utf-8") as log:
                log.write(event)
                log.write("\n\n")
        except OSError as error:
            print(f"Alert logging error: could not write to {self.log_file}: {error}")
            return False

        self.state.record_logged_detection()
        print(event)

        return True

    def print_summary(self, status="Stopped"):
        """Display a summary of this session's packets and detections."""
        statistics = self.get_statistics()
        display_status = status if status != "Stopped" else self.state.get_status().title()
        print("\n========== SESSION SUMMARY ==========")
        print(f"Monitoring Status : {display_status}")
        print(f"Packets Processed : {statistics['packets']}")
        print(f"Total Detections  : {statistics['detections']}")
        print()
        print(f"LOW Alerts        : {statistics['low']}")
        print(f"MEDIUM Alerts     : {statistics['medium']}")
        print(f"HIGH Alerts       : {statistics['high']}")
        print()
        print(f"Port Scan Alerts  : {statistics['port_scans']}")
        print(f"DoS/Flood Alerts  : {statistics['dos_alerts']}")
        print(f"Log File          : {self.log_file}")
        print("=====================================")

    def get_statistics(self):
        """Return a thread-safe snapshot of the session counters."""
        return self.state.get_statistics()

    def get_recent_alerts(self):
        """Return a thread-safe copy of the latest session alerts."""
        return self.state.get_recent_alerts()

    @property
    def packets_processed(self):
        return self.get_statistics()["packets"]

    @property
    def total_detections(self):
        return self.get_statistics()["detections"]

    @property
    def severity_counts(self):
        statistics = self.get_statistics()
        return {
            "LOW": statistics["low"],
            "MEDIUM": statistics["medium"],
            "HIGH": statistics["high"],
        }

    @property
    def port_scan_detections(self):
        return self.get_statistics()["port_scans"]

    @property
    def dos_detections(self):
        return self.get_statistics()["dos_alerts"]

    @staticmethod
    def _format_event(timestamp, detection_result):
        """Create a readable alert with safe placeholders for missing values."""
        def value_or_na(key):
            value = detection_result.get(key)
            return "N/A" if value is None or value == "" else str(value)

        return "\n".join(
            [
                "[DETECTION ALERT]",
                f"Timestamp        : {timestamp}",
                f"Detection Type   : {value_or_na('type')}",
                f"Severity         : {value_or_na('severity')}",
                f"Source IP        : {value_or_na('source_ip')}",
                f"Destination IP   : {value_or_na('destination_ip')}",
                f"Source Port      : {value_or_na('source_port')}",
                f"Destination Port : {value_or_na('destination_port')}",
                f"Message          : {value_or_na('message')}",
            ]
        )

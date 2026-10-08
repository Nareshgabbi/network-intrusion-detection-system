"""Thread-safe in-memory state for one NIDS monitoring session."""

from collections import deque
from threading import Lock


class NidsState:
    """Store monitoring status, session counters, and recent alert records."""

    def __init__(self, recent_alert_limit=20):
        self._lock = Lock()
        self._status = "stopped"
        self._packets = 0
        self._detections = 0
        self._logged_detections = 0
        self._severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        self._port_scans = 0
        self._dos_alerts = 0
        self._recent_alerts = deque(maxlen=recent_alert_limit)
        self._processed_event_ids = set()
        self._processed_event_order = deque(maxlen=1024)

    def set_status(self, status):
        """Set the actual packet-monitoring status."""
        if status not in {"running", "stopped"}:
            raise ValueError("NIDS status must be 'running' or 'stopped'.")
        with self._lock:
            self._status = status

    def get_status(self):
        """Return the current packet-monitoring status."""
        with self._lock:
            return self._status

    def clear_session(self):
        """Reset counters and retained alerts only while monitoring is stopped."""
        with self._lock:
            if self._status != "stopped":
                raise RuntimeError("Stop NIDS monitoring before clearing session data.")
            self._packets = 0
            self._detections = 0
            self._logged_detections = 0
            self._severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            self._port_scans = 0
            self._dos_alerts = 0
            self._recent_alerts.clear()
            self._processed_event_ids.clear()
            self._processed_event_order.clear()

    def record_packet(self):
        """Record one packet after it has entered the analysis pipeline."""
        with self._lock:
            self._packets += 1

    def record_logged_detection(self):
        """Count one detection successfully appended to the log file."""
        with self._lock:
            self._logged_detections += 1

    def get_logged_detection_count(self):
        """Return the number of session alerts successfully written to disk."""
        with self._lock:
            return self._logged_detections

    def record_detection(self, detection_result, timestamp, event_id=None):
        """Record one detection and retain its dashboard alert representation.

        Returns False if this event ID has already been processed.
        """
        with self._lock:
            if event_id is not None and event_id in self._processed_event_ids:
                return False
            if event_id is not None:
                if len(self._processed_event_order) == self._processed_event_order.maxlen:
                    oldest_event_id = self._processed_event_order.popleft()
                    self._processed_event_ids.discard(oldest_event_id)
                self._processed_event_order.append(event_id)
                self._processed_event_ids.add(event_id)

            self._detections += 1
            severity = detection_result.get("severity")
            if severity in self._severity_counts:
                self._severity_counts[severity] += 1

            detection_type = detection_result.get("type")
            if detection_type == "POSSIBLE_PORT_SCAN":
                self._port_scans += 1
            elif detection_type == "POSSIBLE_DOS":
                self._dos_alerts += 1

            self._recent_alerts.append(
                {
                    "timestamp": timestamp,
                    "type": detection_result.get("type"),
                    "severity": severity,
                    "source_ip": detection_result.get("source_ip"),
                    "destination_ip": detection_result.get("destination_ip"),
                    "source_port": detection_result.get("source_port"),
                    "destination_port": detection_result.get("destination_port"),
                    "message": detection_result.get("message"),
                }
            )
            return True

    def get_statistics(self):
        """Return a consistent snapshot of the current session counters."""
        with self._lock:
            return {
                "packets": self._packets,
                "detections": self._detections,
                "low": self._severity_counts["LOW"],
                "medium": self._severity_counts["MEDIUM"],
                "high": self._severity_counts["HIGH"],
                "port_scans": self._port_scans,
                "dos_alerts": self._dos_alerts,
            }

    def get_recent_alerts(self):
        """Return a newest-first copy of the retained alert records."""
        with self._lock:
            return [alert.copy() for alert in reversed(self._recent_alerts)]

"""Tests for the read-only Flask dashboard and its API."""

import contextlib
import io
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from alerts.alert_manager import AlertManager
from core.nids_state import NidsState
from web.app import DashboardRuntime
from web.app import create_app


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        log_file = Path(self.temp_directory.name) / "logs" / "nids.log"
        self.state = NidsState()
        self.manager = AlertManager(log_file=log_file, state=self.state)
        runtime = DashboardRuntime(alert_manager=self.manager)
        self.client = create_app(runtime=runtime).test_client()

    def test_dashboard_page_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Network Intrusion Detection System", response.data)
        self.assertIn(b"Real-Time Network Security Monitoring", response.data)
        self.assertIn(b"NIDS STATUS", response.data)
        self.assertIn(b"Packets Processed", response.data)
        self.assertIn(b"Low Alerts", response.data)
        self.assertIn(b"Medium Alerts", response.data)
        self.assertIn(b"High Alerts", response.data)
        self.assertIn(b"Possible Port Scans", response.data)
        self.assertIn(b"Possible DoS / Flood", response.data)
        self.assertIn(b"Source IP", response.data)
        self.assertIn(b"Destination IP", response.data)
        self.assertIn(b"Loading alerts", response.data)
        self.assertIn(b"START MONITORING", response.data)
        self.assertIn(b"STOP MONITORING", response.data)
        self.assertIn(b"CLEAR SESSION DATA", response.data)

    def test_dashboard_stylesheet_and_script_load(self):
        css_response = self.client.get("/static/css/style.css")
        js_response = self.client.get("/static/js/dashboard.js")
        css = css_response.get_data()
        javascript = js_response.get_data()
        css_response.close()
        js_response.close()

        self.assertEqual(css_response.status_code, 200)
        self.assertIn(b".status-dot.running", css)
        self.assertIn(b".severity-tag.high", css)
        self.assertEqual(js_response.status_code, 200)
        self.assertIn(b"setInterval(refreshDashboard, 3000)", javascript)
        self.assertIn(b"No alerts detected", javascript)
        self.assertIn(
            b"Are you sure you want to clear the current session data and logs? This cannot be undone.",
            javascript,
        )

    def test_status_endpoint_returns_json(self):
        self.state.set_status("running")
        response = self.client.get("/api/status")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json(), {"status": "running"})

    def test_dashboard_runtime_starts_stopped(self):
        client = create_app().test_client()

        self.assertEqual(client.get("/api/status").get_json(), {"status": "stopped"})

    @patch("web.app.start_capture")
    def test_start_endpoint_starts_capture_and_updates_shared_state(self, mock_capture):
        capture_started = threading.Event()

        def run_until_stopped(**kwargs):
            kwargs["nids_state"].set_status("running")
            kwargs["started_event"].set()
            capture_started.set()
            kwargs["stop_event"].wait(timeout=2)

        mock_capture.side_effect = run_until_stopped
        response = self.client.post("/api/start")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "NIDS monitoring started successfully")
        self.assertTrue(capture_started.wait(timeout=1))
        self.assertEqual(self.client.get("/api/status").get_json(), {"status": "running"})

        self.manager.record_packet()
        self.assertEqual(self.client.get("/api/statistics").get_json()["packets"], 1)
        stopped = self.client.post("/api/stop")
        self.assertEqual(stopped.status_code, 200)
        self.assertEqual(stopped.get_json()["message"], "NIDS monitoring stopped successfully")
        self.assertEqual(self.client.get("/api/status").get_json(), {"status": "stopped"})
        self.assertEqual(self.client.get("/api/statistics").get_json()["packets"], 1)
        mock_capture.assert_called_once()

    def test_stopping_when_already_stopped_reports_current_state(self):
        response = create_app().test_client().post("/api/stop")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "NIDS is already stopped")
        self.assertEqual(response.get_json()["status"], "stopped")

    def _record_session_data(self):
        self.manager.record_packet()
        self.manager.record_packet()
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.handle_detection(
                {
                    "detected": True,
                    "type": "POSSIBLE_PORT_SCAN",
                    "severity": "MEDIUM",
                    "source_ip": "192.0.2.20",
                    "destination_ip": "198.51.100.20",
                    "source_port": 50000,
                    "destination_port": 443,
                    "message": "Possible scan indicator",
                },
                event_id="clear-session-event",
            )

    def test_clear_endpoint_resets_all_statistics_alerts_and_log(self):
        self._record_session_data()
        self.assertGreater(self.manager.log_file.stat().st_size, 0)

        response = self.client.post("/api/clear")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "stopped")
        statistics = self.client.get("/api/statistics").get_json()
        self.assertEqual(
            {
                key: value
                for key, value in statistics.items()
                if key not in {"log_file"}
            },
            {
                "packets": 0,
                "detections": 0,
                "low": 0,
                "medium": 0,
                "high": 0,
                "port_scans": 0,
                "dos_alerts": 0,
                "logged_detections": 0,
            },
        )
        self.assertEqual(self.client.get("/api/alerts").get_json()["alerts"], [])
        self.assertTrue(self.manager.log_file.exists())
        self.assertEqual(self.manager.log_file.read_text(encoding="utf-8"), "")

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(
                self.manager.handle_detection(
                    {
                        "detected": True,
                        "type": "POSSIBLE_PORT_SCAN",
                        "severity": "MEDIUM",
                    },
                    event_id="clear-session-event",
                )
            )
        self.assertIn(
            "Detection Type   : POSSIBLE_PORT_SCAN",
            self.manager.log_file.read_text(encoding="utf-8"),
        )

    @patch("web.app.start_capture")
    def test_clear_while_running_is_rejected_without_changing_session_data(
        self, mock_capture
    ):
        capture_started = threading.Event()

        def run_until_stopped(**kwargs):
            kwargs["nids_state"].set_status("running")
            kwargs["started_event"].set()
            capture_started.set()
            kwargs["stop_event"].wait(timeout=2)

        mock_capture.side_effect = run_until_stopped
        self._record_session_data()
        original_log = self.manager.log_file.read_text(encoding="utf-8")
        runtime = self.client.application.config["NIDS_RUNTIME"]
        self.assertTrue(runtime.start())
        self.assertTrue(capture_started.wait(timeout=1))

        response = self.client.post("/api/clear")

        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.get_json()["message"],
            "Stop NIDS monitoring before clearing session data.",
        )
        self.assertEqual(self.client.get("/api/statistics").get_json()["detections"], 1)
        self.assertEqual(self.manager.log_file.read_text(encoding="utf-8"), original_log)
        self.assertTrue(runtime.stop())

    def test_clear_creates_empty_log_if_current_log_does_not_exist(self):
        self.assertFalse(self.manager.log_file.exists())

        response = self.client.post("/api/clear")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.manager.log_file.is_file())
        self.assertEqual(self.manager.log_file.read_text(encoding="utf-8"), "")

    def test_log_permission_error_does_not_clear_statistics(self):
        self._record_session_data()
        original_log = self.manager.log_file.read_text(encoding="utf-8")

        with patch("pathlib.Path.open", side_effect=PermissionError("access denied")):
            response = self.client.post("/api/clear")

        self.assertEqual(response.status_code, 500)
        self.assertIn("access denied", response.get_json()["message"])
        self.assertEqual(self.client.get("/api/statistics").get_json()["detections"], 1)
        self.assertEqual(self.manager.log_file.read_text(encoding="utf-8"), original_log)

    def test_repeated_clear_requests_are_safe_and_idempotent(self):
        self._record_session_data()

        first = self.client.post("/api/clear")
        second = self.client.post("/api/clear")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(self.client.get("/api/statistics").get_json()["packets"], 0)
        self.assertEqual(self.client.get("/api/alerts").get_json()["alerts"], [])
        self.assertEqual(self.manager.log_file.read_text(encoding="utf-8"), "")

    @patch("web.app.start_capture")
    def test_starting_when_already_running_does_not_start_another_thread(self, mock_capture):
        capture_started = threading.Event()

        def run_until_stopped(**kwargs):
            kwargs["nids_state"].set_status("running")
            kwargs["started_event"].set()
            capture_started.set()
            kwargs["stop_event"].wait(timeout=2)

        mock_capture.side_effect = run_until_stopped
        first = self.client.post("/api/start")
        second = self.client.post("/api/start")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json()["message"], "NIDS is already running")
        self.assertTrue(capture_started.is_set())
        mock_capture.assert_called_once()
        self.client.post("/api/stop")

    @patch("web.app.start_capture")
    def test_runtime_does_not_overlap_a_thread_that_is_shutting_down(self, mock_capture):
        def run_until_stopped(**kwargs):
            kwargs["nids_state"].set_status("running")
            kwargs["started_event"].set()
            kwargs["stop_event"].wait(timeout=2)

        mock_capture.side_effect = run_until_stopped
        runtime = DashboardRuntime()

        self.assertTrue(runtime.start())
        runtime.state.set_status("stopped")

        self.assertFalse(runtime.start())
        mock_capture.assert_called_once()
        self.assertTrue(runtime.stop())

    @patch("web.app.start_capture", return_value="Capture permission denied.")
    def test_capture_startup_failure_is_reported_without_crashing_dashboard(
        self, mock_capture
    ):
        response = self.client.post("/api/start")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "stopped")
        self.assertIn("permission denied", response.get_json()["message"])
        status = self.client.get("/api/status").get_json()
        self.assertEqual(status["status"], "stopped")
        self.assertIn("permission denied", status["error"])
        self.assertEqual(self.client.get("/").status_code, 200)
        mock_capture.assert_called_once()

    @patch("web.app.start_capture", side_effect=RuntimeError("capture driver failed"))
    def test_unexpected_capture_error_is_returned_and_dashboard_stays_available(
        self, mock_capture
    ):
        response = self.client.post("/api/start")

        self.assertEqual(response.status_code, 503)
        self.assertIn("capture driver failed", response.get_json()["message"])
        status = self.client.get("/api/status").get_json()
        self.assertEqual(status["status"], "stopped")
        self.assertIn("capture driver failed", status["error"])
        self.assertEqual(self.client.get("/").status_code, 200)
        mock_capture.assert_called_once()

    def test_statistics_endpoint_returns_session_values_as_json(self):
        self.manager.record_packet()
        self.manager.record_packet()
        detection = {
            "detected": True,
            "type": "POSSIBLE_DOS",
            "severity": "HIGH",
            "source_ip": "192.0.2.5",
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "message": "Possible flood indicator",
        }
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.handle_detection(detection, event_id="dos-1")

        response = self.client.get("/api/statistics")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        data = response.get_json()
        self.assertEqual(data["packets"], 2)
        self.assertEqual(data["detections"], 1)
        self.assertEqual(data["high"], 1)
        self.assertEqual(data["dos_alerts"], 1)
        self.assertEqual(data["logged_detections"], 1)
        self.assertTrue(data["log_file"].endswith("nids.log"))

    def test_alerts_endpoint_returns_recent_json_alerts(self):
        with contextlib.redirect_stdout(io.StringIO()):
            for index in range(12):
                self.manager.handle_detection(
                    {
                        "detected": True,
                        "type": "MONITORED_PORT",
                        "severity": "LOW",
                        "source_ip": f"192.0.2.{index}",
                        "destination_ip": "198.51.100.1",
                        "source_port": 50000,
                        "destination_port": 443,
                        "message": "Monitored service traffic",
                    },
                    event_id=f"event-{index}",
                )

        response = self.client.get("/api/alerts")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        data = response.get_json()
        self.assertEqual(data["limit"], 10)
        self.assertEqual(len(data["alerts"]), 10)
        self.assertEqual(data["alerts"][0]["source_ip"], "192.0.2.11")
        self.assertIn("timestamp", data["alerts"][0])

    def test_status_endpoint_reads_current_monitor_status(self):
        self.state.set_status("stopped")

        response = self.client.get("/api/status")

        self.assertEqual(response.get_json(), {"status": "stopped"})

    @patch("web.app.start_capture")
    def test_runtime_shares_live_monitor_state_with_api(self, mock_capture):
        capture_started = threading.Event()

        def run_until_stopped(**kwargs):
            kwargs["nids_state"].set_status("running")
            kwargs["started_event"].set()
            capture_started.set()
            kwargs["stop_event"].wait(timeout=2)

        mock_capture.side_effect = run_until_stopped
        runtime = DashboardRuntime(alert_manager=self.manager)
        client = create_app(runtime=runtime).test_client()

        runtime.start()
        self.assertTrue(capture_started.wait(timeout=1))
        self.manager.record_packet()
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.handle_detection(
                {
                    "detected": True,
                    "type": "POSSIBLE_PORT_SCAN",
                    "severity": "MEDIUM",
                    "source_ip": "192.0.2.1",
                    "destination_ip": "198.51.100.2",
                    "source_port": 50000,
                    "destination_port": 443,
                    "message": "Possible scan indicator",
                },
                event_id="live-scan",
            )

        self.assertEqual(client.get("/api/status").get_json(), {"status": "running"})
        statistics = client.get("/api/statistics").get_json()
        self.assertEqual(statistics["packets"], 1)
        self.assertEqual(statistics["detections"], 1)
        self.assertEqual(statistics["port_scans"], 1)
        self.assertEqual(len(client.get("/api/alerts").get_json()["alerts"]), 1)

        runtime.stop()
        self.assertEqual(client.get("/api/status").get_json(), {"status": "stopped"})


if __name__ == "__main__":
    unittest.main()

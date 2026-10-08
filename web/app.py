"""Local dashboard server for the NIDS monitoring pipeline."""

from threading import Event, Lock, Thread

from flask import Flask, jsonify, render_template

from alerts.alert_manager import AlertManager
from core.packet_capture import start_capture
from core.nids_state import NidsState


class DashboardRuntime:
    """Run packet capture in the dashboard process and share its session data."""

    def __init__(self, alert_manager=None, state=None):
        if alert_manager is not None and state is not None and alert_manager.state is not state:
            raise ValueError("The runtime and AlertManager must share the same NIDS state.")
        self.state = state or (alert_manager.state if alert_manager is not None else NidsState())
        self.alert_manager = alert_manager or AlertManager(state=self.state)
        self._lock = Lock()
        self._stop_event = None
        self._thread = None
        self._started_event = None
        self.last_error = None

    @property
    def status(self):
        return self.state.get_status()

    def start(self):
        """Start continuous packet capture in a background thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False

            self._stop_event = Event()
            self._started_event = Event()
            self.last_error = None
            self._thread = Thread(
                target=self._capture,
                args=(self._stop_event, self._started_event),
                daemon=True,
            )
            try:
                self._thread.start()
            except RuntimeError as error:
                self.last_error = f"Unable to start NIDS monitoring: {error}"
                self.state.set_status("stopped")
                return False

            if self._started_event.wait(timeout=10):
                return self.status == "running"

            self.last_error = "Timed out waiting for packet capture to start."
            self._stop_event.set()
            self._thread.join(timeout=3)
            if not self._thread.is_alive():
                self.state.set_status("stopped")
            return False

    def _capture(self, stop_event, started_event):
        try:
            error = start_capture(
                packet_count=0,
                alert_manager=self.alert_manager,
                stop_event=stop_event,
                nids_state=self.state,
                started_event=started_event,
            )
            if error:
                self.last_error = error
        except Exception as error:
            self.last_error = f"Unexpected NIDS monitoring error: {error}"
            print(self.last_error)
        finally:
            self.state.set_status("stopped")
            started_event.set()

    def stop(self):
        """Ask capture to stop and wait briefly for its one-second sniff timeout."""
        with self._lock:
            stop_event = self._stop_event
            thread = self._thread
            if self.status == "stopped" and (
                thread is None or not thread.is_alive()
            ):
                return False
        if stop_event is not None:
            stop_event.set()
        if thread is not None:
            thread.join(timeout=3)
            if thread.is_alive():
                self.last_error = "Timed out waiting for packet capture to stop."
                return False
        self.state.set_status("stopped")
        return True

    def clear_session(self):
        """Clear the stopped session's in-memory data and configured log."""
        with self._lock:
            if self.status != "stopped":
                raise RuntimeError("Stop NIDS monitoring before clearing session data.")

            log_file = self.alert_manager.log_file
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with log_file.open("a", encoding="utf-8"):
                pass
            self.state.clear_session()
            with log_file.open("w", encoding="utf-8"):
                pass
            self.last_error = None


def create_app(alert_manager=None, runtime=None):
    """Create the dashboard app; injection keeps API tests independent of capture."""
    if runtime is None:
        runtime = DashboardRuntime(alert_manager)
    elif alert_manager is not None and runtime.alert_manager is not alert_manager:
        raise ValueError("The runtime and dashboard must share the same AlertManager.")

    app = Flask(__name__)
    app.config["NIDS_RUNTIME"] = runtime

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/api/status")
    def api_status():
        response = {"status": runtime.status}
        if runtime.last_error:
            response["error"] = runtime.last_error
        return jsonify(response)

    @app.post("/api/start")
    def api_start():
        try:
            if runtime.start():
                return jsonify(
                    {
                        "status": runtime.status,
                        "message": "NIDS monitoring started successfully",
                    }
                )
            if runtime.last_error:
                return (
                    jsonify({"status": runtime.status, "message": runtime.last_error}),
                    503,
                )
            if runtime.status == "running":
                return jsonify(
                    {"status": "running", "message": "NIDS is already running"}
                )
            return (
                jsonify(
                    {
                        "status": "stopped",
                        "message": runtime.last_error or "Unable to start NIDS monitoring.",
                    }
                ),
                503,
            )
        except Exception as error:
            runtime.last_error = f"Unable to start NIDS monitoring: {error}"
            runtime.state.set_status("stopped")
            return jsonify({"status": "stopped", "message": runtime.last_error}), 500

    @app.post("/api/stop")
    def api_stop():
        try:
            if runtime.stop():
                return jsonify(
                    {
                        "status": "stopped",
                        "message": "NIDS monitoring stopped successfully",
                    }
                )
            if runtime.status == "stopped":
                return jsonify(
                    {"status": "stopped", "message": "NIDS is already stopped"}
                )
            return (
                jsonify(
                    {
                        "status": runtime.status,
                        "message": runtime.last_error or "Unable to stop NIDS monitoring.",
                    }
                ),
                500,
            )
        except Exception as error:
            runtime.last_error = f"Unable to stop NIDS monitoring: {error}"
            return jsonify({"status": runtime.status, "message": runtime.last_error}), 500

    @app.post("/api/clear")
    def api_clear():
        try:
            runtime.clear_session()
            return jsonify(
                {
                    "status": "stopped",
                    "message": "Session statistics, recent alerts, and NIDS log cleared successfully",
                }
            )
        except RuntimeError as error:
            return jsonify({"status": runtime.status, "message": str(error)}), 409
        except OSError as error:
            runtime.last_error = f"Unable to clear NIDS log: {error}"
            return jsonify({"status": runtime.status, "message": runtime.last_error}), 500
        except Exception as error:
            runtime.last_error = f"Unable to clear NIDS session data: {error}"
            return jsonify({"status": runtime.status, "message": runtime.last_error}), 500

    @app.get("/api/statistics")
    def api_statistics():
        statistics = runtime.state.get_statistics()
        statistics["logged_detections"] = runtime.state.get_logged_detection_count()
        statistics["log_file"] = runtime.alert_manager.log_file.as_posix()
        return jsonify(statistics)

    @app.get("/api/alerts")
    def api_alerts():
        alerts = runtime.state.get_recent_alerts()[:10]
        return jsonify({"alerts": alerts, "limit": 10})

    return app


def main():
    """Serve the local dashboard; packet monitoring starts on user request."""
    runtime = DashboardRuntime()
    app = create_app(runtime=runtime)
    try:
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        runtime.stop()
        runtime.alert_manager.print_summary()
        print("NIDS stopped successfully.")


if __name__ == "__main__":
    main()

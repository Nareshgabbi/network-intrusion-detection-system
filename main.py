"""Entry point for the basic NIDS packet-capture prototype."""

from alerts.alert_manager import AlertManager
from core.packet_capture import start_capture


def main():
    """Start the NIDS prototype and begin packet capture."""
    print("Starting NIDS...")
    print("Packet capture module initialized.")
    alert_manager = AlertManager()

    try:
        start_capture(alert_manager=alert_manager)
    except KeyboardInterrupt:
        print("\nStopping NIDS...")
    finally:
        alert_manager.print_summary()

    print("NIDS stopped successfully.")


if __name__ == "__main__":
    main()

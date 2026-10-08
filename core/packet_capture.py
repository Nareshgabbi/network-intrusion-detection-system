"""Simple live packet capture using Scapy."""

from analysis.packet_analyzer import analyze_packet, display_packet_info
from alerts.alert_manager import AlertManager
from config.settings import CAPTURE_INTERFACE, CAPTURE_PACKET_COUNT
from detection.behavior_analyzer import BehaviorAnalyzer
from detection.rules import DetectionEngine
from core.nids_state import NidsState


def start_capture(
    packet_count=None,
    interface=None,
    alert_manager=None,
    stop_event=None,
    nids_state=None,
    started_event=None,
):
    """Capture and display a limited number of packets from a network interface."""
    if packet_count is None:
        packet_count = CAPTURE_PACKET_COUNT
    if interface is None:
        interface = CAPTURE_INTERFACE

    if not isinstance(packet_count, int) or packet_count < 0:
        print("Capture error: packet count must be zero or a positive whole number.")
        return "Capture packet count must be zero or a positive whole number."

    try:
        from scapy.all import sniff
        from scapy.error import Scapy_Exception
    except ImportError:
        print("Capture error: Scapy is not installed. Run: pip install -r requirements.txt")
        return "Scapy is not installed. Run: pip install -r requirements.txt."

    captured_count = 0
    detection_engine = DetectionEngine()
    behavior_analyzer = BehaviorAnalyzer()
    if alert_manager is None:
        alert_manager = AlertManager(state=nids_state)
    if nids_state is None:
        nids_state = alert_manager.state
    elif alert_manager.state is not nids_state:
        raise ValueError("Packet capture and AlertManager must share the same NIDS state.")

    def display_packet(packet):
        nonlocal captured_count
        captured_count += 1
        alert_manager.record_packet()
        packet_info = analyze_packet(packet)
        display_packet_info(captured_count, packet_info)
        detection_result = detection_engine.analyze(packet_info)
        if detection_result["detected"]:
            alert_manager.handle_detection(
                detection_result,
                event_id=(captured_count, detection_result["type"]),
            )
        for behavior_index, behavior_result in enumerate(
            behavior_analyzer.analyze(packet_info)
        ):
            alert_manager.handle_detection(
                behavior_result,
                event_id=(captured_count, "behavior", behavior_index),
            )

    interface_name = interface if interface else "default interface"
    capture_limit = f"up to {packet_count}" if packet_count else "continuously"
    print(f"Capturing {capture_limit} packet(s) on {interface_name}...")

    def mark_capture_started():
        nids_state.set_status("running")
        if started_event is not None:
            started_event.set()

    try:
        while stop_event is None or not stop_event.is_set():
            remaining = (
                max(packet_count - captured_count, 0)
                if packet_count
                else 0
            )
            sniff(
                iface=interface,
                count=remaining,
                prn=display_packet,
                store=False,
                timeout=1 if stop_event is not None else None,
                stop_filter=(
                    (lambda _: stop_event.is_set())
                    if stop_event is not None
                    else None
                ),
                started_callback=mark_capture_started,
            )
            if packet_count and captured_count >= packet_count:
                break
            if stop_event is None:
                break
    except PermissionError:
        message = (
            "Capture permission denied. Run the terminal as Administrator "
            "(Windows) or with sudo/root privileges (Linux/macOS)."
        )
        print(f"Capture error: {message}")
        return message
    except OSError as error:
        if getattr(error, "winerror", None) == 10013 or error.errno in (1, 13):
            message = (
                "Capture permission denied. Run the terminal as Administrator "
                "(Windows) or with sudo/root privileges (Linux/macOS)."
            )
            print(f"Capture error: {message}")
        else:
            message = f"Operating system could not access the interface: {error}"
            print(f"Capture error: {message}")
        return message
    except Scapy_Exception as error:
        message = (
            f"Scapy could not start packet capture: {error}. "
            "Check the interface name and packet-capture driver."
        )
        print(f"Capture error: {message}")
        return message
    else:
        print(f"Capture finished. Displayed {captured_count} packet(s).")
    finally:
        nids_state.set_status("stopped")

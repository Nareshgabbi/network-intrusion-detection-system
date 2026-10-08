"""Extract basic network information from Scapy packets."""


def analyze_packet(packet):
    """Return common network fields from a packet as a dictionary.

    Fields that are not present in the packet are returned as None.
    """
    try:
        from scapy.all import ICMP, IP, TCP, UDP
    except ImportError as error:
        raise RuntimeError(
            "Scapy is required for packet analysis. Install it with "
            "'python -m pip install -r requirements.txt'."
        ) from error

    packet_info = {
        "source_ip": None,
        "destination_ip": None,
        "protocol": "Non-IP",
        "source_port": None,
        "destination_port": None,
        "packet_length": None,
        "ttl": None,
        "tcp_flags": None,
        "icmp_type": None,
        "icmp_code": None,
        "analysis_error": None,
    }

    try:
        packet_info["packet_length"] = len(packet)

        if packet.haslayer(IP):
            ip_packet = packet[IP]
            packet_info["source_ip"] = getattr(ip_packet, "src", None)
            packet_info["destination_ip"] = getattr(ip_packet, "dst", None)
            packet_info["ttl"] = getattr(ip_packet, "ttl", None)

            if packet.haslayer(TCP):
                tcp_packet = packet[TCP]
                packet_info["protocol"] = "TCP"
                packet_info["source_port"] = getattr(tcp_packet, "sport", None)
                packet_info["destination_port"] = getattr(tcp_packet, "dport", None)
                flags = getattr(tcp_packet, "flags", None)
                packet_info["tcp_flags"] = str(flags) if flags is not None else None
            elif packet.haslayer(UDP):
                udp_packet = packet[UDP]
                packet_info["protocol"] = "UDP"
                packet_info["source_port"] = getattr(udp_packet, "sport", None)
                packet_info["destination_port"] = getattr(udp_packet, "dport", None)
            elif packet.haslayer(ICMP):
                icmp_packet = packet[ICMP]
                packet_info["protocol"] = "ICMP"
                packet_info["icmp_type"] = getattr(icmp_packet, "type", None)
                packet_info["icmp_code"] = getattr(icmp_packet, "code", None)
            else:
                ip_protocol = getattr(ip_packet, "proto", None)
                packet_info["protocol"] = (
                    f"Other IP ({ip_protocol})"
                    if ip_protocol is not None
                    else "Other IP"
                )
    except (AttributeError, IndexError, TypeError, ValueError) as error:
        packet_info["analysis_error"] = f"Could not fully analyze packet: {error}"

    return packet_info


def display_packet_info(packet_number, packet_info):
    """Print analyzed packet details in a readable format."""
    def show(value):
        return "N/A" if value is None else value

    print(f"\n--- Packet #{packet_number} ---")
    print(f"Source IP       : {show(packet_info['source_ip'])}")
    print(f"Destination IP  : {show(packet_info['destination_ip'])}")
    print(f"Protocol        : {packet_info['protocol']}")
    print(f"Source Port     : {show(packet_info['source_port'])}")
    print(f"Destination Port: {show(packet_info['destination_port'])}")
    print(f"Packet Length   : {show(packet_info['packet_length'])}")
    print(f"TTL             : {show(packet_info['ttl'])}")

    if packet_info["tcp_flags"] is not None:
        print(f"TCP Flags       : {packet_info['tcp_flags']}")
    if packet_info["icmp_type"] is not None:
        print(f"ICMP Type       : {packet_info['icmp_type']}")
    if packet_info["icmp_code"] is not None:
        print(f"ICMP Code       : {packet_info['icmp_code']}")
    if packet_info["analysis_error"] is not None:
        print(f"Analysis note   : {packet_info['analysis_error']}")

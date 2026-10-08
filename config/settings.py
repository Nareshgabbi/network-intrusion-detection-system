"""Basic configuration placeholders for the NIDS prototype."""

PROJECT_NAME = "Network Intrusion Detection System"
LOG_FILE = "logs/nids.log"
ALERT_LOG_FILE = "logs/alerts.log"
DETECTION_ENABLED = True

# Capture up to this many packets when the prototype starts.
CAPTURE_PACKET_COUNT = 10

# None lets Scapy use the default network interface. Set an interface name to
# select a specific adapter.
CAPTURE_INTERFACE = None

# These ports are monitored for traffic indicators, not treated as malicious.
MONITORED_PORTS = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389]

# Destination ports greater than this value are marked as high-port traffic.
DESTINATION_PORT_THRESHOLD = 1024

# Behavioral indicators are based on observed rates, not proof of an attack.
DOS_PACKET_THRESHOLD = 100
DOS_TIME_WINDOW = 10
DOS_ALERT_COOLDOWN = 60

# A source contacting more than this many distinct TCP ports in the window
# receives a possible port-scan indicator.
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_TIME_WINDOW = 60
PORT_SCAN_ALERT_COOLDOWN = 60

# Network Intrusion Detection System (NIDS)

## What this project is

This is a beginner-friendly college project that will be developed step by
step into a Network Intrusion Detection System.

## What NIDS means

NIDS stands for **Network Intrusion Detection System**. A NIDS monitors
network traffic and looks for activity that may indicate an intrusion or
other security concern.

## Current project status

The project captures live network packets using Scapy, analyzes packet details,
and reports configurable rule-based indicators. Behavioral analysis can report
possible TCP port scans and high-rate traffic from an individual source. These
indicators do not prove that an attack occurred. Detected indicators are
displayed and appended to `logs/nids.log`.

The Flask dashboard starts the packet monitor in a background thread only when
the user selects **START MONITORING**. Dashboard and monitor use a shared,
thread-safe in-memory NIDS state, so status, counters, and recent alerts reflect
actual monitoring events. The dashboard refreshes automatically and binds to
the local computer only. The command-line prototype continues to be available
separately and prints a session summary when capture ends or Ctrl+C is pressed.

## Project architecture

- `core/`: Live packet capture and basic packet details.
- `analysis/`: Extracts structured information from captured packets.
- `detection/`: Basic rules and per-source behavioral indicators.
- `alerts/`: Displays detections and appends logs.
- `core/nids_state.py`: Thread-safe runtime status, counters, and recent alerts.
- `web/`: Local Flask dashboard, monitoring controls, and statistics API.
- `config/`: Capture and detection settings.
- `logs/`: Append-only NIDS log file.
- `tests/`: Unit and Flask test-client tests.

## Install dependencies

Open the project folder in VS Code and install the required packages:

```bash
python -m pip install -r requirements.txt
```

## Run the command-line prototype

```powershell
python main.py
```

Press Ctrl+C to stop command-line monitoring and print its session summary.

## Run the web dashboard

Start the local dashboard:

```powershell
python -m web.app
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000/) in your browser. Monitoring
starts in the stopped state. Use **START MONITORING** and **STOP MONITORING** to
control capture. When stopped, **CLEAR SESSION DATA** prompts for confirmation
before resetting the session counters, recent alerts, and `logs/nids.log`.
Stop the dashboard server itself with Ctrl+C. The server binds only to
`127.0.0.1` and runs without Flask debug mode.

The dashboard displays NIDS status, packets processed, detections, severity
counts, possible port scans, possible DoS/flood indicators, log location, and
the latest 10 alerts. It refreshes every three seconds.

### Dashboard API

- `GET /api/status` — current capture status.
- `GET /api/statistics` — current session counters and configured log location.
- `GET /api/alerts` — latest 10 alert records from this monitoring session.
- `POST /api/start` — start packet capture in the background monitoring thread.
- `POST /api/stop` — gracefully stop packet capture.
- `POST /api/clear` — clear stopped-session counters, recent alerts, and log.

Packet capture and AlertManager update the shared `core/nids_state.py` instance;
Flask reads snapshots of that state for its API. Only the latest 20 alert
records are retained in memory. The dashboard does not expose file access.

Packet capture may require an elevated terminal: run VS Code as Administrator
on Windows, or use `sudo` on Linux/macOS. Windows also requires the Npcap
capture driver. Only monitor networks you are authorized to inspect.

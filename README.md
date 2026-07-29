# Rule-Based Intrusion Detection System (IDS)

A real-time, signature-based network intrusion detection tool built in Python.
It captures live packets, checks them against a configurable set of high-risk
ports/protocols, logs alerts, and displays activity on a live terminal dashboard.

## What it does

- Captures live network traffic using **Scapy**
- Flags packets against a signature ruleset of 35+ commonly-targeted ports
  (SSH, RDP, Telnet, SMB, FTP, database ports, VNC, etc.)
- Logs every alert with timestamp, source/destination IP, port, and protocol
- Tracks unique source IPs and maintains a running suspicious-IP list
- Displays live stats (total packets, alerts, unique IPs) on a terminal dashboard

## Project structure

```
IDS_Project/
├── main.py              # Entry point — starts capture, detection, and dashboard
├── packet_capture.py    # Live packet sniffing (Scapy)
├── detector.py          # Rule-based signature matching against suspicious_ports
├── logger.py            # Writes structured alerts to logs/alerts.log
├── gui.py                # Terminal dashboard rendering
├── dashboard.py          # Dashboard stats/state
├── data/
│   ├── suspicious_ips.txt   # IPs that triggered alerts
│   └── blocked_ips.txt      # IPs flagged for blocking
├── logs/
│   └── alerts.log        # Full alert history
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
```

## Running it

Live packet capture requires raw socket access, so it needs root:

```bash
sudo python3 main.py
```

## GUI dashboard (in progress)

In addition to the terminal dashboard, there's a Tkinter/Matplotlib GUI
(`gui.py`) showing live stat counters (Total Packets, Suspicious Alerts,
Unique IPs, Blocked IPs) alongside four charts: Live Network Activity,
Alerts Over Time, Packets Per Port, and Top Source IPs.

**Current status:** Live Network Activity renders correctly. The other
three charts (Alerts Over Time, Packets Per Port, Top Source IPs) are not
yet populating with data — root cause not yet identified. Next step is
tracing whether the plotting functions for those charts are being called
with real data or not being triggered at all.

## Sample output

```
==== IDS DASHBOARD ====
Total Packets: 1281
Suspicious Alerts: 85
Unique IPs Detected: 22

[01:11:36] Packet #1040
SRC: 192.168.153.128 -> DST: 192.178.211.94
PORT: 80
PROTOCOL: TCP
ALERT: Suspicious Port Detected! (HTTP)
```

## Known limitation

The current ruleset flags traffic on *any* monitored port, including ports
that carry constant, legitimate traffic (e.g. HTTP on port 80, DNS on port 53).
In testing, this produced a high false-positive rate on normal web browsing
traffic. A production-grade version would need:

- Baseline/allowlist filtering for known-normal traffic patterns
- Frequency-based thresholds (e.g. alert only on repeated attempts within a
  time window) instead of alerting on every matching packet
- Separating "port of interest" from "confirmed suspicious behavior"

This is a learning project focused on packet capture, rule-based detection
logic, and logging/dashboarding — not a tuned production IDS.

## Stack

Python 3.13 · Scapy · Tkinter · Matplotlib

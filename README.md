# ARP Shield – ARP Spoofing Detection System

ARP Shield is a defensive cybersecurity application that passively monitors ARP traffic on a local network and flags suspicious IP-to-MAC behavior. It uses Scapy for packet capture, SQLite for alert storage, and Flask for a professional web dashboard.

## Features

- Passive ARP packet monitoring
- IP-to-MAC mapping change detection
- Multiple MAC addresses associated with one IP detection
- Multiple IP addresses associated with one MAC detection
- Gratuitous ARP detection
- Rapid ARP reply-rate detection
- HIGH / MEDIUM / LOW severity classification
- SQLite alert storage
- File-based event logging
- Start/stop monitoring from the dashboard
- 50 alerts per page with pagination
- Dashboard status and alert statistics
- Graceful capture-error reporting

## Architecture

```text
Network Interface
       ↓
Scapy ARP Sniffer
       ↓
ARP Detection Engine
       ↓
Threat Classification
       ↓
SQLite Database + Event Log
       ↓
Flask Backend
       ↓
Web Dashboard
```

## Project Structure

```text
ARP-Shield/
├── app.py
├── detector.py
├── db.py
├── requirements.txt
├── README.md
├── templates/
│   └── dashboard.html
├── static/
│   └── style.css
└── logs/
    └── arp_events.log
```

`arp_shield.db` is created automatically when the application starts.

## Installation

Create and activate a virtual environment if desired:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Windows requirement

Scapy packet capture on Windows normally requires **Npcap** and an elevated terminal. Install Npcap if it is not already installed, then open Command Prompt or PowerShell as **Administrator** before starting the application.

### Linux

Run the application with the privileges required by your capture configuration, for example:

```bash
sudo python app.py
```

## Run

From the project directory:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

Click **Start Monitoring** to begin passive ARP capture.

## Detection Methodology

### IP-MAC mapping change

If an IP that has already been learned later appears with a different MAC address, ARP Shield creates a HIGH-severity ARP Spoofing alert.

### Multiple MACs for one IP

If the same IP is observed with multiple MAC addresses, the system creates a HIGH-severity alert.

### Multiple IPs for one MAC

If a MAC address claims multiple IP addresses, the system creates a MEDIUM-severity alert. This can be legitimate in some network configurations, so it should be investigated rather than treated as proof of an attack.

### Gratuitous ARP

ARP replies where the sender IP and target IP are the same are flagged as MEDIUM severity. Gratuitous ARP can be legitimate, so this is an anomaly signal rather than a definitive attack verdict.

### Rapid ARP replies

The detector tracks ARP replies over a short time window and raises a HIGH-severity alert when the configured threshold is exceeded.

## Safety

ARP Shield is intentionally **passive**. It does not generate ARP poisoning traffic, inject packets, intercept credentials, block devices, or perform denial-of-service actions.

Use it only on networks you own or are authorized to monitor.

## Limitations

- ARP anomalies are not always malicious; legitimate network changes can trigger alerts.
- The mapping is held in memory and is reset when the detector restarts.
- Packet capture privileges depend on the operating system and Npcap/libpcap configuration.
- The current version is designed as a local defensive monitoring project, not a production IDS.

## Future Improvements

- Persistent IP-MAC baseline management
- Configurable detection thresholds
- Alert acknowledgement and investigation workflow
- Exportable incident reports
- Email or webhook notifications
- More detailed packet metadata
- Optional PCAP evidence capture
- Integration with a SIEM in an authorized environment

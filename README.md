# Network Black Box

Network Black Box is a small network tool. It takes one or more PCAP files, summarizes the traffic into a SQLite database, runs 5 detection rules, and then generates reports and evidence bundles.

It is a very lightweight version of tools like Zeek / Suricata / NetworkMiner, but implemented in Python with a CLI.

---

## Features

- Ingest one PCAP file or a folder of PCAPs
- Extract flow events (connection summaries) into a `flows` table
- Extract DNS events into a `dns_events` table
- Store all data in a local SQLite database (`blackbox.db`)
- Run 5 basic detection rules:
  - Port scan (many different ports hit by one source)
  - Brute-force (many connections to SSH/RDP)
  - Suspicious ports (traffic to specific risky ports)
  - DNS spike (very high number of DNS queries from one host)
  - New host observed (new internal IP address)
- Create alerts and group them into incidents
- Export evidence bundles (CSV, JSON, ZIP) per incident

---

## Requirements

- Python 3.9+
- Python packages: `dpkt` `typer`

---

## Setup

From the project root, set up a virtual environment and install the package:

```powershell
python -m venv .venv
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned)
.\.venv\Scripts\Activate.ps1
pip install -e .
```

To exit the virtual environment when you are done:

```powershell
deactivate
```

---

## Running the Tool

### Help

```powershell
python -m blackbox --help
```

### Initializes the DB

```powershell
python -m blackbox init-db --db blackbox.db
```

### Ingest PCAP files

You can open `blackbox.db` in DB Browser for SQLite afterwards to review the ingested data.

```powershell
python -m blackbox ingest --pcap .\pcaps\smallFlows.pcap --db blackbox.db
```

### Detection rules on ingested data

```powershell
python -m blackbox detect --db blackbox.db
```

### Generate summaries

```powershell
python -m blackbox report --db blackbox.db --out .\output
```

### Quick and easy — all steps at once

```powershell
python -m blackbox init-db --db blackbox.db
python -m blackbox run --pcap .\pcaps\ --out .\output --db blackbox.db
```

---

## Output

After running `report`, the output folder will contain:

```
output/
  summary.txt         # totals, top talkers, top ports, alerts by type
  incident_001/
    report.txt        # incident summary and recommended next steps
    flows.csv         # flows tied to the incident
    dns.csv           # DNS events tied to the incident
    alerts.json       # alerts that triggered the incident
  incident_001.zip    # everything above bundled into one file
```

---

## Detection Rules

| Rule | What it flags |
|---|---|
| `portscan_unique_ports` | One source hitting 20+ different ports on a target |
| `bruteforce_repeated_flows` | 30+ connections to SSH (22) or RDP (3389) |
| `suspicious_port_usage` | Any traffic to ports 23, 4444, or 6667 |
| `dns_query_spike` | 200+ DNS queries from one host |
| `new_internal_host` | A new internal IP seen for the first time |

Thresholds can be adjusted directly in `blackbox/config.py`.

---

## Project Structure

```
blackbox/
  __init__.py     # package marker and version
  __main__.py     # entry point for python -m blackbox
  cli.py          # CLI commands
  config.py       # configuration and detection thresholds
  db.py           # SQLite schema and connection
  ingest.py       # PCAP/PCAPNG parsing, flow aggregation, DNS extraction
  detect.py       # detection rules, alert storage, incident correlation
  report.py       # report and evidence bundle generation
```

## Challeneg faced

The most significant challenge was building the ingestion pipeline in ingest.py. Specifically the flow tracking system where you're taking individual raw packets and reassembling them into meaningful conversations in real time. 
You're working at the lowest level of network data, manually peeling back every protocol layer yourself, Ethernet to IP to TCP or UDP, and any packet can be corrupt or unexpected at any point. 
On top of that you have to manage memory by evicting idle flows, handle both pcap and pcapng formats, and do a second DNS parsing pass on port 53 traffic, all inside a single packet loop. 
It was a lot of moving pieces that all had to work together correctly before a single row could be written to the database.

The way I approached it was by breaking it into smaller pieces instead of trying to solve everything at once. Each responsibility got its own function. 
The flush handles memory management, the insert handles database writing, the DNS handler handles DNS parsing, and the main packet loop just coordinates all of them. 
This way each piece could be written and understood independently before being combined. 
When bugs came up, and there were many, having isolated functions made it much easier to pinpoint exactly where the problem was rather than debugging one giant block of code.

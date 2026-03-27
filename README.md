# Network Black Box
 
Network Black Box is a small offline network tool 
It takes one or more PCAP files, summarizes the traffic into a SQLite database, runs a few simple detection rules, and then generates reports and evidence bundles.
 
It is a very lightweight version of tools like Zeek / Suricata / NetworkMiner, but implemented in Python with a CLI.

## Features
- Ingest one PCAP file or a folder of PCAPs.
- Extract flow events (connection summaries) into a flows table.
- Extract DNS events into a dns_events table.
- Store all data in a local SQLite database (`blackbox.db`).
- Run 5 basic detection rules:
  - Port scan (many different ports hit by one source).
  - Brute-force (many connections to SSH/RDP).
  - Suspicious ports (traffic to specific risky ports).
  - DNS spike (very high number of DNS queries from one host).
  - New host observed (new internal IP address).
- Create alerts and group them into incidents.

## Requirements
- Python 3.9+  
- Python packages:
  dpkt
  typer
 
## Running the tool (What I have as of current, still in progress)
From the project root, you initiaize the db and and all the tables.

pip install . (for blackbox dir)

0. Extra Info

- Help

python -m blackbox --help

1. Initializes the DB

 python -m blackbox init-db --db blackbox.db

2. Ingest PCAP files (You can go onto SQLite and review the ingested data)

python -m blackbox ingest --pcap .\pcaps\smallFlows.pcap --db blackbox.db

3. Detection rules on ingested data (WIP)

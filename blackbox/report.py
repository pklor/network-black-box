from __future__ import annotations
import csv
import json
import zipfile
from pathlib import Path
from typing import Dict, List
from .config import BlackboxConfig
from .db import get_conn   

def _write_dataset_summary(conn, out_dir: Path) -> None:
    pcaps=conn.execute("SELECT COUNT(*) AS c, MIN(ts_start) as min_ts, MAX(ts_end) AS max_ts FROM pcaps").fetchone()
    flows=conn.execute("SELECT COUNT(*) AS c FROM flows").fetchone()
    dns=conn.execute("SELECT COUNT(*) AS c FROM dns_events").fetchone()
    alerts=conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()
    incidents=conn.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()

    top_talkers=conn.execute(
        """
        SELECT src_ip, COUNT(*) AS flow_count
        FROM flows
        GROUP BY src_ip
        ORDER BY flow_count DESC
        LIMIT 10
        """
    ).fetchall()

    top_ports=conn.execute(
        """
        SELECT dst_port, COUNT(*) AS flow_count
        FROM flows
        GROUP BY dst_port
        ORDER BY flow_count DESC
        LIMIT 10
        """
    ).fetchall()

    top_domains=conn.execute(
        """
        SELECT query_name, COUNT(*) AS q_count
        FROM dns_events
        WHERE query_name IS NOT NULL
        GROUP BY query_name
        ORDER BY q_count DESC
        LIMIT 10
        """
    ).fetchall()

    alerts_by_type=conn.execute(
        "SELECT rule_name, COUNT() AS c FROM alerts GROUP BY rule_name"
    ).fetchall()

    summary_path =out_dir / "summary.txt"
    with summary_path.open("W", encoding="utf-8") as f:
        f.write("=== Network Black Box Data Summary ===\n\n")
        f.write(f"PCAP files ingested: {pcaps['c']}\n")
        f.write(f"Time range: {pcaps['min_ts']} to {pcaps['max_ts']}\n")
        f.write(f"Total flows: {flows['c']}\n")
        f.write(f"Total DNS events: {dns['c']}\n")
        f.write(f"Total alerts: {alerts['c']}\n")
        f.write(f"Total incidents: {incidents['c']}\n\n")




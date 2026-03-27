from __future__ import annotations
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional
from .config import BlackboxConfig
from .db import get_conn


@dataclass
class Alert:
    ts_start: float
    ts_end: float
    rule_name: str
    severity: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    details: str

#opens db connection and runs detections
def run_detections(db_path: Path, config: BlackboxConfig, since_alert_id: Optional[int] = None) -> None:
    conn = get_conn(db_path)
    try:
        alerts: List[Alert] = []
        alerts.extend(_rule_portscan(conn, config))
        alerts.extend(_rule_bruteforce(conn, config))
    finally:
        conn.close()

def _rule_portscan(conn: sqlite3.Connection, config: BlackboxConfig) -> List[Alert]:
    p = config.thresholds
    sql = """
        SELECT src_ip, dst_ip,
                MIN(ts_start) AS ts_start
                MAX(ts_end) AS ts_end
                COUNT(DISTINCT dst port) AS unique ports
        FROM flows
        GROUP BY src_ip, dst_ip
        HAVING unique_ports >= ?
    """

    cur = conn.execute(sql, (p.portscan_ports,))
    alerts: List[Alert] = []
    for row in cur:
        details = (
            f"Port scan suspected: {row['unique_ports']} unique destination ports "
            f"from {row['src_ip']} to {row['dst_ip']}"
        )
        alerts.append(
            Alert(
                ts_start=row["ts_start"],
                ts_end=row["ts_end"],
                rule_name="portscan_ports",
                severity="high",
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                details=details,
            )
        )
    return alerts


def _rule_bruteforce(conn: sqlite3.Connection, config: BlackboxConfig) -> List[Alert]:
    p = config.thresholds
    ports_tuple = tuple(sorted(p.bruteforce_ports))
    pholders = ",".join(["?"] * len(ports_tuple))
    sql = f"""
        SELECT src_ip, dst_ip, dst_port,
                MIN(ts_start) AS ts_start,
                MAX(ts_end) AS ts_end,
                COUNT(*) AS attempts
        FROM flows
        WHERE dst_port IN ({pholders})
        GROUP BY src_ip, dst_ip, dst_port
        HAVING attempts >= ?
    """

    cur = conn.execute(sql, (*ports_tuple, p.bruteforce_attempts))
    alerts: List[Alert] = []
    for row in cur:
        details = (
            f"Brute force suspected on port {row['dst_port']}: "
            f"{row['attempts']} flows from {row['src_ip']} to {row['dst_ip']}"
        )
        alerts.append(
            Alert(
                ts_start=row["ts_start"],
                ts_end=row["ts_end"],
                rule_name="bruteforce_repeated_flows",
                severity="high",
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                details=details,
            )
        )
    return alerts
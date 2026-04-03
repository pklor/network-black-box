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

def _rule_dns_spike(conn: sqlite3.Connection, config: BlackboxConfig) -> List[Alert]:
    t = config.thresholds
    sql = """
        SELECT src_ip,
                MIN(ts) AS ts_start,
                MAX(ts) AS ts_end,
                COUNT(*) AS queries
        FROM dns_events
        GROUP BY src_ip
        HAVING queries >= ?
    """

    cur = conn.execute(sql, (t.dns_spike_queries,))
    alerts: List[Alert] = []
    for row in cur:
        details = f"DNS spike: {row['queries']} queries from {row['src_ip']}"
        alerts.append (
            Alert (
                ts_start=row["ts_start"],
                ts_end=row["ts_end"],
                rule_name="dns-query_spike",
                severity="medium",
                src_ip=row["src_ip"],
                dst_ip=None,
                details=details,
            )
        )
    return alerts

def _rules_suspicious_ports(conn: sqlite3.Connection, config: BlackboxConfig) -> List[Alert]:
    ports_tuple = tuple(sorted(config.sus_ports))
    if not ports_tuple:
        return []
    ph = ",".join(["?"] * len(ports_tuple))
    sql = f"""
        SELECT src_ip, dst_ip, dst_port,
                MIN(ts_start) AS ts_start,
                MAX(ts_end) AS ts_end,
                COUNT(*) AS flows_count
        FROM flows
        WHERE dst_port IN ({ph})
        GROUP BY src_ip, dst_ip, dst_port
    """

    cur = conn.execute(sql, ports_tuple)
    alerts: List[Alert] = []
    for row in cur:
        details = (
            f"Suspicious port usage: {row['flows_count']} flows to port {row['dst_port']} "
            f"from {row['src_ip']} to {row['dst_ip']}"
        )
        alerts.append(
            Alert(
                ts_start=row["ts_start"],
                ts_end=["ts_end"],
                rule_name="suspicous_port_usage",
                severity="medium",
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                details=details,
            )
        )
    return alerts

def _rules_new_internals_host(conn: sqlite3.Connection, config: BlackboxConfig) -> List[Alert]:
    sql= """
        SELECT src_ip, MIN(ts_start) AS ts_first_seen, MAX(ts_end) AS ts_last_seen
        FROM flows
        GROUP BY src_ip
    """
    cur = conn.execute(sql)
    alerts: List[Alert] = []
    for row in cur:
        src_ip = row["src_ip"]
        details = f"New host observed: {src_ip} first seen at {row['ts_first_seen']}"
        alerts.append(
            Alert(
                ts_start=row["ts_first_seen"],
                ts_end=row["ts_last_seen"],
                rule_name="new_internal_host",
                severity="low",
                src_ip=src_ip,
                dst_ip=None,
                details=details,
            )
        )
    return alerts

def _store_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert]) -> None:
    for a in alerts:
        conn.execute(
            """
            INSERT INTO alerts(ts_start, ts_end, rule_name, severity, src_ip, dst_ip, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                a.ts_start,
                a.ts_end,
                a.rule_name,
                a.severity,
                a.src_ip,
                a.dst_ip,
                a.details, 
            ),
        )
from __future__ import annotations
import ipaddress
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional
from .config import BlackboxConfig
from .db import _connect


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
def run_detections(db_path: Path, config: BlackboxConfig) -> None:
    conn = _connect(db_path)
    try:
        alerts: List[Alert] = []
        alerts.extend(_rule_portscan(conn, config))
        alerts.extend(_rule_bruteforce(conn, config))
        alerts.extend(_rule_dns_spike(conn, config))
        alerts.extend(_rules_suspicious_ports(conn, config))
        alerts.extend(_rules_new_internals_host(conn, config))
        _store_alerts(conn, alerts)
        _correlate_incidents(conn)
        conn.commit()
    finally:
        conn.close()

def _rule_portscan(conn: sqlite3.Connection, config: BlackboxConfig) -> List[Alert]:
    p = config.thresholds
    sql = """
        SELECT src_ip, dst_ip,
                MIN(ts_start) AS ts_start,
                MAX(ts_end) AS ts_end,
                COUNT(DISTINCT dst_port) AS unique_ports
        FROM flows
        GROUP BY src_ip, dst_ip,
                        CAST(ts_start / ? AS INTEGER) -- time bucket
        HAVING unique_ports >= ?
    """

    cur = conn.execute(sql, (p.portscan_window_sec, p.portscan_ports))
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
        GROUP BY src_ip,
                 CAST(ts / ? AS INTEGER)
        HAVING queries >= ?
    """

    cur = conn.execute(sql, (t.dn_spike_window_sec, t.dns_spike_queries))
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
                ts_end=row["ts_end"],
                rule_name="suspicous_port_usage",
                severity="medium",
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                details=details,
            )
        )
    return alerts

def _rules_new_internals_host(conn: sqlite3.Connection, config: BlackboxConfig) -> List[Alert]:
    networks =[]
    for subnet in config.internal_subnets:
        try:
            networks.append(ipaddress.ip_network(subnet, strict=False))
        except ValueError:
            continue
    def _is_internal(ip_str: str) -> bool:
        try:
            ip=ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in n for n in networks)
    
    seen_rows=conn.execute(
        "SELECT DISTINCT src_ip FROM alerts WHERE rule_name = 'new_internal_host'"
    ).fetchall()
    already_alerted={r["src_ip"] for r in seen_rows if r["src_ip"] is not None}

    sql= """
        SELECT src_ip, MIN(ts_start) AS ts_first_seen, MAX(ts_end) AS ts_last_seen
        FROM flows
        GROUP BY src_ip
    """
    cur = conn.execute(sql)
    alerts: List[Alert] = []
    for row in cur:
        src_ip = row["src_ip"]
        if not _is_internal(src_ip):
            continue
        if src_ip in already_alerted:
            continue
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
        existing=conn.execute(
            """
            SELECT 1 FROM alerts
            WHERE rule_name = ?
              AND IFNULL(src_ip, '') = IFNULL(?, '')
              AND IFNULL(dst_ip, '') = IFNULL(?, '')
            LIMIT 1
            """,
            (a.rule_name, a.src_ip, a.dst_ip),
        ).fetchone()
        if existing is not None:
            continue
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
def _correlate_incidents(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM incident_alerts")
    conn.execute("DELETE FROM incidents")
    sql= """
        SELECT src_ip,
                MIN(ts_start) AS ts_start,
                MAX(ts_end) AS ts_end,
                COUNT(*) AS alert_count,
                GROUP_CONCAT(id) AS alert_ids
        FROM alerts
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
    """

    cur = conn.execute(sql)
    for row in cur:
        src_ip=row["src_ip"]
        ts_start=row["ts_start"]
        ts_end=row["ts_end"]
        alert_ids=[int(x) for x in row["alert_ids"].split(",")]
        summary=f"Incident for {src_ip}: {row['alert_count']} related alerts"
        severity="high" if row["alert_count"] >= 3 else "medium"

        conn.execute(
            """
            INSERT INTO incidents(ts_start, ts_end, primary_src_ip, severity, summary)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ts_start, ts_end, src_ip, severity, summary)
        )
        incident_id=conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        for aid in alert_ids:
            conn.execute(
                "INSERT OR IGNORE INTO incident_alerts(incident_id, alert_id) VALUES(?, ?)",
                (incident_id, aid)
            )
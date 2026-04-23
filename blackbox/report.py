from __future__ import annotations
import csv
import json
import zipfile
from pathlib import Path
from typing import Dict, List
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

        f.write("Top talkers (by flow count):\n")
        for row in top_talkers:
            f.write(f" {row['src_ip']}: {row['flow_count']} flows\n")
        f.write("\nTop destination ports:\n")
        for row in top_ports:
            f.write(f" {row['dst_port']}: {row['flow_count']} flows\n")
        f.write("\nTop DNS queries:\n")
        for row in top_domains:
            f.write(f" {row['query_name']}: {row['q_count']} queries\n")
        f.write("\nAlerts by type:\n")
        for row in alerts_by_type:
            f.write(f" {row['rule_name']}: {row['c']} alerts\n")

def _write_incident_reports_and_evidence(conn, out_dir: Path) -> None:
    incidents=conn.execute(
        "SELECT * FROM incidents ORDER BY id"
    ).fetchall()

    for inc in incidents:
        inc_id=inc["id"]
        base_name=f"incident_{inc_id:03d}"
        incident_dir=out_dir/base_name
        incident_dir.mkdir(exist_ok=True)

        alert_rows=conn.execute(
            """
            SELECT a.* FROM alerts a
            JOIN incident_alerts ia ON ia.alert_id = a.id
            WHERE ia.incident_id = ?
            ORDER BY a.ts_start
            """,
            (inc_id),
        ).fetchall()

        ts_start=inc["ts_start"]
        ts_end=inc["ts_end"]
        src_ip=inc["primary_src_ip"]

        flows=conn.execute(
            """
            SELECT * FROM flows
            WHERE ts_start >= ? AND ts_end <= ? AND src_ip = ?
            """,
        ).fetchall()

        dns=conn.execute(
            """ 
            SELECT * FROM dns_events
            WHERE ts >= ? AND ts <= ? AND src_ip = ?
            """,
            (ts_start, ts_end, src_ip),
        ).fetchall()

        report_path=incident_dir / "report.txt"
        with report_path.open("W", encoding="utf-8") as f:
            f.write(f"Incident {inc_id}\n")
            f.write("="*40+"\n")
            f.write(f"Time Window: {ts_start}-{ts_end}\n")
            f.write(f"Primary SOurce IP: {src_ip}\n")
            f.write(f"Severity: {inc['severity']}\n")
            f.write(f"Summary: {inc['summary']}\n\n")

            f.write("Related alerts:\n")
            for a in alert_rows:
                f.write(
                    f"-[{a['rule_name']}] {a['ts_start']} - {a['ts_end']} "
                    f"src={a['src_ip']} dst={a['dst_ip']} details={a['details']}\n"
                )

            f.write("\nAssessment:\n")
            f.write(" This activity is consistent with suspicous behavior.\n")
            f.write("\nRecommended next steps:\n")
            f.write(" - Verify whether the source IP is an authorized system.\n")
            f.write(" - Correlated with endpoint logs or authentication logs.\n")
            f.write(" - Consider blocking or further monitoring.\n")

        flows_csv = incident_dir / "flows.csv"
        with flows_csv.open("W", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "id",
                    "pcap_id",
                    "ts_start",
                    "ts_end",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "protocol",
                    "packet_count",
                    "byte_count",
                    "tcp_flags",
                ]
            )
            for r in flows:
                writer.writerow(
                    [
                    r["id"],
                    r["pcap_id"],
                    r["ts_start"],
                    r["ts_end"],
                    r["src_ip"],
                    r["dst_ip"],
                    r["src_port"],
                    r["dst_port"],
                    r["protocol"],
                    r["packet_count"],
                    r["byte_count"],
                    r["tcp_flags"],                    
                    ]
                )

        dns_csv=incident_dir/"dns.csv"
        with dns_csv.open("W", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "id",
                    "pcap_id",
                    "ts",
                    "src_ip",
                    "dst_ip",
                    "query_name",
                    "qtype",
                    "rcode",
                    "answers",
                ]
            )
            for r in dns:
                writer.writerow(
                    [
                    r["id"],
                    r["pcap_id"],
                    r["ts"],
                    r["src_ip"],
                    r["dst_ip"],
                    r["query_name"],
                    r["qtype"],
                    r["rcode"],
                    r["answers"],    
                    ]
                )
        
        alert_json_path = incident_dir / "alerts.json"
        with alert_json_path.open("W", encoding="utf-8") as f:
            json.dump(
                [
                    {
                        "id:": a["id"],
                        "ts_start": a["ts_start"],
                        "ts_end": a["ts_end"],
                        "rule_name": a["rule_name"],
                        "severity": a["serverity"],
                        "src_ip": a["src_ip"],
                        "dst_ip": a["dst_ip"],
                        "details": a["details"],
                    }
                    for a in alert_rows
                ],
                f,
                indent=2,
            )
        zip_path=out_dir/f"{base_name}.zip"
        with zipfile.ZipFile(zip_path, "W", compression=zipfile.ZIP_DEFLATED) as zf:
            for child in incident_dir.iterdir():
                zf.write(child, arcname=child.name)
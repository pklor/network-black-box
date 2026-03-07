from __future__ import annotations

import hashlib
import os
import socket

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

import dpkt

from .config import BlackboxConfig
from .db import get_conn

@dataclass
class FlowRec:
    pcap_id: int
    ts_start: float
    ts_end: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int=0
    byte_count: int=0
    tcp_flags:str=""

FlowStruc = Tuple[str, str, int, int, str]

def ingest_pcaps(db_path: Path, pcap_path: Path, config: BlackboxConfig) -> None:
    if not pcap_path.exists():
        raise SystemExit(f"Path not found: {pcap_path}")
    
    #Collect files
    files = []
    if pcap_path.is_dir():
        for root, _, filenames in os.walk(pcap_path):
            for name in filenames:
                if name.lower().endswith((".pcap", ".pcapng")):
                    files.append(Path(root) / name)
    else:
        if not pcap_path.name.lower().endswith((".pcap", ".pcapng")):
            raise SystemExit("File is incorrect")
        files.append(pcap_path)
    
    if not files:
        raise SystemExit("No Pcap found")
    
    files.sort()

    conn = get_conn(db_path)
    try:
        for file in files:
            _ingest_single_pcap(conn, file, config)
        conn.commit()
    finally:
        conn.close()

def _ingest_single_pcap(conn, file_path: Path, config: BlackboxConfig) -> None:
    filesize = file_path.stat().st_size
    sha256 = _hash_file(file_path)

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO pcaps(filename, filesize_bytes, sha256) VALUES(?, ?, ?)",
        (str(file_path), filesize, sha256),
    )
    pcap_id = cur.lastrowid
    active_flows: Dict[FlowStruc, FlowRec] ={}
    ts_first=None
    ts_last=None

    with file_path.open("rb") as f:
        pcap= dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            if ts_first is None:
                ts_first=ts
            ts_last=ts

            try:
                eth =dpkt.ethernet.Ethernet(buf)
            except (dpkt.NeedData, dpkt.UnpackError):
                continue
            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            src_ip= _format_ip(ip.src)
            dst_ip= _format_ip(ip.dst)

            proto=None
            src_port=None
            dst_port=None
            tcp_flags=""

            if isinstance(ip.data, dpkt.tcp.TCP):
                proto= "TCP"
                tcp = ip.data
                src_port= tcp.sport
                dst_port= tcp.dport
                tcp_flags= _tcp_flags_str(tcp.flags)
                payload_len = len(tcp.data)
            elif isinstance(ip.data, dpkt.udp.UDP):
                proto= "UDP"
                udp = ip.data
                src_port= udp.sport
                dst_port= udp.dport
                payload_len = len(udp.data)
            else:
                continue

            key: FlowStruc= (src_ip, dst_ip, src_port, dst_port, proto)
            fr= active_flows.get(key)
            if fr is None:
                fr = FlowRec(
                    pcap_id=pcap_id,
                    ts_start=ts,
                    ts_end=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    packet_count=1,
                    byte_count=payload_len,
                    tcp_flags=tcp_flags,
                )
                active_flows[key]=fr
            else:
                fr.ts_end=ts
                fr.packet_count+=1
                fr.byte_count+=payload_len
                if tcp_flags and tcp_flags not in fr.tcp_flags:
                    fr.tcp_flags+=tcp_flags

            if 53 in (src_port, dst_port):
                _handle_dns_packets(conn, pcap_id, ts, src_ip, dst_ip, ip.data)
            _flush_idle_flows(conn, active_flows, ts, config.flow_idle_timeout_sec)

    for fr in active_flows.values():
        _insert_flow(conn, fr)

    if ts_first is not None and ts_last is not None:
        cur.execute(
            "UPDATE pcaps SET ts_start = ?, ts_end = ? WHERE id = ?",
            (ts_first, ts_last, pcap_id),
        )

def _flush_idle_flows(conn, active_flows: Dict[FlowStruc, FlowRec], now_ts: float, timeout: int) -> None:
    to_delete = []
    for key, fr in active_flows.items():
        if now_ts - fr.ts_end > timeout:
            _insert_flow(conn, fr)
            to_delete.append(key)
    for key in to_delete:
        del active_flows[key]

def _insert_flow(conn, fr: FlowRec) -> None:
    conn.execute(
        """
        INSERT INTO flows (
            pcap_id, ts_start, ts_end, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, tcp_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            fr.pcap_id,
            fr.ts_start,
            fr.ts_end,
            fr.src_ip,
            fr.dst_ip,
            fr.src_port,
            fr.dst_port,
            fr.protocol,
            fr.packet_count,
            fr.byte_count,
            fr.tcp_flags,
        ),
    )

def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
        return h.hexdigest()
    


def _format_ip(raw: bytes) -> str:
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    elif len(raw)==16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return "unknown"

def _tcp_flags_str(flags: int) -> str:
    bits=[]
    if flags & dpkt.tcp.TH_SYN:
        bits.append("SYN")
    if flags & dpkt.tcp.TH_ACK:
        bits.append("ACK")
    if flags & dpkt.tcp.TH_FIN:
        bits.append("FIN")
    if flags & dpkt.tcp.TH_RST:
        bits.append("RST")
    return ",".join(bits)

def _handle_dns_packets(conn, pcap_id: int, ts: float, src_ip: str, dst_ip: str, l4) -> None:
    try:
        dns= dpkt.dns.DNS(l4.data)
    except (dpkt.NeedData, dpkt.UnpackError):
        return
    
    qname=None
    qtype=None
    if dns.qd:
        q=dns.qd[0]
        qname=q.name
        qtype= str(q.type)

    rcode = str(dns.rcode)
    answers=[]
    for ans in dns.an:
        if ans.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA):
            try:
                family = socket.AF_INET if ans.type == dpkt.dns.DNS_A else socket.AF_INET6
                answers.append(socket.inet_ntop(family, ans.rdata))
            except Exception:
                continue

    answers_str = ",".join(answers) if answers else None
    conn.execute(
        """
        INSERT INTO dns_events(pcap_id, ts, src_ip, dst_ip, query_name, qtype, rcode, answers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (pcap_id, ts, src_ip, dst_ip, qname, qtype, rcode, answers_str),
    )
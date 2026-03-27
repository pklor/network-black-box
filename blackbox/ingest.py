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

## store info about network flow
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

# flow key structure, used to identify the unique flows
FlowStruc = Tuple[str, str, int, int, str]

# ingestion starts here
# checks if path exists, if not, program doesn't do anything
def ingest_pcaps(db_path: Path, pcap_path: Path, config: BlackboxConfig) -> None:
    if not pcap_path.exists():
        raise SystemExit(f"Path not found: {pcap_path}")
    
    # Creates emtpy list to store pcap files
    # if path is a dir, walk through folders and subfolders
    # if ends with .pcap or .pcapng, add it to the list
    files = []
    if pcap_path.is_dir():
        for root, _, filenames in os.walk(pcap_path):
            for name in filenames:
                if name.lower().endswith((".pcap", ".pcapng")):
                    files.append(Path(root) / name)
    # for single file
    else:
        if not pcap_path.name.lower().endswith((".pcap", ".pcapng")):
            raise SystemExit("File is incorrect")
        files.append(pcap_path)
    # if no pcap file found
    if not files:
        raise SystemExit("No Pcap found")
    # sorts it alphabetically 
    files.sort()

    # connects to db 
    conn = get_conn(db_path)

    # call ingest single pcap and saves to db
    try:
        for file in files:
            _ingest_single_pcap(conn, file, config)
        conn.commit()
    finally:
        conn.close()

# ingest single pcap
def _ingest_single_pcap(conn, file_path: Path, config: BlackboxConfig) -> None:

    # gets file size
    #creates a SHA256 hash of file
    filesize = file_path.stat().st_size
    sha256 = _hash_file(file_path)

    # creates db cursor to send commands from here instead of going to SQL
    # essential bc we're running the commands from CLI
    cur = conn.cursor()

    # inserts pcap metadata into db
    cur.execute(
        "INSERT INTO pcaps(filename, filesize_bytes, sha256) VALUES(?, ?, ?)",
        (str(file_path), filesize, sha256),
    )
    # gets ID of inserted pcap rec
    pcap_id = cur.lastrowid

    # dict storing currently active flows KEY/VALUE
    active_flows: Dict[FlowStruc, FlowRec] ={}

    # tracks first and last ts
    ts_first=None
    ts_last=None

    # open pcap file and create packet reader
    with file_path.open("rb") as f:
        pcap= dpkt.pcap.Reader(f)

        # loop through each packet and store first and last ts
        for ts, buf in pcap:
            if ts_first is None:
                ts_first=ts
            ts_last=ts

            # parse Ethernet frame, if corrupted, skip packet
            try:
                eth =dpkt.ethernet.Ethernet(buf)
            except (dpkt.NeedData, dpkt.UnpackError):
                continue

            # extract ip from Ethernet frame
            ip = eth.data

            # if not IPv4 or IPv6, skip
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            # convert raw IP bytes into readable IP string
            src_ip= _format_ip(ip.src)
            dst_ip= _format_ip(ip.dst)

            proto=None
            src_port=None
            dst_port=None
            tcp_flags=""

            # if packet is TCP, extract ports, tcp flags, payload size
            if isinstance(ip.data, dpkt.tcp.TCP):
                proto= "TCP"
                tcp = ip.data
                src_port= tcp.sport
                dst_port= tcp.dport
                tcp_flags= _tcp_flags_str(tcp.flags)
                payload_len = len(tcp.data)
            # if packet is UDP
            elif isinstance(ip.data, dpkt.udp.UDP):
                proto= "UDP"
                udp = ip.data
                src_port= udp.sport
                dst_port= udp.dport
                payload_len = len(udp.data)
            else:
                continue

            # unique flow identifier
            key: FlowStruc= (src_ip, dst_ip, src_port, dst_port, proto)

            # checks if flow already exists, if new flow, creates FlowRec obj and adds to dict
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
            # if existing flows, updates end time, packet count, byte count, and TCP flags
            else:
                fr.ts_end=ts
                fr.packet_count+=1
                fr.byte_count+=payload_len
                if tcp_flags and tcp_flags not in fr.tcp_flags:
                    fr.tcp_flags+=tcp_flags

            # if port 53, process DNS packet
            if 53 in (src_port, dst_port):
                _handle_dns_packets(conn, pcap_id, ts, src_ip, dst_ip, ip.data)
            # if flow has been inactive for too long, insert into DB and remove from memory
            _flush_idle_flows(conn, active_flows, ts, config.flow_idle_timeout_sec)
    # insert remaining flows into db
    for fr in active_flows.values():
        _insert_flow(conn, fr)

    # stores first and last pacjet ts
    if ts_first is not None and ts_last is not None:
        cur.execute(
            "UPDATE pcaps SET ts_start = ?, ts_end = ? WHERE id = ?",
            (ts_first, ts_last, pcap_id),
        )

# helper func, deletes flows that have been inactive longer than timeout
def _flush_idle_flows(conn, active_flows: Dict[FlowStruc, FlowRec], now_ts: float, timeout: int) -> None:
    to_delete = []
    for key, fr in active_flows.items():
        if now_ts - fr.ts_end > timeout:
            _insert_flow(conn, fr)
            to_delete.append(key)
    for key in to_delete:
        del active_flows[key]

# helper func, inserts flow into flows table
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

# reads file in chunks and computes SHA256 hash
def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
        return h.hexdigest()
    

# converts raw bytes into IPv4 or IPv6 string
def _format_ip(raw: bytes) -> str:
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    elif len(raw)==16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return "unknown"

# converts TCP flags but into SYN, ACK, FIN, RST
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

# parses DNS packets, query name, query type, response code, ip address and then inserts into DNS events
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
import sqlite3
from pathlib import Path
from . import __version__
from .config import BlackboxConfig

# db_path.parent is the folder containing the db file, make sure the directory exists before creating the folder and any missing parent folders
# opens SQLite file at the path, if it doesn't exist, SQLite creates it
# so for this one, it lets you do row["src_ip"] instead of row[0], SQLite returns rows as tuples, but with this you can access by columns
def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS metadata (
    key Text PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pcaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    filesize_bytes INTEGER NOT NULL,
    sha256 TEXT,
    ts_start REAL,
    ts_end REAL
);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_id INTEGER,
    ts_start REAL NOT NULL,
    ts_end REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    tcp_flags TEXT,
    FOREIGN KEY (pcap_id) REFERENCES pcaps(id)
);

CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(ts_start, ts_end);
CREATE INDEX IF NOT EXISTS idx_flows_ips ON flows(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_ports ON flows(dst_port);

CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_id INTEGER,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    query_name TEXT,
    qtype TEXT,
    rcode TEXT,
    answers TEXT,
    FOREIGN KEY (pcap_id) REFERENCES pcaps(id)
);

CREATE INDEX IF NOT EXISTS idx_dns_time ON dns_events(ts);
CREATE INDEX IF NOT EXISTS idx_dns_query ON dns_events(query_name);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_start REAL NOT NULL,
    ts_end REAL NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    details TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(ts_start, ts_end);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_name);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_start REAL NOT NULL,
    ts_end REAL NOT NULL,
    primary_src_ip TEXT,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INTEGER NOT NULL,
    alert_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, alert_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id),
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

CREATE TABLE IF NOT EXISTS incident_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL,
    path TEXT NOT NULL,
    meta TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

"""
# runs the schema sql script I did above
# the _set_metadata writes key value pairs into metadat table and join is for turning ip range into a single column
def init_db(db_path: Path, config: BlackboxConfig) -> None:
    """Create tables, indexes, and store metadate"""
    conn = _connect(db_path)
    try: 
        conn.executescript(SCHEMA_SQL)
        _set_metadata(conn, "tool_version", __version__)
        _set_metadata(conn, "internal_subnets", ",".join(config.internal_subnets))
        conn.commit()
    finally:
        conn.close()

# the sql is for when nothing exists, inserts new row, and if already exists, update it
# the on conflict is when the key column violates the unique constraint and excluded.value refers to the value from the first insert
def _set_metadata(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO metadata(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value),
    )
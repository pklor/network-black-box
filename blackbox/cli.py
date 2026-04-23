from pathlib import Path
import typer
from .config import load_config
from .db import init_db
from .ingest import ingest_pcaps
from .detect import run_detections
from .report import generate_reports

app = typer.Typer(help="Network Black Box")

# This function allows the user to choose which db file to use
# Loads the programs settings, and hands both to the rest of the program so they can be reused everywhere
def _common_options(
    db: Path = typer.Option(
        Path("blackbox.db"),
        "--db",
        help="Path to SQLite db (default: blackbox.db)",
    ),
):
    config = load_config()
    return db, config

# 
@app.command("init-db")
def cmd_init_db(
    db: Path = typer.Option(
        Path("blackbox.db"),
        "--db",
        help="Path to SQLite db"
    ),
) -> None:
    """Initialize SQLite schema and metadata."""

    db_path, config = _common_options(db=db)
    init_db(db_path, config)

@app.command("ingest")
def cmd_ingest(
    pcap: Path = typer.Option(
        ..., "--pcap", help="PCAP file or directory containing PCAP files"
    ),
    db: Path = typer.Option(
        Path("blackbox.db"),
        "--db",
        help="Path to SQLite db "
    ), 
) -> None:
    """Ingesting into SQLite"""

    db_path, config = _common_options(db=db)
    ingest_pcaps(db_path, pcap, config)

@app.command("detect")
def cmd_detect(
    db: Path = typer.Option(
        Path("blakbox.db"),
        "--db",
        help="Path to SQLite db (default: blackbox.db)",
    ),
) -> None:
    
    db_path, config = _common_options(db=db)
    run_detections(db_path, config)

@app.command("report")
def cmd_report(
    out: Path=typer.Option(
        ..., "--out", help="Output directory for reports and evidence"
    ),
    db: Path=typer.Option(
        Path("blackbox.db"),
        "--db",
        help="Path to SQLite DB (default: blackbox.db)",
    ),
) -> None:
    """ Generate reports and evidence bundles"""
    db_path, _ = _common_options(db=db)
    generate_reports(db_path, out)

@app.command("run")
def cmd_run(
    pcap: Path=typer.Option(..., "--pcap", help="PCAP file or directory"),
    out: Path=typer.Option(
        ..., "--out", help="Output directory for reports and evidence"
    ),
) -> None:
    """Convenience: ingest -> detect -> report in one shot."""

    db_path, config = _common_options(db=db)
    ingest_pcaps(db_path, pcap, config)
    run_detections(db_path, config)
    generate_reports(db_path, out)
    
def main() -> None:
    app(prog_name="blackbox")


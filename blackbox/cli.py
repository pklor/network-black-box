from pathlib import Path
import typer
from . import __version__
from .config import load_config
from .db import init_db
from .ingest import ingest_pcaps

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
    config_path: Path | None = typer.Option(
        None,
        "--config",
    )
) -> None:
    """Ingesting into SQLite"""

    db_path, config = _common_options(db=db)
    ingest_pcaps(db_path, pcap, config)

@app.command("detect")



def main() -> None:
    app(prog_name="blackbox")


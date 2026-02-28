from pathlib import Path
import typer
from . import __version__
from .config import load_config
from .db import init_db

app = typer.Typer(help="Network Black Box")

# This function allows the user to choose which db file to use
# Loads the programs settings, and hands both to the rest of the program so they can be reused everywhere
def options(
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
def init_db(
    db: Path = typer.Option(
        Path("blackbox.db"),
        "--db",
        help="Path to SQLite db"
    ),
) -> None:
    """Initialize SQLite schema and metadata."""

    db


def main() -> None:
    app(prog_name="blackbox")


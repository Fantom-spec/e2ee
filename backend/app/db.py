"""SQLite access and schema initialisation (stdlib only)."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
SCHEMA_VERSION = 1


def connect(db_path: str | os.PathLike[str], *, check_same_thread: bool = True) -> sqlite3.Connection:
    """Open a connection with foreign-key enforcement and WAL enabled.

    ``check_same_thread=False`` is only for per-request connections handed
    between FastAPI worker threads; such a connection is never used by two
    threads at once.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    # SQLite does not enforce foreign keys unless asked, per connection.
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(db_path: str | os.PathLike[str]) -> None:
    """Create the schema if missing. Safe to call repeatedly; never drops data."""
    path = Path(db_path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    finally:
        conn.close()
    if str(path) != ":memory:":
        # Restrict the database file to the owning user (no-op on Windows).
        os.chmod(path, 0o600)

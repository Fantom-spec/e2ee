"""Initialise the SQLite database from configuration.

Usage (from the project root, with the venv active):
    python scripts/init_db.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.config import ConfigError, load_settings  # noqa: E402
from app.db import init_db  # noqa: E402


def main() -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    init_db(settings.db_path)
    print(f"Database ready at {settings.db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

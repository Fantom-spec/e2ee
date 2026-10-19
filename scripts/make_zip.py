"""Build a clean ZIP of the project (no venv, node_modules, .env, databases).

Usage:  python scripts/make_zip.py SecureChat_Part01.zip
"""

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "data", "dist"}
SKIP_NAMES = {".env", ".DS_Store"}
SKIP_SUFFIXES = {".pyc", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".db", ".zip", ".pem", ".key"}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_zip.py OUTPUT.zip", file=sys.stderr)
        return 2
    out = Path(sys.argv[1]).resolve()
    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(ROOT.rglob("*")):
            rel = path.relative_to(ROOT)
            if not path.is_file() or any(p in SKIP_DIRS for p in rel.parts):
                continue
            if path.name in SKIP_NAMES or path.suffix in SKIP_SUFFIXES:
                continue
            zf.write(path, Path("SecureChat") / rel)
            count += 1
    print(f"Wrote {out} ({count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

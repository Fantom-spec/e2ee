"""Heuristic scan for accidentally committed secrets, caches and databases.

Usage:  python scripts/check_secrets.py [directory]
Exit code 1 if anything suspicious is found. This is a coarse safety net, not
a substitute for a real secret scanner.
"""

import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}
BAD_NAMES = {".env"}
BAD_SUFFIXES = {".pem", ".key", ".sqlite3", ".db", ".sqlite3-wal", ".sqlite3-shm"}
PATTERNS = {
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "non-empty SECRET_KEY assignment": re.compile(r"^SECURECHAT_SECRET_KEY=\S+", re.M),
}


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts) or not path.is_file():
            continue
        rel = path.relative_to(root)
        if path.name in BAD_NAMES or path.suffix in BAD_SUFFIXES:
            findings.append(f"{rel}: forbidden file type")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern in PATTERNS.items():
            if label.startswith("non-empty") and path.name != ".env.example":
                continue
            if pattern.search(text):
                findings.append(f"{rel}: {label}")
    return findings


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    findings = scan(root)
    for f in findings:
        print(f"FOUND  {f}")
    print("OK: nothing suspicious found" if not findings else f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

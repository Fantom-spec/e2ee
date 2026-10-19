"""Shared test helpers (real SQLite files, real hashing at low cost)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app import auth_service
from app.db import connect, init_db
from app.security import PasswordHasher

NOW = 1_800_000_000
SECRET = "unit-test-only-secret-not-for-real-use-0123456789"
PASSWORD = "correct horse battery staple"


def fast_hasher() -> PasswordHasher:
    # log_n=10 keeps tests fast. Production enforces log_n >= 15 (config.py).
    return PasswordHasher(log_n=10)


class DbTestCase(unittest.TestCase):
    """Creates a fresh database file per test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmpdir = Path(self._tmp.name)
        self.db_path = str(self.tmpdir / "chat.sqlite3")
        init_db(self.db_path)
        self.hasher = fast_hasher()

    def conn(self):
        c = connect(self.db_path)
        self.addCleanup(c.close)
        return c

    def make_user(self, username: str, password: str = PASSWORD) -> str:
        c = self.conn()
        uid = auth_service.register(c, self.hasher, username, username.title(), password, NOW)
        c.commit()
        return uid

    def login(self, username: str, password: str = PASSWORD, now: int = NOW, ttl: int = 86_400):
        c = self.conn()
        result = auth_service.login(c, self.hasher, SECRET, username, password, now, ttl)
        c.commit()
        return result

    def db_bytes(self) -> bytes:
        """Raw bytes of the database and its WAL/SHM side files."""
        return b"".join(p.read_bytes() for p in sorted(self.tmpdir.glob("chat.sqlite3*")))

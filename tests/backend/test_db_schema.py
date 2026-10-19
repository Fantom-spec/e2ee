"""Schema tests against a real SQLite file: structure, constraints, persistence."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.db import SCHEMA_VERSION, connect, init_db

U1 = "11111111-1111-1111-1111-111111111111"
U2 = "22222222-2222-2222-2222-222222222222"
FORBIDDEN_COLUMN_FRAGMENTS = ("plaintext", "private", "body", "content", "secret")


def add_user(conn: sqlite3.Connection, uid: str, name: str) -> None:
    conn.execute(
        "INSERT INTO users (id, username, display_name, password_hash, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (uid, name, name.title(), "argon2-placeholder", 1_700_000_000),
    )


class SchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Path(self._tmp.name) / "nested" / "chat.sqlite3"
        init_db(self.db)

    def test_expected_tables_exist(self) -> None:
        conn = connect(self.db)
        self.addCleanup(conn.close)
        names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("users", "auth_sessions", "identity_keys", "identity_key_history",
                      "one_time_prekeys", "messages"):
            self.assertIn(table, names)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)

    def test_no_column_can_hold_plaintext_or_private_keys(self) -> None:
        conn = connect(self.db)
        self.addCleanup(conn.close)
        tables = [r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            for col in conn.execute(f"PRAGMA table_info({table})"):
                for frag in FORBIDDEN_COLUMN_FRAGMENTS:
                    self.assertNotIn(frag, col["name"].lower(), f"{table}.{col['name']}")

    def test_foreign_keys_are_enforced(self) -> None:
        conn = connect(self.db)
        self.addCleanup(conn.close)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO messages (id, sender_id, recipient_id, envelope, created_at, expires_at)"
                " VALUES (?, ?, ?, 'AAAA', 1, 2)",
                ("33333333-3333-3333-3333-333333333333", U1, U2),
            )

    def test_username_is_case_insensitively_unique(self) -> None:
        conn = connect(self.db)
        self.addCleanup(conn.close)
        add_user(conn, U1, "alice")
        with self.assertRaises(sqlite3.IntegrityError):
            add_user(conn, U2, "ALICE")

    def test_oversized_and_empty_envelopes_are_rejected(self) -> None:
        conn = connect(self.db)
        self.addCleanup(conn.close)
        add_user(conn, U1, "alice")
        add_user(conn, U2, "bobby")
        for envelope in ("", "A" * 131_073):
            with self.subTest(length=len(envelope)), self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO messages (id, sender_id, recipient_id, envelope, created_at, expires_at)"
                    " VALUES (?, ?, ?, ?, 1, 2)",
                    ("44444444-4444-4444-4444-444444444444", U1, U2, envelope),
                )

    def test_duplicate_message_id_from_same_sender_is_rejected(self) -> None:
        conn = connect(self.db)
        self.addCleanup(conn.close)
        add_user(conn, U1, "alice")
        add_user(conn, U2, "bobby")
        row = ("55555555-5555-5555-5555-555555555555", U1, U2, "AAAA", 1, 2)
        sql = ("INSERT INTO messages (id, sender_id, recipient_id, envelope, created_at, expires_at)"
               " VALUES (?, ?, ?, ?, ?, ?)")
        conn.execute(sql, row)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(sql, row)

    def test_data_survives_reopen_and_reinit(self) -> None:
        conn = connect(self.db)
        add_user(conn, U1, "alice")
        conn.commit()
        conn.close()

        init_db(self.db)  # must be idempotent and must not wipe data
        conn = connect(self.db)
        self.addCleanup(conn.close)
        row = conn.execute("SELECT username FROM users WHERE id = ?", (U1,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "alice")

    def test_deleting_a_user_cascades_to_their_messages(self) -> None:
        conn = connect(self.db)
        self.addCleanup(conn.close)
        add_user(conn, U1, "alice")
        add_user(conn, U2, "bobby")
        conn.execute(
            "INSERT INTO messages (id, sender_id, recipient_id, envelope, created_at, expires_at)"
            " VALUES ('66666666-6666-6666-6666-666666666666', ?, ?, 'AAAA', 1, 2)", (U1, U2))
        conn.execute("DELETE FROM users WHERE id = ?", (U1,))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()

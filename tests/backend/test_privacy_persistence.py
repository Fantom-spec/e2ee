"""Privacy and persistence tests (Person 2).

1. Logs and the SQLite files never contain passwords, session tokens or
   (for logs) the ciphertext envelope.
2. A message queued for an offline user survives a full server restart.
"""

import base64
import logging
import os
import tempfile
import unittest
from pathlib import Path

from app.config import load_settings

try:
    from fastapi.testclient import TestClient

    from app.main import create_app

    HAVE_WEB = True
except ImportError:  # pragma: no cover
    HAVE_WEB = False

SECRET = "unit-test-only-secret-not-for-real-use-0123456789"
ORIGIN = "http://localhost:5173"
PW = "correct horse battery staple"
BAD_PW = "wrong-password-1"


class _Capture(logging.Handler):
    """Collects every log line produced while a test runs."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.append(self.format(record))
        except Exception:  # pragma: no cover
            pass


@unittest.skipUnless(HAVE_WEB, "fastapi/httpx not installed in this environment")
class PrivacyAndPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.settings = load_settings({
            "SECURECHAT_ENV": "development",
            "SECURECHAT_SECRET_KEY": SECRET,
            "SECURECHAT_ALLOWED_ORIGINS": ORIGIN,
            "SECURECHAT_DB_PATH": str(self.dir / "privacy.sqlite3"),
            "SECURECHAT_SCRYPT_LOG_N": "10",  # fast hashing for tests only
        })

    # -- helpers
    def account(self, client, name: str) -> dict:
        r = client.post("/api/auth/register",
                        json={"username": name, "display_name": name.title(), "password": PW})
        self.assertEqual(r.status_code, 201)
        body = client.post("/api/auth/login", json={"username": name, "password": PW}).json()
        return {"id": body["user"]["id"], "token": body["token"],
                "headers": {"Authorization": f"Bearer {body['token']}"}}

    @staticmethod
    def open_socket(client, acct: dict):
        ticket = client.post("/api/ws/ticket", headers=acct["headers"]).json()["ticket"]
        return client.websocket_connect(f"/ws?ticket={ticket}", headers={"origin": ORIGIN})

    # -- 1. nothing sensitive in logs or on disk
    def test_logs_and_database_never_contain_secrets_or_ciphertext(self) -> None:
        capture = _Capture()
        root = logging.getLogger()
        old_level = root.level
        root.setLevel(logging.DEBUG)
        root.addHandler(capture)
        self.addCleanup(root.setLevel, old_level)
        self.addCleanup(root.removeHandler, capture)

        envelope = base64.b64encode(os.urandom(48)).decode()
        msg_id = "523e4567-e89b-12d3-a456-426614174000"

        with TestClient(create_app(self.settings)) as client:
            a = self.account(client, "alice")
            b = self.account(client, "bobby")
            client.post("/api/auth/login", json={"username": "alice", "password": BAD_PW})
            with self.open_socket(client, a) as wa:  # bobby is offline: message stays queued
                wa.receive_json()
                wa.send_json({"type": "send", "id": msg_id, "to": b["id"], "envelope": envelope})
                self.assertEqual(wa.receive_json()["type"], "accepted")

            blobs = b"".join(p.read_bytes() for p in self.dir.iterdir() if p.is_file())
            self.assertIn(b"alice", blobs)  # sanity check: the scan really sees the DB contents
            for secret in (PW, BAD_PW, a["token"], b["token"]):
                with self.subTest(where="database file", secret=secret[:6]):
                    self.assertNotIn(secret.encode(), blobs)

        log_text = "\n".join(capture.lines)
        for secret in (PW, BAD_PW, a["token"], b["token"], envelope):
            with self.subTest(where="logs", secret=secret[:6]):
                self.assertNotIn(secret, log_text)

    # -- 2. persistence across a server restart
    def test_queued_message_survives_server_restart(self) -> None:
        msg_id = "423e4567-e89b-12d3-a456-426614174000"
        envelope = "AAAA"

        with TestClient(create_app(self.settings)) as first_server:
            a = self.account(first_server, "alice")
            b = self.account(first_server, "bobby")
            with self.open_socket(first_server, a) as wa:
                wa.receive_json()
                wa.send_json({"type": "send", "id": msg_id, "to": b["id"], "envelope": envelope})
                self.assertEqual(wa.receive_json()["type"], "accepted")
        # first server is now fully shut down; start a brand-new one on the same database file

        with TestClient(create_app(self.settings)) as second_server:
            body = second_server.post("/api/auth/login",
                                      json={"username": "bobby", "password": PW}).json()
            b2 = {"id": body["user"]["id"],
                  "headers": {"Authorization": f"Bearer {body['token']}"}}
            with self.open_socket(second_server, b2) as wb:
                self.assertEqual(wb.receive_json(),
                                 {"type": "ready", "user_id": b["id"], "pending": 1})
                got = wb.receive_json()
                self.assertEqual((got["id"], got["from"], got["envelope"]),
                                 (msg_id, a["id"], envelope))


if __name__ == "__main__":
    unittest.main()
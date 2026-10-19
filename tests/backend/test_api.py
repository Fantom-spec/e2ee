"""End-to-end HTTP + WebSocket tests through the real FastAPI app.

Require fastapi + httpx (backend/requirements-dev.txt). They are reported as
SKIPPED, never passed, when those packages are missing. NOTE: at the time of
writing these have NEVER been executed (the authoring sandbox could not
install FastAPI); expect to fix small issues on the first run.
"""

import tempfile
import unittest
from pathlib import Path

from app.config import load_settings

try:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from app.main import create_app

    HAVE_WEB = True
except ImportError:  # pragma: no cover
    HAVE_WEB = False

SECRET = "unit-test-only-secret-not-for-real-use-0123456789"
ORIGIN = "http://localhost:5173"
PW = "correct horse battery staple"


@unittest.skipUnless(HAVE_WEB, "fastapi/httpx not installed in this environment")
class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        settings = load_settings({
            "SECURECHAT_ENV": "development",
            "SECURECHAT_SECRET_KEY": SECRET,
            "SECURECHAT_ALLOWED_ORIGINS": ORIGIN,
            "SECURECHAT_DB_PATH": str(Path(tmp.name) / "api.sqlite3"),
            "SECURECHAT_SCRYPT_LOG_N": "10",  # fast hashing for tests only
        })
        self.client = TestClient(create_app(settings))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    # -- helpers
    def register(self, name: str, password: str = PW):
        return self.client.post("/api/auth/register",
                                json={"username": name, "display_name": name.title(), "password": password})

    def login(self, name: str, password: str = PW):
        return self.client.post("/api/auth/login", json={"username": name, "password": password})

    def account(self, name: str) -> dict:
        self.assertEqual(self.register(name).status_code, 201)
        body = self.login(name).json()
        return {"id": body["user"]["id"], "token": body["token"],
                "headers": {"Authorization": f"Bearer {body['token']}"}}

    def open_socket(self, acct: dict):
        ticket = self.client.post("/api/ws/ticket", headers=acct["headers"]).json()["ticket"]
        return self.client.websocket_connect(f"/ws?ticket={ticket}", headers={"origin": ORIGIN})

    # -- accounts
    def test_register_login_me_logout(self) -> None:
        a = self.account("alice")
        me = self.client.get("/api/auth/me", headers=a["headers"])
        self.assertEqual(me.json()["username"], "alice")
        self.assertNotIn("password", me.text)
        self.assertEqual(self.client.post("/api/auth/logout", headers=a["headers"]).status_code, 204)
        self.assertEqual(self.client.get("/api/auth/me", headers=a["headers"]).status_code, 401)

    def test_duplicate_username_conflicts(self) -> None:
        self.register("alice")
        self.assertEqual(self.register("ALICE").status_code, 409)

    def test_login_failures_are_uniform(self) -> None:
        self.register("alice")
        wrong = self.login("alice", "wrong-password-1")
        unknown = self.login("nobody")
        self.assertEqual((wrong.status_code, unknown.status_code), (401, 401))
        self.assertEqual(wrong.json(), unknown.json())

    def test_unauthenticated_requests_are_denied(self) -> None:
        for method, path in (("get", "/api/auth/me"), ("get", "/api/users/search?q=al"),
                             ("post", "/api/ws/ticket"), ("post", "/api/auth/logout")):
            with self.subTest(path=path):
                self.assertEqual(getattr(self.client, method)(path).status_code, 401)
                bad = getattr(self.client, method)(path, headers={"Authorization": "Bearer nonsense"})
                self.assertEqual(bad.status_code, 401)

    def test_validation_errors_do_not_echo_the_password(self) -> None:
        r = self.register("alice", "Zq9-short")
        self.assertEqual(r.status_code, 422)
        self.assertNotIn("Zq9-short", r.text)

    def test_unknown_fields_rejected(self) -> None:
        r = self.client.post("/api/auth/register", json={
            "username": "alice", "display_name": "A", "password": PW, "is_admin": True})
        self.assertEqual(r.status_code, 422)

    def test_login_is_rate_limited_per_username(self) -> None:
        self.register("alice")
        codes = [self.login("alice", "wrong-password-1").status_code for _ in range(7)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(set(codes[5:]), {429})
        self.assertEqual(self.login("alice", "wrong-password-1").headers.get("retry-after") is not None, True)

    def test_search_returns_only_public_fields(self) -> None:
        a = self.account("alice")
        self.account("alina")
        r = self.client.get("/api/users/search?q=ali", headers=a["headers"])
        self.assertEqual([u["username"] for u in r.json()], ["alina"])
        self.assertEqual(set(r.json()[0]), {"id", "username", "display_name"})
        self.assertEqual(self.client.get("/api/users/search?q=%25", headers=a["headers"]).status_code, 422)

    def test_public_profile_lookup(self) -> None:
        a = self.account("alice")
        b = self.account("bobby")
        bob_id = b["id"]
        r = self.client.get(f"/api/users/{bob_id}", headers=a["headers"])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.json()), {"id", "username", "display_name"})
        self.assertEqual(self.client.get("/api/users/00000000-0000-4000-8000-000000000000", headers=a["headers"]).status_code, 404)
        self.assertEqual(self.client.get("/api/users/not-a-uuid", headers=a["headers"]).status_code, 422)
        self.assertEqual(self.client.get(f"/api/users/{bob_id}").status_code, 401)

    def test_security_headers(self) -> None:
        r = self.client.get("/api/health")
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(r.headers["cache-control"], "no-store")

    # -- key directory
    @staticmethod
    def key_body(identity: int = 1, otps=(1, 2)) -> dict:
        import base64

        def k(n: int) -> str:
            return base64.b64encode(bytes([n % 256]) * 33).decode()

        return {"registration_id": 77, "identity_public": k(identity),
                "signed_prekey": {"id": 3, "public": k(50), "signature": base64.b64encode(bytes([9]) * 64).decode()},
                "one_time_prekeys": [{"id": i, "public": k(100 + i)} for i in otps]}

    def test_key_endpoints_require_authentication(self) -> None:
        for method, path in (("post", "/api/keys"), ("get", "/api/keys/status"),
                             ("get", "/api/keys/123e4567-e89b-12d3-a456-426614174000"),
                             ("get", "/api/keys/123e4567-e89b-12d3-a456-426614174000/identity")):
            with self.subTest(path=path):
                self.assertEqual(getattr(self.client, method)(path).status_code, 401)

    def test_publish_then_fetch_bundle_consumes_one_time_prekeys(self) -> None:
        a, b = self.account("alice"), self.account("bobby")
        r = self.client.post("/api/keys", json=self.key_body(otps=(1,)), headers=a["headers"])
        self.assertEqual(r.json(), {"identity_changed": False, "key_version": 1, "one_time_prekeys_remaining": 1})
        self.assertEqual(self.client.get("/api/keys/status", headers=a["headers"]).json()["one_time_prekeys_remaining"], 1)
        first = self.client.get(f"/api/keys/{a['id']}", headers=b["headers"]).json()
        self.assertEqual(first["one_time_prekey"]["id"], 1)
        self.assertNotIn("private", str(first).lower())
        second = self.client.get(f"/api/keys/{a['id']}", headers=b["headers"]).json()
        self.assertIsNone(second["one_time_prekey"])
        ident = self.client.get(f"/api/keys/{a['id']}/identity", headers=b["headers"]).json()
        self.assertEqual(ident["identity_public"], first["identity_public"])

    def test_key_endpoint_error_cases(self) -> None:
        a, b = self.account("alice"), self.account("bobby")
        self.assertEqual(self.client.get(f"/api/keys/{b['id']}", headers=b["headers"]).status_code, 400)  # self
        self.assertEqual(self.client.get(f"/api/keys/{a['id']}", headers=b["headers"]).status_code, 404)  # no keys yet
        self.assertEqual(self.client.get("/api/keys/not-a-uuid", headers=b["headers"]).status_code, 422)
        bad = self.key_body()
        bad["identity_public"] = "###"
        self.assertEqual(self.client.post("/api/keys", json=bad, headers=a["headers"]).status_code, 422)

    def test_identity_change_is_reported(self) -> None:
        a = self.account("alice")
        self.client.post("/api/keys", json=self.key_body(identity=1), headers=a["headers"])
        r = self.client.post("/api/keys", json=self.key_body(identity=2, otps=(9,)), headers=a["headers"])
        self.assertEqual((r.json()["identity_changed"], r.json()["key_version"]), (True, 2))

    def test_bundle_fetch_is_rate_limited(self) -> None:
        a, b = self.account("alice"), self.account("bobby")
        self.client.post("/api/keys", json=self.key_body(), headers=a["headers"])
        codes = [self.client.get(f"/api/keys/{a['id']}", headers=b["headers"]).status_code for _ in range(32)]
        self.assertEqual(codes[:30], [200] * 30)
        self.assertEqual(set(codes[30:]), {429})

    # -- websocket
    def test_socket_requires_a_valid_single_use_ticket(self) -> None:
        a = self.account("alice")
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/ws?ticket=bogus", headers={"origin": ORIGIN}):
                pass
        ticket = self.client.post("/api/ws/ticket", headers=a["headers"]).json()["ticket"]
        with self.client.websocket_connect(f"/ws?ticket={ticket}", headers={"origin": ORIGIN}) as ws:
            self.assertEqual(ws.receive_json()["type"], "ready")
        with self.assertRaises(WebSocketDisconnect):  # ticket already used
            with self.client.websocket_connect(f"/ws?ticket={ticket}", headers={"origin": ORIGIN}):
                pass

    def test_socket_rejects_foreign_origin(self) -> None:
        a = self.account("alice")
        ticket = self.client.post("/api/ws/ticket", headers=a["headers"]).json()["ticket"]
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect(f"/ws?ticket={ticket}", headers={"origin": "https://evil.example"}):
                pass

    def test_two_users_exchange_opaque_envelopes_and_acknowledge(self) -> None:
        a, b = self.account("alice"), self.account("bobby")
        envelope = "ZHVtbXktY2lwaGVydGV4dA=="
        msg_id = "123e4567-e89b-12d3-a456-426614174000"
        with self.open_socket(a) as wa, self.open_socket(b) as wb:
            self.assertEqual(wa.receive_json()["type"], "ready")
            self.assertEqual(wb.receive_json()["type"], "ready")
            wa.send_json({"type": "send", "id": msg_id, "to": b["id"], "envelope": envelope})
            self.assertEqual(wa.receive_json(), {"type": "accepted", "id": msg_id, "duplicate": False})
            got = wb.receive_json()
            self.assertEqual((got["from"], got["envelope"]), (a["id"], envelope))
            wb.send_json({"type": "ack", "id": msg_id, "from": a["id"]})
            self.assertEqual(wa.receive_json(), {"type": "delivered", "id": msg_id})

    def test_offline_message_delivered_after_reconnect(self) -> None:
        a, b = self.account("alice"), self.account("bobby")
        msg_id = "223e4567-e89b-12d3-a456-426614174000"
        with self.open_socket(a) as wa:
            wa.receive_json()
            wa.send_json({"type": "send", "id": msg_id, "to": b["id"], "envelope": "AAAA"})
            self.assertEqual(wa.receive_json()["type"], "accepted")
        with self.open_socket(b) as wb:
            self.assertEqual(wb.receive_json(), {"type": "ready", "user_id": b["id"], "pending": 1})
            self.assertEqual(wb.receive_json()["id"], msg_id)

    def test_spoofed_sender_field_is_rejected_over_the_wire(self) -> None:
        a, b, c = self.account("alice"), self.account("bobby"), self.account("carol")
        with self.open_socket(a) as wa:
            wa.receive_json()
            wa.send_json({"type": "send", "id": "323e4567-e89b-12d3-a456-426614174000",
                          "to": b["id"], "envelope": "AAAA", "from": c["id"]})
            self.assertEqual(wa.receive_json()["code"], "unexpected_field")

    def test_logout_disconnects_live_socket(self) -> None:
        a = self.account("alice")
        with self.open_socket(a) as wa:
            wa.receive_json()
            self.client.post("/api/auth/logout", headers=a["headers"])
            with self.assertRaises(WebSocketDisconnect) as cm:
                wa.receive_json()
            self.assertEqual(cm.exception.code, 4401)


if __name__ == "__main__":
    unittest.main()

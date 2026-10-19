"""Relay behaviour with real SQLite, real sessions and in-memory fake sockets.

Envelopes here are dummy base64 blobs: Stage 2 tests the relay's routing,
authorization and queueing, not encryption (that arrives in Stage 3).
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from app import auth_service, repo
from app.db import connect, init_db
from app.relay import (
    CLOSE_MESSAGE_TOO_BIG,
    CLOSE_UNAUTHENTICATED,
    Hub,
    RelayLimits,
    RelayService,
)
from app.security import new_id
from helpers import NOW, PASSWORD, SECRET, fast_hasher


def blob(text: str = "dummy-ciphertext") -> str:
    return base64.b64encode(text.encode()).decode()


class FakeConn:
    def __init__(self, session_id: str, fail_sends: bool = False) -> None:
        self.session_id = session_id
        self.sent: list[dict] = []
        self.closed: int | None = None
        self.fail_sends = fail_sends

    async def send_json(self, obj: dict) -> None:
        if self.fail_sends:
            raise ConnectionError("simulated broken socket")
        self.sent.append(obj)

    async def close(self, code: int) -> None:
        self.closed = code

    def of_type(self, kind: str) -> list[dict]:
        return [f for f in self.sent if f["type"] == kind]


class RelayTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = str(Path(self._tmp.name) / "chat.sqlite3")
        init_db(self.db_path)
        self.now = NOW
        self.limits = RelayLimits(max_envelope_chars=2_000, max_pending_per_recipient=50,
                                  message_ttl_seconds=60, sends_per_window=100)
        self.hub = Hub(max_per_user=3)
        self.relay = self._make_relay(self.limits)
        self.hasher = fast_hasher()

    def _make_relay(self, limits: RelayLimits) -> RelayService:
        return RelayService(self.db_path, self.hub, limits, clock=lambda: self.now)

    def _db(self):
        c = connect(self.db_path)
        self.addCleanup(c.close)
        return c

    def user(self, name: str):
        """Create an account and a real session; return (AuthContext, FakeConn)."""
        c = self._db()
        auth_service.register(c, self.hasher, name, name.title(), PASSWORD, NOW)
        c.commit()
        result = auth_service.login(c, self.hasher, SECRET, name, PASSWORD, NOW, 86_400)
        c.commit()
        return result.context, FakeConn(result.context.session_id)

    async def online(self, name: str):
        ctx, conn = self.user(name)
        self.assertTrue(self.hub.register(ctx.user_id, conn))
        await self.relay.on_connect(ctx, conn)
        return ctx, conn

    async def send(self, ctx, conn, to_id: str, envelope: str | None = None, msg_id: str | None = None, **extra):
        frame = {"type": "send", "id": msg_id or new_id(), "to": to_id,
                 "envelope": envelope or blob(), **extra}
        await self.relay.on_frame(ctx, conn, json.dumps(frame))
        return frame["id"]

    def row(self, sender_id: str, msg_id: str):
        return self._db().execute("SELECT * FROM messages WHERE sender_id = ? AND id = ?",
                                  (sender_id, msg_id)).fetchone()


class DeliveryTests(RelayTestCase):
    async def test_online_delivery_uses_server_derived_sender(self) -> None:
        a, ca = await self.online("alice")
        b, cb = await self.online("bobby")
        env = blob("hello-bob")
        mid = await self.send(a, ca, b.user_id, env)
        self.assertEqual(ca.of_type("accepted"), [{"type": "accepted", "id": mid, "duplicate": False}])
        (msg,) = cb.of_type("message")
        self.assertEqual((msg["id"], msg["from"], msg["envelope"]), (mid, a.user_id, env))

    async def test_offline_message_is_queued_and_delivered_on_connect(self) -> None:
        a, ca = await self.online("alice")
        b, cb = self.user("bobby")
        mid = await self.send(a, ca, b.user_id)
        self.assertIsNotNone(self.row(a.user_id, mid))
        self.hub.register(b.user_id, cb)
        await self.relay.on_connect(b, cb)
        self.assertEqual(cb.of_type("ready")[0]["pending"], 1)
        self.assertEqual(cb.of_type("message")[0]["id"], mid)

    async def test_ack_erases_ciphertext_notifies_sender_and_is_idempotent(self) -> None:
        a, ca = await self.online("alice")
        b, cb = await self.online("bobby")
        mid = await self.send(a, ca, b.user_id, blob("secret-bytes"))
        ack = json.dumps({"type": "ack", "id": mid, "from": a.user_id})
        await self.relay.on_frame(b, cb, ack)
        await self.relay.on_frame(b, cb, ack)  # duplicate ack
        self.assertEqual(ca.of_type("delivered"), [{"type": "delivered", "id": mid}])
        row = self.row(a.user_id, mid)
        self.assertEqual(row["envelope"], repo.TOMBSTONE)
        self.assertIsNotNone(row["delivered_at"])
        # Nothing left to redeliver after reconnect.
        cb2 = FakeConn(b.session_id)
        await self.relay.on_connect(b, cb2)
        self.assertEqual(cb2.of_type("ready")[0]["pending"], 0)

    async def test_unacknowledged_message_is_redelivered_on_reconnect(self) -> None:
        a, ca = await self.online("alice")
        b, cb = await self.online("bobby")
        mid = await self.send(a, ca, b.user_id)
        self.hub.unregister(b.user_id, cb)
        cb2 = FakeConn(b.session_id)
        await self.relay.on_connect(b, cb2)
        self.assertEqual([m["id"] for m in cb2.of_type("message")], [mid])  # at-least-once

    async def test_messages_arrive_in_send_order(self) -> None:
        a, ca = await self.online("alice")
        b, cb = self.user("bobby")
        ids = [await self.send(a, ca, b.user_id, blob(str(i))) for i in range(5)]
        await self.relay.on_connect(b, cb)
        self.assertEqual([m["id"] for m in cb.of_type("message")], ids)

    async def test_messages_expire(self) -> None:
        a, ca = await self.online("alice")
        b, cb = self.user("bobby")
        await self.send(a, ca, b.user_id)
        self.now += 61  # past the 60 s test TTL
        await self.relay.on_connect(b, cb)
        self.assertEqual(cb.of_type("ready")[0]["pending"], 0)
        c = self._db()
        self.assertEqual(repo.purge_expired_messages(c, self.now), 1)


class IsolationAndAuthorizationTests(RelayTestCase):
    async def test_third_user_receives_nothing(self) -> None:
        a, ca = await self.online("alice")
        b, _ = await self.online("bobby")
        _, cc = await self.online("carol")
        await self.send(a, ca, b.user_id)
        self.assertEqual(cc.of_type("message"), [])

    async def test_client_supplied_sender_is_rejected(self) -> None:
        a, ca = await self.online("alice")
        b, cb = await self.online("bobby")
        c, _ = await self.online("carol")
        mid = new_id()
        await self.send(a, ca, b.user_id, msg_id=mid, **{"from": c.user_id})
        self.assertEqual(ca.of_type("error")[0]["code"], "unexpected_field")
        self.assertEqual(cb.of_type("message"), [])
        self.assertIsNone(self.row(a.user_id, mid))
        self.assertIsNone(self.row(c.user_id, mid))

    async def test_only_the_recipient_can_acknowledge(self) -> None:
        a, ca = await self.online("alice")
        b, cb = await self.online("bobby")
        c, cc = await self.online("carol")
        mid = await self.send(a, ca, b.user_id, blob("keep-me"))
        await self.relay.on_frame(c, cc, json.dumps({"type": "ack", "id": mid, "from": a.user_id}))
        await self.relay.on_frame(a, ca, json.dumps({"type": "ack", "id": mid, "from": a.user_id}))
        row = self.row(a.user_id, mid)
        self.assertIsNone(row["delivered_at"])
        self.assertEqual(row["envelope"], blob("keep-me"))
        self.assertEqual(ca.of_type("delivered"), [])

    async def test_unknown_or_self_recipient_rejected(self) -> None:
        a, ca = await self.online("alice")
        await self.send(a, ca, new_id())
        await self.send(a, ca, a.user_id)
        self.assertEqual([e["code"] for e in ca.of_type("error")], ["invalid_recipient"] * 2)

    async def test_revoked_session_is_disconnected_on_next_frame(self) -> None:
        a, ca = await self.online("alice")
        b, _ = await self.online("bobby")
        c = self._db()
        auth_service.logout(c, a.session_id, NOW + 1)
        c.commit()
        mid = await self.send(a, ca, b.user_id)
        self.assertEqual(ca.closed, CLOSE_UNAUTHENTICATED)
        self.assertIsNone(self.row(a.user_id, mid))

    async def test_expired_session_is_disconnected(self) -> None:
        a, ca = await self.online("alice")
        b, _ = await self.online("bobby")
        self.now += 86_401
        await self.send(a, ca, b.user_id)
        self.assertEqual(ca.closed, CLOSE_UNAUTHENTICATED)

    async def test_hub_close_session_closes_only_that_session(self) -> None:
        a, ca = await self.online("alice")
        _, cb = await self.online("bobby")
        await self.hub.close_session(a.session_id)
        self.assertEqual(ca.closed, CLOSE_UNAUTHENTICATED)
        self.assertIsNone(cb.closed)

    async def test_connection_limit_per_user(self) -> None:
        a, _ = await self.online("alice")
        extra = [FakeConn(a.session_id) for _ in range(3)]
        results = [self.hub.register(a.user_id, c) for c in extra]
        self.assertEqual(results, [True, True, False])  # 1 existing + 2 = limit of 3


class ValidationTests(RelayTestCase):
    async def test_malformed_frames_get_errors_and_store_nothing(self) -> None:
        a, ca = await self.online("alice")
        b, _ = await self.online("bobby")
        for raw in ("not json", "[]", "42", '{"no":"type"}', '{"type":5}', '{"type":"bogus"}'):
            await self.relay.on_frame(a, ca, raw)
        self.assertEqual([e["code"] for e in ca.of_type("error")],
                         ["bad_frame"] * 5 + ["unknown_type"])
        self.assertEqual(self._db().execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)

    async def test_invalid_fields_are_rejected(self) -> None:
        a, ca = await self.online("alice")
        b, _ = await self.online("bobby")
        good = {"type": "send", "id": new_id(), "to": b.user_id, "envelope": blob()}
        bad_variants = [
            {**good, "id": "nope"}, {**good, "to": "nope"}, {**good, "envelope": "***"},
            # Over the 2000-char envelope limit but under the frame limit, so it
            # gets an error frame (a frame over the limit closes the socket instead).
            {**good, "envelope": ""}, {**good, "envelope": blob("x" * 1800)},
            {**good, "envelope": 12}, {k: v for k, v in good.items() if k != "envelope"},
        ]
        for frame in bad_variants:
            await self.relay.on_frame(a, ca, json.dumps(frame))
        self.assertEqual({e["code"] for e in ca.of_type("error")}, {"invalid_message"})
        self.assertEqual(len(ca.of_type("error")), len(bad_variants))
        self.assertEqual(self._db().execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)

    async def test_oversized_frame_closes_connection(self) -> None:
        a, ca = await self.online("alice")
        await self.relay.on_frame(a, ca, " " * (self.limits.max_frame_chars + 1))
        self.assertEqual(ca.closed, CLOSE_MESSAGE_TOO_BIG)

    async def test_ack_validation(self) -> None:
        a, ca = await self.online("alice")
        await self.relay.on_frame(a, ca, json.dumps({"type": "ack", "id": "x", "from": "y"}))
        await self.relay.on_frame(a, ca, json.dumps({"type": "ack", "id": new_id(), "from": new_id(), "extra": 1}))
        self.assertEqual([e["code"] for e in ca.of_type("error")], ["invalid_ack", "unexpected_field"])

    async def test_ping(self) -> None:
        a, ca = await self.online("alice")
        await self.relay.on_frame(a, ca, '{"type":"ping"}')
        self.assertEqual(ca.of_type("pong"), [{"type": "pong"}])


class ReliabilityAndAbuseTests(RelayTestCase):
    async def test_duplicate_submission_is_idempotent_even_after_delivery(self) -> None:
        a, ca = await self.online("alice")
        b, cb = await self.online("bobby")
        mid = new_id()
        await self.send(a, ca, b.user_id, msg_id=mid)
        await self.send(a, ca, b.user_id, msg_id=mid)
        self.assertEqual([m["duplicate"] for m in ca.of_type("accepted")], [False, True])
        self.assertEqual(len(cb.of_type("message")), 1)
        await self.relay.on_frame(b, cb, json.dumps({"type": "ack", "id": mid, "from": a.user_id}))
        await self.send(a, ca, b.user_id, msg_id=mid)  # replay after ack
        self.assertTrue(ca.of_type("accepted")[-1]["duplicate"])
        self.assertEqual(len(cb.of_type("message")), 1)

    async def test_same_message_id_from_different_senders_does_not_collide(self) -> None:
        a, ca = await self.online("alice")
        b, cb = await self.online("bobby")
        c, cc = await self.online("carol")
        mid = new_id()
        await self.send(a, ca, c.user_id, msg_id=mid)
        await self.send(b, cb, c.user_id, msg_id=mid)
        self.assertEqual({m["from"] for m in cc.of_type("message")}, {a.user_id, b.user_id})

    async def test_send_rate_limit(self) -> None:
        relay = self._make_relay(RelayLimits(2_000, 50, 60, sends_per_window=3, send_window_seconds=60))
        self.relay = relay
        a, ca = await self.online("alice")
        b, _ = await self.online("bobby")
        for _ in range(5):
            await self.send(a, ca, b.user_id)
        self.assertEqual(len(ca.of_type("accepted")), 3)
        self.assertEqual([e["code"] for e in ca.of_type("error")], ["rate_limited"] * 2)

    async def test_queue_cap_per_recipient(self) -> None:
        self.relay = self._make_relay(RelayLimits(2_000, 2, 60, sends_per_window=100))
        a, ca = await self.online("alice")
        b, _ = self.user("bobby")
        for _ in range(3):
            await self.send(a, ca, b.user_id)
        self.assertEqual(len(ca.of_type("accepted")), 2)
        self.assertEqual(ca.of_type("error")[0]["code"], "queue_full")

    async def test_failed_push_is_logged_and_message_stays_queued(self) -> None:
        a, ca = await self.online("alice")
        b, _ = self.user("bobby")
        broken = FakeConn(b.session_id, fail_sends=True)
        self.hub.register(b.user_id, broken)
        with self.assertLogs("securechat.relay", level="WARNING") as logs:
            mid = await self.send(a, ca, b.user_id)
        self.assertEqual(ca.of_type("accepted")[0]["id"], mid)
        self.assertIsNone(self.row(a.user_id, mid)["delivered_at"])
        self.assertNotIn("dummy-ciphertext", "".join(logs.output))
        self.assertNotIn(blob(), "".join(logs.output))

    async def test_server_state_contains_only_what_the_client_sent(self) -> None:
        """The relay stores the opaque envelope verbatim and nothing derived from it."""
        a, ca = await self.online("alice")
        b, _ = self.user("bobby")
        env = blob("opaque-bytes-the-server-cannot-interpret")
        mid = await self.send(a, ca, b.user_id, env)
        row = self.row(a.user_id, mid)
        self.assertEqual(row["envelope"], env)
        self.assertEqual(set(row.keys()), {"id", "sender_id", "recipient_id", "envelope",
                                           "created_at", "expires_at", "delivered_at"})


if __name__ == "__main__":
    unittest.main()

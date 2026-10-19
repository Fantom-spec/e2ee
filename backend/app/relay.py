"""WebSocket relay logic, independent of FastAPI so it can be tested directly.

The relay moves OPAQUE ciphertext envelopes between authenticated users. It
never parses or interprets an envelope. Security-relevant rules enforced here:

* The sender identity always comes from the authenticated session, never from
  the frame. A frame that tries to supply `from` is rejected.
* Every frame re-checks that the session is still valid (logout/expiry).
* Strict schema: unknown fields, bad UUIDs, non-base64 or oversized envelopes
  are rejected before anything is stored.
* Per-user send rate limit and per-recipient queue cap.
* Delivery is at-least-once: an unacknowledged message is re-sent on the
  recipient's next connection, so clients MUST deduplicate by (from, id).
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol, TypeVar

from . import repo
from .auth_service import AuthContext
from .db import connect
from .ratelimit import RateLimiter
from .validation import ValidationError, validate_envelope, validate_uuid

logger = logging.getLogger("securechat.relay")
T = TypeVar("T")

CLOSE_MESSAGE_TOO_BIG = 1009
CLOSE_POLICY = 1008
CLOSE_UNAUTHENTICATED = 4401

_SEND_FIELDS = {"type", "id", "to", "envelope"}
_ACK_FIELDS = {"type", "id", "from"}


class Connection(Protocol):
    session_id: str

    async def send_json(self, obj: dict[str, Any]) -> None: ...
    async def close(self, code: int) -> None: ...


class Hub:
    """Registry of live connections, keyed by user."""

    def __init__(self, max_per_user: int) -> None:
        self.max_per_user = max_per_user
        self._by_user: dict[str, list[Connection]] = {}

    def register(self, user_id: str, conn: Connection) -> bool:
        conns = self._by_user.setdefault(user_id, [])
        if len(conns) >= self.max_per_user:
            return False
        conns.append(conn)
        return True

    def unregister(self, user_id: str, conn: Connection) -> None:
        conns = self._by_user.get(user_id, [])
        if conn in conns:
            conns.remove(conn)
        if not conns:
            self._by_user.pop(user_id, None)

    def connections_for(self, user_id: str) -> list[Connection]:
        return list(self._by_user.get(user_id, []))

    def is_online(self, user_id: str) -> bool:
        return bool(self._by_user.get(user_id))

    async def close_session(self, session_id: str, code: int = CLOSE_UNAUTHENTICATED) -> None:
        for conns in list(self._by_user.values()):
            for conn in list(conns):
                if conn.session_id == session_id:
                    await conn.close(code)


@dataclass(frozen=True)
class RelayLimits:
    max_envelope_chars: int
    max_pending_per_recipient: int
    message_ttl_seconds: int
    sends_per_window: int = 30
    send_window_seconds: float = 10.0

    @property
    def max_frame_chars(self) -> int:
        return self.max_envelope_chars + 1024  # envelope plus JSON framing


def _run(db_path: str, fn: Callable[[sqlite3.Connection], T]) -> T:
    conn = connect(db_path)
    try:
        result = fn(conn)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class RelayService:
    def __init__(self, db_path: str, hub: Hub, limits: RelayLimits,
                 clock: Callable[[], float] = time.time) -> None:
        self.db_path = db_path
        self.hub = hub
        self.limits = limits
        self._clock = clock
        self._send_limiter = RateLimiter(limits.sends_per_window, limits.send_window_seconds)

    def _now(self) -> int:
        return int(self._clock())

    async def _db(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        # SQLite calls are short but blocking; run them off the event loop.
        return await asyncio.to_thread(_run, self.db_path, fn)

    @staticmethod
    async def _error(conn: Connection, code: str, msg_id: Optional[str] = None) -> None:
        frame: dict[str, Any] = {"type": "error", "code": code}
        if msg_id is not None:
            frame["id"] = msg_id
        await conn.send_json(frame)

    @staticmethod
    def _frame(row: sqlite3.Row) -> dict[str, Any]:
        return {"type": "message", "id": row["id"], "from": row["sender_id"],
                "envelope": row["envelope"], "created_at": row["created_at"]}

    async def on_connect(self, ctx: AuthContext, conn: Connection) -> None:
        now = self._now()
        pending = await self._db(lambda c: repo.pending_for(c, ctx.user_id, now))
        await conn.send_json({"type": "ready", "user_id": ctx.user_id, "pending": len(pending)})
        for row in pending:
            await conn.send_json(self._frame(row))

    async def on_frame(self, ctx: AuthContext, conn: Connection, raw: str) -> None:
        if len(raw) > self.limits.max_frame_chars:
            await conn.close(CLOSE_MESSAGE_TOO_BIG)
            return

        now = self._now()
        if not await self._db(lambda c: repo.session_is_active(c, ctx.session_id, now)):
            await conn.close(CLOSE_UNAUTHENTICATED)
            return

        try:
            frame = json.loads(raw)
        except ValueError:
            await self._error(conn, "bad_frame")
            return
        if not isinstance(frame, dict) or not isinstance(frame.get("type"), str):
            await self._error(conn, "bad_frame")
            return

        kind = frame["type"]
        if kind == "ping":
            await conn.send_json({"type": "pong"})
        elif kind == "send":
            await self._handle_send(ctx, conn, frame, now)
        elif kind == "ack":
            await self._handle_ack(ctx, conn, frame, now)
        else:
            await self._error(conn, "unknown_type")

    async def _handle_send(self, ctx: AuthContext, conn: Connection, frame: dict[str, Any], now: int) -> None:
        raw_id = frame.get("id") if isinstance(frame.get("id"), str) else None
        if set(frame) - _SEND_FIELDS:
            # Includes any attempt to supply `from`: identity is never client-supplied.
            await self._error(conn, "unexpected_field", raw_id)
            return
        try:
            msg_id = validate_uuid(frame.get("id"), "id")
            recipient_id = validate_uuid(frame.get("to"), "to")
            envelope = validate_envelope(frame.get("envelope"), self.limits.max_envelope_chars)
        except ValidationError:
            await self._error(conn, "invalid_message", raw_id)
            return
        if recipient_id == ctx.user_id:
            await self._error(conn, "invalid_recipient", msg_id)
            return
        if not self._send_limiter.allow(ctx.user_id):
            await self._error(conn, "rate_limited", msg_id)
            return

        expires_at = now + self.limits.message_ttl_seconds

        def store(c: sqlite3.Connection) -> str:
            target = repo.get_user(c, recipient_id)
            if target is None or target["disabled"]:
                return "invalid_recipient"
            if repo.count_pending(c, recipient_id, now) >= self.limits.max_pending_per_recipient:
                return "queue_full"
            inserted = repo.enqueue_message(c, msg_id, ctx.user_id, recipient_id, envelope, now, expires_at)
            return "queued" if inserted else "duplicate"

        outcome = await self._db(store)
        if outcome in ("invalid_recipient", "queue_full"):
            await self._error(conn, outcome, msg_id)
            return

        await conn.send_json({"type": "accepted", "id": msg_id, "duplicate": outcome == "duplicate"})
        if outcome == "queued":
            await self._push(recipient_id, {"type": "message", "id": msg_id, "from": ctx.user_id,
                                            "envelope": envelope, "created_at": now})

    async def _handle_ack(self, ctx: AuthContext, conn: Connection, frame: dict[str, Any], now: int) -> None:
        raw_id = frame.get("id") if isinstance(frame.get("id"), str) else None
        if set(frame) - _ACK_FIELDS:
            await self._error(conn, "unexpected_field", raw_id)
            return
        try:
            msg_id = validate_uuid(frame.get("id"), "id")
            sender_id = validate_uuid(frame.get("from"), "from")
        except ValidationError:
            await self._error(conn, "invalid_ack", raw_id)
            return
        # Scoped by recipient=ctx.user_id: you can only acknowledge your own mail.
        changed = await self._db(lambda c: repo.mark_delivered(c, ctx.user_id, sender_id, msg_id, now))
        if changed:
            await self._push(sender_id, {"type": "delivered", "id": msg_id})

    async def _push(self, user_id: str, frame: dict[str, Any]) -> None:
        for target in self.hub.connections_for(user_id):
            try:
                await target.send_json(frame)
            except Exception:
                # Never log frame contents. The message stays queued and is
                # redelivered on the next connection.
                logger.warning("push to a connection of user %s failed", user_id, exc_info=True)

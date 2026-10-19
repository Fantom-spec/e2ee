"""Short-lived, single-use tickets for authenticating WebSocket connections.

Browsers cannot set an Authorization header on a WebSocket handshake. Instead
the client obtains a ticket over authenticated HTTPS and presents it once in
the WebSocket URL. The long-lived session token never appears in a URL (URLs
end up in access logs); a leaked ticket is useless after one use or 30 s.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Callable, Optional

TICKET_TTL_SECONDS = 30
_MAX_OUTSTANDING = 10_000


class TicketStore:
    def __init__(self, ttl: float = TICKET_TTL_SECONDS, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl
        self._clock = clock
        self._items: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(ticket: str) -> str:
        return hashlib.sha256(ticket.encode("utf-8")).hexdigest()

    def issue(self, user_id: str, session_id: str) -> str:
        ticket = secrets.token_urlsafe(24)
        with self._lock:
            now = self._clock()
            self._items = {k: v for k, v in self._items.items() if v[2] > now}
            if len(self._items) >= _MAX_OUTSTANDING:
                raise RuntimeError("too many outstanding tickets")
            self._items[self._key(ticket)] = (user_id, session_id, now + self.ttl)
        return ticket

    def consume(self, ticket: str) -> Optional[tuple[str, str]]:
        """Return (user_id, session_id) once, then forget the ticket."""
        if not ticket or len(ticket) > 128:
            return None
        with self._lock:
            item = self._items.pop(self._key(ticket), None)
            if item is None or item[2] <= self._clock():
                return None
            return item[0], item[1]

"""In-memory sliding-window rate limiter.

Adequate for a single-process demo server. State is lost on restart and is
not shared between processes; a multi-process deployment would need a shared
store. Limits are a speed bump against password guessing and flooding, not a
substitute for strong passwords.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from typing import Callable, Deque


class RateLimiter:
    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_events < 1 or window_seconds <= 0:
            raise ValueError("invalid rate limit")
        self.max_events = max_events
        self.window = window_seconds
        self._clock = clock
        self._events: dict[str, Deque[float]] = {}
        self._lock = threading.Lock()
        self._calls = 0

    def _prune(self, key: str, now: float) -> Deque[float]:
        q = self._events.setdefault(key, deque())
        cutoff = now - self.window
        while q and q[0] <= cutoff:
            q.popleft()
        return q

    def allow(self, key: str) -> bool:
        """Record an attempt; return False (without recording) if over the limit."""
        with self._lock:
            now = self._clock()
            q = self._prune(key, now)
            self._calls += 1
            if self._calls % 1000 == 0:
                self._collect(now)
            if len(q) >= self.max_events:
                return False
            q.append(now)
            return True

    def retry_after(self, key: str) -> int:
        with self._lock:
            now = self._clock()
            q = self._prune(key, now)
            if len(q) < self.max_events:
                return 0
            return max(1, math.ceil(q[0] + self.window - now))

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    def _collect(self, now: float) -> None:
        """Drop keys whose window has fully expired so memory stays bounded."""
        cutoff = now - self.window
        for key in [k for k, q in self._events.items() if not q or q[-1] <= cutoff]:
            del self._events[key]

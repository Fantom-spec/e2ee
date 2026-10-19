"""Wiring of long-lived server objects (kept on app.state)."""

from __future__ import annotations

from dataclasses import dataclass

from .config import Settings
from .ratelimit import RateLimiter
from .relay import Hub, RelayLimits, RelayService
from .security import PasswordHasher
from .tickets import TicketStore


@dataclass
class Services:
    settings: Settings
    hasher: PasswordHasher
    register_limiter: RateLimiter      # per client IP
    login_ip_limiter: RateLimiter      # per client IP
    login_user_limiter: RateLimiter    # per target username (slows password guessing)
    keys_fetch_limiter: RateLimiter    # per requesting user: bounds one-time-prekey draining
    tickets: TicketStore
    hub: Hub
    relay: RelayService


def build_services(settings: Settings) -> Services:
    hub = Hub(settings.max_connections_per_user)
    limits = RelayLimits(
        max_envelope_chars=settings.max_envelope_bytes,
        max_pending_per_recipient=settings.max_pending_per_recipient,
        message_ttl_seconds=settings.message_ttl_seconds,
    )
    return Services(
        settings=settings,
        hasher=PasswordHasher(log_n=settings.scrypt_log_n),
        register_limiter=RateLimiter(10, 3600),
        login_ip_limiter=RateLimiter(30, 300),
        login_user_limiter=RateLimiter(5, 300),
        keys_fetch_limiter=RateLimiter(30, 600),
        tickets=TicketStore(),
        hub=hub,
        relay=RelayService(str(settings.db_path), hub, limits),
    )

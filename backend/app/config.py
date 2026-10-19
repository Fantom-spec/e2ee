"""Environment-driven configuration that fails safe.

Security decisions:
* There is no default for the secret key: the server refuses to start without
  a strong one, instead of silently running with a guessable value.
* CORS origins must be listed explicitly. A wildcard is rejected outright.
* The default environment is "production", so API docs stay disabled and
  non-HTTPS origins are rejected unless the operator opts in to "development".
* Nothing here hardcodes hosts or tunnel URLs; everything comes from env vars.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

MIN_SECRET_LEN = 32
_PLACEHOLDER_PREFIXES = ("change-me", "changeme", "replace-me", "your-secret")
_VALID_ENVS = ("development", "production")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or unsafe."""


@dataclass(frozen=True)
class Settings:
    env: str
    # repr=False keeps the secret out of logs and tracebacks.
    secret_key: str = field(repr=False)
    db_path: Path
    allowed_origins: tuple[str, ...]
    session_ttl_seconds: int
    message_ttl_seconds: int
    max_envelope_bytes: int
    max_pending_per_recipient: int
    max_connections_per_user: int
    scrypt_log_n: int
    # Only trust CF-Connecting-IP when the server is reachable exclusively
    # through Cloudflare Tunnel; otherwise any client could spoof its IP and
    # dodge per-IP rate limits.
    trust_cf_connecting_ip: bool

    @property
    def is_development(self) -> bool:
        return self.env == "development"


def _get_int(environ: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {value}")
    return value


def _get_bool(environ: Mapping[str, str], name: str, default: bool) -> bool:
    raw = environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes"):
        return True
    if value in ("0", "false", "no"):
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def _parse_origins(raw: str, env: str) -> tuple[str, ...]:
    origins: list[str] = []
    for item in raw.split(","):
        origin = item.strip().rstrip("/")
        if not origin:
            continue
        if origin == "*" or "*" in origin:
            raise ConfigError("SECURECHAT_ALLOWED_ORIGINS must not contain wildcards")
        parts = urlsplit(origin)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ConfigError(f"Invalid origin {origin!r}: expected scheme://host[:port]")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ConfigError(f"Invalid origin {origin!r}: must not include a path or query")
        if env == "production" and parts.scheme != "https":
            raise ConfigError(
                f"Origin {origin!r} is not https; set SECURECHAT_ENV=development for local HTTP"
            )
        origins.append(f"{parts.scheme}://{parts.netloc}")
    if not origins:
        raise ConfigError("SECURECHAT_ALLOWED_ORIGINS must list at least one origin")
    return tuple(dict.fromkeys(origins))  # de-duplicate, keep order


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from the environment, raising ConfigError if unsafe.

    When ``environ`` is None the process environment is used, after loading an
    optional ``.env`` file (never overriding variables already set).
    """
    if environ is None:
        from dotenv import load_dotenv  # declared in backend/requirements.txt

        load_dotenv(override=False)
        environ = os.environ

    env = environ.get("SECURECHAT_ENV", "production").strip().lower()
    if env not in _VALID_ENVS:
        raise ConfigError(f"SECURECHAT_ENV must be one of {_VALID_ENVS}, got {env!r}")

    secret = environ.get("SECURECHAT_SECRET_KEY", "")
    if not secret:
        raise ConfigError("SECURECHAT_SECRET_KEY is required (see .env.example)")
    if len(secret) < MIN_SECRET_LEN:
        raise ConfigError(f"SECURECHAT_SECRET_KEY must be at least {MIN_SECRET_LEN} characters")
    if secret.lower().startswith(_PLACEHOLDER_PREFIXES):
        raise ConfigError("SECURECHAT_SECRET_KEY still holds the placeholder value")

    origins = _parse_origins(environ.get("SECURECHAT_ALLOWED_ORIGINS", ""), env)
    db_path = Path(environ.get("SECURECHAT_DB_PATH", "data/securechat.sqlite3"))

    scrypt_log_n = _get_int(environ, "SECURECHAT_SCRYPT_LOG_N", 17, 10, 20)
    if env == "production" and scrypt_log_n < 15:
        raise ConfigError("SECURECHAT_SCRYPT_LOG_N must be at least 15 in production")

    return Settings(
        env=env,
        secret_key=secret,
        db_path=db_path,
        allowed_origins=origins,
        session_ttl_seconds=_get_int(environ, "SECURECHAT_SESSION_TTL_SECONDS", 43_200, 300, 2_592_000),
        message_ttl_seconds=_get_int(environ, "SECURECHAT_MESSAGE_TTL_SECONDS", 604_800, 60, 7_776_000),
        max_envelope_bytes=_get_int(environ, "SECURECHAT_MAX_ENVELOPE_BYTES", 65_536, 1_024, 1_048_576),
        max_pending_per_recipient=_get_int(environ, "SECURECHAT_MAX_PENDING_PER_RECIPIENT", 1_000, 1, 100_000),
        max_connections_per_user=_get_int(environ, "SECURECHAT_MAX_CONNECTIONS_PER_USER", 5, 1, 50),
        scrypt_log_n=scrypt_log_n,
        trust_cf_connecting_ip=_get_bool(environ, "SECURECHAT_TRUST_CF_CONNECTING_IP", False),
    )

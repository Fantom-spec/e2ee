"""Account and session logic, independent of the web framework."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Optional

from . import repo
from .security import PasswordHasher, new_id, new_token, token_digest
from .validation import (
    ValidationError,
    normalize_username,
    validate_display_name,
    validate_password,
)


class AuthError(Exception):
    """Invalid credentials. Deliberately gives no detail about which part failed."""


@dataclass(frozen=True)
class AuthContext:
    user_id: str
    session_id: str
    username: str
    display_name: str


@dataclass(frozen=True)
class LoginResult:
    token: str  # returned to the client exactly once; only its digest is stored
    expires_at: int
    context: AuthContext


def register(conn: sqlite3.Connection, hasher: PasswordHasher, username: str, display_name: str,
             password: str, now: int) -> str:
    """Create an account and return its id. Raises ValidationError or repo.UsernameTaken."""
    username = normalize_username(username)
    display_name = validate_display_name(display_name)
    password = validate_password(password)
    user_id = new_id()
    repo.create_user(conn, user_id, username, display_name, hasher.hash(password), now)
    return user_id


def login(conn: sqlite3.Connection, hasher: PasswordHasher, secret_key: str, username: str,
          password: str, now: int, session_ttl: int) -> LoginResult:
    try:
        name = normalize_username(username)
        row: Optional[sqlite3.Row] = repo.get_user_by_username(conn, name)
    except ValidationError:
        row = None

    if row is None or row["disabled"]:
        hasher.verify(hasher.dummy_hash, password)  # equalise timing
        raise AuthError()
    if not isinstance(password, str) or not hasher.verify(row["password_hash"], password):
        raise AuthError()

    token = new_token()
    session_id = new_id()
    expires_at = now + session_ttl
    repo.create_session(conn, session_id, row["id"], token_digest(token, secret_key), now, expires_at)
    ctx = AuthContext(row["id"], session_id, row["username"], row["display_name"])
    return LoginResult(token, expires_at, ctx)


def authenticate(conn: sqlite3.Connection, secret_key: str, token: str, now: int) -> Optional[AuthContext]:
    if not token or len(token) > 256:
        return None
    row = repo.get_active_session_by_token(conn, token_digest(token, secret_key), now)
    if row is None:
        return None
    return AuthContext(row["user_id"], row["session_id"], row["username"], row["display_name"])


def logout(conn: sqlite3.Connection, session_id: str, now: int) -> None:
    repo.revoke_session(conn, session_id, now)

"""Data-access functions. Every query is parameterised (no string-built SQL
except the fixed ESCAPE pattern for LIKE); callers pass in a connection and
own the transaction."""

from __future__ import annotations

import sqlite3
from typing import Optional

TOMBSTONE = "-"  # replaces the ciphertext once delivery is acknowledged


class UsernameTaken(Exception):
    pass


# --- users ---------------------------------------------------------------

def create_user(conn: sqlite3.Connection, user_id: str, username: str, display_name: str,
                password_hash: str, now: int) -> None:
    try:
        conn.execute(
            "INSERT INTO users (id, username, display_name, password_hash, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (user_id, username, display_name, password_hash, now),
        )
    except sqlite3.IntegrityError as exc:
        if "users.username" in str(exc):
            raise UsernameTaken(username) from exc
        raise


def get_user(conn: sqlite3.Connection, user_id: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id, username, display_name, password_hash, disabled FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id, username, display_name, password_hash, disabled FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def search_users(conn: sqlite3.Connection, prefix: str, exclude_user_id: str, limit: int = 20) -> list[sqlite3.Row]:
    """Username-prefix search. Prefix-only (not substring) and capped, to make
    bulk enumeration of accounts harder."""
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return conn.execute(
        "SELECT id, username, display_name FROM users"
        " WHERE username LIKE ? ESCAPE '\\' AND id != ? AND disabled = 0"
        " ORDER BY username LIMIT ?",
        (escaped + "%", exclude_user_id, limit),
    ).fetchall()


# --- sessions ------------------------------------------------------------

def create_session(conn: sqlite3.Connection, session_id: str, user_id: str, token_hash: str,
                   now: int, expires_at: int) -> None:
    conn.execute(
        "INSERT INTO auth_sessions (id, user_id, token_hash, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (session_id, user_id, token_hash, now, expires_at),
    )


def get_active_session_by_token(conn: sqlite3.Connection, token_hash: str, now: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT s.id AS session_id, u.id AS user_id, u.username, u.display_name"
        " FROM auth_sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND u.disabled = 0",
        (token_hash, now),
    ).fetchone()


def session_is_active(conn: sqlite3.Connection, session_id: str, now: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM auth_sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.id = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND u.disabled = 0",
        (session_id, now),
    ).fetchone()
    return row is not None


def revoke_session(conn: sqlite3.Connection, session_id: str, now: int) -> None:
    conn.execute(
        "UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        (now, session_id),
    )


def purge_expired_sessions(conn: sqlite3.Connection, now: int) -> int:
    return conn.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,)).rowcount


# --- messages (opaque ciphertext queue) ---------------------------------

def count_pending(conn: sqlite3.Connection, recipient_id: str, now: int) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND delivered_at IS NULL AND expires_at > ?",
        (recipient_id, now),
    ).fetchone()[0]


def enqueue_message(conn: sqlite3.Connection, msg_id: str, sender_id: str, recipient_id: str,
                    envelope: str, now: int, expires_at: int) -> bool:
    """Insert once per (sender, id). Returns False if it was already present,
    which makes client retries idempotent."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO messages (id, sender_id, recipient_id, envelope, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (msg_id, sender_id, recipient_id, envelope, now, expires_at),
    )
    return cur.rowcount == 1


def pending_for(conn: sqlite3.Connection, recipient_id: str, now: int, limit: int = 500) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, sender_id, envelope, created_at FROM messages"
        " WHERE recipient_id = ? AND delivered_at IS NULL AND expires_at > ?"
        " ORDER BY created_at, rowid LIMIT ?",
        (recipient_id, now, limit),
    ).fetchall()


def mark_delivered(conn: sqlite3.Connection, recipient_id: str, sender_id: str, msg_id: str, now: int) -> bool:
    """Recipient acknowledges receipt. The ciphertext is erased immediately;
    a small metadata row stays until expiry so a replayed submission with the
    same id is still recognised as a duplicate."""
    cur = conn.execute(
        "UPDATE messages SET delivered_at = ?, envelope = ?"
        " WHERE sender_id = ? AND id = ? AND recipient_id = ? AND delivered_at IS NULL",
        (now, TOMBSTONE, sender_id, msg_id, recipient_id),
    )
    return cur.rowcount == 1


def purge_expired_messages(conn: sqlite3.Connection, now: int) -> int:
    return conn.execute("DELETE FROM messages WHERE expires_at <= ?", (now,)).rowcount


# --- public key directory (Stage 3) ----------------------------------------

def begin_immediate(conn: sqlite3.Connection) -> None:
    """Take the write lock up front so read-then-write sequences are atomic."""
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def get_identity_row(conn: sqlite3.Connection, user_id: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM identity_keys WHERE user_id = ?", (user_id,)).fetchone()


def insert_identity(conn: sqlite3.Connection, user_id: str, registration_id: int, identity_public: str,
                    spk_id: int, spk_public: str, spk_signature: str, now: int) -> None:
    conn.execute(
        "INSERT INTO identity_keys (user_id, registration_id, identity_public, signed_prekey_id,"
        " signed_prekey_public, signed_prekey_signature, key_version, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
        (user_id, registration_id, identity_public, spk_id, spk_public, spk_signature, now),
    )
    conn.execute(
        "INSERT INTO identity_key_history (user_id, key_version, identity_public, recorded_at)"
        " VALUES (?, 1, ?, ?)", (user_id, identity_public, now))


def update_identity(conn: sqlite3.Connection, user_id: str, registration_id: int, identity_public: str,
                    spk_id: int, spk_public: str, spk_signature: str, key_version: int, now: int) -> None:
    conn.execute(
        "UPDATE identity_keys SET registration_id = ?, identity_public = ?, signed_prekey_id = ?,"
        " signed_prekey_public = ?, signed_prekey_signature = ?, key_version = ?, updated_at = ?"
        " WHERE user_id = ?",
        (registration_id, identity_public, spk_id, spk_public, spk_signature, key_version, now, user_id),
    )


def add_history(conn: sqlite3.Connection, user_id: str, key_version: int, identity_public: str, now: int) -> None:
    conn.execute(
        "INSERT INTO identity_key_history (user_id, key_version, identity_public, recorded_at)"
        " VALUES (?, ?, ?, ?)", (user_id, key_version, identity_public, now))


def delete_all_one_time_prekeys(conn: sqlite3.Connection, user_id: str) -> None:
    conn.execute("DELETE FROM one_time_prekeys WHERE user_id = ?", (user_id,))


def get_one_time_prekey(conn: sqlite3.Connection, user_id: str, key_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT key_id, public_key FROM one_time_prekeys WHERE user_id = ? AND key_id = ?",
                        (user_id, key_id)).fetchone()


def insert_one_time_prekey(conn: sqlite3.Connection, user_id: str, key_id: int, public_key: str) -> None:
    conn.execute("INSERT INTO one_time_prekeys (user_id, key_id, public_key) VALUES (?, ?, ?)",
                 (user_id, key_id, public_key))


def count_one_time_prekeys(conn: sqlite3.Connection, user_id: str) -> int:
    return conn.execute("SELECT COUNT(*) FROM one_time_prekeys WHERE user_id = ? AND consumed_at IS NULL",
                        (user_id,)).fetchone()[0]


def take_one_time_prekey(conn: sqlite3.Connection, user_id: str) -> Optional[sqlite3.Row]:
    """Remove and return one unused one-time prekey. Each is handed out at most
    once: the row is deleted in the same transaction that read it."""
    row = conn.execute(
        "SELECT key_id, public_key FROM one_time_prekeys WHERE user_id = ? AND consumed_at IS NULL"
        " ORDER BY key_id LIMIT 1", (user_id,)).fetchone()
    if row is None:
        return None
    deleted = conn.execute("DELETE FROM one_time_prekeys WHERE user_id = ? AND key_id = ?",
                           (user_id, row["key_id"])).rowcount
    return row if deleted == 1 else None

"""Public key directory: identity binding, prekey bundles, identity history.

The server stores and serves only PUBLIC key material. It cannot verify the
signed-prekey signature (that needs the Signal library); clients verify it
when they build a session, and pin the identity key they first see (TOFU).
A malicious server can still hand out a substituted identity key at first
contact; safety-number comparison between users is the defence (Stage 3 UI).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from . import repo
from .validation import (
    ValidationError,
    validate_key_id,
    validate_public_key,
    validate_signature,
)

MAX_ONE_TIME_PREKEYS_STORED = 100
MAX_ONE_TIME_PREKEYS_PER_UPLOAD = 100
REGISTRATION_ID_MAX = 2**31 - 1


class KeyConflict(Exception):
    """A one-time prekey id is already stored with different key material."""


@dataclass(frozen=True)
class SignedPreKeyIn:
    key_id: int
    public: str
    signature: str


@dataclass(frozen=True)
class KeyUpload:
    registration_id: int
    identity_public: str
    signed_prekey: SignedPreKeyIn
    one_time_prekeys: tuple[tuple[int, str], ...]


@dataclass(frozen=True)
class PublishResult:
    identity_changed: bool
    key_version: int
    one_time_prekeys_remaining: int


def parse_upload(raw: dict[str, Any]) -> KeyUpload:
    """Validate an untrusted upload (framework-independent)."""
    reg = raw.get("registration_id")
    if isinstance(reg, bool) or not isinstance(reg, int) or not 0 <= reg <= REGISTRATION_ID_MAX:
        raise ValidationError("registration_id must be a non-negative integer")
    spk = raw.get("signed_prekey")
    if not isinstance(spk, dict):
        raise ValidationError("signed_prekey is required")
    otps = raw.get("one_time_prekeys", [])
    if not isinstance(otps, list) or len(otps) > MAX_ONE_TIME_PREKEYS_PER_UPLOAD:
        raise ValidationError(f"one_time_prekeys must be a list of at most {MAX_ONE_TIME_PREKEYS_PER_UPLOAD}")
    parsed: list[tuple[int, str]] = []
    seen: set[int] = set()
    for item in otps:
        if not isinstance(item, dict):
            raise ValidationError("one_time_prekeys entries must be objects")
        key_id = validate_key_id(item.get("id"), "one-time prekey id")
        if key_id in seen:
            raise ValidationError("duplicate one-time prekey id in upload")
        seen.add(key_id)
        parsed.append((key_id, validate_public_key(item.get("public"), "one-time prekey")))
    return KeyUpload(
        registration_id=reg,
        identity_public=validate_public_key(raw.get("identity_public"), "identity key"),
        signed_prekey=SignedPreKeyIn(
            validate_key_id(spk.get("id"), "signed prekey id"),
            validate_public_key(spk.get("public"), "signed prekey"),
            validate_signature(spk.get("signature"), "signed prekey signature"),
        ),
        one_time_prekeys=tuple(parsed),
    )


def publish_keys(conn: sqlite3.Connection, user_id: str, upload: KeyUpload, now: int) -> PublishResult:
    """Bind/refresh the caller's public keys. The caller commits.

    * First upload binds the identity key to the account.
    * Same identity key: refresh the signed prekey and add one-time prekeys.
    * Different identity key (for example after clearing browser data): allowed,
      but the version is bumped, the change is recorded, and all old one-time
      prekeys are discarded. Contacts see a safety-number change.
    """
    repo.begin_immediate(conn)
    spk = upload.signed_prekey
    row = repo.get_identity_row(conn, user_id)
    changed = False
    if row is None:
        version = 1
        repo.insert_identity(conn, user_id, upload.registration_id, upload.identity_public,
                             spk.key_id, spk.public, spk.signature, now)
    elif row["identity_public"] == upload.identity_public:
        version = row["key_version"]
        repo.update_identity(conn, user_id, upload.registration_id, upload.identity_public,
                             spk.key_id, spk.public, spk.signature, version, now)
    else:
        changed = True
        version = row["key_version"] + 1
        repo.update_identity(conn, user_id, upload.registration_id, upload.identity_public,
                             spk.key_id, spk.public, spk.signature, version, now)
        repo.add_history(conn, user_id, version, upload.identity_public, now)
        repo.delete_all_one_time_prekeys(conn, user_id)

    for key_id, public in upload.one_time_prekeys:
        existing = repo.get_one_time_prekey(conn, user_id, key_id)
        if existing is None:
            repo.insert_one_time_prekey(conn, user_id, key_id, public)
        elif existing["public_key"] != public:
            raise KeyConflict(f"one-time prekey id {key_id} is already in use")
    remaining = repo.count_one_time_prekeys(conn, user_id)
    if remaining > MAX_ONE_TIME_PREKEYS_STORED:
        raise ValidationError(f"at most {MAX_ONE_TIME_PREKEYS_STORED} one-time prekeys may be stored")
    return PublishResult(changed, version, remaining)


def fetch_bundle(conn: sqlite3.Connection, target_id: str) -> Optional[dict[str, Any]]:
    """Prekey bundle for starting a session with ``target_id``. Consumes one
    one-time prekey (if any remain). On success the caller must commit; when
    nothing is found (returns None) the transaction is already rolled back."""
    repo.begin_immediate(conn)
    user = repo.get_user(conn, target_id)
    ident = repo.get_identity_row(conn, target_id)
    if user is None or user["disabled"] or ident is None:
        conn.rollback()  # nothing was changed; release the write lock now
        return None
    otp = repo.take_one_time_prekey(conn, target_id)
    return {
        "user_id": target_id,
        "registration_id": ident["registration_id"],
        "identity_public": ident["identity_public"],
        "key_version": ident["key_version"],
        "signed_prekey": {
            "id": ident["signed_prekey_id"],
            "public": ident["signed_prekey_public"],
            "signature": ident["signed_prekey_signature"],
        },
        "one_time_prekey": None if otp is None else {"id": otp["key_id"], "public": otp["public_key"]},
    }


def get_identity(conn: sqlite3.Connection, target_id: str) -> Optional[dict[str, Any]]:
    """Identity key and version without consuming anything (for verification)."""
    user = repo.get_user(conn, target_id)
    ident = repo.get_identity_row(conn, target_id)
    if user is None or user["disabled"] or ident is None:
        return None
    return {"user_id": target_id, "identity_public": ident["identity_public"],
            "key_version": ident["key_version"], "updated_at": ident["updated_at"]}


def key_status(conn: sqlite3.Connection, user_id: str) -> dict[str, Any]:
    ident = repo.get_identity_row(conn, user_id)
    return {
        "has_keys": ident is not None,
        "key_version": None if ident is None else ident["key_version"],
        "one_time_prekeys_remaining": repo.count_one_time_prekeys(conn, user_id),
    }


def history_versions(conn: sqlite3.Connection, user_id: str) -> Sequence[int]:
    rows = conn.execute("SELECT key_version FROM identity_key_history WHERE user_id = ? ORDER BY key_version",
                        (user_id,)).fetchall()
    return [r["key_version"] for r in rows]

"""Pure-Python validators for all untrusted input (no framework imports).

Every value that arrives from a client (HTTP body, query string, WebSocket
frame) passes through one of these before it touches the database or other
users. Validators return the normalised value or raise ValidationError.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

PASSWORD_MIN = 10
PASSWORD_MAX = 128
DISPLAY_NAME_MAX = 64
SEARCH_MIN = 2
SEARCH_MAX = 32


class ValidationError(ValueError):
    """Input failed validation. The message is safe to show to the client."""


def normalize_username(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValidationError("username must be a string")
    value = raw.strip().lower()
    if not USERNAME_RE.match(value):
        raise ValidationError("username must be 3-32 characters: letters, digits, underscore")
    return value


def validate_display_name(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValidationError("display name must be a string")
    value = unicodedata.normalize("NFC", raw).strip()
    if not 1 <= len(value) <= DISPLAY_NAME_MAX:
        raise ValidationError(f"display name must be 1-{DISPLAY_NAME_MAX} characters")
    # Reject control, format (e.g. bidi overrides) and unassigned characters,
    # which can be used to spoof names in the UI.
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise ValidationError("display name contains unsupported characters")
    return value


def validate_password(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValidationError("password must be a string")
    if not PASSWORD_MIN <= len(raw) <= PASSWORD_MAX:
        raise ValidationError(f"password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters")
    if "\x00" in raw:
        raise ValidationError("password contains unsupported characters")
    if not raw.strip():
        raise ValidationError("password must not be only whitespace")
    return raw


def validate_uuid(raw: object, what: str = "id") -> str:
    if not isinstance(raw, str):
        raise ValidationError(f"{what} must be a string")
    value = raw.strip().lower()
    if not UUID_RE.match(value):
        raise ValidationError(f"{what} must be a UUID")
    return value


def validate_search_query(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValidationError("query must be a string")
    value = raw.strip().lower()
    if not SEARCH_MIN <= len(value) <= SEARCH_MAX:
        raise ValidationError(f"query must be {SEARCH_MIN}-{SEARCH_MAX} characters")
    if not re.match(r"^[a-z0-9_]+$", value):
        raise ValidationError("query may only contain letters, digits, underscore")
    return value


def validate_envelope(raw: object, max_len: int) -> str:
    """An opaque ciphertext envelope: standard base64 text, bounded in size.

    The server never interprets the contents; it only checks the shape so
    malformed or oversized data is rejected before storage.
    """
    if not isinstance(raw, str):
        raise ValidationError("envelope must be a string")
    if not 1 <= len(raw) <= max_len:
        raise ValidationError(f"envelope must be 1-{max_len} characters")
    try:
        base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("envelope must be valid base64") from exc
    return raw


# --- public key material (Stage 3) -----------------------------------------

KEY_MIN_BYTES = 32
KEY_MAX_BYTES = 40   # Curve25519 public keys are 32 bytes, 33 with a type prefix
SIG_MIN_BYTES = 64
SIG_MAX_BYTES = 72
KEY_ID_MAX = 2**31 - 1


def _canonical_b64(raw: object, what: str, lo: int, hi: int) -> str:
    """Standard base64 that round-trips exactly, so the same key always has one
    textual form. The server compares keys as strings to detect identity changes."""
    if not isinstance(raw, str):
        raise ValidationError(f"{what} must be a string")
    try:
        data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError(f"{what} must be base64") from exc
    if base64.b64encode(data).decode("ascii") != raw:
        raise ValidationError(f"{what} must be canonical base64")
    if not lo <= len(data) <= hi:
        raise ValidationError(f"{what} has an unexpected length")
    return raw


def validate_public_key(raw: object, what: str = "public key") -> str:
    return _canonical_b64(raw, what, KEY_MIN_BYTES, KEY_MAX_BYTES)


def validate_signature(raw: object, what: str = "signature") -> str:
    return _canonical_b64(raw, what, SIG_MIN_BYTES, SIG_MAX_BYTES)


def validate_key_id(raw: object, what: str = "key id") -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= KEY_ID_MAX:
        raise ValidationError(f"{what} must be an integer between 0 and {KEY_ID_MAX}")
    return raw

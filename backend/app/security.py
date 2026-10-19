"""Password hashing and token primitives (standard library only).

Decision: scrypt (hashlib.scrypt) is used for passwords. It is a memory-hard
KDF listed by OWASP, ships with Python (no extra dependency to audit), and
is available in the test environment. Argon2id is the other recommended
choice; switching later only requires changing PasswordHasher because the
cost parameters are stored inside each hash string.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import uuid
from functools import cached_property

_SCHEME = "scrypt"
_MAX_N = 2**20  # refuse absurd parameters in stored hashes


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class PasswordHasher:
    def __init__(self, log_n: int = 17, r: int = 8, p: int = 1, salt_len: int = 16, dk_len: int = 32) -> None:
        if not 10 <= log_n <= 20:
            raise ValueError("log_n out of range")
        self.n = 2**log_n
        self.r = r
        self.p = p
        self.salt_len = salt_len
        self.dk_len = dk_len

    @staticmethod
    def _maxmem(n: int, r: int) -> int:
        # scrypt needs about 128*n*r bytes; allow 2x headroom.
        return 256 * n * r

    def _derive(self, password: str, salt: bytes, n: int, r: int, p: int, dk_len: int) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
            maxmem=self._maxmem(n, r), dklen=dk_len,
        )

    def hash(self, password: str) -> str:
        salt = secrets.token_bytes(self.salt_len)  # CSPRNG, unique per password
        digest = self._derive(password, salt, self.n, self.r, self.p, self.dk_len)
        return f"{_SCHEME}${self.n}${self.r}${self.p}${_b64(salt)}${_b64(digest)}"

    def verify(self, stored: str, password: str) -> bool:
        """Constant-time check. Malformed stored hashes verify as False."""
        try:
            scheme, n_s, r_s, p_s, salt_b64, digest_b64 = stored.split("$")
            n, r, p = int(n_s), int(r_s), int(p_s)
            salt = base64.b64decode(salt_b64, validate=True)
            expected = base64.b64decode(digest_b64, validate=True)
        except (ValueError, binascii.Error):
            return False
        if scheme != _SCHEME or n < 2**10 or n > _MAX_N or n & (n - 1) or not 1 <= r <= 16 or not 1 <= p <= 4:
            return False
        actual = self._derive(password, salt, n, r, p, len(expected))
        return hmac.compare_digest(actual, expected)

    @cached_property
    def dummy_hash(self) -> str:
        """A valid hash of a random password, used to equalise login timing.

        When a username does not exist we still run one full verification so
        response time does not reveal whether the account exists.
        """
        return self.hash(secrets.token_urlsafe(16))


def new_id() -> str:
    return str(uuid.uuid4())


def new_token() -> str:
    """256 bits of CSPRNG output; this is the bearer credential."""
    return secrets.token_urlsafe(32)


def token_digest(token: str, secret_key: str) -> str:
    """Keyed hash stored in the database instead of the token itself.

    A leaked database alone cannot be turned into valid sessions, and without
    the server secret the digests cannot even be checked against guesses.
    """
    return hmac.new(secret_key.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()

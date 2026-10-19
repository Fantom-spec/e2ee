# Database schema (version 1)

Source of truth: `backend/app/schema.sql`. SQLite, foreign keys enforced on
every connection, WAL mode, file mode 0600. Timestamps are Unix epoch seconds.

## What the server stores, and for how long

| Table | Contents | Retention | Used from |
|---|---|---|---|
| `users` | UUID, username, display name, scrypt password verifier, created time, disabled flag | Until account deletion | Stage 2 |
| `auth_sessions` | Session id, user id, HMAC-SHA-256 digest (keyed with the server secret) of the bearer token, never the token itself, created/expiry/revoked times | Until expiry (default 12 h), then purged | Stage 2 |
| `identity_keys` | **Public** identity key, signed prekey (public + signature), registration id, key version | Until replaced or account deletion | Stage 3 |
| `identity_key_history` | Append-only list of past public identity keys, for key-change warnings | Until account deletion | Stage 3 |
| `one_time_prekeys` | **Public** one-time prekeys; a prekey is deleted in the same transaction that hands it out | Until consumed | Stage 3 |
| `messages` | Client-generated message UUID, sender id, recipient id, opaque base64 ciphertext envelope, created/expiry/delivered times | On the recipient's acknowledgement the ciphertext is overwritten with a `-` placeholder, but the metadata row (ids, timestamps) stays until expiry (default 7 days) so a replayed submission is still recognised as a duplicate. Expired rows are deleted every 10 minutes. | Stage 2 |

Stage 3 additionally writes `identity_keys`, `identity_key_history` and `one_time_prekeys`.

## Metadata the server can see

Even with perfect E2EE the relay learns: which accounts exist, who sends to
whom, when, how large each envelope is, when each user connects, and (from
network-level data, and Cloudflare likewise) client IP addresses. This is
inherent to the architecture and is not hidden.

## What is deliberately absent

There is no column for message plaintext, private keys, session keys or raw
authentication tokens. `tests/backend/test_db_schema.py` asserts that no column
name contains `plaintext`, `private`, `body`, `content` or `secret`. This
catches accidental schema regressions; it is **not** proof that no plaintext
can ever reach the server (that needs the Stage 3/4 end-to-end tests).

## Constraints worth knowing

* `messages` primary key is `(sender_id, id)`: re-submitting the same message id from the same sender is rejected, which gives server-side idempotency.
* `envelope` is limited to 1 to 131 072 characters at the database level. The application-level limit (`SECURECHAT_MAX_ENVELOPE_BYTES`, default 65 536 bytes) is enforced before insertion in Stage 4.
* Usernames are unique case-insensitively.
* Deleting a user cascades to their sessions, keys and messages.

# Protocol and design decisions

Status legend: **Decided**, **Provisional** (must pass the stated check before
use), **Open**.

## Decided

| Topic | Decision | Why |
|---|---|---|
| Client platform | React + TypeScript web app, no native app | Project requirement |
| Server | Python FastAPI, SQLite, WebSocket relay | Project requirement |
| Public access | Single hostname through Cloudflare Tunnel; backend serves API, WebSocket and (in deployment) the built frontend, so the browser is same-origin | Simplifies CORS and avoids exposing two services |
| Password hashing | scrypt via Python's `hashlib` (N=2^17, r=8, p=1; production requires N >= 2^15), parameters stored in each hash string | Memory-hard, OWASP-listed, no extra dependency to audit. Argon2id would be a reasonable swap (needs the `argon2-cffi` package, which could not be installed while writing Stage 2). |
| Session tokens | Random bearer tokens; only a hash is stored server-side | A database leak must not yield usable sessions |
| Message dedup | Client-generated UUID, `(sender_id, id)` unique | See `spec-review.md` #7 |
| Retention | Ciphertext erased on recipient ack (metadata row kept until expiry for duplicate detection); everything expires after 7 days | See `database-schema.md` |
| Custom cryptography | **Not allowed.** No hand-written ratchet, KDF or cipher composition | Project requirement |

## Decided in Stage 3: end-to-end encryption library

**Choice:** `@privacyresearch/libsignal-protocol-typescript`, pinned to exactly `0.0.16`
(X3DH key agreement + Double Ratchet; no PQXDH). It sits behind the `CipherBackend`
interface (`frontend/src/crypto/cipher.ts`), so it can be replaced by another
implementation (official libsignal or vodozemac as WASM) without touching the engine.

Checklist results (what could and could not be verified from the sandbox, which has no npm access):

- [ ] Current version and last-release date: **not verified** (registry and GitHub history blocked).
- [x] Licence: **GPL-3.0-only** (from the project README; confirm in `node_modules`). Distributing the whole application then requires GPL-compatible terms.
- [ ] Browser support without weakening randomness: **not verified**. The library ships an asm.js curve25519 and falls back to msrcrypto where needed.
- [x] API covers identity/prekey generation, bundle session setup, encrypt/decrypt, pluggable store (from its documentation; our adapter `signal.ts` is untested).
- [ ] Security audit: **none known**; treat as unaudited.
- [ ] Tamper/replay failure demonstrated by a test we ran: written (`frontend/tests/signal/signal.spec.ts`) but **not executed**.
- [x] State store lets us persist atomically with the processed-id set: the engine keeps sessions and processed ids in one state object saved in one vault write.

**Other Stage 3 decisions**

| Topic | Decision |
|---|---|
| Browser key storage | One AES-256-GCM vault blob in IndexedDB, key from PBKDF2-SHA256 (600k iterations) over the account password, non-extractable, fresh IV per write, AAD binds the blob to the user. Documented limitation: the server also sees the password. |
| Identity trust | Trust on first use, pinned in the vault; change blocks sending, quarantines incoming messages, resets "verified". |
| Safety number | SHA-512 over a domain-separated, canonically ordered pair of (user id, identity key); 12 groups of 5 digits. Not Signal's algorithm. |
| Envelope | `base64(JSON{v:1, t:type, b:base64 body})`; plaintext is JSON `{v:1, text, sent_at}`; text limit 4000 characters. |
| Ordering/times | Local receive time is used for display; sender-claimed time is not trusted. |
| Local data loss | A new browser creates a new identity; contacts see a safety-number change. |

**Properties we may claim** (each only once its test has been run): confidentiality from the relay, ciphertext integrity, replay rejection. Forward secrecy and post-compromise security are not claimed.

**Decided in Stage 2:** WebSocket authentication uses a single-use ticket (30 s) fetched over authenticated HTTPS and passed as `?ticket=` on the handshake. The long-lived session token never appears in a URL.

## Open (decide in the stated stage)

| Topic | Stage |
|---|---|
| Rate-limit thresholds (Stage 2 ships an in-memory limiter; values are first guesses, not tuned) | 4 |
| Change-password flow that re-wraps the vault | 4 |

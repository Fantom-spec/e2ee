# Security policy

This is an academic project and has **not** been independently reviewed or
audited. Do not use it to protect sensitive real-world communications.

## Current security status (Stage 3 frontend verification)

| Property | Claimed? | Evidence |
|---|---|---|
| End-to-end encryption of messages (Signal protocol via a third-party library) | **Implemented; automated tests pass, but not independently audited** | `frontend/tests/signal/`: 11 real-library tests pass |
| Engine handles duplicates, replays, tampered results, key changes, offline retry and storage failure correctly | Yes, against a FAKE cipher | `frontend/tests/node/engine.test.ts`, 38 tests executed, passing (includes restart, replay-after-restart, truncation and held-message-after-restart cases) |
| Local keys and history encrypted at rest (AES-256-GCM, PBKDF2 600k) | Yes (vault logic) | `frontend/tests/node/primitives.test.ts`, executed, passing. IndexedDB storage itself never run |
| Server stores only public keys; one-time prekeys consumed atomically; identity change recorded | Yes (service level) | `tests/backend/test_keys_service.py`, executed, passing |
| Forward secrecy / post-compromise security | **No claim** (library feature, no test of ours) | none |
| Fail-safe configuration (secret required, no wildcard origins) | Yes | `tests/backend/test_config.py`, executed and passing |
| Database schema holds no plaintext/private-key columns | Yes (structure only) | `tests/backend/test_db_schema.py`, executed and passing |
| Passwords stored only as scrypt hashes; login failures indistinguishable; sessions expire and can be revoked; only a keyed digest of the session token is stored | Yes (service level) | `test_security.py`, `test_auth_service.py`: executed, passing |
| Relay derives sender from the session, rejects spoofed senders, scopes acknowledgements to the recipient, rejects malformed/oversized frames, is duplicate-safe, enforces rate/queue/connection limits | Yes (relay level, fake sockets, real SQLite) | `test_relay.py`: executed, passing |
| The same behaviour through real HTTP and WebSocket endpoints (CORS allow-list, docs off in production, 401s, 422 bodies not echoing passwords, ticket single-use, origin check) | **Written, unverified** | `test_api.py`, `test_health.py`: skipped here because FastAPI could not be installed; never executed |
| React UI behaviour (responsive layout, trust badges, warnings) | **Build passes; full browser/backend integration not verified** | `npm run build` succeeds; manual UI and live-backend testing remain necessary. See `docs/crypto-design.md` section 9 |

## Limits of the current controls

* Rate limiting is in-memory and single-process; it resets on restart. Behind Cloudflare Tunnel, per-IP limits only work if `SECURECHAT_TRUST_CF_CONNECTING_IP=true`, which is safe only when the server is reachable exclusively through the tunnel.
* The session token and the password live in page memory and are readable by any script in the page (XSS = full compromise). No Content-Security-Policy yet (Stage 4).
* The vault uses a random 256-bit key (generated per browser profile) to encrypt the actual payload; this vault key is then wrapped (encrypted) with a key derived from the account password via PBKDF2-SHA256 (600k iterations). The server receives the password at login, so a malicious server could learn it and, with a copy of the browser's IndexedDB data, unwrap the vault key and decrypt the vault.
* The encryption library is GPL-3.0, unaudited, and its maintenance status is unverified.
* Safety numbers are SecureChat's own construction (SHA-512 over ordered user ids and identity keys) and do not interoperate with Signal.
* The server cannot verify the signed prekey signature; clients do (inside the library).
* Search lets any logged-in user enumerate usernames by prefix (capped at 20 results, rate limiting of search is not implemented).
* Although the real-library tests pass, verify identity and safety numbers with a second account. Do not rely on this unaudited academic project for sensitive private communications.

## Things to keep in mind

* TLS (including through Cloudflare Tunnel) protects the connection only. It is not end-to-end encryption, and Cloudflare terminates TLS.
* A browser E2EE app downloads its code from the server. A malicious or compromised server can replace that code and steal keys or plaintext. This build does not defend against that.
* Authentication (who you are to the server), identity verification (whether you are talking to the right person) and message confidentiality are three different things; each is handled separately.
* Never commit `.env`, databases, tunnel credentials or keys. `python scripts/check_secrets.py` runs a coarse check.

## Reporting a problem

This is a student project: open an issue or contact the repository owner
directly. Do not post exploit details publicly before the owner has had a
chance to respond.

## Third-party dependency licensing

The frontend dependency report (`frontend/licenses.json`) identifies these
Signal-related packages as GPL-3.0-only:

- `@privacyresearch/curve25519-typescript@0.0.12`
- `@privacyresearch/libsignal-protocol-protobuf-ts@0.0.9`
- `@privacyresearch/libsignal-protocol-typescript@0.0.16`

Other dependencies have their own licence terms. Review the licence files
and applicable obligations before distributing this project. This note is
a dependency inventory, not a legal determination of compatibility or
redistribution rights.


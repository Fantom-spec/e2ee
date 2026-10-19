# PROGRESS: SecureChat_Part03 (Stage 3)

**INCOMPLETE DEVELOPMENT CHECKPOINT. The real-cryptography glue and the whole UI
have never been executed.** They were written in a sandbox where PyPI and npm are
blocked, so the encryption library, FastAPI, React, Vite and vitest could not be
installed. Only code that needs none of them was run. Read "What was executed"
before trusting anything here.

## What Stage 3 adds

* **Key directory (server):** publishes/serves PUBLIC keys only. Identity change bumps `key_version`, keeps history and deletes the old one-time prekeys. One-time prekeys are consumed atomically (`BEGIN IMMEDIATE`). Bundle fetches are rate limited. New endpoints: `POST /api/keys`, `GET /api/keys/status`, `GET /api/keys/{id}` (bundle), `GET /api/keys/{id}/identity`, `GET /api/users/{id}`.
* **Client crypto (`frontend/src/crypto/`):**
  * `cipher.ts` the interface to the protocol library; `signal.ts` implements it with `@privacyresearch/libsignal-protocol-typescript@0.0.16` (X3DH + Double Ratchet). **No custom cryptography anywhere.**
  * `vault.ts` encrypts all local state (keys, sessions, history) with AES-256-GCM under a PBKDF2-SHA256 (600k iterations) key derived from the account password; `idb.ts` stores that blob in IndexedDB.
  * `engine.ts` the chat logic: key publication/refill, trust-on-first-use identity pinning, key-change blocking and quarantine, dedup before decrypt, persist-before-ack, persist-before-send, outbox that re-sends the same ciphertext, fail-closed on storage failure.
  * `fingerprint.ts` safety numbers (SecureChat's own SHA-512 construction, NOT Signal's).
* **UI:** conversation list, chat window with delivery status, safety-number panel (verify / accept new key), warnings. Session restore on reload was removed: keys unlock with the password at login, so a reload requires logging in again.

## What was executed (real results)

| Check | Result |
|---|---|
| Backend: `PYTHONPATH=backend:tests/backend python3 -B -m unittest discover -s tests/backend` | 130 run: **105 passed, 25 skipped, 0 failed**. Skipped = HTTP/WebSocket tests (fastapi/httpx not installable here). |
| Frontend logic: `cd frontend && node --test "tests/node/*.test.ts"` | **51 passed, 0 failed** (21 primitives: base64/envelope/safety number/vault; 30 engine tests) |
| `tsc` over `src/crypto/*` (except `signal.ts`' library import) and the other TS | No errors apart from missing-package errors (React, the library, CSS) caused by the sandbox |

During development several tests failed first and were fixed: 4 were mistakes in
the tests (stale object reference, wrong test setup, an incorrect assertion);
2 exposed real engine defects, now fixed (a missing-keys 404 surfaced as a raw
error instead of a clear message; a storage failure while handling a relay
frame threw out of `handleFrame` instead of stopping the engine cleanly).

**Important limit of the 30 engine tests:** they use a FAKE cipher (`frontend/tests/helpers/fakes.ts`, clearly labelled, not cryptography). They prove the engine's behaviour around duplicates, replays, tampering results, persistence order, key changes, quarantine and offline retry. They do NOT prove the encryption itself.

## NOT executed (written, unverified)

* `frontend/src/crypto/signal.ts`: written from the library's documented API; the real types may differ (expect `tsc` errors to fix on first build).
* `frontend/tests/signal/signal.spec.ts` (7 tests: round trip, relay never sees plaintext, tamper rejection, replay rejection, duplicate, identity change, restart persistence): **never run**. These are what actually test the real encryption.
* `idb.ts`, `session.ts`, `useRelay.ts`, `ChatApp.tsx`, `ChatWindow.tsx`, `SafetyPanel.tsx`, `App.tsx`: never type-checked against React, built or run.
* Backend HTTP layer for the new endpoints (`routes.py`, `test_api.py` key and profile tests): skipped here.

## Library status (see docs/protocol-decisions.md)

`@privacyresearch/libsignal-protocol-typescript` 0.0.16: **GPL-3.0-only** (affects how you may distribute the whole project), **not independently audited**, release dates and maintenance status **could not be verified** from the sandbox. It is hidden behind `CipherBackend` so it can be swapped.

## Security properties: claimed vs not

* Claimed only after you run `npm run test:signal` successfully: confidentiality from the relay, ciphertext integrity, replay rejection.
* Forward secrecy and post-compromise security are properties of the Double Ratchet as implemented by the library; **we have no test demonstrating key evolution yet**, so they are not claimed.
* Not defended: a malicious server shipping modified JavaScript; XSS; the server seeing the password at login (the vault key derives from it).

## Known issues and limitations

* Password is both login credential and vault key; changing it later breaks vault unlock (no change-password flow). A forgotten password loses local keys/history.
* No multi-device; a second browser for the same account replaces the identity key (contacts see a safety-number warning). The engine stops publishing if it sees another browser replaced its keys.
* Identity checks are throttled to once per 10 s per contact on send (first-use session setup always checks).
* In-memory rate limits, no CSP yet, session token in memory only now (no sessionStorage).
* No lock files; dependency versions unresolved except the library pin.

## Remaining tasks

Stage 4 hardening (client-side reconnect/ack tests, CSP, rate-limit tuning, message size at DB layer), Stage 5 (UI polish, benchmark script, Cloudflare Tunnel guide, demo guide, lock files), Stage 6 (final verification and `SecureChat_FINAL.zip`).

## Exact next steps (on your machine)

1. Backend: `pip install -r backend/requirements-dev.txt && pytest` (the 25 skipped tests will run; send me any failures).
2. Frontend: `cd frontend && npm install` then `npm run typecheck`. **Send me every error**, especially from `src/crypto/signal.ts`.
3. `npm run test:unit` (should match 51 passing) then `npm run test:signal` (the real-crypto tests; send me the output whatever it is).
4. `npm run build`, then run backend + `npm run dev`, register two accounts in two browser profiles, send messages, check the safety numbers match.
5. Then ask for Stage 4.

## Platform requirements

Python 3.11+, Node.js 20+ (22 recommended; unit tests use Node's TypeScript stripping), npm, a browser with Web Crypto and IndexedDB over HTTPS or localhost. No Docker.

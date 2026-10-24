# Client cryptography design, dependency licensing and security limitations

Owner: Person 1 (E2EE cryptography and frontend). Scope: `frontend/src/crypto/`,
the React UI, and the frontend tests. Backend and relay are covered by
`architecture.md`, `database-schema.md` and `THREAT_MODEL.md`.

> **Verification status (2026-10-22).** Run by the project owner on Windows (Node v24.14.1), on
> the current toolchain (Vite 6.4.5, vitest 4.1.11, `@vitejs/plugin-react` 5.x, locked in
> `package-lock.json`): `npm run typecheck` clean, `npm run test:unit` 59 passed (60 in the final
> package, which adds one test), `npm run test:signal` 11 passed against the real Signal library,
> `npm run build` succeeded, `npm audit --omit=dev` found 0 vulnerabilities, backend `pytest`
> 130 passed. Two real users were run in two browser profiles on laptop and phone widths.
> Section 9 has the exact table.

## 1. Design in one page

| Layer | Choice | Where |
|---|---|---|
| Protocol | Signal protocol: **X3DH** session setup (identity key + signed prekey + one-time prekey) and **Double Ratchet** message protection. No PQXDH. | library: `@privacyresearch/libsignal-protocol-typescript` 0.0.16 |
| Our code's role | Store state, map library calls and errors to our interface. **No cryptographic primitive, KDF, cipher composition or ratchet is written by us.** | `crypto/signal.ts`, `crypto/cipher.ts` |
| Chat logic | Dedup, persistence ordering, trust decisions, outbox, quarantine | `crypto/engine.ts` |
| Local secrets | One JSON state object (identity private key, prekeys, sessions, contacts, history) sealed with AES-256-GCM under a **random 256-bit vault key**; the vault key is wrapped (encrypted) with AES-256-GCM under a PBKDF2-SHA256 (600 000 iterations) key derived from the account password. Stored in IndexedDB. | `crypto/vault.ts`, `crypto/idb.ts` |
| Identity verification | Trust on first use (TOFU) plus a safety number the users compare out of band | `crypto/fingerprint.ts`, `SafetyPanel.tsx` |
| Wire format | `base64(JSON{v:1, t:1\|3, b:base64 ciphertext})`; plaintext is `JSON{v:1, text, sent_at}` encrypted by the Signal session | `crypto/envelope.ts` |

The engine talks only to the `CipherBackend` interface, so the library can be replaced
(official libsignal or vodozemac compiled to WebAssembly, or a PQXDH-capable
implementation) without touching the engine.

### 1.1 Session setup (X3DH)

1. On first login on a browser the client generates an identity key pair, a signed prekey
   (signed by the identity key) and 50 one-time prekeys. **They are saved to the encrypted
   vault before anything is published.**
2. Only public halves are uploaded (`POST /api/keys`). One-time prekeys are topped up when the
   server reports fewer than 20 left; ids are never uploaded twice.
3. To message someone for the first time the sender fetches their bundle, the library verifies the
   signed-prekey signature, runs X3DH and produces a *pre-key message* (type 3). The recipient's
   library consumes the one-time prekey (single use) when it decrypts that message.

### 1.2 Message flow and ordering rules (engine)

Sending: validate text length, check the contact's identity key, make sure a session exists,
encrypt, **save (ratchet advance + outbox entry) to the vault, only then touch the network**. A
dropped connection re-sends the *same ciphertext and id*; it never re-encrypts, so the ratchet
does not advance twice and the relay can de-duplicate.

Receiving: drop duplicates by `(sender, message id)` **before** decryption; decrypt; save the
plaintext and the ratchet state together; only then acknowledge to the relay. If the save fails
the engine stops (fails closed) and does not acknowledge. A message that fails authentication, is
a replay, or is malformed is discarded, never displayed, and acknowledged so it is not redelivered
forever. A "could not be verified" notice is recorded instead.

All state-changing work runs one at a time (`runExclusive`) so two overlapping encrypt/decrypt
calls cannot corrupt a session.

### 1.3 Identity keys and warnings

* The first identity key seen for a contact is **pinned**.
* A different key (found when opening a chat, before sending, when fetching a bundle, or inside an
  incoming pre-key message) sets a `keyChange` flag, **blocks sending**, **holds incoming messages
  as ciphertext** (quarantine, not shown), clears any "verified" mark, and adds a visible note.
* The user must open the safety-number panel and explicitly accept the new key. Accepting resets the
  session, leaves the contact **unverified**, then retries the held messages.
* The UI shows a status for every contact in the list and in the chat header: `unverified`,
  `✔ verified`, or `⚠ key changed`. An unverified contact gets a non-blocking banner with a
  "Verify now" action; a changed key gets a blocking banner.

### 1.4 Safety number

SHA-512 over a domain-separated, canonically ordered pair of (user id, identity public key),
rendered as 12 groups of 5 digits. It is **SecureChat's own construction, not Signal's**, and does
not interoperate with Signal. Both parties compute the same value; the UI says so.

### 1.5 Session persistence

All sessions live in the encrypted vault blob and are written on every state change. After a
restart the client restores sessions, the processed-id set (so duplicates and replays stay
rejected), pinned identities, verification marks, held messages and the unsent outbox. Tests in
`tests/node/engine.test.ts` cover restart with a fake cipher; `tests/signal/signal.spec.ts` covers
restart with the real ratchet (not yet run, see section 9).

A reload requires logging in again, because the vault key comes from the password and the password
is never stored (not in `localStorage`, `sessionStorage` or IndexedDB).

## 2. Defect found and fixed in this revision

React `StrictMode` (development) runs effects twice. `ChatApp` called `openEngine` from an effect,
so two unlocks of a **new** account ran concurrently, each saw "no vault yet", generated
**different identity keys** and raced to write them to IndexedDB. `openEngine` now shares one
in-flight attempt per user and socket link (`crypto/session.ts`).

Also fixed: a test assertion ending in `|| true` could never fail; it now checks that the held
message sits in the quarantine as ciphertext.

## 3. Dependency licensing

Not legal advice; confirm before distributing.

| Package | Role | License | Status of this information |
|---|---|---|---|
| `@privacyresearch/libsignal-protocol-typescript` 0.0.16 | Signal protocol (X3DH, Double Ratchet) | **GPL-3.0-only** | Confirmed by `frontend/licenses.json` (license-checker, production dependencies) |
| `@privacyresearch/curve25519-typescript` 0.0.12 | curve25519 (asm.js) used by the library | **GPL-3.0-only** | Confirmed by `licenses.json` |
| `@privacyresearch/libsignal-protocol-protobuf-ts` 0.0.9 | protobuf message definitions used by the library | **GPL-3.0-only** | Confirmed by `licenses.json` |
| the other 26 production packages (React, `long`, `protobufjs`, etc.) | UI and support code | MIT (10), BSD-3-Clause (10), Apache-2.0 (3), ISC (2), plus the project's own private package (reported as UNLICENSED) | From `licenses.json`; the report lists only licence identifiers, so licence texts and notice obligations were not reviewed |

Check on a machine with network access, after `npm install`:

```bash
cd frontend
npx --yes license-checker --production --summary
npx --yes license-checker --production --csv > ../docs/third-party-licenses.csv
```

**What GPL-3.0 means here.** The built JavaScript bundle contains the library, and serving it to
users is distribution of that bundle. The whole frontend then has to be offered under
GPL-3.0-compatible terms with its source. That is workable for a coursework project (publish the
repository under GPL-3.0 or a compatible licence, keep the notice in the repo, and say so in the
report). If a permissive licence is needed instead, replace the backend behind `CipherBackend`.
No source of the library is copied into this repository.

## 4. Security properties and the evidence behind them

| Claim | Basis | Status |
|---|---|---|
| Relay cannot read messages | Only `base64(JSON{ciphertext})` envelopes are sent; tests assert the marker text and the sender's private identity key never appear in anything the relay saw | Engine behaviour proven with a fake cipher (executed). Real encryption: test written, **not run** |
| Tampered or truncated ciphertext is rejected, nothing shown | Library MAC check; engine discards and records a notice | Engine behaviour executed (fake cipher). Library MAC behaviour: tests written, **not run** |
| Replays and duplicates do not show twice | Dedup by id before decryption (executed) and library one-time message keys (not run) | Partly executed |
| Identity change is detected, blocks sending, holds messages, resets verification | Engine logic | Executed (fake cipher), including across a restart |
| Local keys and history are encrypted at rest | AES-256-GCM + PBKDF2 vault with **key wrapping** (random vault key wrapped by password-derived key) | Vault logic executed; IndexedDB never run |
| Forward secrecy, post-compromise security | Properties of the Double Ratchet as implemented by the library | **Not claimed.** The out-of-order and "same plaintext, different ciphertext" tests show the ratchet advancing, but there is no test that models a key compromise |

## 5. Security limitations

1. **Library:** GPL-3.0, unaudited, maintenance status not verified, no PQXDH (no protection against
   "harvest now, decrypt later" attacks by a future quantum adversary).
2. **Modified code:** a browser E2EE app is delivered by the server. A compromised or malicious
   server (or CDN, or Cloudflare) can ship JavaScript that steals keys or plaintext. Not defended.
3. **XSS:** any script in the page can read the in-memory password, session token and decrypted
   history. No Content-Security-Policy yet. A CSP meta tag was deliberately not added: it would break
   the Vite dev server and could not be tested here.
4. **Password is also used to wrap the vault key.** The server receives the password at login, so a malicious server can learn it. The vault uses a random 256-bit key (generated per browser profile) to encrypt the actual payload; this vault key is then wrapped (encrypted) with a key derived from the account password via PBKDF2-SHA256 (600k iterations). A malicious server with a copy of the browser's IndexedDB data could unwrap the vault key and decrypt the vault. There is no change-password flow (changing it later would require re-wrapping the vault key) and no recovery: forgetting the password loses keys and history.
5. **TOFU:** the first key seen is trusted. A malicious relay can substitute keys at first contact
   until users compare safety numbers. The UI warns about unverified contacts but does not force
   verification.
6. **Safety number is not Signal's** and only matches inside SecureChat.
7. **No multi-device.** A second browser creates a new identity; contacts get a safety-number
   change. The first browser stops publishing when it notices its keys were replaced.
8. **Metadata:** the relay sees who talks to whom, when, and message sizes.
9. **Local data loss:** a new browser starts with new keys and no history; contacts see a change.
10. **Quarantine and processed-id lists are bounded** (100 held messages; 5000 ids per sender, oldest
    dropped). A replay of a message older than the last 5000 from one sender would reach the
    library, which still rejects it, but the first line of defence no longer remembers it.
11. **Identity check throttle:** when sending, the contact's server-side key is re-checked at most
    once every 10 seconds (first-time session setup always checks).
12. **Endpoint compromise, screenshots, notification previews and malicious extensions** are outside
    anything this application can protect.
13. **Unlock is not rate-limited locally** beyond PBKDF2's cost (600 000 iterations per guess).

## 6. UI behaviour summary

* **Login/registration:** `AuthScreen`; warns that the password is used to wrap (encrypt) the local vault key, not directly as the encryption key.
* **Contacts and conversations:** sidebar lists conversations with trust badge and last-message
  preview; search by username prefix starts a conversation.
* **Chat:** delivery status shown as symbol plus word (`…` sending, `✓` sent to relay, `✓✓`
  delivered, `⚠` failed), offline notice, system notes for discarded or held messages.
* **Safety number panel:** 12 groups in a grid, copy button, "they match: mark as verified", and for a
  changed key the new number next to the previous one with an explicit accept button.
* **Responsive:** one pane at a time on phones (Back button), sidebar plus chat from 52 rem (about
  830 px) upward; 16 px inputs and 44 px touch targets (no iOS zoom), `dvh` heights that follow the
  on-screen keyboard, safe-area insets, visible focus rings, reduced-motion support, dark mode.
  Checked in Chrome at laptop width and in device emulation (iPhone 12 Pro): no sideways scroll, no
  overlap. On a phone the yellow unverified banner takes about a third of the screen. Not tested on a
  physical phone or with a screen reader.

## 7. How to run everything (on a machine with network access)

```bash
cd frontend
npm install
npm run typecheck        # tsc --noEmit
npm run test:unit        # engine + primitives (Node's test runner; no install needed beyond Node 22)
npm run test:signal      # REAL library through the real engine (vitest)
npm run build            # type-check then production build
```

Please keep the **full output** of `typecheck` and `test:signal`. If `typecheck` reports errors in
`src/crypto/signal.ts`, they are expected to be about the library's real type declarations; the
adapter was written from the library's documented API and has not been compiled against it.

## 8. Dependency pinning

The Signal library is pinned to exactly `0.0.16`. `package-lock.json` exists (generated on the
owner's machine) and should be committed so builds are reproducible. Build and test tools were
upgraded by `npm audit fix` (Vite 6, vitest 4, plugin-react 5); all checks in section 9 were
re-run afterwards and pass.

## 9. What was and was not executed

| Check | Result |
|---|---|
| `npm install` (Windows, Node v24.14.1) | Run: 121 packages, 6 audit warnings (3 moderate, 1 high, 2 critical) |
| `npm run typecheck` (real React and library types) | Run: no errors, before and after the toolchain upgrade |
| `npm run test:unit` | Run: **59 passed, 0 failed** (21 primitives, 38 engine tests with a fake cipher), also after the upgrade |
| `npm run test:signal` (real Signal library through the real engine; vitest 2.1.9, then re-run on 4.1.11) | Run: **11 passed, 0 failed**. The first run had 2 failures, both mistakes in the new tests (they counted the client's own sent message as received); fixed, then all passed |
| `npm run build` (tsc then vite build; Vite 5.4.21, then re-run on 6.4.5) | Run: success both times (bundle 587 kB, 198 kB gzip on Vite 6). Warnings: Vite externalised Node's `path` and `fs` for the library's curve25519 asm code (not used in the browser); the JS bundle is 581 kB (195 kB gzip) |
| Mutation check of the new engine tests | Run: breaking dedup or the verification reset made the relevant tests fail; code restored |
| License inventory (`license-checker`, production dependencies) | Run: 29 packages; 3 GPL-3.0-only (the Signal packages); see section 3 |
| Dev server on the upgraded toolchain (Vite 6.4.5) | Starts (observed) |
| Typecheck, unit tests, real-library tests and build after the upgrade to Vite 6.4.5 / vitest 4.1.11 / plugin-react 5.x | Run: all pass (2026-10-21 14:35) |
| `npm audit --omit=dev` | Run: **found 0 vulnerabilities** (the earlier 6 warnings were in build/test tools and went away with the Vite 6 / vitest 4 upgrade) |
| Backend started locally; `/api/health` | Run: healthy |
| Backend tests (`pytest`, Python 3.12.10) including the 25 HTTP/WebSocket tests skipped earlier | Run: **130 passed, 0 failed** (1 deprecation warning from Starlette's test client) |
| UI with two real users (Alice, Bob) in two browser profiles | Run: relay connected, messages sent and shown as delivered, safety numbers matched, verified badge, offline delivery, key-change warning and accept all observed |
| Key change detection | Run: after Bob's browser data was cleared and he logged in again, Alice saw the red "safety number changed" banner, sending was blocked, and accepting left the contact unverified. Found and fixed on the way: the contact list badge did not refresh when the change was discovered while sending (UI is now notified), and the open chat re-checks the contact's key every 15 s |
| Laptop layout and phone layout (Chrome device emulation, iPhone 12 Pro) | Run: two panes on laptop; one pane with Back button on phone; no horizontal scroll. Physical phone and screen reader **not tested** |
| Bright colour theme | Applied by the owner and viewed in the browser |
| Unit tests in the final package | 60 passed (the extra test checks that sending after a contact's key changed notifies the UI; mutation-checked). Run by the author on the final code; the owner's last run was 59 |

Incident worth recording: a scripted text replacement used to add the UI notification also changed a
line that should have stayed conditional, which made every send throw a key-change error. Type
checking and the build still passed; the unit and real-library tests caught it. It was repaired and
the full suite re-run. Lesson: type-check and build do not replace the tests.

All results from the owner's machine were reported back to the author of this revision, who could
not run npm in its own environment.

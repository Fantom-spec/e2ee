# Threat model

Status: design document for the **target** system. Stage 2 implements accounts,
sessions and the relay; encryption and key verification (Stage 3) do not exist yet.

## Assets

1. Message contents (confidentiality, integrity).
2. Users' private keys and session state (live only in the browser).
3. Account credentials and session tokens.
4. Communication metadata (who talks to whom, when, how much).
5. Service availability.

## Parties and trust

| Party | Trusted for | Not trusted for |
|---|---|---|
| Sender / recipient browser | Plaintext, private keys | n/a (if compromised, game over for that user) |
| Relay (FastAPI + SQLite on the laptop) | Routing, queueing, availability (best effort) | Message confidentiality; honesty about key directory and delivery receipts |
| **Cloudflare (tunnel edge)** | Carrying traffic | Anything beyond transport: it terminates TLS, so it can read HTTP/WebSocket traffic and see metadata and ciphertext |
| Network observers | n/a | Everything |
| Other authenticated users | n/a | Everything; may send malformed or hostile input |

## Adversaries and expected outcomes

| Adversary | Can do | E2EE design should result in |
|---|---|---|
| Passive network observer | See endpoints, timing, sizes | Cannot read content (TLS + E2EE). Metadata is visible. |
| Active network attacker | Drop, delay, reorder, modify | Modification detected by AEAD; drops and delays are not preventable. |
| Honest-but-curious relay operator | Read database and logs | Sees only ciphertext and metadata. |
| Malicious relay (modifies behaviour, not code) | Replay, drop, reorder, forge receipts, swap prekeys | Replays rejected by clients; **key substitution at first contact is possible until users verify safety numbers**; receipts are untrusted. |
| **Malicious relay that alters the delivered JavaScript** | Ship code that steals keys or plaintext | **Not defended.** This is the fundamental limit of browser-delivered E2EE. |
| Malicious authenticated user | Impersonation attempts, oversized/malformed input, enumeration | Server-side authorization on every operation; schema and size validation; rate limits (planned). |
| Compromised endpoint (malware, shoulder surfing, XSS) | Read plaintext and keys | Not defended. XSS in our own app is treated as endpoint compromise; strict CSP is planned. |

## Security goals (target) and current status (Stage 3)

| Goal | Status |
|---|---|
| Relay cannot read message contents | Implemented (client-side Signal encryption); engine tests show only envelopes reach the relay (fake cipher); real-library test written, **not run** |
| Ciphertext tampering detected | Delegated to the library's authenticated encryption; engine discards and acknowledges failures (tested with fake cipher); real-library test **not run** |
| Replay / duplicate rejection | Engine dedups by (sender, id) before decrypting (tested); replay under a new id relies on the library's ratchet (fake-cipher test passes, real-library test **not run**) |
| Authenticated, authorized API and WebSocket | Implemented; logic tested; HTTP/WebSocket layer **not executed** |
| Key-change detection and fingerprint verification | Implemented: identity pinned on first use, change blocks sending and quarantines incoming messages, verification reset (engine tests, executed). First contact is still trust-on-first-use until users compare safety numbers. |
| Fail-safe configuration, no wildcard CORS, docs off in production | Implemented; logic tested, HTTP layer **not executed** |
| Brute-force / flooding resistance | In-memory limiters (login, registration, send, bundle fetch); limiter logic tested; resets on restart |
| Forward secrecy / post-compromise security | Not claimed: no test of ours demonstrates key evolution |

## Explicit non-goals and limitations

* No protection against a server (or CDN) that modifies client JavaScript.
* No metadata protection or traffic-analysis resistance.
* No multi-device sync, group chat, backups, or account recovery of message history.
* A lost browser profile means lost keys and local history; sessions must be re-established.
* Screenshots, clipboard, notifications and browser extensions are out of scope.
* Tests demonstrate behaviour for tested scenarios; they are not a formal proof.

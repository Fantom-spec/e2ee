# SecureChat: end-to-end encrypted chat (Computer Networks project)

> **Status: Stage 3 frontend verification checkpoint.** The frontend unit tests, real Signal-library tests and production build have been run successfully. This remains an unaudited academic project; passing tests do not establish safety for sensitive real-world communications.

## What this is

A browser-based one-to-one chat where messages are encrypted on the clients and
the server only relays ciphertext. Target demo: a phone on mobile data and a
second laptop on another network talk through a FastAPI relay running on your
laptop, exposed with Cloudflare Tunnel.

* Frontend: React + TypeScript (Vite)
* Backend: Python FastAPI, WebSocket relay, SQLite
* Crypto: `@privacyresearch/libsignal-protocol-typescript` 0.0.16 (Signal protocol; GPL-3.0, unaudited, see `docs/protocol-decisions.md` and `docs/crypto-design.md`); no homemade cryptography
* Public access: Cloudflare Tunnel (no Docker, no cloud backend)

## What exists today (Stage 3)

* Everything from Stage 2 (accounts, sessions, rate limits, search, WebSocket ciphertext relay)
* Public-key directory: identity key, signed prekey, one-time prekeys; key-change history
* Client-side end-to-end encryption through the Signal protocol library; the server relays opaque envelopes
* Encrypted local key/history vault (AES-GCM, PBKDF2) in IndexedDB
* Trust-on-first-use identity pinning, safety numbers, key-change blocking, verification marks
* Chat UI: conversations, delivery status, offline queue that re-sends the same ciphertext, safety-number panel
* Not yet: hardening pass, benchmarks, Cloudflare Tunnel guide, demo guide (Stages 4 to 6)

## Repository layout

```
backend/            FastAPI app, schema, requirements
frontend/           React + TypeScript (Vite)
tests/backend/      unittest-style tests (run under pytest or unittest)
frontend/tests/     node/ (logic tests, fake cipher), signal/ (real-library tests), helpers/
scripts/            init_db.py, check_secrets.py, make_zip.py
docs/               architecture, spec-review, database-schema, protocol-decisions, original specification
.env.example        backend configuration template
THREAT_MODEL.md  SECURITY.md  PROGRESS.md
```

## Setup (run from the project root)

Requirements: Python 3.11+ (3.13 was present in the authoring sandbox), Node.js 20+ with npm, git.

### 1. Backend

Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements-dev.txt
cp .env.example .env
```
Windows (PowerShell):
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements-dev.txt
Copy-Item .env.example .env
```

Generate a secret and paste it into `.env` as `SECURECHAT_SECRET_KEY=`:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```
The server **refuses to start** without a secret of at least 32 characters.

Initialise the database and start the API:
```bash
python scripts/init_db.py
uvicorn app.main:create_app --factory --app-dir backend --host 127.0.0.1 --port 8000
```
Check it: open `http://127.0.0.1:8000/api/health`. Expected JSON: `{"status":"ok","version":"0.1.0","stage":2}`.

### 2. Frontend (second terminal)

```bash
cd frontend
cp .env.example .env        # Windows: Copy-Item .env.example .env
npm install
npm run dev
```
Open the URL Vite prints (default `http://localhost:5173`). It proxies `/api` to
the backend address in `frontend/.env`. You should see the registration/login screen. Register an account, then log in: the page shows "Relay connected" once the WebSocket is up. Open a second browser profile to create a second account and find it with the search box.
Production build (type-checks first): `npm run build`.

### 3. Tests

```bash
# with the venv active, from the project root
pytest                                    # full suite
# or, with no extra packages (HTTP tests will show as SKIPPED):
PYTHONPATH=backend python -m unittest discover -s tests/backend -v
```
Windows unittest form: `$env:PYTHONPATH="backend"; python -m unittest discover -s tests/backend -v`

Frontend (from `frontend/`, after `npm install`):

```bash
npm run test:unit     # Node built-in runner: primitives + engine logic with a FAKE cipher (60 tests)
npm run test:signal   # vitest: the REAL Signal library through the engine (11 tests)
npm test              # Run both frontend test suites
```

Housekeeping check before sharing a ZIP: `python scripts/check_secrets.py`

## Not written yet (planned stages)

| Stage | Content |
|---|---|
| 2 | **Done (partly unverified):** see above |
| 3 | **Frontend tests and production build pass; browser/backend integration still needs verification** |
| 4 | Reliability and hardening, CSP, remaining security tests |
| 5 | Responsive UI, benchmark script, Cloudflare Tunnel guide, demo guide |
| 6 | Full verification and `SecureChat_FINAL.zip` |

The Cloudflare Tunnel guide, benchmark instructions and academic demonstration
guide are deliberately **not** included yet: they must match code that does not
exist, and unverified instructions would be misleading.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Configuration error: SECURECHAT_SECRET_KEY is required` | Create `.env` from `.env.example` and set a secret of 32+ characters. |
| `Origin ... is not https` | `SECURECHAT_ENV` is unset (defaults to production). Set `SECURECHAT_ENV=development` for local http. |
| Page says "Cannot reach the server" | Backend not running, or `VITE_DEV_BACKEND_URL` in `frontend/.env` is wrong. Restart `npm run dev` after editing `.env`. |
| `Origin ... is not https` / startup error about `SCRYPT_LOG_N` | In production mode the scrypt cost must be at least 15; leave it at the default 17. |
| Login returns 429 | Rate limit hit (5 failures per username / 5 min). Wait, or restart the backend in development. |
| Relay stays on "disconnected, retrying" | Check the backend terminal; the frontend dev proxy must forward `/ws` (it does when `VITE_DEV_BACKEND_URL` is set) and the page origin must be in `SECURECHAT_ALLOWED_ORIGINS`. |
| Browser CORS error when `VITE_API_BASE_URL` is set | Add that origin to `SECURECHAT_ALLOWED_ORIGINS`. |
| `pip` or `npm` dependency conflicts | Run npm audit in frontend/; review GPL-3.0-only licensing separately. |

## Security notice

Read `SECURITY.md` and `THREAT_MODEL.md`. In particular: a browser E2EE app
downloads its code from the server, so a malicious server can steal keys, and
Cloudflare Tunnel terminates TLS at Cloudflare. This project does not defend
against either.


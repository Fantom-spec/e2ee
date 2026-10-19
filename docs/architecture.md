# Architecture

Derived from the uploaded `architecture.md` specification, adapted to a browser
client hosted from a single laptop and exposed through Cloudflare Tunnel.
Corrections to the specification are listed in `spec-review.md`.

```mermaid
flowchart LR
    subgraph A["Client A: browser (phone, mobile data)"]
        AUI["React UI"]
        ASTORE["IndexedDB: identity + session state (Stage 3)"]
        AENG["Protocol engine (Stage 3)"]
        AUI --> AENG
        ASTORE <--> AENG
    end

    CF["Cloudflare edge<br/>(terminates TLS, sees metadata + ciphertext)"]

    subgraph H["Hosting laptop"]
        CFD["cloudflared tunnel"]
        subgraph API["FastAPI process"]
            REST["REST: auth, users, prekeys"]
            WS["WebSocket relay"]
            Q["Offline queue"]
        end
        DB[("SQLite: accounts, public keys,<br/>ciphertext envelopes")]
        CFD --> REST
        CFD --> WS
        WS --> Q
        REST --> DB
        Q --> DB
    end

    subgraph B["Client B: browser (laptop, other Wi-Fi)"]
        BUI["React UI"]
        BSTORE["IndexedDB (Stage 3)"]
        BENG["Protocol engine (Stage 3)"]
        BUI --> BENG
        BSTORE <--> BENG
    end

    AENG -- "HTTPS / WSS" --> CF
    BENG -- "HTTPS / WSS" --> CF
    CF -- "tunnel" --> CFD
```

## Message data flow (target design, Stages 2 to 4)

```mermaid
sequenceDiagram
    participant A as Client A
    participant S as Relay (FastAPI)
    participant B as Client B
    A->>S: GET prekey bundle for B (authenticated)
    S-->>A: B's public identity + prekeys
    A->>A: Establish session, encrypt (never leaves the browser in plaintext)
    A->>S: WSS send {id, to: B, envelope(ciphertext)}
    alt B online
        S->>B: deliver envelope
    else B offline
        S->>S: store envelope (expires after TTL)
        B->>S: reconnect, authenticate, fetch pending
        S->>B: deliver envelope
    end
    B->>B: verify + decrypt, deduplicate by id
    B->>S: ack(id)
    S->>S: delete stored envelope
    S-->>A: delivered (relay-reported)
```

## Implementation status (Stage 2)

| Component | Status |
|---|---|
| Config loading with fail-safe validation | Implemented, tested |
| SQLite schema + initialisation, repository functions | Implemented, tested |
| Auth service (register/login/session/logout), password + token primitives | Implemented, tested |
| Validators, rate limiter, WebSocket ticket store | Implemented, tested |
| Relay logic (routing, offline queue, ack, dedup, limits) | Implemented, tested with fake sockets over real SQLite |
| FastAPI routes, WebSocket endpoint, middleware | Written, **not executed** |
| React auth screens, user search, relay status | Written, **not built or run** |
| E2EE protocol, identity verification, chat UI | Not started (Stage 3) |

## Trust boundaries

1. Browser ⇄ Cloudflare: TLS (Cloudflare can read HTTP-level data).
2. Cloudflare ⇄ laptop: Cloudflare Tunnel connection.
3. Relay process ⇄ SQLite: local file, mode 0600.
4. Browser tab ⇄ the code the relay delivered: **a malicious server can change this code** (see `THREAT_MODEL.md`).

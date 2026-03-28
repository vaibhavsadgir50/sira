# SIRA Developer Documentation

SIRA is a secure, stateless web protocol that encrypts all communication between browser and server using WebSocket frames. It hides **how** your application works from the network — not just the data, but the structure, field names, and business logic.

> **Core philosophy:** Server owns all state. Browser owns nothing.

---

## What SIRA does

| Without SIRA | With SIRA |
|---|---|
| `POST /api/search?q=shoes` | `WS /w` → 1024-byte encrypted binary frame |
| Field names visible on the wire | Field names, action types, routes — all encrypted |
| REST structure reveals your app's data model | Single encrypted channel reveals nothing |
| Server-side sessions or JWT in localStorage | Stateless session encrypted in HttpOnly cookie |

---

## Key properties

- **Wire encryption** — Every frame is exactly 1024 bytes of AES-256-GCM ciphertext
- **Stateless sessions** — No session table on the server. Sessions live in an encrypted cookie
- **Horizontal scaling** — Any server instance with the master secret can serve any client
- **Three server SDKs** — Rust, Node.js, Python — all cross-verified with shared test vectors
- **One browser SDK** — Vanilla ES6 module, no build step required
- **Developer model** — Write one `pipeline` function instead of many REST routes

---

## How it works (30 seconds)

```
Browser                              Server
  │                                    │
  │── POST /h (32-byte public key) ───>│  X25519 handshake
  │<── server public key + cookie ─────│  Derives AES key
  │                                    │  Stores key in encrypted cookie
  │                                    │
  │── WebSocket /w (cookie attached) ──│  Decrypts cookie, recovers AES key
  │                                    │
  │── encrypted CLsend frame ─────────>│  Decrypt → call pipeline(action)
  │<── encrypted SVsend frame ─────────│  Encrypt pipeline's response
  │                                    │
  └── close ───────────────────────────┘
```

---

## Sections

| Section | What you'll find |
|---|---|
| [Quick Start](quickstart.md) | Running your first SIRA server in 5 minutes |
| [Core Concepts](concepts.md) | Sessions, state hashing, chunking |
| [API Reference](api-reference.md) | HTTP endpoints: `/h`, `/r`, `/w` |
| [WebSocket Protocol](websocket.md) | Frame format, CLsend, SVsend, BEAT |
| [Browser Client](browser-client.md) | `sira.js` — `open`, `send`, `refreshAuth`, `close` |
| [Server: Rust](server-rust.md) | `Pipeline` trait, `SiraState`, `router()` |
| [Server: Node.js](server-node.md) | `SiraServer`, `Pipeline` class |
| [Server: Python](server-python.md) | `SiraServer`, `Pipeline` ABC |
| [Authentication](authentication.md) | `/r` refresh flow, user identity |
| [Configuration](configuration.md) | Environment variables, deployment |
| [Security Model](security.md) | What SIRA protects and what it doesn't |
| [Test Vectors](test-vectors.md) | Cross-language conformance testing |

# Core Concepts

---

## Sessions

SIRA sessions are **stateless** — the server keeps no session table. The session is stored entirely in an encrypted HttpOnly cookie called `__s`.

When a client performs the handshake (`POST /h`):

1. An X25519 key exchange happens. Both sides derive the same AES-256 wire key independently.
2. The server creates a `SessionToken` object containing the wire key and a timestamp.
3. The server encrypts the `SessionToken` with a cookie key derived from the master secret.
4. The encrypted token is set as a cookie: `__s=<base64url>; HttpOnly; Secure; SameSite=Strict`

When the client opens a WebSocket (`GET /w`):

1. The browser automatically sends the `__s` cookie.
2. The server decrypts the cookie, recovers the `SessionToken` and the wire key.
3. No lookup needed — no Redis, no database, no sticky sessions.

### Session fields

| Field | Type | Description |
|---|---|---|
| `key` | 32 bytes | The AES-256 wire encryption key |
| `created_at` | Unix timestamp | When the session was created |
| `persistent` | bool | `true` = 7-day cookie, `false` = 1-day cookie |
| `user_id` | string or null | Set after a successful `/r` auth refresh |

---

## Window IDs

Each browser window (or tab) gets a unique `window_id` — a random 16-character hex string generated on `sira.open()`.

Every message includes the window ID in the `w` field. This lets a single session support **multiple browser windows** over separate WebSocket connections. Your pipeline receives `window_id` so you can track per-window state if needed.

---

## State Hashing

SIRA uses a hash chain to prevent replay attacks and state desync.

### The substate

The `substate` (`s` field in CLsend/SVsend) is an **opaque byte blob** that the client carries between requests. The server doesn't store it — the client echoes it back on every request.

### How hashing works

Before sending a CLsend, the client computes:

```
If substate is set:
  expected_hash = SHA256(substate_bytes)
Else:
  expected_hash = SHA256("sst-initial-" + window_id_bytes)
```

The server independently computes the same hash and rejects any CLsend where `h` doesn't match.

### Why this matters

- If a middleman replays or reorders frames, the hash won't match and the server rejects it.
- If client and server get out of sync, the connection fails loudly instead of silently producing wrong results.

### Using substate in your app

Most apps don't need substate. It's optional (`s` field can be `null`). Use it when you need the server to carry a small amount of per-window state across multiple calls **without storing it server-side**.

---

## Wire Frame Format

Every SIRA message — in both directions — is exactly **1024 bytes**.

```
┌──────────────────────────────────────────────┐
│  IV (12 bytes)                               │
├──────────────────────────────────────────────┤
│  AES-256-GCM ciphertext (1012 bytes)         │
│  ┌────────────────────────────────────────┐  │
│  │  request_id (16 bytes)                 │  │
│  ├────────────────────────────────────────┤  │
│  │  MessagePack payload (up to 980 bytes) │  │
│  ├────────────────────────────────────────┤  │
│  │  zero padding                          │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

The fixed 1024-byte size means all SIRA traffic looks identical on the wire — an observer can't tell small messages from large ones, or heartbeats from real requests.

### request_id

The `request_id` is a random 16-byte value that pairs a CLsend with its SVsend response. The browser matches incoming frames by `request_id` to resolve the correct `await sira.send()` promise.

---

## Chunking

When a MessagePack payload exceeds 980 bytes, it's split into multiple **chunk frames**.

Each chunk is a separate 1024-byte encrypted frame containing a `ChunkPayload`:

```json
{ "k": "ch", "i": 2, "n": 5, "d": "<bytes>" }
```

| Field | Meaning |
|---|---|
| `k` | Always `"ch"` (chunk marker) |
| `i` | Chunk index (0-based) |
| `n` | Total chunks |
| `d` | Raw data bytes |

All chunks share the same `request_id`. The receiver buffers chunks and reassembles them when all `n` chunks arrive.

**Limits:**
- Max assembled payload: 8 MB
- Max chunk count: 16,384

As a developer, chunking is handled automatically — you never write chunk logic.

---

## Heartbeats

To keep the WebSocket alive and detect dead connections:

- Every 30 seconds, either side sends a `BEAT` frame: `{ "beat": true, "w": "<window_id>" }`
- If no message is received for 60 seconds, the connection is dropped

The browser SDK manages heartbeats automatically.

---

## Rate Limiting

The server enforces per-IP rate limits on a rolling 60-second window:

| Endpoint | Limit |
|---|---|
| `POST /h` | 120 requests / 60 s |
| `POST /r` | 120 requests / 60 s |
| `GET /w` | 60 upgrades / 60 s |

---

## Master Secret

The `SIRA_MASTER_SECRET` is a 32-byte (64 hex chars) key used to **encrypt session cookies**. It's the root of trust for your deployment.

- All server instances in your fleet must share the same master secret
- Rotating the master secret invalidates all existing sessions
- The master secret never leaves the server — it's never sent to clients

The cookie key is derived from the master secret:

```
cookie_key = HKDF-SHA256(master_secret, info="sst-session-token-v1")
```

This separation means you could theoretically use different HKDF info strings to derive multiple purpose-specific keys from one master secret.

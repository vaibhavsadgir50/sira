# WebSocket Protocol

All application communication happens over the encrypted WebSocket at `/w`. This page covers the frame formats and the three message types you'll encounter.

---

## Frame Format

Every WebSocket message — in both directions — is exactly **1024 bytes** of binary data.

```
Byte offset    Content
───────────    ───────────────────────────────────────────────────────
0 – 11         IV (12 bytes, random per frame)
12 – 1023      AES-256-GCM ciphertext (1012 bytes)

Inside the ciphertext (after decryption, 996 bytes):
0 – 15         request_id (16 bytes, random, links request to response)
16 – 995       MessagePack payload (zero-padded to fill 980 bytes)
```

The fixed 1024-byte size is intentional. Every frame looks identical to a passive observer — you can't tell a heartbeat from a large payload just by watching traffic.

---

## Message Types

### CLsend (Client → Server)

The client sends a CLsend frame for every application request.

```json
{
  "h": "a3f8e2c1...",
  "a": { "type": "search", "q": "shoes" },
  "w": "d4b7a1c2e5f8b3a0",
  "s": null
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `h` | string | Yes | State hash (SHA-256 hex). Must match the server's expected hash. |
| `a` | any JSON | Yes | Action payload. Shape is defined by your app. |
| `w` | string | Yes | Window ID (16 hex chars). Unique per browser window. |
| `s` | bytes or null | No | Opaque substate. The client carries this; the server hashes it. |

The `h` value is computed by the client:

```
If s is set:   h = SHA256(s)
If s is null:  h = SHA256("sst-initial-" + window_id_bytes)
```

The server rejects any CLsend where `h` doesn't match its own computation. This prevents replay attacks.

---

### SVsend (Server → Client)

The server sends a SVsend frame in response to every CLsend.

```json
{
  "h": "b7c9f1e4...",
  "r": { "results": [...], "total": 42 },
  "w": "d4b7a1c2e5f8b3a0",
  "s": null
}
```

| Field | Type | Description |
|---|---|---|
| `h` | string | New state hash (SHA-256 hex). The client stores this for the next request. |
| `r` | any JSON | Render. Your pipeline's return value. Shape is defined by your app. |
| `w` | string | Window ID (echoed from CLsend). |
| `s` | bytes or null | Updated substate (echoed from CLsend). |

The `r` field is what `await sira.send(action)` resolves to in the browser.

---

### BEAT (Heartbeat)

Either side can send a heartbeat. The server sends one every 30 seconds. The client echoes it back.

```json
{ "beat": true, "w": "d4b7a1c2e5f8b3a0" }
```

| Field | Type | Description |
|---|---|---|
| `beat` | bool | Always `true` |
| `w` | string | Window ID |

If no message is received for 60 seconds, the connection is dropped.

---

## Chunked Messages

When a payload exceeds 980 bytes after MessagePack encoding, it's split into multiple **chunk frames**.

Each chunk frame contains a `ChunkPayload`:

```json
{ "k": "ch", "i": 0, "n": 3, "d": "<bytes>" }
```

| Field | Type | Description |
|---|---|---|
| `k` | string | Always `"ch"` (identifies this as a chunk) |
| `i` | integer | Chunk index (0-based) |
| `n` | integer | Total number of chunks |
| `d` | bytes | Chunk data |

All chunks for the same message share the same `request_id`. The receiver buffers chunks until all `n` arrive, then reassembles and deserializes.

**Limits:**
- Max assembled payload: 8 MB
- Max chunks: 16,384
- Chunk reassembly timeout: 120 seconds

---

## request_id

The `request_id` is a random 16-byte value embedded in the plaintext of every frame. It pairs a CLsend with its SVsend response.

The browser SDK uses `request_id` to resolve the correct `await sira.send()` promise when multiple in-flight requests overlap. Your pipeline receives the `request_id` indirectly through `window_id` but typically doesn't need to use it.

---

## State Machine Diagram

```
Browser                           Server
  │                                 │
  │  open()                         │
  │── POST /h ─────────────────────>│
  │<── 32-byte server pubkey ───────│
  │    (Set-Cookie: __s)            │
  │                                 │
  │  sira.send(action)              │
  │── WS /w (Cookie: __s) ─────────>│  ← WebSocket upgrade
  │── [encrypted CLsend, 1024 B] ──>│
  │                                 │  pipeline(action) called
  │<── [encrypted SVsend, 1024 B] ──│
  │                                 │
  │  30s later...                   │
  │── [encrypted BEAT, 1024 B] ────>│  (or server sends first)
  │<── [encrypted BEAT, 1024 B] ────│
  │                                 │
  │  close()                        │
  │── WS close ────────────────────>│
  └─────────────────────────────────┘
```

# API Reference

SIRA exposes three HTTP endpoints. These are the **transport layer** — developers don't interact with them directly. The browser SDK and server SDKs handle them automatically.

---

## POST /h — Handshake

Initiates a new session. Performs an X25519 key exchange and sets the session cookie.

### Request

```
POST /h
Content-Type: application/octet-stream
Body: 32 bytes (client X25519 public key)
```

Optional query parameter:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `persistent` | bool | `false` | `true` = 7-day cookie, `false` = 1-day cookie |

Example: `POST /h?persistent=true`

### Response

**200 OK**

```
Set-Cookie: __s=<base64url>; HttpOnly; Secure; SameSite=Strict; Max-Age=86400
Content-Type: application/octet-stream
Body: 32 bytes (server X25519 public key)
```

Both sides now independently derive the same AES-256 wire key from the X25519 shared secret.

**400 Bad Request** — body is not 32 bytes

**429 Too Many Requests** — rate limit exceeded (120 requests / 60 s per IP)

### What happens inside

```
1. Server generates ephemeral X25519 keypair
2. ECDH(server_private, client_public) → shared_secret (32 B)
3. HKDF-SHA256(shared_secret, info="sst-aes-gcm-v1") → aes_key (32 B)
4. Create SessionToken { key: aes_key, created_at: now, persistent, user_id: null }
5. Serialize SessionToken as MessagePack
6. Encrypt with cookie_key (derived from master_secret via HKDF)
7. Return: Set-Cookie __s + server public key (32 B)
```

---

## GET /w — WebSocket

Upgrades the connection to an encrypted WebSocket. All application communication happens here.

### Request

```
GET /w
Connection: Upgrade
Upgrade: websocket
Cookie: __s=<value>
```

The `__s` cookie is sent automatically by the browser on every request to the same origin.

### Response

**101 Switching Protocols** — WebSocket established

**401 Unauthorized** — missing or invalid `__s` cookie (returns 1024 bytes of random noise)

**429 Too Many Requests** — rate limit exceeded (60 upgrades / 60 s per IP)

### What happens inside

```
1. Server extracts __s cookie from request headers
2. Decrypts cookie → recovers SessionToken and wire key
3. Checks revocation (if enabled)
4. Upgrades to WebSocket
5. Begins message loop:
   - Receive 1024-byte binary frame
   - Decrypt with wire key → request_id + payload
   - If BEAT → send BEAT back
   - If ChunkPayload → buffer and reassemble
   - If CLsend → validate state hash, call pipeline, send SVsend
   - Timeout 60s with no message → close
```

### Message format

All WebSocket messages are binary, exactly 1024 bytes. See [WebSocket Protocol](websocket.md) for the frame structure.

---

## POST /r — Auth Refresh

Updates the session with a `user_id`. Use this when you have an app token (from OAuth, magic link, etc.) and want to associate a user identity with the session.

### Request

```
POST /r
Cookie: __s=<value>
Content-Type: application/octet-stream
Body: 1024 bytes (encrypted CLsend frame)
```

The CLsend `action` payload must include an `auth.token` field:

```json
{
  "a": {
    "auth": {
      "token": "your-app-token-here"
    }
  },
  "h": "<state_hash>",
  "w": "<window_id>"
}
```

The `auth.token` value is passed to your `RefreshAuthenticator` implementation.

### Response

**200 OK** — token validated, session updated

```
Set-Cookie: __s=<base64url>; HttpOnly; Secure; SameSite=Strict
Content-Type: application/octet-stream
Body: 1024 bytes (encrypted SVsend frame)
```

The new `__s` cookie contains the same wire key but now includes `user_id`.

**401 Unauthorized** — token invalid or `RefreshAuthenticator` returned an error (returns 1024 bytes of random noise, indistinguishable from a valid error response)

**429 Too Many Requests** — rate limit exceeded

### What happens inside

```
1. Server extracts and decrypts __s cookie
2. Decrypts 1024-byte request body
3. Deserializes CLsend → extracts action.auth.token
4. Calls RefreshAuthenticator.authenticate_app_token(token)
5. On success: create new SessionToken with user_id set
6. Encrypt new SessionToken → new __s cookie
7. Return encrypted SVsend with new cookie
```

---

## Error Responses

SIRA error responses are always **1024 bytes of cryptographically random noise**. This ensures that errors (401, 500) are indistinguishable from valid responses to a passive observer.

Clients detect errors by failing to decrypt the response — a wrong-key decrypt will fail AES-GCM authentication.

---

## Summary

| Endpoint | Method | Purpose | Rate limit |
|---|---|---|---|
| `/h` | POST | X25519 handshake, create session | 120 / 60s |
| `/w` | GET (WS) | Encrypted WebSocket connection | 60 / 60s |
| `/r` | POST | Auth refresh, set user_id | 120 / 60s |

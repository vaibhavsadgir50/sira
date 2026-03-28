# Security Model

SIRA's goal is to protect **how** your application works — not just the data it handles. This page explains exactly what SIRA protects, what it doesn't, and how the cryptography works.

---

## What SIRA protects

### Application structure

Without SIRA, an observer watching your network traffic can see:

```
GET /api/users/42
POST /api/orders { "product_id": 7, "quantity": 2 }
DELETE /api/sessions/current
```

From this, they can infer your data model, your routes, your business logic.

With SIRA, all they see is:

```
POST /h  →  32 random-looking bytes
GET /w   →  WebSocket: stream of 1024-byte binary frames
```

Nothing is readable. Not the action type, not the field names, not the values.

### Wire encryption

Every frame is encrypted with AES-256-GCM:

- **Confidentiality:** Encrypted content is unreadable without the key
- **Integrity:** Any modification to the ciphertext causes decryption to fail (GCM authentication tag)
- **Forward secrecy:** Each session uses a fresh ephemeral X25519 key — compromising the master secret doesn't decrypt past sessions

### Session integrity

SIRA uses a hash chain to prevent replay and reordering attacks:

```
Session start:   h = SHA256("sst-initial-" + window_id)
After each msg:  h = SHA256(new_substate)   -- or same initial hash if no substate
```

The server rejects any CLsend where `h` doesn't match. An attacker who captures a frame can't replay it in a different context.

### Stateless sessions

There's no session table on the server. Sessions are stored in an encrypted cookie. This means:

- No server memory to steal sessions from
- No session fixation (each handshake produces a fresh key)
- Sessions survive server restarts (as long as master secret is the same)

---

## What SIRA does NOT protect against

### Compromised client JavaScript

If an attacker can inject JavaScript into your page, they can:
- Call `sira.send()` with arbitrary actions
- Read the decrypted responses
- Observe the AES key in memory

SIRA does not protect against XSS. Use Content Security Policy (CSP) to limit script execution.

### Traffic metadata

An observer can see:
- That you're connecting to a SIRA server (the endpoints `/h`, `/w` are recognizable)
- How many frames are exchanged and when
- Frame timing patterns
- IP addresses of clients

SIRA does not hide **that** communication is happening, only **what** is communicated.

### Server compromise

If an attacker gains access to your server, they can:
- Read the master secret
- Decrypt any session cookie
- Read all pipeline logic
- Observe all plaintext actions and responses

This is the same as any web application. SIRA does not protect server-side code.

### Timing attacks

SIRA does not add random delays to responses. A sophisticated attacker watching response timing may be able to infer something about your pipeline's processing time.

---

## Cryptographic Primitives

| Primitive | Usage | Standard |
|---|---|---|
| X25519 | Key exchange (handshake) | RFC 7748 |
| HKDF-SHA256 | Key derivation (wire key, cookie key) | RFC 5869 |
| AES-256-GCM | Frame encryption and authentication | NIST SP 800-38D |
| SHA-256 | State hash, HKDF internal | FIPS 180-4 |

### Key derivation

```
Client ephemeral X25519 private key (random)
  + Server ephemeral X25519 public key
  → X25519 shared secret

HKDF-SHA256(shared_secret, info="sst-aes-gcm-v1")
  → 32-byte AES wire key (used for all WebSocket frames)

HKDF-SHA256(master_secret, info="sst-session-token-v1")
  → 32-byte cookie key (used to encrypt the __s cookie)
```

### Wire frame encryption

```
Plaintext (996 bytes):
  request_id (16 B) || msgpack_payload || zero_padding

Encryption:
  IV = random 12 bytes
  ciphertext = AES-256-GCM(wire_key, IV, plaintext) → 1012 bytes

Frame = IV || ciphertext → 1024 bytes
```

The GCM authentication tag is embedded in the ciphertext. If any bit of the ciphertext is modified, decryption returns an error.

### Session cookie encryption

```
SessionToken (msgpack-encoded)
  → AES-256-GCM(cookie_key, random_IV) → IV || ciphertext
  → base64url(IV || ciphertext)
  → Cookie: __s=<value>; HttpOnly; Secure; SameSite=Strict
```

---

## Threat Model

### What SIRA assumes about the attacker

- Can observe all network traffic (passive network adversary)
- Does not control client JavaScript (no XSS)
- Does not have access to the server
- Does not know the master secret

### What SIRA does NOT assume about the attacker

- Cannot observe client memory
- Cannot inject JavaScript into pages
- Cannot compromise the server

### In scope

| Threat | Protected? |
|---|---|
| Passive network observation of actions/responses | Yes |
| Passive observation of API structure / routes | Yes |
| Active frame tampering (modification) | Yes — GCM tag fails |
| Active frame replay | Yes — state hash chain detects it |
| Session hijacking via stolen cookie | Partially — cookie is HttpOnly (not JS-readable), but network theft is possible if TLS is missing |

### Out of scope

| Threat | Protected? |
|---|---|
| XSS — attacker can run JS in your page | No |
| Compromised server | No |
| Timing-based inference | No |
| IP address / metadata leakage | No |
| Brute-forcing master secret | Depends on key strength (use `openssl rand -hex 32`) |

---

## Cookie Security

The `__s` cookie is the session credential. It's protected by:

- **HttpOnly** — JavaScript can't read it (protects against XSS cookie theft)
- **Secure** — Only sent over HTTPS (requires TLS in production)
- **SameSite=Strict** — Not sent on cross-site requests (protects against CSRF)
- **Encrypted content** — Even if someone reads the cookie value, they can't forge a different session without the master secret

The cookie does not contain the master secret. It contains the wire key (and user_id) encrypted with a key derived from the master secret.

---

## Responsible Disclosure

If you discover a security issue, please open a private issue at [https://github.com/vaibhavsadgir50/sira](https://github.com/vaibhavsadgir50/sira) rather than filing a public bug report.

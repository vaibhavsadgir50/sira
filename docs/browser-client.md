# Browser Client

`sira-js/sira.js` is the browser client library. It's an ES6 module with no build step required.

**Dependencies** (included in `sira-js/node_modules`):
- `tweetnacl` — X25519 key generation and ECDH
- `@msgpack/msgpack` — Frame serialization
- `crypto.subtle` — AES-256-GCM (built into browsers)

---

## Installation

Serve the `sira-js/` directory as a static asset and import directly:

```html
<script type="module">
  import { Sira } from '/sira-js/sira.js'
  // ...
</script>
```

Or copy `sira.js` and its `node_modules` into your project's public folder.

---

## Constructor

```javascript
const sira = new Sira(options)
```

| Option | Type | Default | Description |
|---|---|---|---|
| `host` | string | `window.location.host` | Server host (e.g. `"api.example.com"`) |
| `secure` | bool | `window.location.protocol === 'https:'` | Use `wss://` instead of `ws://` |

```javascript
// Same origin (most common)
const sira = new Sira()

// Different host
const sira = new Sira({ host: 'api.example.com', secure: true })
```

---

## open(options)

Performs the handshake and opens the WebSocket connection.

```javascript
await sira.open(options)
```

| Option | Type | Default | Description |
|---|---|---|---|
| `persistent` | bool | `false` | `true` = 7-day session cookie, `false` = 1-day |

```javascript
// Temporary session (default)
await sira.open()

// Persistent session (7 days)
await sira.open({ persistent: true })
```

**What it does:**
1. Generates a random `window_id`
2. Generates an ephemeral X25519 keypair
3. `POST /h` → sends client public key, receives server public key + session cookie
4. Derives AES-256 wire key via ECDH + HKDF
5. Opens WebSocket `ws://<host>/w` (cookie is sent automatically)
6. Starts heartbeat loop (BEAT every 30 s)

---

## send(action)

Sends an action to the server and waits for the pipeline response.

```javascript
const render = await sira.send(action)
```

| Parameter | Type | Description |
|---|---|---|
| `action` | any (JSON-serializable) | Your action payload. Structure is defined by your app. |

Returns the `r` field of the server's SVsend response — whatever your pipeline returned.

```javascript
// Simple action
const result = await sira.send({ type: 'getUser', id: 42 })
console.log(result.user.name)

// Multiple concurrent sends (each gets its own request_id)
const [a, b] = await Promise.all([
    sira.send({ type: 'getUser', id: 1 }),
    sira.send({ type: 'getUser', id: 2 }),
])

// Large payloads work automatically (chunked if > 980 bytes)
const data = await sira.send({ type: 'upload', payload: largeBase64String })
```

**What it does:**
1. Builds a CLsend: `{ h, a: action, w: windowId, s: substate }`
2. Serializes to MessagePack
3. Splits into chunks if needed
4. Encrypts each chunk as a 1024-byte frame with a random `request_id`
5. Sends all frames on the WebSocket
6. Waits for matching SVsend frame(s) with the same `request_id`
7. Decrypts, reassembles if chunked, deserializes
8. Updates internal state hash
9. Returns `svSend.r`

---

## refreshAuth(appToken)

Authenticates the session by sending an app token to `/r`. Sets `user_id` on the session.

```javascript
await sira.refreshAuth(appToken)
```

| Parameter | Type | Description |
|---|---|---|
| `appToken` | string | Your application's auth token (e.g. OAuth code, magic link token) |

```javascript
// After user logs in and you have their OAuth token
const oauthToken = 'user_token_from_your_auth_system'
await sira.refreshAuth(oauthToken)

// Now sira.send() calls will reach the pipeline with user_id set
const profile = await sira.send({ type: 'getMyProfile' })
```

**What it does:**
1. Builds a CLsend with `action = { auth: { token: appToken } }`
2. Encrypts and sends to `POST /r`
3. Server calls your `RefreshAuthenticator.authenticate_app_token(token)`
4. On success, server returns a new `__s` cookie with `user_id` set
5. `refreshAuth` stores the new cookie and reconnects the WebSocket

Throws if the server returns 401 (invalid token).

---

## once(action)

One-shot: open a connection, send one action, return the result, close.

```javascript
const render = await sira.once(action)
```

Equivalent to:

```javascript
await sira.open()
const render = await sira.send(action)
await sira.close()
return render
```

Use this for background requests where you don't need a persistent connection.

```javascript
// Fire and forget lookup
const result = await new Sira().once({ type: 'lookup', id: 99 })
```

---

## close()

Closes the WebSocket and stops the heartbeat.

```javascript
await sira.close()
```

---

## Properties

After `open()` is called, the following properties are available:

| Property | Type | Description |
|---|---|---|
| `sira.windowId` | string | The current window ID (16 hex chars) |
| `sira.stateHash` | string | Current state hash (SHA-256 hex) |
| `sira.substate` | Uint8Array or null | Current opaque substate |
| `sira.persistent` | bool | Whether this is a persistent session |

---

## Error Handling

```javascript
try {
    await sira.open()
} catch (err) {
    // Network error, handshake failed
}

try {
    await sira.refreshAuth(token)
} catch (err) {
    // Token rejected by server (401)
}

try {
    const result = await sira.send(action)
} catch (err) {
    // WebSocket closed, decryption failed, timeout
}
```

---

## Full Example

```javascript
import { Sira } from '/sira-js/sira.js'

const sira = new Sira()

// Connect
await sira.open()

// Authenticate (if needed)
const token = await loginUser() // your own login flow
await sira.refreshAuth(token)

// Send actions
const dashboard = await sira.send({ type: 'getDashboard' })
renderDashboard(dashboard)

const updated = await sira.send({ type: 'updateName', name: 'Alice' })
showSuccessMessage(updated.message)

// Disconnect
await sira.close()
```

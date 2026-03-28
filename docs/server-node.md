# Server: Node.js

The Node.js implementation is in `sira-node/`. It uses the built-in `http` module and the `ws` library for WebSockets.

**Requirements:** Node 18+

---

## Installation

```bash
cd sira-node
npm install
```

Or in your own project:

```bash
# Copy the sira-node/src/ directory into your project
# Or symlink it for development
```

---

## The Pipeline Class

Extend the `Pipeline` class and implement `process()`.

```javascript
import { SiraServer, Pipeline } from './sira-node/src/index.js'

class MyApp extends Pipeline {
    constructor(db) {
        super()
        this.db = db
    }

    async process(action, { sessionId, windowId, userId }) {
        switch (action.type) {
            case 'getProducts': {
                const products = await this.db.listProducts()
                return { products }
            }
            case 'addToCart': {
                await this.db.addToCart(sessionId, action.itemId)
                return { ok: true }
            }
            default:
                return { error: 'unknown action' }
        }
    }
}
```

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `action` | object | The action from CLsend. You define the shape. |
| `sessionId` | string | Stable session identifier (hex, ~16 chars). |
| `windowId` | string | Per-window identifier. Different tabs = different window IDs. |
| `userId` | string or null | Set after a successful `/r` auth refresh. `null` if not authenticated. |

**Return value:** Any JSON-serializable value. Becomes `svSend.r` — what `await sira.send()` resolves to in the browser.

---

## Starting the Server

```javascript
import { SiraServer, Pipeline } from './sira-node/src/index.js'

const masterSecret = Buffer.from(process.env.SIRA_MASTER_SECRET, 'hex')

const server = new SiraServer(masterSecret, new MyApp(db))
await server.listen(3000)
console.log('Listening on :3000')
```

---

## SiraServer

```javascript
new SiraServer(masterSecret, pipeline, options)
```

| Parameter | Type | Description |
|---|---|---|
| `masterSecret` | Buffer (32 bytes) | The master secret for session cookie encryption |
| `pipeline` | Pipeline instance | Your pipeline implementation |
| `options.revocationState` | RevocationState | Optional token revocation |
| `options.refreshAuthenticator` | object | Optional auth refresh handler |

### Methods

```javascript
await server.listen(port)
// Start listening. Returns when server is ready.

server.close()
// Graceful shutdown.
```

---

## Auth Refresh

Implement a `refreshAuthenticator` object with `authenticate_app_token`:

```javascript
const refreshAuth = {
    async authenticate_app_token(token) {
        const userId = await db.validateToken(token)
        return userId // return string on success, null/undefined to reject
    }
}

const server = new SiraServer(masterSecret, new MyApp(), {
    refreshAuthenticator: refreshAuth
})
```

Returning `null` or `undefined` causes the server to respond with 401 noise.

---

## Revocation

```javascript
import { RevocationState } from './sira-node/src/index.js'

const revocation = new RevocationState('/etc/sira-revocation')

const server = new SiraServer(masterSecret, new MyApp(), {
    revocationState: revocation
})
```

The revocation file contains Unix timestamps, one per line. Sessions created at or before the highest timestamp are rejected.

```
# /etc/sira-revocation
# Comments are ignored
1711929600
1711950000
```

---

## Module Exports

```javascript
import {
    SiraServer,      // Main server class
    Pipeline,        // Base class to extend
    RevocationState, // Optional token revocation
} from './sira-node/src/index.js'

// Low-level crypto (for testing/interop)
import * as crypto from './sira-node/src/crypto.js'
```

---

## Crypto Module

The crypto module is exposed for testing and cross-language validation. You don't need it for normal development.

```javascript
import * as crypto from './sira-node/src/crypto.js'

const { aesKey, serverPublicKey } = await crypto.handshake(clientPubBytes)
const frame = crypto.encrypt(payload, key, requestId)
const { requestId, payload } = crypto.decrypt(frame, key)
```

---

## Full Echo Example

```javascript
// sira-node/example/echo.js
import { SiraServer, Pipeline } from '../src/index.js'

class EchoPipeline extends Pipeline {
    async process(action, { sessionId, windowId, userId }) {
        return {
            echo: action,
            session: sessionId,
            window: windowId,
            user_id: userId,
        }
    }
}

const masterSecret = Buffer.from(process.env.SIRA_MASTER_SECRET, 'hex')
const server = new SiraServer(masterSecret, new EchoPipeline())
await server.listen(3000)
```

```bash
export SIRA_MASTER_SECRET="$(openssl rand -hex 32)"
node example/echo.js
```

---

## Running Tests

```bash
cd sira-node
npm install
npm test
```

Tests cover:
- `tests/vectors.test.js` — Cross-language test vector conformance
- `tests/roundtrip.test.js` — Encrypt/decrypt roundtrip, cookie roundtrip

---

## Dependencies

```json
{
  "@noble/curves": "^1.3.0",
  "@noble/hashes": "^1.3.3",
  "@msgpack/msgpack": "^3.0.0",
  "ws": "^8.16.0"
}
```

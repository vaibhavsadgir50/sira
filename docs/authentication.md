# Authentication

SIRA separates connection security (always on) from user authentication (optional). Every connection is encrypted. Whether you know *who* is connected depends on whether you use the auth refresh flow.

---

## Two Levels

| Level | When | How |
|---|---|---|
| **Connection security** | Always | X25519 handshake + AES-256-GCM on every frame |
| **User identity** | Optional | `POST /r` with your app token → `user_id` in session |

---

## The Auth Refresh Flow

The `/r` endpoint links a SIRA session to an application user. Here's the full flow:

```
1. Browser:  user enters credentials (email/password, OAuth, magic link)
2. Browser:  get an app token from your own auth system
3. Browser:  call sira.refreshAuth(appToken)
4. sira.js:  POST /r with encrypted CLsend containing { auth: { token: appToken } }
5. Server:   calls RefreshAuthenticator.authenticate_app_token(appToken)
6. Server:   on success, creates new session cookie with user_id set
7. Browser:  reconnects WebSocket with new cookie
8. Pipeline: user_id is now available in every process() call
```

---

## Implementing RefreshAuthenticator

### Rust

```rust
use sira::RefreshAuthenticator;
use async_trait::async_trait;

struct MyAuth;

#[async_trait]
impl RefreshAuthenticator for MyAuth {
    async fn authenticate_app_token(&self, token: &str) -> Result<String, ()> {
        // token = the value from action.auth.token in the browser's refreshAuth() call
        // Return Ok(user_id) to accept, Err(()) to reject

        match verify_jwt(token) {
            Ok(claims) => Ok(claims.sub),   // user_id = JWT subject
            Err(_) => Err(()),
        }
    }
}
```

### Node.js

```javascript
const refreshAuth = {
    async authenticate_app_token(token) {
        try {
            const payload = verifyJwt(token)
            return payload.userId  // return string = accept
        } catch {
            return null            // return null/undefined = reject
        }
    }
}

const server = new SiraServer(masterSecret, new MyApp(), { refreshAuthenticator: refreshAuth })
```

### Python

```python
from sira import RefreshAuthenticator

class MyAuth(RefreshAuthenticator):
    async def authenticate_app_token(self, token: str) -> str:
        try:
            payload = verify_jwt(token)
            return payload['userId']   # return str = accept
        except Exception:
            raise                      # raise anything = reject
```

---

## Using user_id in the Pipeline

After a successful `/r` refresh, `user_id` is available in every `process()` call:

```python
# Python
async def process(self, action, session_id, window_id, user_id):
    if user_id is None:
        return {'error': 'not authenticated'}

    user = await self.db.get_user(user_id)
    # ...
```

```javascript
// Node.js
async process(action, { sessionId, windowId, userId }) {
    if (!userId) return { error: 'not authenticated' }

    const user = await db.getUser(userId)
    // ...
}
```

```rust
// Rust
async fn process(&self, action: Value, session_id: &str, window_id: &str, user_id: Option<&str>) -> Value {
    let Some(uid) = user_id else {
        return json!({ "error": "not authenticated" });
    };
    // ...
}
```

---

## Session Persistence

Sessions last either 1 day or 7 days, depending on the `persistent` flag set during `open()`:

```javascript
// 1-day session (default)
await sira.open()

// 7-day session
await sira.open({ persistent: true })
```

The `user_id` stays in the session for its full lifetime. Users don't need to re-authenticate on every page load as long as their cookie is valid.

---

## Token Revocation

If you need to invalidate sessions (e.g., forced logout, breach response), use the revocation file.

The revocation cutoff is a Unix timestamp. Any session created at or before that timestamp is rejected.

```bash
# Revoke all sessions created before a certain time
echo "$(date +%s)" > /etc/sira-revocation
```

The server reloads the file every 60 seconds. There's no per-user revocation — it's a single global cutoff. For per-user revocation, check a database in your pipeline or RefreshAuthenticator.

---

## What "authenticated" means in SIRA

SIRA's security model is:

- **Encrypted:** ✓ Always. Every frame is AES-256-GCM.
- **Authenticated transport:** ✓ Always. AES-GCM provides message authentication — modified frames are detected and dropped.
- **User identity:** ✓ Optional. Only after `/r` refresh.
- **Authorization:** Your responsibility. The pipeline receives `user_id`; you decide what actions are allowed.

---

## Common Patterns

### Require auth for all actions

```python
async def process(self, action, session_id, window_id, user_id):
    if not user_id:
        return {'error': 'authentication required', 'code': 401}

    # proceed with user_id
```

### Allow some actions before auth

```python
UNAUTHENTICATED_ACTIONS = {'ping', 'getPublicData', 'login'}

async def process(self, action, session_id, window_id, user_id):
    action_type = action.get('type')

    if action_type not in UNAUTHENTICATED_ACTIONS and not user_id:
        return {'error': 'authentication required'}

    # proceed
```

### Login flow

```javascript
// Browser
const email = 'user@example.com'
const password = 'hunter2'

// 1. Get app token from your API (this is YOUR auth system, not SIRA)
const { token } = await fetch('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
    headers: { 'Content-Type': 'application/json' }
}).then(r => r.json())

// 2. Attach the token to the SIRA session
await sira.refreshAuth(token)

// 3. Now every sira.send() call has user_id set
const profile = await sira.send({ type: 'getProfile' })
```

# Quick Start

Get a SIRA server running and talking to a browser in under 5 minutes.

---

## Prerequisites

Pick your server language:

| Language | Requirement |
|---|---|
| Rust | Rust 1.75+ (`rustup`) |
| Node.js | Node 18+ |
| Python | Python 3.11+ |

---

## Step 1 — Generate a master secret

The master secret encrypts session cookies. Every server in your deployment must share this value.

```bash
openssl rand -hex 32
# Example output: a3f8e2c1d4b7...
```

Export it:

```bash
export SIRA_MASTER_SECRET="your_64_hex_chars_here"
```

---

## Step 2 — Start the echo server

### Rust

```bash
git clone https://github.com/vaibhavsadgir50/sira.git
cd sira
cargo run
# Listening on http://0.0.0.0:3000
```

### Node.js

```bash
cd sira-node
npm install
node example/echo.js
# Listening on http://0.0.0.0:3000
```

### Python

```bash
cd sira-python
pip install -e .
python example/echo_server.py
# Listening on http://0.0.0.0:3000
```

All three echo servers are **interchangeable** — the browser client works with any of them.

---

## Step 3 — Connect from the browser

Open `index.html` in the repo root (serve it from the same origin so the cookie works):

```bash
# From the repo root
python -m http.server 3000
# Open http://localhost:3000/index.html
```

Or write a minimal HTML page:

```html
<!DOCTYPE html>
<html>
<head><script type="module">
  import { Sira } from '/sira-js/sira.js'

  const sira = new Sira()
  await sira.open()

  const result = await sira.send({ type: 'greet', name: 'world' })
  console.log(result)
  // → { echo: { type: 'greet', name: 'world' }, message: 'SIRA is working' }

  await sira.close()
</script></head>
<body>Open the console</body>
</html>
```

---

## Step 4 — Write your first pipeline

Replace the echo pipeline with your own logic. This is the **only function you write**.

### Rust

```rust
use sira::{Pipeline, SiraState, router};
use serde_json::{json, Value};
use async_trait::async_trait;

struct MyApp;

#[async_trait]
impl Pipeline for MyApp {
    async fn process(
        &self,
        action: Value,
        session_id: &str,
        window_id: &str,
        user_id: Option<&str>,
    ) -> Value {
        match action["type"].as_str() {
            Some("greet") => json!({ "message": "Hello!" }),
            Some("add") => {
                let a = action["a"].as_f64().unwrap_or(0.0);
                let b = action["b"].as_f64().unwrap_or(0.0);
                json!({ "result": a + b })
            }
            _ => json!({ "error": "unknown action" }),
        }
    }
}
```

### Node.js

```javascript
import { SiraServer, Pipeline } from 'sira-node'

class MyApp extends Pipeline {
    async process(action, { sessionId, windowId, userId }) {
        if (action.type === 'greet') return { message: 'Hello!' }
        if (action.type === 'add')   return { result: action.a + action.b }
        return { error: 'unknown action' }
    }
}

const server = new SiraServer(
    Buffer.from(process.env.SIRA_MASTER_SECRET, 'hex'),
    new MyApp()
)
await server.listen(3000)
```

### Python

```python
from sira import SiraServer, Pipeline

class MyApp(Pipeline):
    async def process(self, action, session_id, window_id, user_id):
        if action.get('type') == 'greet': return {'message': 'Hello!'}
        if action.get('type') == 'add':   return {'result': action['a'] + action['b']}
        return {'error': 'unknown action'}

import asyncio, os
server = SiraServer(bytes.fromhex(os.environ['SIRA_MASTER_SECRET']), MyApp())
asyncio.run(server.run())
```

### Browser — calling your pipeline

```javascript
// greet
const r1 = await sira.send({ type: 'greet' })
console.log(r1.message) // "Hello!"

// add
const r2 = await sira.send({ type: 'add', a: 3, b: 4 })
console.log(r2.result)  // 7
```

---

## What you just built

- The browser connected via encrypted WebSocket
- Every frame is 1024 bytes of AES-256-GCM ciphertext
- The action payload (`{ type: 'greet' }`) is invisible on the wire
- Sessions live in an encrypted HttpOnly cookie — no localStorage, no JWTs

**Next:** Read [Core Concepts](concepts.md) to understand sessions, state hashing, and chunking.

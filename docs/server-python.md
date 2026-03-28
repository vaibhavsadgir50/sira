# Server: Python

The Python implementation is in `sira-python/`. It uses [Starlette](https://www.starlette.io/) as the ASGI framework and [uvicorn](https://www.uvicorn.org/) as the server.

**Requirements:** Python 3.11+

---

## Installation

```bash
cd sira-python
pip install -e .
```

Or install dependencies directly:

```bash
pip install cryptography msgpack starlette uvicorn
```

---

## The Pipeline Class

Subclass `Pipeline` and implement `process()`.

```python
from sira import Pipeline, SiraServer
from typing import Any

class MyApp(Pipeline):
    def __init__(self, db):
        self.db = db

    async def process(
        self,
        action: Any,
        session_id: str,
        window_id: str,
        user_id: str | None,
    ) -> Any:
        match action.get('type'):
            case 'getProducts':
                products = await self.db.list_products()
                return {'products': products}
            case 'addToCart':
                await self.db.add_to_cart(session_id, action['itemId'])
                return {'ok': True}
            case _:
                return {'error': 'unknown action'}
```

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `action` | `Any` (usually dict) | The action from CLsend. You define the shape. |
| `session_id` | `str` | Stable session identifier (hex, ~16 chars). |
| `window_id` | `str` | Per-window identifier. Different tabs = different window IDs. |
| `user_id` | `str or None` | Set after a successful `/r` auth refresh. `None` if not authenticated. |

**Return value:** Any JSON-serializable value. Becomes `svSend.r` — what `await sira.send()` resolves to in the browser.

---

## Starting the Server

```python
import asyncio
import os
from sira import SiraServer

server = SiraServer(
    master_secret=bytes.fromhex(os.environ['SIRA_MASTER_SECRET']),
    pipeline=MyApp(db),
)

asyncio.run(server.run(host='0.0.0.0', port=3000))
```

---

## SiraServer

```python
SiraServer(
    master_secret: bytes,        # 32 bytes
    pipeline: Pipeline,
    revocation: RevocationState | None = None,
    refresh_auth: RefreshAuthenticator | None = None,
)
```

### Methods

```python
await server.run(host='0.0.0.0', port=3000)
# Starts uvicorn and blocks until shutdown

app = create_app(master_secret, pipeline, revocation, refresh_auth)
# Returns a Starlette ASGI app (use with uvicorn.run or other ASGI servers)
```

---

## Using create_app (ASGI)

If you want to integrate SIRA into an existing ASGI application:

```python
import uvicorn
from sira import create_app

app = create_app(
    master_secret=bytes.fromhex(os.environ['SIRA_MASTER_SECRET']),
    pipeline=MyApp(),
)

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=3000)
```

---

## RefreshAuthenticator

Subclass `RefreshAuthenticator` to support the `/r` auth refresh endpoint.

```python
from sira import RefreshAuthenticator

class MyAuth(RefreshAuthenticator):
    def __init__(self, db):
        self.db = db

    async def authenticate_app_token(self, token: str) -> str:
        user_id = await self.db.validate_token(token)
        if user_id is None:
            raise ValueError('invalid token')
        return user_id

server = SiraServer(
    master_secret=...,
    pipeline=MyApp(),
    refresh_auth=MyAuth(db),
)
```

Return the `user_id` string on success. Raise any exception to reject the token (returns 401 noise to client).

---

## Revocation

```python
from sira import RevocationState
from pathlib import Path

revocation = RevocationState(Path('/etc/sira-revocation'))

server = SiraServer(
    master_secret=...,
    pipeline=MyApp(),
    revocation=revocation,
)
```

The revocation file format is one Unix timestamp per line (comments with `#` are ignored):

```
# /etc/sira-revocation
1711929600
1711950000
```

Sessions with `created_at <= max(timestamps)` are rejected.

---

## Key Types

```python
from sira import SessionToken, CLsend, SVsend, Beat

# SessionToken — stored in encrypted cookie
@dataclass
class SessionToken:
    key: bytes          # 32-byte AES wire key
    created_at: int     # Unix timestamp
    persistent: bool
    user_id: str | None = None

    def fingerprint(self) -> str: ...  # Returns session_id string

# CLsend — client → server
@dataclass
class CLsend:
    h: str              # State hash
    a: Any              # Action payload
    w: str              # Window ID
    s: bytes | None     # Opaque substate

# SVsend — server → client
@dataclass
class SVsend:
    h: str              # New state hash
    r: Any              # Render (your pipeline's return value)
    w: str              # Window ID
    s: bytes | None     # Updated substate
```

---

## Full Echo Example

```python
# sira-python/example/echo_server.py
import asyncio
import os
from sira import SiraServer, Pipeline

class EchoPipeline(Pipeline):
    async def process(self, action, session_id, window_id, user_id):
        return {
            'echo': action,
            'session': session_id[:16],
            'window': window_id,
            'user_id': user_id,
        }

async def main():
    server = SiraServer(
        master_secret=bytes.fromhex(os.environ['SIRA_MASTER_SECRET']),
        pipeline=EchoPipeline(),
    )
    await server.run()

asyncio.run(main())
```

```bash
export SIRA_MASTER_SECRET="$(openssl rand -hex 32)"
python example/echo_server.py
```

---

## Running Tests

```bash
cd sira-python
pip install -e ".[dev]"
pytest tests/
```

Tests cover:
- `tests/test_vectors.py` — Cross-language test vector conformance
- `tests/test_roundtrip.py` — Encrypt/decrypt roundtrip, cookie roundtrip

---

## Dependencies

```toml
[project.dependencies]
cryptography = ">=41.0"    # X25519, HKDF, AES-GCM
msgpack = ">=1.0"          # Wire frame serialization
starlette = ">=0.37"       # ASGI web framework
uvicorn = ">=0.27"         # ASGI server
websockets = ">=12.0"      # WebSocket support
```

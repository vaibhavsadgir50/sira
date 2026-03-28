# Configuration

---

## Environment Variables

| Variable | Required | Format | Description |
|---|---|---|---|
| `SIRA_MASTER_SECRET` | **Yes** (in production) | 64 hex characters | Root key for session cookie encryption |
| `SIRA_PORT` | No (default: `3000`) | Integer | HTTP server port |
| `SIRA_REVOCATION_STORE` | No | File path | Path to revocation timestamps file |

### SIRA_MASTER_SECRET

Generate with:

```bash
openssl rand -hex 32
```

This produces a 64-character hex string representing 32 random bytes.

**Critical rules:**
- Every server instance in your fleet must share the **same** master secret
- In debug/dev builds, an all-zero key is used if unset (with a warning). In release builds, the server panics if unset.
- Rotating the master secret invalidates all existing sessions

```bash
export SIRA_MASTER_SECRET="a3f8e2c1d4b7f6e9a2c5d8b1e4f7a0c3..."
```

### SIRA_PORT

```bash
export SIRA_PORT=8080
```

### SIRA_REVOCATION_STORE

```bash
export SIRA_REVOCATION_STORE="/var/lib/sira/revocation"
```

See [Authentication → Token Revocation](authentication.md#token-revocation) for the file format.

---

## Revocation File Format

```
# Lines starting with # are comments
# Each line is a Unix timestamp (seconds since epoch)
# Sessions created at or before the max timestamp are rejected

1711929600
1711950000
```

The server reloads this file every 60 seconds. You can update it without restarting the server.

---

## Running in Production

### Docker

```dockerfile
FROM rust:1.75 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/sira /usr/local/bin/sira
EXPOSE 3000
CMD ["sira"]
```

```bash
docker run \
  -e SIRA_MASTER_SECRET="$(openssl rand -hex 32)" \
  -p 3000:3000 \
  my-sira-app
```

### Systemd

```ini
[Unit]
Description=SIRA Server
After=network.target

[Service]
Type=simple
User=www-data
EnvironmentFile=/etc/sira/env
ExecStart=/usr/local/bin/sira
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/sira/env`:

```
SIRA_MASTER_SECRET=a3f8e2c1d4b7f6e9a2c5d8b1e4f7a0c3...
SIRA_PORT=3000
SIRA_REVOCATION_STORE=/var/lib/sira/revocation
```

---

## Horizontal Scaling

Because sessions are stateless (encrypted in the cookie), scaling is straightforward.

```
                    ┌──────────────────┐
                    │  Load Balancer   │
                    │  (any algorithm) │
                    └────────┬─────────┘
              ┌──────────────┼──────────────┐
              │              │              │
      ┌───────▼──────┐ ┌─────▼──────┐ ┌────▼───────┐
      │  SIRA Server │ │ SIRA Server│ │ SIRA Server│
      │  (port 3000) │ │ (port 3000)│ │ (port 3000)│
      │              │ │            │ │            │
      │  Same        │ │  Same      │ │  Same      │
      │  MASTER_     │ │  MASTER_   │ │  MASTER_   │
      │  SECRET      │ │  SECRET    │ │  SECRET    │
      └──────────────┘ └────────────┘ └────────────┘
```

**Requirements for scaling:**
1. All instances share the same `SIRA_MASTER_SECRET`
2. No sticky sessions needed — any instance can serve any client
3. No shared session store needed — sessions are in cookies
4. If using revocation, all instances need access to the same revocation file (shared filesystem or same content)

**WebSocket consideration:** WebSocket connections are long-lived. Once a client connects to one instance, it stays there for the duration of that WebSocket session. When the client reconnects (e.g., after a network drop), it may land on a different instance — which is fine, because the session is in the cookie.

---

## TLS / HTTPS

SIRA does not handle TLS termination. Run it behind a reverse proxy (nginx, Caddy, AWS ALB):

### nginx

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

The `Upgrade` and `Connection` headers are required for WebSocket proxying.

### Caddy

```
api.example.com {
    reverse_proxy localhost:3000
}
```

Caddy handles TLS automatically and forwards WebSocket upgrades by default.

---

## CORS

The built-in SIRA router doesn't configure CORS. If your browser client is on a different origin than your SIRA server, add CORS headers.

### Rust (tower-http)

```rust
use tower_http::cors::{CorsLayer, Any};

let app = sira::router(state)
    .layer(
        CorsLayer::new()
            .allow_origin("https://app.example.com".parse::<HeaderValue>().unwrap())
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(Any)
            .allow_credentials(true)  // required for cookies
    );
```

### Node.js

```javascript
import { createServer } from 'http'

// Add CORS headers in the request handler
server.httpServer.on('request', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com')
    res.setHeader('Access-Control-Allow-Credentials', 'true')
    // ...
})
```

**Note:** The `__s` cookie requires `allow_credentials: true` in CORS configuration. Same-origin deployments don't need CORS at all.

---

## Cookie Configuration

The `__s` cookie is set with:

```
__s=<value>; HttpOnly; Secure; SameSite=Strict; Max-Age=<seconds>
```

| Attribute | Value | Purpose |
|---|---|---|
| `HttpOnly` | always | Prevents JavaScript from reading the cookie (XSS protection) |
| `Secure` | always | Cookie only sent over HTTPS (requires TLS in production) |
| `SameSite=Strict` | always | Cookie not sent on cross-site requests (CSRF protection) |
| `Max-Age` | 86400 (1 day) or 604800 (7 days) | Session lifetime |

In development (HTTP), the `Secure` flag will prevent the cookie from being set. Use a local HTTPS proxy or temporarily remove the `Secure` flag for local development.

---

## Session Lifetimes

| Cookie type | Max-Age | When to use |
|---|---|---|
| Default | 86400 s (1 day) | Most web apps |
| Persistent | 604800 s (7 days) | "Remember me" functionality |

Set via `sira.open({ persistent: true })` in the browser.

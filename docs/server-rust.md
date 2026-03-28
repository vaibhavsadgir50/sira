# Server: Rust

The Rust implementation is the reference server. It's built on [Axum](https://github.com/tokio-rs/axum) and [Tokio](https://tokio.rs/).

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
sira = { git = "https://github.com/vaibhavsadgir50/sira.git" }
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
serde_json = "1"
```

---

## The Pipeline Trait

The only thing you implement. Called for every CLsend frame.

```rust
use sira::Pipeline;
use serde_json::{json, Value};
use async_trait::async_trait;

struct MyApp {
    db: Arc<Database>, // your dependencies
}

#[async_trait]
impl Pipeline for MyApp {
    async fn process(
        &self,
        action: Value,        // CLsend.a — your action payload
        session_id: &str,     // hex fingerprint of wire key (first 8 bytes)
        window_id: &str,      // unique per browser window
        user_id: Option<&str>, // set after successful /r auth
    ) -> Value {              // SVsend.r — your response
        match action["type"].as_str() {
            Some("getProducts") => {
                let products = self.db.list_products().await;
                json!({ "products": products })
            }
            Some("addToCart") => {
                let item_id = action["itemId"].as_str().unwrap();
                self.db.add_to_cart(session_id, item_id).await;
                json!({ "ok": true })
            }
            _ => json!({ "error": "unknown action" }),
        }
    }
}
```

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `action` | `serde_json::Value` | The action from CLsend. You define the shape. |
| `session_id` | `&str` | Stable session identifier (hex, ~16 chars). Consistent across reconnects for the same cookie. |
| `window_id` | `&str` | Per-window identifier. Different tabs = different window IDs. |
| `user_id` | `Option<&str>` | Set after a successful `/r` auth refresh. `None` if not authenticated. |

**Return value:** Any JSON value. This becomes `svSend.r` — what `await sira.send()` resolves to in the browser.

---

## Starting the Server

```rust
use sira::{
    load_master_secret_from_env, router, SiraState,
    RevocationState,
};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let master_secret = load_master_secret_from_env();

    let state = SiraState::new(
        master_secret,
        Arc::new(MyApp { db: Arc::new(Database::connect().await) }),
    );

    let app = router(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on :3000");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
```

---

## SiraState

`SiraState` holds all server-wide shared state. You pass it to `router()`.

```rust
pub struct SiraState {
    pub cookie_key: [u8; 32],
    pub pipeline: Arc<dyn Pipeline>,
    pub chunks: Arc<ChunkBuffers>,
    pub hs_limit: Arc<MinuteRateLimiter>,
    pub ws_limit: Arc<MinuteRateLimiter>,
    pub refresh_limit: Arc<MinuteRateLimiter>,
    pub refresh_auth: Option<Arc<dyn RefreshAuthenticator>>,
    pub revocation: Option<Arc<RevocationState>>,
}
```

Build it with `SiraState::new(master_secret, pipeline)` or configure optional fields:

```rust
use sira::{SiraState, RevocationState};
use std::path::PathBuf;

let revocation = RevocationState::new(PathBuf::from("/etc/sira-revocation"));

let state = SiraState {
    cookie_key: sira::derive_session_cookie_key(&master_secret),
    pipeline: Arc::new(MyApp::new()),
    chunks: Arc::new(ChunkBuffers::new()),
    hs_limit: Arc::new(MinuteRateLimiter::new(120)),
    ws_limit: Arc::new(MinuteRateLimiter::new(60)),
    refresh_limit: Arc::new(MinuteRateLimiter::new(120)),
    refresh_auth: Some(Arc::new(MyAuth)),
    revocation: Some(Arc::new(revocation)),
};
```

---

## RefreshAuthenticator Trait

Implement this to support the `/r` auth refresh endpoint.

```rust
use sira::RefreshAuthenticator;
use async_trait::async_trait;

struct MyAuth {
    db: Arc<Database>,
}

#[async_trait]
impl RefreshAuthenticator for MyAuth {
    async fn authenticate_app_token(&self, token: &str) -> Result<String, ()> {
        match self.db.validate_token(token).await {
            Some(user_id) => Ok(user_id),
            None => Err(()),
        }
    }
}
```

| Parameter | Type | Description |
|---|---|---|
| `token` | `&str` | The `action.auth.token` value from the client's `/r` request |

Returns `Ok(user_id)` to accept (the `user_id` is stored in the session), or `Err(())` to reject (returns 401 noise to client).

---

## Router

`router()` returns an Axum `Router` with the three endpoints wired up:

```rust
pub fn router(state: SiraState) -> Router {
    Router::new()
        .route("/h", post(handshake_handler))
        .route("/r", post(refresh_handler))
        .route("/w", get(ws_handler))
        .with_state(state)
}
```

You can layer this into a larger Axum app:

```rust
let sira_routes = sira::router(sira_state);

let app = Router::new()
    .merge(sira_routes)
    .route("/healthz", get(|| async { "ok" }))
    .layer(tower_http::cors::CorsLayer::permissive());
```

---

## Maintenance Loop

The server needs a background maintenance task that:
- Purges expired rate-limiter entries
- Reloads the revocation file (if configured)
- Times out stale chunk reassembly buffers

```rust
let state_clone = state.clone();
tokio::spawn(async move {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        state_clone.hs_limit.purge();
        state_clone.ws_limit.purge();
        state_clone.refresh_limit.purge();
        state_clone.chunks.purge_stale();
        if let Some(rev) = &state_clone.revocation {
            rev.reload();
        }
    }
});
```

The echo server in `main.rs` shows a complete example.

---

## Key Types

### SessionToken

```rust
pub struct SessionToken {
    pub key: [u8; 32],           // AES-256 wire key
    pub created_at: u64,         // Unix timestamp
    pub persistent: bool,        // 7-day vs 1-day cookie
    pub user_id: Option<String>, // Set after /r auth
}
```

### CLsend

```rust
pub struct CLsend {
    pub h: String,               // State hash (SHA-256 hex)
    pub a: serde_json::Value,    // Action payload
    pub w: String,               // Window ID
    pub s: Option<Vec<u8>>,      // Opaque substate
}
```

### SVsend

```rust
pub struct SVsend {
    pub h: String,               // New state hash
    pub r: serde_json::Value,    // Render (your pipeline's return value)
    pub w: String,               // Window ID
    pub s: Option<Vec<u8>>,      // Updated substate
}
```

---

## Dependencies

```toml
[dependencies]
axum = { version = "0.7", features = ["ws", "macros"] }
tokio = { version = "1", features = ["full"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
aes-gcm = "0.10"
hkdf = "0.12"
sha2 = "0.10"
rand = "0.8"
rmp-serde = "1"
serde_json = "1"
dashmap = "5"
base64 = "0.22"
async-trait = "0.1"
```

---

## Running Tests

```bash
# Unit tests
cargo test

# With test vectors
cargo test -- --include-ignored

# Specific test
cargo test test_session_token_cookie_roundtrip
```

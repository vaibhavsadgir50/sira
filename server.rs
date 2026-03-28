// sira/src/server.rs
// Axum server — /h handshake, /w WebSocket, /r session refresh (auth)

use axum::{
    body::{Body, Bytes},
    extract::{
        connect_info::ConnectInfo,
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use serde::Deserialize;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::Duration as TokioDuration;
use tracing::{error, info, warn};

use crate::{
    config::RevocationState,
    crypto,
    types::{
        compute_hash, expected_clsend_hash, initial_hash, now_unix, Beat, CLsend, ChunkPayload,
        SVsend, SessionToken, COOKIE_MAX_AGE_PERSISTENT_SECS, COOKIE_MAX_AGE_SECS,
        HEARTBEAT_TIMEOUT_SECS, MAX_ASSEMBLED_PAYLOAD, MAX_CHUNK_COUNT, MAX_CHUNK_DATA,
        MESSAGE_SIZE,
    },
};

// ── Rate limiting (per peer IP, rolling 60s) ───────────────────────────────

pub struct MinuteRateLimiter {
    inner: DashMap<String, Vec<u64>>,
    max: usize,
}

impl MinuteRateLimiter {
    pub fn new(max_per_rolling_minute: usize) -> Self {
        Self {
            inner: DashMap::new(),
            max: max_per_rolling_minute,
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        let now = now_unix();
        let mut v = self.inner.entry(key.to_string()).or_default();
        v.retain(|&t| now.saturating_sub(t) < 60);
        if v.len() >= self.max {
            return false;
        }
        v.push(now);
        true
    }

    pub fn purge_stale(&self) {
        let now = now_unix();
        self.inner.retain(|_, v| {
            v.retain(|&t| now.saturating_sub(t) < 60);
            !v.is_empty()
        });
    }
}

// ── Chunk reassembly ───────────────────────────────────────────────────────

struct ChunkSlot {
    n: u32,
    parts: Vec<Option<Vec<u8>>>,
    filled: u32,
    bytes: usize,
    started: Instant,
}

#[derive(Clone)]
pub struct ChunkBuffers {
    inner: Arc<DashMap<String, ChunkSlot>>,
}

impl ChunkBuffers {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }
}

impl Default for ChunkBuffers {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkBuffers {
    fn purge_stale(&self, max_age: Duration) {
        self.inner
            .retain(|_, slot| slot.started.elapsed() <= max_age);
    }

    fn push(&self, assembly_key: &str, ch: ChunkPayload) -> Result<Option<Vec<u8>>, ()> {
        if ch.k != "ch"
            || ch.n == 0
            || ch.n > MAX_CHUNK_COUNT
            || ch.i >= ch.n
            || ch.d.len() > MAX_CHUNK_DATA
        {
            return Err(());
        }

        let mut entry = self
            .inner
            .entry(assembly_key.to_string())
            .or_insert_with(|| ChunkSlot {
                n: ch.n,
                parts: vec![None; ch.n as usize],
                filled: 0,
                bytes: 0,
                started: Instant::now(),
            });

        if entry.started.elapsed() > Duration::from_secs(120) {
            *entry = ChunkSlot {
                n: ch.n,
                parts: vec![None; ch.n as usize],
                filled: 0,
                bytes: 0,
                started: Instant::now(),
            };
        }

        if entry.n != ch.n {
            return Err(());
        }

        let slot = &mut *entry;
        let idx = ch.i as usize;
        if slot.parts.get(idx).and_then(|o| o.as_ref()).is_some() {
            return Err(());
        }

        let add = ch.d.len();
        if slot.bytes.saturating_add(add) > MAX_ASSEMBLED_PAYLOAD {
            return Err(());
        }

        slot.parts[idx] = Some(ch.d);
        slot.filled += 1;
        slot.bytes += add;

        if slot.filled < ch.n {
            return Ok(None);
        }

        let mut out = Vec::with_capacity(slot.bytes);
        for p in slot.parts.iter().flatten() {
            out.extend_from_slice(p);
        }
        drop(entry);
        self.inner.remove(assembly_key);
        Ok(Some(out))
    }
}

// ── Auth refresh (`POST /r`) ───────────────────────────────────────────────

/// Validates `CLsend.a.auth.token` during `POST /r` and returns the `user_id` to store in `SessionToken`.
#[async_trait::async_trait]
pub trait RefreshAuthenticator: Send + Sync {
    async fn authenticate_app_token(&self, app_token: &str) -> Result<String, ()>;
}

#[derive(Clone)]
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

impl SiraState {
    pub fn new(
        master_secret: [u8; 32],
        pipeline: Arc<dyn Pipeline>,
        revocation: Option<Arc<RevocationState>>,
        refresh_auth: Option<Arc<dyn RefreshAuthenticator>>,
    ) -> Self {
        Self {
            cookie_key: crypto::derive_session_cookie_key(&master_secret),
            pipeline,
            chunks: Arc::new(ChunkBuffers::new()),
            hs_limit: Arc::new(MinuteRateLimiter::new(120)),
            ws_limit: Arc::new(MinuteRateLimiter::new(60)),
            refresh_limit: Arc::new(MinuteRateLimiter::new(120)),
            refresh_auth,
            revocation,
        }
    }

    pub fn spawn_maintenance(self) {
        let chunks = self.chunks.clone();
        let hs = self.hs_limit.clone();
        let ws = self.ws_limit.clone();
        let rf = self.refresh_limit.clone();
        let rev = self.revocation.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TokioDuration::from_secs(60));
            loop {
                tick.tick().await;
                if let Some(r) = rev.as_ref() {
                    r.reload();
                }
                hs.purge_stale();
                ws.purge_stale();
                rf.purge_stale();
                chunks.purge_stale(Duration::from_secs(120));
            }
        });
    }

    fn token_revoked(&self, token: &SessionToken) -> bool {
        self.revocation
            .as_ref()
            .map(|r| r.is_revoked(token.created_at))
            .unwrap_or(false)
    }
}

#[async_trait::async_trait]
pub trait Pipeline: Send + Sync {
    async fn process(
        &self,
        action: serde_json::Value,
        session_id: &str,
        window_id: &str,
        user_id: Option<&str>,
    ) -> serde_json::Value;
}

pub fn router(state: SiraState) -> Router {
    Router::new()
        .route("/h", post(handshake_handler))
        .route("/r", post(refresh_handler))
        .route("/w", get(ws_handler))
        .with_state(state)
}

fn __s_cookie_header(value: &str, persistent: bool) -> String {
    let max_age = if persistent {
        COOKIE_MAX_AGE_PERSISTENT_SECS
    } else {
        COOKIE_MAX_AGE_SECS
    };
    format!(
        "__s={}; HttpOnly; Secure; SameSite=Strict; Max-Age={}; Path=/",
        value, max_age
    )
}

fn extract_auth_app_token(a: &serde_json::Value) -> Option<&str> {
    a.get("auth")?.get("token")?.as_str()
}

fn unauthorized_noise_response() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(crypto::noise()))
        .unwrap()
}

#[derive(Deserialize)]
pub struct HandshakeQuery {
    pub persistent: Option<bool>,
}

pub async fn handshake_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<SiraState>,
    Query(q): Query<HandshakeQuery>,
    body: Bytes,
) -> Response {
    let ip = peer.ip().to_string();
    if !state.hs_limit.allow(&ip) {
        warn!("Handshake rate limited: {}", ip);
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    if body.len() != 32 {
        return (StatusCode::BAD_REQUEST, "expected 32 bytes").into_response();
    }

    let persistent = q.persistent.unwrap_or(false);

    match crypto::handshake(&body) {
        Ok(result) => {
            let token = SessionToken::new(result.aes_key, persistent);
            let cookie_val = match crypto::encrypt_session_token(&token, &state.cookie_key) {
                Ok(s) => s,
                Err(e) => {
                    error!("Session token encrypt failed: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, "token error").into_response();
                }
            };

            info!("Handshake ok (stateless cookie issued)");

            let cookie = __s_cookie_header(&cookie_val, persistent);

            let mut headers = HeaderMap::new();
            headers.insert(header::SET_COOKIE, cookie.parse().unwrap());
            headers.insert(
                header::CONTENT_TYPE,
                "application/octet-stream".parse().unwrap(),
            );

            (headers, result.server_public_key.to_vec()).into_response()
        }
        Err(e) => {
            error!("Handshake failed: {}", e);
            (StatusCode::BAD_REQUEST, "handshake failed").into_response()
        }
    }
}

/// `POST /r` — encrypted 1024 B body (same wire format as `/w`).  
/// `CLsend.a` must include `{ "auth": { "token": "<app token>" } }`.  
/// On success: `200` + new `Set-Cookie: __s=...` with `user_id` set.  
/// On failure: `401` + 1024 B noise.
pub async fn refresh_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<SiraState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = peer.ip().to_string();
    if !state.refresh_limit.allow(&ip) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let Some(auth) = state.refresh_auth.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "POST /r requires a RefreshAuthenticator — none configured",
        )
            .into_response();
    };

    let cookie_raw = extract_session_cookie(&headers);
    let token = match cookie_raw {
        None => return unauthorized_noise_response(),
        Some(raw) => match crypto::decrypt_session_token(&raw, &state.cookie_key) {
            Ok(t) => t,
            Err(_) => return unauthorized_noise_response(),
        },
    };

    if state.token_revoked(&token) {
        return unauthorized_noise_response();
    }

    if body.len() != MESSAGE_SIZE {
        return unauthorized_noise_response();
    }

    let key = token.key;
    let (request_id, payload) = match crypto::decrypt(&body, &key) {
        Ok(x) => x,
        Err(_) => return unauthorized_noise_response(),
    };

    let _ = request_id;

    let clsend: CLsend = match rmp_serde::from_slice(&payload) {
        Ok(m) => m,
        Err(_) => return unauthorized_noise_response(),
    };

    let expected = expected_clsend_hash(&clsend.w, &clsend.s);
    if clsend.h != expected {
        return unauthorized_noise_response();
    }

    let Some(app_tok) = extract_auth_app_token(&clsend.a) else {
        return unauthorized_noise_response();
    };

    let user_id = match auth.authenticate_app_token(app_tok).await {
        Ok(u) => u,
        Err(_) => return unauthorized_noise_response(),
    };

    let new_token = token.with_user_id(user_id);
    let cookie_val = match crypto::encrypt_session_token(&new_token, &state.cookie_key) {
        Ok(s) => s,
        Err(_) => return unauthorized_noise_response(),
    };

    let cookie = __s_cookie_header(&cookie_val, new_token.persistent);
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::OK;
    res.headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    res
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<SiraState>,
    headers: HeaderMap,
) -> Response {
    let ip = peer.ip().to_string();
    if !state.ws_limit.allow(&ip) {
        warn!("WebSocket upgrade rate limited: {}", ip);
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let cookie_raw = extract_session_cookie(&headers);
    let token = match cookie_raw {
        None => {
            return unauthorized_noise_response();
        }
        Some(raw) => match crypto::decrypt_session_token(&raw, &state.cookie_key) {
            Ok(t) => t,
            Err(_) => {
                return unauthorized_noise_response();
            }
        },
    };

    if state.token_revoked(&token) {
        return unauthorized_noise_response();
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state, token))
}

async fn handle_socket(mut socket: WebSocket, state: SiraState, token: SessionToken) {
    let key = token.key;
    let session_fp = token.fingerprint();
    let user_id = token.user_id.clone();

    loop {
        let timeout = TokioDuration::from_secs(HEARTBEAT_TIMEOUT_SECS);
        let receive = tokio::time::timeout(timeout, socket.recv()).await;

        match receive {
            Err(_) => {
                warn!(
                    "Heartbeat timeout: session {}",
                    &session_fp[..session_fp.len().min(8)]
                );
                break;
            }
            Ok(None) => {
                info!(
                    "Window closed: session {}",
                    &session_fp[..session_fp.len().min(8)]
                );
                break;
            }
            Ok(Some(Err(e))) => {
                error!("Socket error: {}", e);
                break;
            }
            Ok(Some(Ok(msg))) => match msg {
                Message::Binary(raw) => {
                    if state.token_revoked(&token) {
                        break;
                    }

                    if raw.len() != MESSAGE_SIZE {
                        let _ = socket.send(Message::Binary(crypto::noise())).await;
                        continue;
                    }

                    let (request_id, payload) = match crypto::decrypt(&raw, &key) {
                        Ok(r) => r,
                        Err(_) => {
                            let _ = socket.send(Message::Binary(crypto::noise())).await;
                            continue;
                        }
                    };

                    if let Ok(beat) = rmp_serde::from_slice::<Beat>(&payload) {
                        let beat_response = Beat {
                            beat: true,
                            w: beat.w,
                        };
                        if let Ok(encoded) = rmp_serde::to_vec_named(&beat_response) {
                            if let Ok(encrypted) = crypto::encrypt(&encoded, &key, &request_id) {
                                let _ = socket.send(Message::Binary(encrypted)).await;
                            }
                        }
                        continue;
                    }

                    let assembly_key = format!("{}:{}", session_fp, hex::encode(request_id));

                    let clsend_bytes =
                        if let Ok(ch) = rmp_serde::from_slice::<ChunkPayload>(&payload) {
                            match state.chunks.push(&assembly_key, ch) {
                                Ok(Some(full)) => full,
                                Ok(None) => continue,
                                Err(()) => {
                                    let _ = socket.send(Message::Binary(crypto::noise())).await;
                                    continue;
                                }
                            }
                        } else {
                            payload
                        };

                    let clsend: CLsend = match rmp_serde::from_slice(&clsend_bytes) {
                        Ok(msg) => msg,
                        Err(_) => {
                            let _ = socket.send(Message::Binary(crypto::noise())).await;
                            continue;
                        }
                    };

                    let expected = expected_clsend_hash(&clsend.w, &clsend.s);
                    if clsend.h != expected {
                        warn!(
                            "Hash mismatch: session {} window {}",
                            &session_fp[..session_fp.len().min(8)],
                            clsend.w
                        );
                        let _ = socket.send(Message::Binary(crypto::noise())).await;
                        continue;
                    }

                    let substate_bytes = clsend.s.clone();
                    let new_hash = match &substate_bytes {
                        Some(s) => compute_hash(s),
                        None => initial_hash(&clsend.w),
                    };

                    let uid_ref = user_id.as_deref();
                    let render = state
                        .pipeline
                        .process(clsend.a.clone(), &session_fp, &clsend.w, uid_ref)
                        .await;

                    let response = SVsend {
                        h: new_hash,
                        r: render,
                        w: clsend.w.clone(),
                        s: substate_bytes,
                    };

                    let encoded = match rmp_serde::to_vec_named(&response) {
                        Ok(b) => b,
                        Err(e) => {
                            error!("Serialization failed: {}", e);
                            continue;
                        }
                    };

                    let encrypted =
                        match crypto::encrypt_svsend_chunked(&encoded, &key, &request_id) {
                            Ok(frames) => frames,
                            Err(e) => {
                                error!("Encryption failed: {}", e);
                                continue;
                            }
                        };

                    for frame in encrypted {
                        if let Err(e) = socket.send(Message::Binary(frame)).await {
                            error!("ws send SVsend failed: {}", e);
                        }
                    }
                }

                Message::Close(_) => {
                    info!(
                        "Window closed cleanly: session {}",
                        &session_fp[..session_fp.len().min(8)]
                    );
                    break;
                }

                _ => {}
            },
        }
    }
}

fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("__s=").map(|rest| rest.to_string())
            })
        })
}

//! Wire crypto and types — aligned with sira reference (Rust); standalone copy.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio_tungstenite::{
    tungstenite::client::IntoClientRequest,
    tungstenite::Message,
    MaybeTlsStream, WebSocketStream,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub const HKDF_INFO: &[u8] = b"sst-aes-gcm-v1";
pub const MESSAGE_SIZE: usize = 1024;
pub const IV_SIZE: usize = 12;
pub const ID_SIZE: usize = 16;
pub const CIPHERTEXT_SIZE: usize = MESSAGE_SIZE - IV_SIZE;
pub const PAYLOAD_SIZE: usize = CIPHERTEXT_SIZE - 16;
pub const DATA_SIZE: usize = PAYLOAD_SIZE - ID_SIZE;
pub const MAX_CHUNK_COUNT: u32 = 16_384;
pub const MAX_CHUNK_DATA: usize = DATA_SIZE.saturating_sub(64);
pub const MAX_ASSEMBLED_PAYLOAD: usize = 8 * 1024 * 1024;
const CHUNK_SAFE: usize = 900;

#[derive(Debug, Serialize)]
pub struct CLsend {
    pub h: String,
    pub a: serde_json::Value,
    pub w: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct SVsend {
    pub h: String,
    pub r: serde_json::Value,
    #[allow(dead_code)]
    pub w: String,
    #[serde(default)]
    pub s: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Beat {
    pub beat: bool,
    pub w: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkPayload {
    pub k: String,
    pub i: u32,
    pub n: u32,
    pub d: Vec<u8>,
}

pub fn initial_hash(window_id: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(b"sst-initial-");
    hasher.update(window_id.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn encrypt(payload: &[u8], key: &[u8; 32], request_id: &[u8; 16]) -> Result<Vec<u8>, String> {
    let mut plaintext = vec![0u8; PAYLOAD_SIZE];
    plaintext[..ID_SIZE].copy_from_slice(request_id);
    let data_len = payload.len().min(DATA_SIZE);
    plaintext[ID_SIZE..ID_SIZE + data_len].copy_from_slice(&payload[..data_len]);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES key init failed")?;
    let mut iv = [0u8; IV_SIZE];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| "encrypt failed")?;
    let mut message = Vec::with_capacity(MESSAGE_SIZE);
    message.extend_from_slice(&iv);
    message.extend_from_slice(&ciphertext);
    if message.len() != MESSAGE_SIZE {
        return Err(format!("bad message size {}", message.len()));
    }
    Ok(message)
}

pub fn decrypt(message: &[u8], key: &[u8; 32]) -> Result<([u8; 16], Vec<u8>), String> {
    if message.len() != MESSAGE_SIZE {
        return Err(format!("expected {} bytes, got {}", MESSAGE_SIZE, message.len()));
    }
    let iv = &message[..IV_SIZE];
    let ciphertext = &message[IV_SIZE..];
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES key init failed")?;
    let nonce = Nonce::from_slice(iv);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decrypt failed")?;
    let mut request_id = [0u8; ID_SIZE];
    request_id.copy_from_slice(&plaintext[..ID_SIZE]);
    let data = plaintext[ID_SIZE..]
        .iter()
        .rev()
        .skip_while(|&&b| b == 0)
        .cloned()
        .collect::<Vec<u8>>()
        .into_iter()
        .rev()
        .collect();
    Ok((request_id, data))
}

pub fn new_request_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

fn encrypt_svsend_chunked(
    payload: &[u8],
    key: &[u8; 32],
    request_id: &[u8; 16],
) -> Result<Vec<Vec<u8>>, String> {
    if payload.len() <= DATA_SIZE {
        return Ok(vec![encrypt(payload, key, request_id)?]);
    }
    let nchunks = payload.len().div_ceil(CHUNK_SAFE);
    if nchunks > MAX_CHUNK_COUNT as usize {
        return Err("payload too large".into());
    }
    let n = nchunks as u32;
    let mut out = Vec::with_capacity(nchunks);
    for (i, slc) in payload.chunks(CHUNK_SAFE).enumerate() {
        let cp = ChunkPayload {
            k: "ch".into(),
            i: i as u32,
            n,
            d: slc.to_vec(),
        };
        let buf = rmp_serde::to_vec_named(&cp).map_err(|e| e.to_string())?;
        if buf.len() > DATA_SIZE {
            return Err("chunk frame too large".into());
        }
        out.push(encrypt(&buf, key, request_id)?);
    }
    Ok(out)
}

pub fn pack_clsend(cl: &CLsend) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec_named(cl).map_err(|e| e.to_string())
}

pub fn try_chunk(pl: &[u8]) -> Option<ChunkPayload> {
    rmp_serde::from_slice::<ChunkPayload>(pl)
        .ok()
        .filter(|c| c.k == "ch")
}

pub async fn http_post_handshake(
    http_base: &str,
    persistent: bool,
) -> Result<([u8; 32], String), String> {
    let client_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let client_public = PublicKey::from(&client_secret);
    let mut url = format!("{}/h", http_base.trim_end_matches('/'));
    if persistent {
        url.push_str("?persistent=true");
    }
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .body(client_public.as_bytes().to_vec())
        .send()
        .await
        .map_err(|e| format!("POST /h failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("handshake HTTP {}", resp.status()));
    }
    let cookie = parse_set_cookie(resp.headers()).ok_or_else(|| {
        "missing __s in Set-Cookie — server did not issue session cookie".to_string()
    })?;
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    if body.len() < 32 {
        return Err("handshake response too short".into());
    }
    let server_pk: [u8; 32] = body[..32]
        .try_into()
        .map_err(|_| "invalid server public key")?;
    let server_public = PublicKey::from(server_pk);
    let shared = client_secret.diffie_hellman(&server_public);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok((aes_key, cookie))
}

fn parse_set_cookie(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let values = headers.get_all(reqwest::header::SET_COOKIE);
    for v in values.iter() {
        let s = v.to_str().ok()?;
        let idx = s.find("__s=")?;
        let rest = &s[idx + 4..];
        let end = rest.find(';').unwrap_or(rest.len());
        return Some(rest[..end].trim().to_string());
    }
    None
}

pub struct WsSession {
    pub ws: WsStream,
    pub key: [u8; 32],
    pub window_id: String,
    pub state_hash: String,
    pub substate: Option<Vec<u8>>,
}

pub async fn connect_ws_session(
    ws_base: &str,
    cookie_value: &str,
    aes_key: [u8; 32],
) -> Result<WsSession, String> {
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::http::{header, HeaderValue};
    let url = format!("{}/w", ws_base.trim_end_matches('/'));
    let mut req = url
        .into_client_request()
        .map_err(|e| format!("bad WebSocket URL: {e}"))?;
    let cookie_header = format!("__s={cookie_value}");
    req.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&cookie_header)
            .map_err(|e| format!("invalid cookie for header: {e}"))?,
    );
    let (ws, _) = connect_async(req)
        .await
        .map_err(|e| format!("WebSocket connect failed: {e}"))?;
    let window_id = format!("{:032x}", rand::random::<u128>());
    let state_hash = initial_hash(&window_id);
    Ok(WsSession {
        ws,
        key: aes_key,
        window_id,
        state_hash,
        substate: None,
    })
}

pub async fn recv_svsend_for_rid(
    session: &mut WsSession,
    expect_rid: &[u8; 16],
    trace_raw: bool,
) -> Result<SVsend, String> {
    use futures_util::StreamExt;
    let session_fp = hex::encode(&session.key[..8]);
    let key_assembly = format!("{}:{}", session_fp, hex::encode(expect_rid));
    let mut chunk_buffers: std::collections::HashMap<String, ChunkRx> =
        std::collections::HashMap::new();

    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(90), session.ws.next())
            .await
            .map_err(|_| "timeout waiting for server message")?
            .ok_or_else(|| "WebSocket closed".to_string())?;
        let raw = match msg.map_err(|e| e.to_string())? {
            Message::Binary(b) => b,
            Message::Close(_) => return Err("WebSocket closed by server".into()),
            _ => continue,
        };
        if raw.len() != MESSAGE_SIZE {
            continue;
        }
        if trace_raw {
            println!("in (encrypted hex): {}", hex::encode(&raw));
        }
        let (rid, mut pl) = match decrypt(&raw, &session.key) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if &rid != expect_rid {
            continue;
        }
        if let Some(ch) = try_chunk(&pl) {
            if ch.n == 0
                || ch.n > MAX_CHUNK_COUNT
                || ch.i >= ch.n
                || ch.d.len() > MAX_CHUNK_DATA
            {
                continue;
            }
            let needs_new = chunk_buffers
                .get(&key_assembly)
                .map(|s| s.n != ch.n)
                .unwrap_or(true);
            if needs_new {
                chunk_buffers.insert(key_assembly.clone(), ChunkRx::new(ch.n));
            }
            let slot = chunk_buffers.get_mut(&key_assembly).unwrap();
            if ch.i as usize >= slot.parts.len() || slot.parts[ch.i as usize].is_some() {
                continue;
            }
            let add = ch.d.len();
            if slot.bytes.saturating_add(add) > MAX_ASSEMBLED_PAYLOAD {
                chunk_buffers.remove(&key_assembly);
                continue;
            }
            slot.parts[ch.i as usize] = Some(ch.d);
            slot.filled += 1;
            slot.bytes += add;
            if slot.filled < ch.n {
                continue;
            }
            let mut out = Vec::with_capacity(slot.bytes);
            for p in &slot.parts {
                if let Some(b) = p {
                    out.extend_from_slice(b);
                }
            }
            chunk_buffers.remove(&key_assembly);
            pl = out;
        }
        let sv: SVsend = match rmp_serde::from_slice(&pl) {
            Ok(v) => v,
            Err(_) => continue,
        };
        session.state_hash = sv.h.clone();
        session.substate = sv.s.clone();
        return Ok(sv);
    }
}

struct ChunkRx {
    n: u32,
    parts: Vec<Option<Vec<u8>>>,
    filled: u32,
    bytes: usize,
}

impl ChunkRx {
    fn new(n: u32) -> Self {
        Self {
            n,
            parts: vec![None; n as usize],
            filled: 0,
            bytes: 0,
        }
    }
}

pub async fn send_clsend(
    session: &mut WsSession,
    action: serde_json::Value,
    print_raw: bool,
) -> Result<serde_json::Value, String> {
    use futures_util::SinkExt;
    let rid = new_request_id();
    let cl = CLsend {
        h: session.state_hash.clone(),
        a: action,
        w: session.window_id.clone(),
        s: session.substate.clone(),
    };
    let payload = pack_clsend(&cl)?;
    let frames = if payload.len() <= DATA_SIZE {
        vec![encrypt(&payload, &session.key, &rid)?]
    } else {
        encrypt_svsend_chunked(&payload, &session.key, &rid)?
    };
    if frames.is_empty() {
        return Err("no frames to send".into());
    }
    if print_raw {
        for f in &frames {
            println!("out (encrypted hex): {}", hex::encode(f));
        }
    }
    for f in &frames {
        session
            .ws
            .send(Message::Binary(f.clone()))
            .await
            .map_err(|e| format!("ws send failed: {e}"))?;
    }
    let sv = recv_svsend_for_rid(session, &rid, print_raw).await?;
    Ok(sv.r)
}

pub async fn send_beat(session: &mut WsSession) -> Result<std::time::Duration, String> {
    use futures_util::{SinkExt, StreamExt};
    let rid = new_request_id();
    let beat = Beat {
        beat: true,
        w: session.window_id.clone(),
    };
    let payload = rmp_serde::to_vec_named(&beat).map_err(|e| e.to_string())?;
    let frame = encrypt(&payload, &session.key, &rid)?;
    let t0 = std::time::Instant::now();
    session
        .ws
        .send(Message::Binary(frame))
        .await
        .map_err(|e| format!("ws send failed: {e}"))?;
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), session.ws.next())
            .await
            .map_err(|_| "BEAT timeout")?
            .ok_or_else(|| "WebSocket closed".to_string())?;
        let raw = match msg.map_err(|e| e.to_string())? {
            Message::Binary(b) => b,
            _ => continue,
        };
        if raw.len() != MESSAGE_SIZE {
            continue;
        }
        let (got_rid, pl) = decrypt(&raw, &session.key)?;
        if got_rid != rid {
            continue;
        }
        if let Ok(b) = rmp_serde::from_slice::<Beat>(&pl) {
            if b.beat {
                return Ok(t0.elapsed());
            }
        }
    }
}

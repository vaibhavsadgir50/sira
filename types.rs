// sira/src/types.rs
// Core SIRA types — language agnostic protocol definitions in Rust

use serde::{Deserialize, Serialize};

// ── Protocol Constants ─────────────────────────────────────────────────────

pub const MESSAGE_SIZE: usize = 1024;
pub const IV_SIZE: usize = 12;
pub const ID_SIZE: usize = 16;
pub const CIPHERTEXT_SIZE: usize = MESSAGE_SIZE - IV_SIZE; // 1012
pub const PAYLOAD_SIZE: usize = CIPHERTEXT_SIZE - 16; // 996 (minus AES-GCM tag)
pub const DATA_SIZE: usize = PAYLOAD_SIZE - ID_SIZE; // 980

/// HKDF-SHA256 info string — must match browser client (`sira.js`).
pub const HKDF_INFO: &[u8] = b"sst-aes-gcm-v1";

/// HKDF info for deriving the AES key used to encrypt `SessionToken` cookies.
pub const SESSION_TOKEN_HKDF_INFO: &[u8] = b"sst-session-token-v1";

/// Max assembled logical payload (after all chunks concatenated).
pub const MAX_ASSEMBLED_PAYLOAD: usize = 8 * 1024 * 1024;

/// Max chunk count per logical message.
pub const MAX_CHUNK_COUNT: u32 = 16_384;

/// Chunk envelope overhead budget — keep each chunk's `d` under this.
pub const MAX_CHUNK_DATA: usize = DATA_SIZE.saturating_sub(64);

pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 60;

/// Default session cookie max-age (seconds).
pub const COOKIE_MAX_AGE_SECS: u64 = 86400;

/// Longer cookie max-age when `persistent` handshake is used.
pub const COOKIE_MAX_AGE_PERSISTENT_SECS: u64 = 604800;

// ── Frame Types ────────────────────────────────────────────────────────────

/// CLsend — everything a client ever sends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CLsend {
    /// State hash: `compute_hash(s)` if `s` is set, else must equal `initial_hash(w)`
    pub h: String,

    /// Action payload — any value, application defined
    pub a: serde_json::Value,

    /// Window identifier — unique per browser window in session
    pub w: String,

    /// Opaque window substate — client carries context; server hashes it for `h`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<Vec<u8>>,
}

/// SVsend — everything a server ever sends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SVsend {
    /// New state hash after transition
    pub h: String,

    /// Complete render — replaces entire window contents
    pub r: serde_json::Value,

    /// Window identifier — which window this targets
    pub w: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<Vec<u8>>,
}

/// BEAT — heartbeat frame, either direction
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Beat {
    pub beat: bool,
    pub w: String,
}

/// Multi-frame CLsend: same AES `request_id` on every chunk; `k` must be `"ch"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkPayload {
    pub k: String,
    pub i: u32,
    pub n: u32,
    pub d: Vec<u8>,
}

// ── Stateless session (encrypted cookie) ───────────────────────────────────

/// Payload encrypted into the `__s` cookie — no server-side session store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionToken {
    /// AES-256-GCM key for the wire protocol (from X25519 + HKDF handshake).
    #[serde(with = "serde_key_32")]
    pub key: [u8; 32],

    pub created_at: u64,

    #[serde(default)]
    pub persistent: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

mod serde_key_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &[u8; 32], ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_bytes(key)
    }

    pub fn deserialize<'de, D>(de: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = <Vec<u8>>::deserialize(de)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("key must be 32 bytes"))
    }
}

impl SessionToken {
    pub fn new(key: [u8; 32], persistent: bool) -> Self {
        Self {
            key,
            created_at: now_unix(),
            persistent,
            user_id: None,
        }
    }

    /// Same wire key and metadata, with `user_id` set (used after successful `POST /r`).
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Stable short id for logging / pipeline (not secret).
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.key[..8])
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SiraError {
    #[error("Invalid message size: expected {MESSAGE_SIZE}, got {0}")]
    InvalidSize(usize),

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid or missing session cookie")]
    SessionNotFound,

    #[error("Hash mismatch — possible replay or tamper")]
    HashMismatch,

    #[error("Serialization error: {0}")]
    Serialization(String),
}

// ── Utilities ──────────────────────────────────────────────────────────────

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn initial_hash(window_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"sst-initial-");
    hasher.update(window_id.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn compute_hash(substate: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(substate);
    hex::encode(hasher.finalize())
}

/// Expected `CLsend.h` from substate / window id (no stored server state).
pub fn expected_clsend_hash(window_id: &str, substate: &Option<Vec<u8>>) -> String {
    match substate {
        Some(s) => compute_hash(s),
        None => initial_hash(window_id),
    }
}

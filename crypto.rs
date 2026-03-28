// sira/src/crypto.rs
// All cryptographic operations for SST
// X25519 key exchange + AES-256-GCM encryption

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::types::{
    ChunkPayload, SiraError, SessionToken, DATA_SIZE, HKDF_INFO, ID_SIZE, IV_SIZE, MAX_CHUNK_COUNT,
    MESSAGE_SIZE, PAYLOAD_SIZE, SESSION_TOKEN_HKDF_INFO,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

// ── Handshake ──────────────────────────────────────────────────────────────

pub struct HandshakeResult {
    /// 32-byte AES key from HKDF-SHA256 over X25519 shared secret
    pub aes_key: [u8; 32],
    /// Server public key bytes to send to client (32 bytes)
    pub server_public_key: [u8; 32],
}

/// Perform X25519 handshake
/// client_public_key_bytes: 32 raw bytes received from client over /h
/// Returns: AES key + server public key to send back
pub fn handshake(client_public_key_bytes: &[u8]) -> Result<HandshakeResult, SiraError> {
    if client_public_key_bytes.len() != 32 {
        return Err(SiraError::DecryptionFailed);
    }

    // Generate server ephemeral keypair
    let server_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let server_public = PublicKey::from(&server_secret);

    // Derive shared secret
    let client_public_bytes: [u8; 32] = client_public_key_bytes
        .try_into()
        .map_err(|_| SiraError::DecryptionFailed)?;
    let client_public = PublicKey::from(client_public_bytes);
    let shared_secret = server_secret.diffie_hellman(&client_public);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| SiraError::DecryptionFailed)?;

    Ok(HandshakeResult {
        aes_key,
        server_public_key: *server_public.as_bytes(),
    })
}

// ── Session cookie (stateless) ─────────────────────────────────────────────

/// Derive AES-256 key for encrypting `SessionToken` in the `__s` cookie.
pub fn derive_session_cookie_key(master_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_secret.as_slice());
    let mut okm = [0u8; 32];
    hk.expand(SESSION_TOKEN_HKDF_INFO, &mut okm)
        .expect("HKDF expand 32 bytes");
    okm
}

/// Cookie value: base64url( IV_12 || AES-GCM-ciphertext ) where plaintext is MessagePack `SessionToken`.
pub fn encrypt_session_token(
    token: &SessionToken,
    cookie_key: &[u8; 32],
) -> Result<String, SiraError> {
    let plain = rmp_serde::to_vec(token).map_err(|e| SiraError::Serialization(e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(cookie_key).map_err(|_| SiraError::DecryptionFailed)?;

    let mut iv = [0u8; IV_SIZE];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plain.as_ref())
        .map_err(|_| SiraError::DecryptionFailed)?;

    let mut wire = Vec::with_capacity(IV_SIZE + ciphertext.len());
    wire.extend_from_slice(&iv);
    wire.extend_from_slice(&ciphertext);

    Ok(URL_SAFE_NO_PAD.encode(wire))
}

pub fn decrypt_session_token(
    cookie_value: &str,
    cookie_key: &[u8; 32],
) -> Result<SessionToken, SiraError> {
    let wire = URL_SAFE_NO_PAD
        .decode(cookie_value.trim())
        .map_err(|_| SiraError::DecryptionFailed)?;

    if wire.len() <= IV_SIZE {
        return Err(SiraError::DecryptionFailed);
    }

    let iv = &wire[..IV_SIZE];
    let ciphertext = &wire[IV_SIZE..];

    let cipher = Aes256Gcm::new_from_slice(cookie_key).map_err(|_| SiraError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(iv);
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SiraError::DecryptionFailed)?;

    rmp_serde::from_slice(&plain).map_err(|e| SiraError::Serialization(e.to_string()))
}

// ── Wire encryption ───────────────────────────────────────────────────────

/// Encrypt a message into exactly MESSAGE_SIZE (1024) bytes
///
/// Wire format:
/// [0:12]    IV  — random 12 bytes
/// [12:1024] CIPHERTEXT — AES-GCM encrypted plaintext
///
/// Plaintext format (before encryption, exactly PAYLOAD_SIZE bytes):
/// [0:16]    ID  — random 16 bytes, request correlation
/// [16:996]  DATA — msgpack encoded payload, zero padded
pub fn encrypt(payload: &[u8], key: &[u8; 32], request_id: &[u8; 16]) -> Result<Vec<u8>, SiraError> {
    // Build plaintext: ID + DATA (zero padded to PAYLOAD_SIZE)
    let mut plaintext = vec![0u8; PAYLOAD_SIZE];
    plaintext[..ID_SIZE].copy_from_slice(request_id);

    let data_len = payload.len().min(DATA_SIZE);
    plaintext[ID_SIZE..ID_SIZE + data_len].copy_from_slice(&payload[..data_len]);

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SiraError::DecryptionFailed)?;

    let mut iv = [0u8; IV_SIZE];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| SiraError::DecryptionFailed)?;

    // Build final message: IV + CIPHERTEXT
    let mut message = Vec::with_capacity(MESSAGE_SIZE);
    message.extend_from_slice(&iv);
    message.extend_from_slice(&ciphertext);

    // Sanity check
    if message.len() != MESSAGE_SIZE {
        return Err(SiraError::InvalidSize(message.len()));
    }

    Ok(message)
}

/// Wire encrypt with a **fixed IV** (for test vectors / conformance — production uses [`encrypt`]).
pub fn encrypt_wire_with_iv(
    payload: &[u8],
    key: &[u8; 32],
    request_id: &[u8; 16],
    iv: &[u8; IV_SIZE],
) -> Result<Vec<u8>, SiraError> {
    let mut plaintext = vec![0u8; PAYLOAD_SIZE];
    plaintext[..ID_SIZE].copy_from_slice(request_id);

    let data_len = payload.len().min(DATA_SIZE);
    plaintext[ID_SIZE..ID_SIZE + data_len].copy_from_slice(&payload[..data_len]);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SiraError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(iv);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| SiraError::DecryptionFailed)?;

    let mut message = Vec::with_capacity(MESSAGE_SIZE);
    message.extend_from_slice(iv);
    message.extend_from_slice(&ciphertext);

    if message.len() != MESSAGE_SIZE {
        return Err(SiraError::InvalidSize(message.len()));
    }

    Ok(message)
}

/// Encrypt a payload that may exceed `DATA_SIZE` using `ChunkPayload` frames (same `request_id` each).
pub fn encrypt_svsend_chunked(
    payload: &[u8],
    key: &[u8; 32],
    request_id: &[u8; 16],
) -> Result<Vec<Vec<u8>>, SiraError> {
    const SAFE: usize = 900;

    if payload.len() <= DATA_SIZE {
        return Ok(vec![encrypt(payload, key, request_id)?]);
    }

    let nchunks = payload.len().div_ceil(SAFE);
    if nchunks > MAX_CHUNK_COUNT as usize {
        return Err(SiraError::Serialization("response too large".into()));
    }
    let n = nchunks as u32;
    let mut out = Vec::with_capacity(nchunks);
    for (i, slc) in payload.chunks(SAFE).enumerate() {
        let cp = ChunkPayload {
            k: "ch".into(),
            i: i as u32,
            n,
            d: slc.to_vec(),
        };
        let buf =
            rmp_serde::to_vec_named(&cp).map_err(|e| SiraError::Serialization(e.to_string()))?;
        if buf.len() > DATA_SIZE {
            return Err(SiraError::Serialization("chunk frame too large".into()));
        }
        out.push(encrypt(&buf, key, request_id)?);
    }
    Ok(out)
}

/// Decrypt a MESSAGE_SIZE (1024) byte message
/// Returns: (request_id: [u8; 16], payload: Vec<u8>)
pub fn decrypt(message: &[u8], key: &[u8; 32]) -> Result<([u8; 16], Vec<u8>), SiraError> {
    if message.len() != MESSAGE_SIZE {
        return Err(SiraError::InvalidSize(message.len()));
    }

    let iv = &message[..IV_SIZE];
    let ciphertext = &message[IV_SIZE..];

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SiraError::DecryptionFailed)?;

    let nonce = Nonce::from_slice(iv);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SiraError::DecryptionFailed)?;

    // Extract ID
    let mut request_id = [0u8; ID_SIZE];
    request_id.copy_from_slice(&plaintext[..ID_SIZE]);

    // Extract data — strip trailing zeros
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

/// Generate a random request ID
pub fn new_request_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Generate random noise — used for error responses
/// Indistinguishable from real messages
pub fn noise() -> Vec<u8> {
    let mut bytes = vec![0u8; MESSAGE_SIZE];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SessionToken;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let payload = b"hello sira";
        let id = new_request_id();

        let encrypted = encrypt(payload, &key, &id).unwrap();
        assert_eq!(encrypted.len(), MESSAGE_SIZE);

        let (decrypted_id, decrypted_payload) = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted_id, id);
        assert_eq!(&decrypted_payload, payload);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let payload = b"hello sira";
        let id = new_request_id();

        let encrypted = encrypt(payload, &key, &id).unwrap();
        assert!(decrypt(&encrypted, &wrong_key).is_err());
    }

    #[test]
    fn test_message_size_always_1024() {
        let key = [1u8; 32];
        let id = new_request_id();

        // Empty payload
        let msg = encrypt(b"", &key, &id).unwrap();
        assert_eq!(msg.len(), MESSAGE_SIZE);

        // Large payload (truncated to fit)
        let large = vec![1u8; 2000];
        let msg = encrypt(&large, &key, &id).unwrap();
        assert_eq!(msg.len(), MESSAGE_SIZE);
    }

    #[test]
    fn test_noise_is_1024() {
        assert_eq!(noise().len(), MESSAGE_SIZE);
    }

    #[test]
    fn test_session_token_cookie_roundtrip() {
        let master = [7u8; 32];
        let ck = derive_session_cookie_key(&master);
        let token = SessionToken::new([3u8; 32], false);
        let s = encrypt_session_token(&token, &ck).unwrap();
        let got = decrypt_session_token(&s, &ck).unwrap();
        assert_eq!(got, token);
    }

    #[test]
    fn test_session_token_wrong_master_fails() {
        let ck = derive_session_cookie_key(&[1u8; 32]);
        let token = SessionToken::new([2u8; 32], true);
        let s = encrypt_session_token(&token, &ck).unwrap();
        let bad = derive_session_cookie_key(&[2u8; 32]);
        assert!(decrypt_session_token(&s, &bad).is_err());
    }
}

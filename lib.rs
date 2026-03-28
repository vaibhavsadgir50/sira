// sira/src/lib.rs
// SIRA — Server state protocol
// Reference implementation in Rust

pub mod config;
pub mod crypto;
pub mod server;
pub mod types;

pub use config::{load_master_secret_from_env, RevocationState};
pub use server::{
    handshake_handler, refresh_handler, router, ws_handler, Pipeline, RefreshAuthenticator,
    SiraState,
};
pub use types::{
    Beat, CLsend, ChunkPayload, SiraError, SVsend, SessionToken, HKDF_INFO, SESSION_TOKEN_HKDF_INFO,
};

#[cfg(test)]
mod test_vectors;

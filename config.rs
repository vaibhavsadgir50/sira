// Master secret and optional revocation file (stateless sessions).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Load `SIRA_MASTER_SECRET`: 64 hex chars (32 bytes). Release builds panic if unset.
pub fn load_master_secret_from_env() -> [u8; 32] {
    match std::env::var("SIRA_MASTER_SECRET") {
        Ok(hex_str) => parse_hex_32(&hex_str).expect("SIRA_MASTER_SECRET must be 64 hex characters"),
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                tracing::warn!(
                    "SIRA_MASTER_SECRET unset; using insecure all-zero key for debug builds only"
                );
                [0u8; 32]
            }
            #[cfg(not(debug_assertions))]
            {
                panic!(
                    "SIRA_MASTER_SECRET must be set to 64 hex characters (32 bytes) in release builds"
                );
            }
        }
    }
}

fn parse_hex_32(hex_str: &str) -> Option<[u8; 32]> {
    let v = hex::decode(hex_str.trim()).ok()?;
    v.try_into().ok()
}

/// Optional path from `SIRA_REVOCATION_STORE`: file of unix timestamps (one per line, `#` comments).
/// Tokens with `created_at <= max(line)` are rejected (global cutoff, same idea as JWT mass-revoke).
#[derive(Clone)]
pub struct RevocationState {
    path: PathBuf,
    cutoff: Arc<AtomicU64>,
}

impl RevocationState {
    pub fn from_env() -> Option<Self> {
        let p = std::env::var("SIRA_REVOCATION_STORE").ok()?;
        if p.is_empty() {
            return None;
        }
        let path = PathBuf::from(p);
        let s = Self {
            path,
            cutoff: Arc::new(AtomicU64::new(0)),
        };
        s.reload();
        Some(s)
    }

    pub fn reload(&self) {
        let c = read_revocation_cutoff(&self.path).unwrap_or(0);
        self.cutoff.store(c, Ordering::Relaxed);
    }

    /// Returns true if the token must be rejected.
    pub fn is_revoked(&self, created_at: u64) -> bool {
        let c = self.cutoff.load(Ordering::Relaxed);
        c > 0 && created_at <= c
    }
}

fn read_revocation_cutoff(path: &Path) -> std::io::Result<u64> {
    let s = fs::read_to_string(path)?;
    let mut m = 0u64;
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let v: u64 = line.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid u64: {e}"))
        })?;
        m = m.max(v);
    }
    Ok(m)
}

"""SIRA protocol constants and frame types (match sira Rust types.rs)."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

MESSAGE_SIZE = 1024
IV_SIZE = 12
ID_SIZE = 16
CIPHERTEXT_SIZE = MESSAGE_SIZE - IV_SIZE
PAYLOAD_SIZE = CIPHERTEXT_SIZE - 16
DATA_SIZE = PAYLOAD_SIZE - ID_SIZE
MAX_ASSEMBLED = 8 * 1024 * 1024
MAX_CHUNK_COUNT = 16_384
MAX_CHUNK_DATA = DATA_SIZE - 64

HKDF_INFO = b"sst-aes-gcm-v1"
SESSION_TOKEN_HKDF_INFO = b"sst-session-token-v1"

HEARTBEAT_INTERVAL = 30
HEARTBEAT_TIMEOUT = 60
COOKIE_MAX_AGE = 86400
COOKIE_MAX_AGE_PERSISTENT = 604800

# Aliases matching Rust names
HEARTBEAT_INTERVAL_SECS = HEARTBEAT_INTERVAL
HEARTBEAT_TIMEOUT_SECS = HEARTBEAT_TIMEOUT
COOKIE_MAX_AGE_SECS = COOKIE_MAX_AGE
COOKIE_MAX_AGE_PERSISTENT_SECS = COOKIE_MAX_AGE_PERSISTENT
MAX_ASSEMBLED_PAYLOAD = MAX_ASSEMBLED


@dataclass
class SessionToken:
    key: bytes
    created_at: int
    persistent: bool
    user_id: str | None = None

    @staticmethod
    def new(key: bytes, persistent: bool) -> SessionToken:
        return SessionToken(
            key=key, created_at=int(time.time()), persistent=persistent, user_id=None
        )

    def with_user_id(self, user_id: str) -> SessionToken:
        return SessionToken(
            key=self.key,
            created_at=self.created_at,
            persistent=self.persistent,
            user_id=user_id,
        )

    def fingerprint(self) -> str:
        return self.key[:8].hex()


@dataclass
class CLsend:
    h: str
    a: Any
    w: str
    s: bytes | None = None


@dataclass
class SVsend:
    h: str
    r: Any
    w: str
    s: bytes | None = None


@dataclass
class Beat:
    beat: bool
    w: str


@dataclass
class ChunkPayload:
    k: str
    i: int
    n: int
    d: bytes


def now_unix() -> int:
    return int(time.time())


def initial_hash(window_id: str) -> str:
    h = hashlib.sha256()
    h.update(b"sst-initial-")
    h.update(window_id.encode())
    return h.hexdigest()


def compute_hash(substate: bytes) -> str:
    return hashlib.sha256(substate).hexdigest()


def expected_clsend_hash(window_id: str, substate: bytes | None) -> str:
    if substate is not None:
        return compute_hash(substate)
    return initial_hash(window_id)

"""Cryptographic primitives — match sira Rust crypto.rs."""

from __future__ import annotations

import base64
import os
import secrets
from typing import TYPE_CHECKING

import msgpack
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sira.types import (
    CIPHERTEXT_SIZE,
    DATA_SIZE,
    HKDF_INFO,
    ID_SIZE,
    IV_SIZE,
    MAX_CHUNK_COUNT,
    MESSAGE_SIZE,
    PAYLOAD_SIZE,
    SESSION_TOKEN_HKDF_INFO,
    SessionToken,
    ChunkPayload,
    compute_hash,
    initial_hash,
)

if TYPE_CHECKING:
    pass


def derive_session_cookie_key(master_secret: bytes) -> bytes:
    assert len(master_secret) == 32
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=SESSION_TOKEN_HKDF_INFO,
    )
    return hkdf.derive(master_secret)


def _pack_session_token(token: SessionToken) -> bytes:
    d: dict = {
        "key": token.key,
        "created_at": token.created_at,
        "persistent": token.persistent,
    }
    if token.user_id is not None:
        d["user_id"] = token.user_id
    return msgpack.packb(d, use_bin_type=True)


def _unpack_session_token(data: bytes) -> SessionToken:
    d = msgpack.unpackb(data, raw=False, strict_map_key=False)
    uid = d.get("user_id")
    return SessionToken(
        key=d["key"],
        created_at=int(d["created_at"]),
        persistent=bool(d.get("persistent", False)),
        user_id=uid if uid is not None else None,
    )


def handshake(client_pub_bytes: bytes) -> tuple[bytes, bytes]:
    if len(client_pub_bytes) != 32:
        raise ValueError("invalid client public key")
    server_priv = X25519PrivateKey.generate()
    server_pub = server_priv.public_key().public_bytes_raw()
    client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared = server_priv.exchange(client_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=HKDF_INFO)
    aes_key = hkdf.derive(shared)
    return aes_key, server_pub


def encrypt(payload: bytes, key: bytes, request_id: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(request_id) != ID_SIZE:
        raise ValueError("request_id must be 16 bytes")
    plaintext = bytearray(PAYLOAD_SIZE)
    plaintext[:ID_SIZE] = request_id
    n = min(len(payload), DATA_SIZE)
    plaintext[ID_SIZE : ID_SIZE + n] = payload[:n]
    iv = os.urandom(IV_SIZE)
    aes = AESGCM(key)
    ct = aes.encrypt(iv, bytes(plaintext), None)
    if len(ct) != CIPHERTEXT_SIZE:
        raise RuntimeError("unexpected ciphertext length")
    return iv + ct


def encrypt_wire_with_iv(
    payload: bytes, key: bytes, request_id: bytes, iv: bytes
) -> bytes:
    if len(iv) != IV_SIZE:
        raise ValueError("iv must be 12 bytes")
    plaintext = bytearray(PAYLOAD_SIZE)
    plaintext[:ID_SIZE] = request_id
    n = min(len(payload), DATA_SIZE)
    plaintext[ID_SIZE : ID_SIZE + n] = payload[:n]
    aes = AESGCM(key)
    ct = aes.encrypt(iv, bytes(plaintext), None)
    return iv + ct


def encrypt_svsend_chunked(
    payload: bytes, key: bytes, request_id: bytes
) -> list[bytes]:
    SAFE = 900
    if len(payload) <= DATA_SIZE:
        return [encrypt(payload, key, request_id)]
    nchunks = (len(payload) + SAFE - 1) // SAFE
    if nchunks > MAX_CHUNK_COUNT:
        raise ValueError("response too large")
    n = int(nchunks)
    out: list[bytes] = []
    for i, start in enumerate(range(0, len(payload), SAFE)):
        slc = payload[start : start + SAFE]
        cp = ChunkPayload(k="ch", i=i, n=n, d=slc)
        buf = msgpack.packb(
            {"k": cp.k, "i": cp.i, "n": cp.n, "d": cp.d}, use_bin_type=True
        )
        if len(buf) > DATA_SIZE:
            raise ValueError("chunk frame too large")
        out.append(encrypt(buf, key, request_id))
    return out


def decrypt(message: bytes, key: bytes) -> tuple[bytes, bytes]:
    if len(message) != MESSAGE_SIZE:
        raise ValueError("invalid message size")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    iv = message[:IV_SIZE]
    ct = message[IV_SIZE:]
    aes = AESGCM(key)
    plaintext = aes.decrypt(iv, ct, None)
    request_id = bytes(plaintext[:ID_SIZE])
    data = bytes(plaintext[ID_SIZE:])
    while data and data[-1] == 0:
        data = data[:-1]
    return request_id, data


def encrypt_session_token(token: SessionToken, master_key: bytes) -> str:
    """Encrypt SessionToken for __s cookie. master_key is 32-byte SIRA secret (HKDF-derived cookie key)."""
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    cookie_key = derive_session_cookie_key(master_key)
    plain = _pack_session_token(token)
    iv = os.urandom(IV_SIZE)
    aes = AESGCM(cookie_key)
    ct = aes.encrypt(iv, plain, None)
    wire = iv + ct
    return base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")


def decrypt_session_token(cookie_value: str, master_key: bytes) -> SessionToken:
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    cookie_key = derive_session_cookie_key(master_key)
    s = cookie_value.strip()
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    wire = base64.urlsafe_b64decode(s.encode("ascii"))
    if len(wire) <= IV_SIZE:
        raise ValueError("invalid cookie")
    iv = wire[:IV_SIZE]
    ct = wire[IV_SIZE:]
    aes = AESGCM(cookie_key)
    plain = aes.decrypt(iv, ct, None)
    return _unpack_session_token(plain)


def new_request_id() -> bytes:
    return secrets.token_bytes(ID_SIZE)


def noise() -> bytes:
    return secrets.token_bytes(MESSAGE_SIZE)

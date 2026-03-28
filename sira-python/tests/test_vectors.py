"""Byte-for-byte checks against TEST_VECTORS.md / sira test_vectors.rs."""

import binascii

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sira.crypto import decrypt, encrypt_wire_with_iv
from sira.types import HKDF_INFO, MESSAGE_SIZE

VECTOR_CLIENT_SK = bytes([0x2A] * 32)
VECTOR_SERVER_SK = bytes([0x3B] * 32)
VECTOR_X25519_SHARED_HEX = (
    "c4b3e9271e6e346b4d3193a7c6d4dd89ccaa148bb38b4c7d40d9ef2a31a6256e"
)
VECTOR_AES_KEY_HEX = (
    "9e75f736ff1929d622ae5f02e2d121629f9cbb0881494f0af83d3085b65f0724"
)
CLIENT_PUBLIC_HEX = "07aaff3e9fc167275544f4c3a6a17cd837f2ec6e78cd8a57b1e3dfb3cc035a76"
SERVER_PUBLIC_HEX = "437f462c58a8964fa718164019ee3dcaab6023db339c857ecd2a31a56b89d54e"
VECTOR_IV = b"0123456789ab"
VECTOR_REQUEST_ID = bytes(range(16))
VECTOR_PLAINTEXT_PAYLOAD_HEX = "81a161a27374"


def _read_wire_hex_from_test_vectors_md() -> str:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    md = (root / "TEST_VECTORS.md").read_text(encoding="utf-8")
    anchor = md.index("### Full wire frame")
    sub = md[anchor:]
    start = sub.index("```") + 3
    end = sub.index("```", start)
    return "".join(sub[start:end].split())


VECTOR_WIRE_FRAME_HEX = _read_wire_hex_from_test_vectors_md()


def test_x25519_public_keys_and_shared_and_hkdf():
    cli_priv = X25519PrivateKey.from_private_bytes(VECTOR_CLIENT_SK)
    srv_priv = X25519PrivateKey.from_private_bytes(VECTOR_SERVER_SK)
    cli_pub = cli_priv.public_key().public_bytes_raw()
    srv_pub = srv_priv.public_key().public_bytes_raw()
    assert cli_pub.hex() == CLIENT_PUBLIC_HEX
    assert srv_pub.hex() == SERVER_PUBLIC_HEX

    shared_c = cli_priv.exchange(X25519PublicKey.from_public_bytes(srv_pub))
    shared_s = srv_priv.exchange(X25519PublicKey.from_public_bytes(cli_pub))
    assert shared_c == shared_s
    assert shared_c.hex() == VECTOR_X25519_SHARED_HEX

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=HKDF_INFO)
    aes_key = hkdf.derive(shared_c)
    assert aes_key.hex() == VECTOR_AES_KEY_HEX


def test_wire_frame_matches_document():
    key = bytes.fromhex(VECTOR_AES_KEY_HEX)
    payload = bytes.fromhex(VECTOR_PLAINTEXT_PAYLOAD_HEX)
    frame = binascii.unhexlify(VECTOR_WIRE_FRAME_HEX.replace("\n", "").strip())
    assert len(frame) == MESSAGE_SIZE
    rid, pt = decrypt(frame, key)
    assert rid == VECTOR_REQUEST_ID
    assert pt == payload
    recomputed = encrypt_wire_with_iv(payload, key, VECTOR_REQUEST_ID, VECTOR_IV)
    assert recomputed == frame

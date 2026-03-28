"""Encrypt/decrypt and session cookie roundtrips."""

import pytest

from sira.crypto import (
    decrypt,
    decrypt_session_token,
    encrypt,
    encrypt_session_token,
    derive_session_cookie_key,
    new_request_id,
    noise,
)
from sira.types import MESSAGE_SIZE, SessionToken


def test_encrypt_decrypt_roundtrip():
    key = bytes([42] * 32)
    payload = b"hello sira"
    rid = new_request_id()
    enc = encrypt(payload, key, rid)
    assert len(enc) == MESSAGE_SIZE
    rid2, pt = decrypt(enc, key)
    assert rid2 == rid
    assert pt == payload


def test_wrong_key_fails():
    key = bytes([42] * 32)
    bad = bytes([99] * 32)
    rid = new_request_id()
    enc = encrypt(b"x", key, rid)
    with pytest.raises(Exception):
        decrypt(enc, bad)


def test_noise_length():
    assert len(noise()) == MESSAGE_SIZE


def test_session_token_cookie_roundtrip():
    master = bytes([7] * 32)
    token = SessionToken.new(bytes([3] * 32), False)
    s = encrypt_session_token(token, master)
    got = decrypt_session_token(s, master)
    assert got.key == token.key
    assert got.created_at == token.created_at
    assert got.persistent == token.persistent
    assert got.user_id is None


def test_session_token_wrong_master_fails():
    master_a = bytes([1] * 32)
    master_b = bytes([2] * 32)
    token = SessionToken.new(bytes([2] * 32), True)
    s = encrypt_session_token(token, master_a)
    with pytest.raises(Exception):
        decrypt_session_token(s, master_b)


def test_derive_session_cookie_key_stable():
    m = bytes(range(32))
    k1 = derive_session_cookie_key(m)
    k2 = derive_session_cookie_key(m)
    assert k1 == k2
    assert len(k1) == 32

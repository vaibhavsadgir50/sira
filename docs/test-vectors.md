# Test Vectors

SIRA provides deterministic test vectors to verify that all three server implementations (Rust, Node.js, Python) produce identical cryptographic output.

---

## Why test vectors

Cryptographic interoperability is easy to get wrong. A single mismatched byte in HKDF info string, key length, or IV position means sessions encrypted by one implementation can't be decrypted by another.

The test vectors in `TEST_VECTORS.md` use fixed inputs and document the expected output at every step. Each implementation runs the same vectors and asserts identical output.

---

## The Vectors

### X25519 Key Exchange

```
Client private key (hex):
  2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
  2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a

Server private key (hex):
  3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b
  3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b
```

Expected outputs:

| Value | Hex |
|---|---|
| Client public key | see `TEST_VECTORS.md` |
| Server public key | see `TEST_VECTORS.md` |
| X25519 shared secret | see `TEST_VECTORS.md` |
| AES wire key (after HKDF) | see `TEST_VECTORS.md` |

The shared secret is the same whether computed as `ECDH(client_private, server_public)` or `ECDH(server_private, client_public)`. Both directions must match.

### HKDF Derivation

```
Input:  X25519 shared secret (from above)
Info:   "sst-aes-gcm-v1"  (UTF-8 bytes)
Length: 32 bytes

Output: AES-256 wire key (see TEST_VECTORS.md)
```

### Wire Frame Encryption

A complete 1024-byte frame, encrypted deterministically:

```
Payload (MessagePack):
  { "a": "st" }    ← CLsend action field

IV (fixed, for determinism):
  30313233343536373839616200000000  (hex)
  = "0123456789ab" in ASCII + zero bytes

Expected output: 1024-byte hex (see TEST_VECTORS.md)
```

---

## Running the Vectors

### Rust

```bash
cargo test x25519_hkdf_matches_documented_vectors
cargo test wire_frame_roundtrip_matches_vector
```

Located in `test_vectors.rs`.

### Node.js

```bash
cd sira-node
npm test -- --reporter=verbose
# Runs tests/vectors.test.js
```

### Python

```bash
cd sira-python
pytest tests/test_vectors.py -v
```

---

## Adding New Implementations

If you're building a new SIRA server implementation, verify conformance by:

1. Read `TEST_VECTORS.md` for the exact input values and expected outputs
2. Implement X25519 + HKDF and run the key derivation vector
3. Implement AES-256-GCM frame encryption and run the wire frame vector
4. Implement session cookie encrypt/decrypt and write a roundtrip test
5. Run the integration tests against your server (see below)

---

## Integration Tests

The `integration/` directory contains end-to-end tests that run all three server implementations and verify they can all serve the same client.

```bash
cd integration
bash run_all.sh
```

This script:
1. Starts Rust, Node.js, and Python echo servers in the background
2. Uses `sira_test_client.py` to send test actions to all three
3. Verifies identical responses
4. Stops all servers

### Manual integration test

```bash
# Start the server you want to test
export SIRA_MASTER_SECRET="$(openssl rand -hex 32)"
cd sira-node && node example/echo.js &

# Run integration tests against it
cd integration
python test_node.py
```

### sira_test_client.py

The integration test client is a standalone Python SIRA client. Use it to test any SIRA server:

```python
from sira_test_client import SiraTestClient

async def test_my_server():
    client = SiraTestClient('localhost', 3000)

    session = await client.handshake()
    result = await client.send(session, { 'type': 'ping' })
    assert result['pong'] == True

    # Test auth
    authed_session = await client.refresh_auth(session, 'my-test-token')
    result = await client.send(authed_session, { 'type': 'whoami' })
    assert result['userId'] == 'user:my-test-token'
```

---

## Cross-Language Conformance Matrix

| Test | Rust | Node.js | Python |
|---|---|---|---|
| X25519 key derivation | `test_vectors.rs` | `vectors.test.js` | `test_vectors.py` |
| Wire frame encrypt/decrypt | `test_vectors.rs` | `vectors.test.js` | `test_vectors.py` |
| Roundtrip (random keys) | `crypto.rs` tests | `roundtrip.test.js` | `test_roundtrip.py` |
| Session cookie roundtrip | `crypto.rs` tests | `roundtrip.test.js` | `test_roundtrip.py` |
| E2E echo server | `integration/test_rust.py` | `integration/test_node.py` | `integration/test_python.py` |
| Cross-server | `integration/test_cross_language.py` | ← same | ← same |

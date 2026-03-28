# SIRA Test Vectors v0.1

These values are checked by `test_vectors.rs` (Rust). Other implementations should reproduce them byte-for-byte to verify X25519 clamping, HKDF, MessagePack, and AES-256-GCM wire framing.

## Conventions

- All multi-byte values are **hex** unless noted.
- Wire frame: **1024 bytes** = **12-byte IV** concatenated with **AES-256-GCM** ciphertext of the inner plaintext (see Rust `crypto::encrypt` / `encrypt_wire_with_iv`).
- Inner plaintext: **996 bytes** = **16-byte `request_id`** + **up to 980 bytes** MessagePack payload, **zero-padded** to 996 bytes before encryption.

## Key derivation (X25519 + HKDF-SHA256)

Scalars are passed to `x25519_dalek::StaticSecret::from([u8;32])` (library applies Curve25519 clamping).

| Field | Hex |
|-------|-----|
| `client_private` | `2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a` |
| `server_private` | `3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b` |
| `client_public` | `07aaff3e9fc167275544f4c3a6a17cd837f2ec6e78cd8a57b1e3dfb3cc035a76` |
| `server_public` | `437f462c58a8964fa718164019ee3dcaab6023db339c857ecd2a31a56b89d54e` |
| `x25519_shared` | `c4b3e9271e6e346b4d3193a7c6d4dd89ccaa148bb38b4c7d40d9ef2a31a6256e` |
| `hkdf_info` | UTF-8 string `sst-aes-gcm-v1` |
| `hkdf_salt` | empty |
| `aes_key` (wire, 32 bytes) | `9e75f736ff1929d622ae5f02e2d121629f9cbb0881494f0af83d3085b65f0724` |

## Wire encryption (single frame)

| Field | Hex / value |
|-------|-------------|
| `key` | Same as `aes_key` above |
| `iv` | ASCII `0123456789ab` → hex `303132333435363738396162` |
| `request_id` | `000102030405060708090a0b0c0d0e0f` |
| `plaintext` (MessagePack) | MessagePack encoding of JSON `{"a":"st"}` → hex `81a161a27374` |
| `ciphertext` (full 1024 B frame) | See long hex below |

### Full wire frame (1024 bytes, hex)

```
30313233343536373839616209569170e7d5175558cfb181754eda17ad320b4e188f6882c671668bc1c41dcc7c7352d60dd6ddd1c11d294ad125f9dfbc783a017d6174faf37735a117b1f69c62e75ab6a974985c5e6a31e052918ef5e347562411868d6960d4babfc074f7cbe569cf677ad0b58dc9aa84416137f4eef7fc2981a102cd07d1df8145aa7f33af6bb14c4fcb53e7bc28d9fe069cc3ef6ec025c429e7b3af7deb021597476a377b9c19425902410c16fa8272ca31bd9933ec9df637c63cd518ae67cc31eac4f5cdfd1426fd05eb6bdca4b2988cae9471b38c2edc1109c976aefefd43a75e3e2679b35c1fbbc08ec1cf1cadffa8f615f10fca603c06713c75b666987b12ef1b1648de550e94554406f72b6b52cbac7a077256b5c183147aa0c04f990f21129ba19638e83ba92451d8e0972db76d548cccdc7715c51599942ce444d5ebf6e445a5a922a677db4daeeb411da818ed0228f4840964c66bbf310cfd132b673f37e7942d15901b9c1155ddfbaa7e5498e820b974ba4d4a1dcb739f7909b311c44e463173a381169e9f438eaa5f6499aa8891eade1dfda5f00aa363d5cc77c897e0974a09643b315db47d0c6e874fae025f0a360f807d6578676ef93746d24537a51c486d677a10d64046cc178892368663459bc23f3b43db810611d78633e317a62b12a0b926995879248e9b87c9cc687a984ef3ceb7ebc0cb9fc125ad700cab6fc42e4ac8c8f57e3ec6342e463bf9808da4a86ccbcf3709fa0fd9c2b0846bbd8f9cd290bf5a02533a21ecafd16b83bfb2aa478d17a6a06dba28b5ff7b36aca2f5b808aa70c870a179c5cfa11339c27adcdbc0d9764a4e3590d8387d7998196730607f5c849ede00746a3f42103fbdad61c31c9e02bc61b48fcadcb04cbba2ac1515d838dd44ea4d481c2098325c422e7859f627a546582018adb2a5955fee8e47e8a8890d80fdf1126d8b4160be900f8afc35b1fb2aa2597987c587af7875b6cbb8901f46228fe213d758ec01759d647e7eccb58b97ce6e2e34de9795c2f655573d58449b1a88b756185baa830c1af7ee554f3eaaa1ae1df34b17e1caa6179a93436ddc39b2a86900ab830211f39c4d9b537643b48714a972d8c2d4d0e6a71cd6fd5ac655efaf766e2e740c6665f40f9ef801ab3a9404dbc47b6bbc3711d5a62834efbc2716355631d46c3a872f749ad8b30bc8e047b83bfae2d186b1f9fe83683d251d8c81576f29c1893a3f5ce689357686a5fd9ef4587c0815852c455e54e5dc5ff72dbafa47860fe05a21e3e5c85b3051ae1d13e4e6dbeace46fe7ec8a2fa91927c791387f7e38424421ba5ea090f5291bbcf05112557d129d88e5e51d50f67850ef9f5572ed3adb46ec26e442d0b5e2754792429b8e6a2f07f3fe6e377c7ce1b332a11092e56112c4547fcd34aa48b977f238ffd58
```

JavaScript interop: derive the same **wire** `aes_key` with Web Crypto **HKDF** (`salt` empty, `info` = UTF-8 `sst-aes-gcm-v1`) over the 32-byte X25519 output from `tweetnacl.scalarMult`, then AES-GCM-decrypt the frame with the fixed `iv` and `key` above to recover the MessagePack payload.

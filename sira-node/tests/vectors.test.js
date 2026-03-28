import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { x25519 } from '@noble/curves/ed25519'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { encode } from '@msgpack/msgpack'

import { decrypt, encryptWireWithIv } from '../src/crypto.js'
import { HKDF_INFO, MESSAGE_SIZE } from '../src/types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(__dirname, '..', '..')

function readWireHex() {
  const md = readFileSync(join(repoRoot, 'TEST_VECTORS.md'), 'utf8')
  const anchor = md.indexOf('### Full wire frame')
  const sub = md.slice(anchor)
  const fence = '```'
  const s = sub.indexOf(fence) + fence.length
  const e = sub.indexOf(fence, s)
  return sub.slice(s, e).replace(/\s/g, '')
}

const VECTOR_CLIENT_SK = new Uint8Array(32).fill(0x2a)
const VECTOR_SERVER_SK = new Uint8Array(32).fill(0x3b)
const VECTOR_X25519_SHARED_HEX =
  'c4b3e9271e6e346b4d3193a7c6d4dd89ccaa148bb38b4c7d40d9ef2a31a6256e'
const VECTOR_AES_KEY_HEX =
  '9e75f736ff1929d622ae5f02e2d121629f9cbb0881494f0af83d3085b65f0724'
const CLIENT_PUBLIC_HEX =
  '07aaff3e9fc167275544f4c3a6a17cd837f2ec6e78cd8a57b1e3dfb3cc035a76'
const SERVER_PUBLIC_HEX =
  '437f462c58a8964fa718164019ee3dcaab6023db339c857ecd2a31a56b89d54e'
const VECTOR_IV = new TextEncoder().encode('0123456789ab')
const VECTOR_REQUEST_ID = Buffer.from(
  '000102030405060708090a0b0c0d0e0f',
  'hex',
)
const VECTOR_PLAINTEXT_PAYLOAD_HEX = '81a161a27374'
const VECTOR_WIRE_FRAME_HEX = readWireHex()

describe('TEST_VECTORS.md', () => {
  it('x25519 + HKDF matches documented vectors', () => {
    const pkc = x25519.getPublicKey(VECTOR_CLIENT_SK)
    const pks = x25519.getPublicKey(VECTOR_SERVER_SK)
    expect(Buffer.from(pkc).toString('hex')).toBe(CLIENT_PUBLIC_HEX)
    expect(Buffer.from(pks).toString('hex')).toBe(SERVER_PUBLIC_HEX)
    const sh1 = x25519.getSharedSecret(VECTOR_CLIENT_SK, pks)
    expect(Buffer.from(sh1).toString('hex')).toBe(VECTOR_X25519_SHARED_HEX)
    const info = new TextEncoder().encode('sst-aes-gcm-v1')
    const aesKey = hkdf(sha256, sh1, new Uint8Array(0), info, 32)
    expect(Buffer.from(aesKey).toString('hex')).toBe(VECTOR_AES_KEY_HEX)
  })

  it('MessagePack payload is {"a":"st"}', () => {
    const b = encode({ a: 'st' })
    expect(Buffer.from(b).toString('hex')).toBe(VECTOR_PLAINTEXT_PAYLOAD_HEX)
  })

  it('full wire frame round-trip', async () => {
    const key = Buffer.from(VECTOR_AES_KEY_HEX, 'hex')
    const payload = Buffer.from(VECTOR_PLAINTEXT_PAYLOAD_HEX, 'hex')
    const frame = Buffer.from(VECTOR_WIRE_FRAME_HEX, 'hex')
    expect(frame.length).toBe(MESSAGE_SIZE)
    const { requestId, payload: pt } = await decrypt(frame, key)
    expect(requestId.equals(VECTOR_REQUEST_ID)).toBe(true)
    expect(Buffer.compare(pt, payload)).toBe(0)
    const recomputed = await encryptWireWithIv(
      payload,
      key,
      VECTOR_REQUEST_ID,
      VECTOR_IV,
    )
    expect(Buffer.compare(recomputed, frame)).toBe(0)
  })
})

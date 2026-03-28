/**
 * SIRA crypto — X25519 (@noble/curves), HKDF (@noble/hashes), AES-GCM (Web Crypto).
 */

import { encode, decode } from '@msgpack/msgpack'
import { x25519 } from '@noble/curves/ed25519'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { randomBytes } from 'node:crypto'

import {
  CIPHERTEXT_SIZE,
  DATA_SIZE,
  HKDF_INFO,
  ID_SIZE,
  IV_SIZE,
  MAX_CHUNK_COUNT,
  MESSAGE_SIZE,
  PAYLOAD_SIZE,
  SESSION_TOKEN_HKDF_INFO,
} from './types.js'

/** @param {Buffer | Uint8Array} masterSecret 32 bytes */
export function deriveSessionCookieKey(masterSecret) {
  const ms = toU8(masterSecret)
  if (ms.length !== 32) throw new Error('master_secret must be 32 bytes')
  return hkdf(sha256, ms, new Uint8Array(0), SESSION_TOKEN_HKDF_INFO, 32)
}

function toU8(b) {
  if (b instanceof Uint8Array) return b
  return new Uint8Array(b)
}

/** @param {Uint8Array} clientPubBytes */
export async function handshake(clientPubBytes) {
  if (clientPubBytes.length !== 32) throw new Error('invalid client public key')
  const serverPriv = x25519.utils.randomPrivateKey()
  const serverPub = x25519.getPublicKey(serverPriv)
  const shared = x25519.getSharedSecret(serverPriv, clientPubBytes)
  const aesKey = hkdf(sha256, shared, new Uint8Array(0), HKDF_INFO, 32)
  return { aesKey, serverPublicKey: serverPub }
}

async function importAesKey(raw) {
  return crypto.subtle.importKey('raw', toU8(raw), 'AES-GCM', false, ['encrypt', 'decrypt'])
}

/** @param {Buffer | Uint8Array} payload @param {Buffer | Uint8Array} key @param {Buffer | Uint8Array} requestId */
export async function encrypt(payload, key, requestId) {
  const k = toU8(key)
  const rid = toU8(requestId)
  if (k.length !== 32) throw new Error('key must be 32 bytes')
  if (rid.length !== ID_SIZE) throw new Error('request_id must be 16 bytes')
  const plaintext = new Uint8Array(PAYLOAD_SIZE)
  plaintext.set(rid, 0)
  const pl = toU8(payload)
  const n = Math.min(pl.length, DATA_SIZE)
  plaintext.set(pl.subarray(0, n), ID_SIZE)
  const iv = randomBytes(IV_SIZE)
  const ck = await importAesKey(k)
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      ck,
      plaintext,
    ),
  )
  if (ct.length !== CIPHERTEXT_SIZE) throw new Error('unexpected ciphertext length')
  return Buffer.concat([Buffer.from(iv), Buffer.from(ct)])
}

/** Deterministic wire frame (test vectors). */
export async function encryptWireWithIv(payload, key, requestId, iv) {
  const k = toU8(key)
  const rid = toU8(requestId)
  const ivb = toU8(iv)
  if (ivb.length !== IV_SIZE) throw new Error('iv must be 12 bytes')
  const plaintext = new Uint8Array(PAYLOAD_SIZE)
  plaintext.set(rid, 0)
  const pl = toU8(payload)
  const n = Math.min(pl.length, DATA_SIZE)
  plaintext.set(pl.subarray(0, n), ID_SIZE)
  const ck = await importAesKey(k)
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: ivb, tagLength: 128 },
      ck,
      plaintext,
    ),
  )
  return Buffer.concat([Buffer.from(ivb), Buffer.from(ct)])
}

/** @param {Buffer | Uint8Array} message @param {Buffer | Uint8Array} key */
export async function decrypt(message, key) {
  const msg = toU8(message)
  const k = toU8(key)
  if (msg.length !== MESSAGE_SIZE) throw new Error('invalid message size')
  if (k.length !== 32) throw new Error('key must be 32 bytes')
  const iv = msg.subarray(0, IV_SIZE)
  const ct = msg.subarray(IV_SIZE)
  const ck = await importAesKey(k)
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, ck, ct),
  )
  const requestId = Buffer.from(plain.subarray(0, ID_SIZE))
  let data = Buffer.from(plain.subarray(ID_SIZE))
  while (data.length && data[data.length - 1] === 0) data = data.subarray(0, -1)
  return { requestId, payload: data }
}

const SAFE = 900

/** @param {Buffer | Uint8Array} payload @param {Buffer | Uint8Array} key @param {Buffer | Uint8Array} requestId */
export async function encryptSvsendChunked(payload, key, requestId) {
  const pl = toU8(payload)
  if (pl.length <= DATA_SIZE) return [await encrypt(pl, key, requestId)]
  const nchunks = Math.ceil(pl.length / SAFE)
  if (nchunks > MAX_CHUNK_COUNT) throw new Error('response too large')
  const n = nchunks
  const out = []
  for (let i = 0; i < n; i++) {
    const start = i * SAFE
    const d = pl.subarray(start, Math.min(start + SAFE, pl.length))
    const buf = encode({ k: 'ch', i, n, d })
    if (buf.length > DATA_SIZE) throw new Error('chunk frame too large')
    out.push(await encrypt(buf, key, requestId))
  }
  return out
}

/** @param {{ key: Buffer | Uint8Array, created_at: number, persistent: boolean, user_id?: string | null }} token */
export async function encryptSessionToken(token, masterSecret) {
  const ms = toU8(masterSecret)
  if (ms.length !== 32) throw new Error('master_secret must be 32 bytes')
  const cookieKey = deriveSessionCookieKey(ms)
  const obj = {
    key: new Uint8Array(token.key),
    created_at: token.created_at,
    persistent: token.persistent,
  }
  if (token.user_id != null) obj.user_id = token.user_id
  const plain = encode(obj)
  const iv = randomBytes(IV_SIZE)
  const ck = await importAesKey(cookieKey)
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      ck,
      plain,
    ),
  )
  const wire = Buffer.concat([Buffer.from(iv), Buffer.from(ct)])
  return wire
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/** @param {string} cookieValue @param {Buffer | Uint8Array} masterSecret */
export async function decryptSessionToken(cookieValue, masterSecret) {
  const ms = toU8(masterSecret)
  if (ms.length !== 32) throw new Error('master_secret must be 32 bytes')
  const cookieKey = deriveSessionCookieKey(ms)
  let s = cookieValue.trim()
  const pad = 4 - (s.length % 4 || 4)
  if (pad !== 4) s += '='.repeat(pad)
  const wire = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
  if (wire.length <= IV_SIZE) throw new Error('invalid cookie')
  const iv = wire.subarray(0, IV_SIZE)
  const ct = wire.subarray(IV_SIZE)
  const ck = await importAesKey(cookieKey)
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, ck, ct),
  )
  const d = decode(plain)
  return {
    key: Buffer.from(d.key),
    created_at: Number(d.created_at),
    persistent: Boolean(d.persistent),
    user_id: d.user_id != null ? String(d.user_id) : null,
  }
}

export function newRequestId() {
  return randomBytes(ID_SIZE)
}

export function noise() {
  return randomBytes(MESSAGE_SIZE)
}

// sira-js/src/sst.js
// SIRA Browser Client
// Dependencies: @msgpack/msgpack, tweetnacl (for X25519)

import { encode, decode } from '@msgpack/msgpack'
import nacl from 'tweetnacl'

// ── Constants (must match server types.rs / crypto.rs) ────────────────────

const MESSAGE_SIZE = 1024
const IV_SIZE = 12
const ID_SIZE = 16
const PAYLOAD_SIZE = MESSAGE_SIZE - IV_SIZE - 16
const DATA_SIZE = PAYLOAD_SIZE - ID_SIZE
const MAX_CHUNK_DATA = DATA_SIZE - 64
const CHUNK_SAFE = 900
const MAX_ASSEMBLED_PAYLOAD = 8 * 1024 * 1024
const MAX_CHUNK_COUNT = 16384
const HEARTBEAT_MS = 30_000

const HKDF_INFO = new TextEncoder().encode('sst-aes-gcm-v1')

// ── Chunk reassembly (server → client SVsend) ─────────────────────────────

class ChunkReassembler {
  constructor() {
    this.map = new Map()
  }

  push(idHex, ch) {
    if (ch.k !== 'ch' || ch.n === 0 || ch.n > MAX_CHUNK_COUNT || ch.i >= ch.n) {
      throw new Error('SIRA: invalid chunk')
    }
    const d = toUint8(ch.d)
    if (d.byteLength > MAX_CHUNK_DATA) throw new Error('SIRA: chunk data too large')

    let slot = this.map.get(idHex)
    const now = Date.now()
    if (!slot || now - slot.t0 > 120_000) {
      slot = {
        n: ch.n,
        parts: new Array(ch.n).fill(null),
        filled: 0,
        bytes: 0,
        t0: now,
      }
      this.map.set(idHex, slot)
    }
    if (slot.n !== ch.n) throw new Error('SIRA: chunk count mismatch')
    if (slot.parts[ch.i]) throw new Error('SIRA: duplicate chunk index')

    slot.parts[ch.i] = d
    slot.filled += 1
    slot.bytes += d.byteLength
    if (slot.bytes > MAX_ASSEMBLED_PAYLOAD) {
      this.map.delete(idHex)
      throw new Error('SIRA: assembled payload too large')
    }
    if (slot.filled < ch.n) return null

    const out = new Uint8Array(slot.bytes)
    let o = 0
    for (const p of slot.parts) {
      out.set(p, o)
      o += p.byteLength
    }
    this.map.delete(idHex)
    return out
  }
}

function toUint8(d) {
  if (d instanceof Uint8Array) return d
  if (ArrayBuffer.isView(d)) {
    return new Uint8Array(d.buffer, d.byteOffset, d.byteLength)
  }
  if (d instanceof ArrayBuffer) return new Uint8Array(d)
  return new Uint8Array(d)
}

// ── SIRA Client ────────────────────────────────────────────────────────────

export class Sira {
  constructor(options = {}) {
    this.host = options.host || window.location.host
    this.secure = options.secure ?? window.location.protocol === 'https:'

    this.key = null
    this.ws = null
    this.windowId = null
    this.stateHash = null
    this.substate = null
    this.persistent = false

    this.pending = new Map()
    this.onrender = null
    this.onbeat = null

    this._beatTimer = null
    this._connected = false
    this._rxChunks = new ChunkReassembler()
  }

  async open(options = {}) {
    this.persistent = options.persistent ?? false
    this.windowId = this._generateWindowId()
    this.key = await this._handshake()
    await this._connectWebSocket()
    this._startHeartbeat()
    this._connected = true
  }

  async once(action) {
    if (this.persistent) {
      throw new Error('SIRA: once() is incompatible with persistent: true')
    }
    await this.open({ persistent: false })
    const result = await this.send(action)
    await this.close()
    return result
  }

  async send(action) {
    if (!this._connected) throw new Error('SIRA: call open() first')

    const requestId = this._randomBytes(ID_SIZE)
    const requestIdHex = this._toHex(requestId)

    const clsend = {
      h: this.stateHash || (await this._initialHash(this.windowId)),
      a: action,
      w: this.windowId,
    }
    if (this.substate) clsend.s = this.substate

    const payload = encode(clsend)

    return new Promise((resolve, reject) => {
      this.pending.set(requestIdHex, { resolve, reject })
      this._sendPayloadChunks(payload, requestId).catch((err) => {
        this.pending.delete(requestIdHex)
        reject(err)
      })
    })
  }

  async _sendPayloadChunks(payload, requestId) {
    if (payload.byteLength <= DATA_SIZE) {
      this.ws.send(await this._encrypt(payload, requestId))
      return
    }
    const n = Math.ceil(payload.byteLength / CHUNK_SAFE)
    if (n > MAX_CHUNK_COUNT) throw new Error('SIRA: payload too large')
    for (let i = 0; i < n; i++) {
      const start = i * CHUNK_SAFE
      const end = Math.min(start + CHUNK_SAFE, payload.byteLength)
      const d = payload.subarray(start, end)
      const ch = { k: 'ch', i, n, d }
      const enc = encode(ch)
      if (enc.byteLength > DATA_SIZE) throw new Error('SIRA: encoded chunk exceeds frame')
      this.ws.send(await this._encrypt(enc, requestId))
    }
  }

  async close() {
    this._connected = false
    this._stopHeartbeat()
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  /// Refresh `__s` with `user_id` via `POST /r` (same 1024 B wire envelope). Reconnects `/w` if the socket was open.
  async refreshAuth(appToken) {
    if (!this.key) throw new Error('SIRA: call open() before refreshAuth')

    const wasConnected = this._connected
    if (this.ws) {
      this._stopHeartbeat()
      this.ws.close()
      this.ws = null
    }
    this._connected = false

    const requestId = this._randomBytes(ID_SIZE)
    const h = this.stateHash || (await this._initialHash(this.windowId))
    const clsend = {
      h,
      a: { auth: { token: String(appToken) } },
      w: this.windowId,
    }
    if (this.substate) clsend.s = this.substate

    const payload = encode(clsend)
    if (payload.byteLength > DATA_SIZE) {
      throw new Error('SIRA: refreshAuth payload exceeds one frame')
    }

    const body = await this._encrypt(payload, requestId)
    const protocol = this.secure ? 'https' : 'http'
    const res = await fetch(`${protocol}://${this.host}/r`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body,
      credentials: 'include',
    })

    if (res.status === 401) {
      await res.arrayBuffer()
      throw new Error('SIRA: refreshAuth rejected')
    }
    if (!res.ok) throw new Error(`SIRA: refreshAuth failed: ${res.status}`)

    if (wasConnected) {
      await this._connectWebSocket()
      this._startHeartbeat()
      this._connected = true
    }
  }

  async _handshake() {
    const keyPair = nacl.box.keyPair()
    const protocol = this.secure ? 'https' : 'http'
    const qs = this.persistent ? '?persistent=true' : ''
    const response = await fetch(`${protocol}://${this.host}/h${qs}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: keyPair.publicKey,
      credentials: 'include',
    })

    if (!response.ok) throw new Error('SST handshake failed')

    const serverPubKeyBytes = new Uint8Array(await response.arrayBuffer())
    const sharedSecret = nacl.scalarMult(keyPair.secretKey, serverPubKeyBytes)

    const baseKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, [
      'deriveKey',
    ])
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
  }

  async _connectWebSocket() {
    const protocol = this.secure ? 'wss' : 'ws'
    const url = `${protocol}://${this.host}/w`

    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(url)
      this.ws.binaryType = 'arraybuffer'

      this.ws.onopen = () => resolve()
      this.ws.onerror = (e) => reject(e)

      this.ws.onmessage = async (event) => {
        await this._handleIncoming(new Uint8Array(event.data))
      }

      this.ws.onclose = () => {
        this._connected = false
        this._stopHeartbeat()
        for (const [, { reject }] of this.pending) {
          reject(new Error('SIRA: connection closed'))
        }
        this.pending.clear()
      }
    })
  }

  async _handleIncoming(raw) {
    if (raw.length !== MESSAGE_SIZE) return

    let requestId
    let payload
    try {
      ;({ requestId, payload } = await this._decrypt(raw))
    } catch {
      return
    }

    const requestIdHex = this._toHex(requestId)

    try {
      const beat = decode(payload)
      if (beat && beat.beat === true) {
        if (this.onbeat) this.onbeat()
        return
      }
    } catch {
      /* not a beat */
    }

    let fullPayload = null
    try {
      const obj = decode(payload)
      if (obj && obj.k === 'ch') {
        try {
          fullPayload = this._rxChunks.push(requestIdHex, obj)
        } catch {
          return
        }
        if (fullPayload === null) return
      }
    } catch {
      /* not msgpack or not chunk */
    }

    if (fullPayload === null) fullPayload = payload

    let svsend
    try {
      svsend = decode(fullPayload)
    } catch (e) {
      console.error('SIRA: failed to decode SVsend', e)
      return
    }

    this.stateHash = svsend.h
    if (svsend.s) this.substate = svsend.s

    const pending = this.pending.get(requestIdHex)
    if (pending) {
      pending.resolve(svsend.r)
      this.pending.delete(requestIdHex)
    } else if (this.onrender) {
      this.onrender(svsend.r, svsend.w)
    }
  }

  _startHeartbeat() {
    const schedule = async () => {
      if (!this._connected || !this.ws) return
      try {
        const beat = encode({ beat: true, w: this.windowId })
        const id = this._randomBytes(ID_SIZE)
        const message = await this._encrypt(beat, id)
        this.ws.send(message)
      } catch {
        /* ignore */
      }
      if (this._connected && this.ws) {
        this._beatTimer = setTimeout(schedule, HEARTBEAT_MS)
      }
    }
    this._beatTimer = setTimeout(schedule, HEARTBEAT_MS)
  }

  _stopHeartbeat() {
    if (this._beatTimer) {
      clearTimeout(this._beatTimer)
      this._beatTimer = null
    }
  }

  async _encrypt(payload, requestId) {
    const plaintext = new Uint8Array(PAYLOAD_SIZE)
    plaintext.set(requestId, 0)
    const dataBytes = payload.byteLength > DATA_SIZE ? payload.subarray(0, DATA_SIZE) : payload
    plaintext.set(dataBytes, ID_SIZE)

    const iv = this._randomBytes(IV_SIZE)
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, plaintext)

    const message = new Uint8Array(MESSAGE_SIZE)
    message.set(iv, 0)
    message.set(new Uint8Array(ciphertext), IV_SIZE)
    return message
  }

  async _decrypt(raw) {
    const iv = raw.slice(0, IV_SIZE)
    const ciphertext = raw.slice(IV_SIZE)

    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, ciphertext)

    const bytes = new Uint8Array(plaintext)
    const requestId = bytes.slice(0, ID_SIZE)

    let end = bytes.length
    while (end > ID_SIZE && bytes[end - 1] === 0) end--
    const payload = bytes.slice(ID_SIZE, end)

    return { requestId, payload }
  }

  _generateWindowId() {
    return 'w_' + this._toHex(this._randomBytes(8))
  }

  _randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n))
  }

  _toHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  }

  async _initialHash(windowId) {
    const encoder = new TextEncoder()
    const data = encoder.encode('sst-initial-' + windowId)
    const hash = await crypto.subtle.digest('SHA-256', data)
    return this._toHex(new Uint8Array(hash))
  }
}

export class SiraWindowManager {
  constructor(options = {}) {
    this.options = options
    this.windows = new Map()
  }

  async openWindow(onrender) {
    const sira = new Sira(this.options)
    sira.onrender = onrender
    await sira.open()
    this.windows.set(sira.windowId, sira)
    return sira
  }

  async closeAll() {
    for (const sira of this.windows.values()) {
      await sira.close()
    }
    this.windows.clear()
  }
}

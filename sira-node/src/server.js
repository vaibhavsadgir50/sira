/**
 * HTTP + WebSocket SIRA server (match sira Rust server.rs).
 */

import { encode, decode } from '@msgpack/msgpack'
import http from 'node:http'
import { WebSocket, WebSocketServer } from 'ws'

import * as crypto from './crypto.js'
import {
  COOKIE_MAX_AGE_PERSISTENT_SECS,
  COOKIE_MAX_AGE_SECS,
  HEARTBEAT_TIMEOUT_SECS,
  MAX_ASSEMBLED_PAYLOAD,
  MAX_CHUNK_COUNT,
  MAX_CHUNK_DATA,
  MESSAGE_SIZE,
  expectedClsendHash,
  computeHash,
  initialHash,
  nowUnix,
} from './types.js'

class MinuteRateLimiter {
  constructor(maxPerRollingMinute) {
    this._data = new Map()
    this._max = maxPerRollingMinute
  }

  allow(key) {
    const now = nowUnix()
    let v = this._data.get(key)
    if (!v) {
      v = []
      this._data.set(key, v)
    }
    const kept = v.filter((t) => now - t < 60)
    v.length = 0
    v.push(...kept)
    if (v.length >= this._max) return false
    v.push(now)
    return true
  }

  purgeStale() {
    const now = nowUnix()
    for (const [k, v] of this._data) {
      const kept = v.filter((t) => now - t < 60)
      if (kept.length) {
        v.length = 0
        v.push(...kept)
      } else this._data.delete(k)
    }
  }
}

class ChunkBuffers {
  constructor() {
    this._inner = new Map()
  }

  purgeStale(maxAgeS) {
    const now = Date.now() / 1000
    for (const [k, slot] of this._inner) {
      if (now - slot.started > maxAgeS) this._inner.delete(k)
    }
  }

  push(assemblyKey, ch) {
    if (
      ch.k !== 'ch' ||
      ch.n === 0 ||
      ch.n > MAX_CHUNK_COUNT ||
      ch.i >= ch.n ||
      ch.d.length > MAX_CHUNK_DATA
    ) {
      throw new Error('bad chunk')
    }
    let slot = this._inner.get(assemblyKey)
    const now = Date.now() / 1000
    if (!slot || now - slot.started > 120) {
      slot = {
        n: ch.n,
        parts: new Array(ch.n).fill(null),
        filled: 0,
        bytes: 0,
        started: now,
      }
      this._inner.set(assemblyKey, slot)
    }
    if (slot.n !== ch.n) throw new Error('chunk n mismatch')
    if (slot.parts[ch.i] != null) throw new Error('dup chunk')
    const add = ch.d.length
    if (slot.bytes + add > MAX_ASSEMBLED_PAYLOAD) throw new Error('too large')
    slot.parts[ch.i] = ch.d
    slot.filled += 1
    slot.bytes += add
    if (slot.filled < ch.n) return null
    const out = Buffer.concat(slot.parts.filter(Boolean))
    this._inner.delete(assemblyKey)
    return out
  }
}

function cookieHeader(value, persistent) {
  const maxAge = persistent ? COOKIE_MAX_AGE_PERSISTENT_SECS : COOKIE_MAX_AGE_SECS
  return `__s=${value}; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}; Path=/`
}

function write401Noise(socket) {
  const body = crypto.noise()
  const head =
    'HTTP/1.1 401 Unauthorized\r\n' +
    'Content-Type: application/octet-stream\r\n' +
    `Content-Length: ${body.length}\r\n` +
    'Connection: close\r\n\r\n'
  socket.write(Buffer.concat([Buffer.from(head, 'utf8'), body]))
  socket.destroy()
}

function extractSessionCookie(headerVal) {
  if (!headerVal) return null
  for (const part of headerVal.split(';')) {
    const p = part.trim()
    if (p.startsWith('__s=')) return p.slice(4)
  }
  return null
}

function extractAuthAppToken(a) {
  if (!a || typeof a !== 'object') return null
  const auth = a.auth
  if (!auth || typeof auth !== 'object') return null
  const t = auth.token
  return t != null ? String(t) : null
}

function clientIp(req) {
  return req.socket?.remoteAddress || 'unknown'
}

function tryBeat(payload) {
  try {
    const d = decode(payload)
    if (
      d &&
      typeof d === 'object' &&
      Object.keys(d).length === 2 &&
      'beat' in d &&
      'w' in d
    ) {
      return { beat: Boolean(d.beat), w: String(d.w) }
    }
  } catch {
    /* ignore */
  }
  return null
}

function tryChunk(payload) {
  try {
    const d = decode(payload)
    if (d && typeof d === 'object' && d.k === 'ch') {
      const raw = d.d
      const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
      return { k: 'ch', i: Number(d.i), n: Number(d.n), d: buf }
    }
  } catch {
    /* ignore */
  }
  return null
}

function unpackClsend(payload) {
  try {
    const d = decode(payload)
    if (!d || typeof d !== 'object') return null
    const s = d.s
    const sb =
      s == null ? null : Buffer.isBuffer(s) ? s : Buffer.from(s)
    return { h: String(d.h), a: d.a, w: String(d.w), s: sb }
  } catch {
    return null
  }
}

function readBody(req, maxLen) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let n = 0
    req.on('data', (c) => {
      n += c.length
      if (n > maxLen) {
        reject(new Error('body too large'))
        req.destroy()
        return
      }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

async function callPipeline(pipeline, action, sessionId, windowId, userId) {
  const ctx = { sessionId, windowId, userId }
  if (typeof pipeline === 'function') return pipeline(action, ctx)
  return pipeline.process(action, ctx)
}

export class Pipeline {
  async process(_action, _ctx) {
    throw new Error('Pipeline.process must be implemented')
  }
}

export class SiraServer {
  constructor({
    pipeline,
    masterSecret,
    refreshAuth = null,
    host = '0.0.0.0',
    port = 3000,
    revocation = null,
    /** Optional async (req, res) => boolean — return true if the response was fully handled */
    httpFallback = null,
  }) {
    if (!Buffer.isBuffer(masterSecret) || masterSecret.length !== 32) {
      throw new Error('masterSecret must be a 32-byte Buffer')
    }
    this.pipeline = pipeline
    this.masterSecret = masterSecret
    this.refreshAuth = refreshAuth
    this.host = host
    this.port = port
    this.revocation = revocation
    this.httpFallback = httpFallback
    this.chunks = new ChunkBuffers()
    this.hsLimit = new MinuteRateLimiter(120)
    this.wsLimit = new MinuteRateLimiter(60)
    this.refreshLimit = new MinuteRateLimiter(120)
    this._http = null
    this._wss = new WebSocketServer({
      noServer: true,
      perMessageDeflate: false,
      maxPayload: 16 * 1024 * 1024,
    })
    this._maintTimer = null
  }

  tokenRevoked(token) {
    if (!this.revocation) return false
    return this.revocation.isRevoked(token.created_at)
  }

  async #onHandshake(req, res) {
    const ip = clientIp(req)
    if (!this.hsLimit.allow(ip)) {
      res.writeHead(429)
      res.end()
      return
    }
    let body
    try {
      body = await readBody(req, 32)
    } catch {
      res.writeHead(400)
      res.end()
      return
    }
    if (body.length !== 32) {
      res.writeHead(400)
      res.end('expected 32 bytes')
      return
    }
    const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
    const persistent = ['1', 'true', 'yes'].includes(
      (u.searchParams.get('persistent') || 'false').toLowerCase(),
    )
    let aesKey
    let serverPub
    try {
      ;({ aesKey, serverPublicKey: serverPub } = await crypto.handshake(body))
    } catch {
      res.writeHead(400)
      res.end('handshake failed')
      return
    }
    const token = {
      key: Buffer.from(aesKey),
      created_at: nowUnix(),
      persistent,
      user_id: null,
    }
    let cookieVal
    try {
      cookieVal = await crypto.encryptSessionToken(token, this.masterSecret)
    } catch {
      res.writeHead(500)
      res.end('token error')
      return
    }
    res.writeHead(200, {
      'Set-Cookie': cookieHeader(cookieVal, persistent),
      'Content-Type': 'application/octet-stream',
    })
    res.end(Buffer.from(serverPub))
  }

  async #onRefresh(req, res) {
    const ip = clientIp(req)
    if (!this.refreshLimit.allow(ip)) {
      res.writeHead(429)
      res.end()
      return
    }
    if (!this.refreshAuth) {
      res.writeHead(503)
      res.end('POST /r requires a RefreshAuthenticator — none configured')
      return
    }
    const raw = extractSessionCookie(req.headers.cookie)
    if (!raw) {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    let token
    try {
      token = await crypto.decryptSessionToken(raw, this.masterSecret)
    } catch {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    if (this.tokenRevoked(token)) {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    let body
    try {
      body = await readBody(req, MESSAGE_SIZE)
    } catch {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    if (body.length !== MESSAGE_SIZE) {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    let payload
    try {
      ;({ payload } = await crypto.decrypt(body, token.key))
    } catch {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    const clsend = unpackClsend(payload)
    if (!clsend) {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    if (clsend.h !== expectedClsendHash(clsend.w, clsend.s)) {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    const appTok = extractAuthAppToken(clsend.a)
    if (!appTok) {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    let userId
    try {
      userId = await this.refreshAuth.authenticateAppToken(appTok)
    } catch {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    const newToken = {
      ...token,
      user_id: userId,
    }
    let cookieVal
    try {
      cookieVal = await crypto.encryptSessionToken(newToken, this.masterSecret)
    } catch {
      res.writeHead(401, { 'Content-Type': 'application/octet-stream' })
      res.end(crypto.noise())
      return
    }
    res.writeHead(200, {
      'Set-Cookie': cookieHeader(cookieVal, newToken.persistent),
    })
    res.end()
  }

  #onHttp(req, res) {
    const finish = () => {
      const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
      if (req.method === 'POST' && u.pathname === '/h') {
        this.#onHandshake(req, res).catch((e) => {
          res.writeHead(500)
          res.end(String(e))
        })
        return
      }
      if (req.method === 'POST' && u.pathname === '/r') {
        this.#onRefresh(req, res).catch((e) => {
          res.writeHead(500)
          res.end(String(e))
        })
        return
      }
      res.writeHead(404)
      res.end()
    }

    if (this.httpFallback) {
      Promise.resolve(this.httpFallback(req, res))
        .then((handled) => {
          if (!handled) finish()
        })
        .catch((e) => {
          if (!res.headersSent) {
            res.writeHead(500)
            res.end(String(e))
          }
        })
      return
    }
    finish()
  }

  async #wsLoop(ws, token) {
    const key = token.key
    const sessionFp = key.subarray(0, 8).toString('hex')
    const userId = token.user_id

    // Buffered queue: one-shot nextFrame() drops frames that arrive while the loop
    // is between listeners (e.g. fast multi-chunk CLsend from the client).
    const queue = []
    const waiters = []
    let fatal = null

    const deliver = (buf) => {
      if (waiters.length > 0) {
        const w = waiters.shift()
        clearTimeout(w.t)
        w.resolve(buf)
      } else {
        queue.push(buf)
      }
    }

    const onMsg = (data, isBinary) => {
      if (!isBinary || fatal) return
      deliver(Buffer.isBuffer(data) ? data : Buffer.from(data))
    }
    const flushWaiters = (err) => {
      fatal = fatal ?? err
      while (waiters.length > 0) {
        const w = waiters.shift()
        clearTimeout(w.t)
        w.reject(fatal)
      }
    }
    const onClose = () => flushWaiters(new Error('closed'))
    const onErr = () => flushWaiters(new Error('ws error'))
    ws.on('message', onMsg)
    ws.on('close', onClose)
    ws.on('error', onErr)

    const nextFrame = () => {
      if (fatal) return Promise.reject(fatal)
      if (queue.length > 0) return Promise.resolve(queue.shift())
      return new Promise((resolve, reject) => {
        const w = {
          resolve,
          reject,
          t: setTimeout(() => {
            const i = waiters.indexOf(w)
            if (i >= 0) waiters.splice(i, 1)
            reject(new Error('timeout'))
          }, HEARTBEAT_TIMEOUT_SECS * 1000),
        }
        waiters.push(w)
      })
    }

    for (;;) {
      let raw
      try {
        raw = await nextFrame()
      } catch {
        break
      }

      if (this.tokenRevoked(token)) break

      if (raw.length !== MESSAGE_SIZE) {
        ws.send(crypto.noise())
        continue
      }
      let requestId
      let payload
      try {
        ;({ requestId, payload } = await crypto.decrypt(raw, key))
      } catch {
        ws.send(crypto.noise())
        continue
      }

      const beat = tryBeat(payload)
      if (beat) {
        try {
          const enc = encode({ beat: true, w: beat.w })
          const frame = await crypto.encrypt(enc, key, requestId)
          ws.send(frame)
        } catch {
          /* ignore */
        }
        continue
      }

      const assemblyKey = `${sessionFp}:${requestId.toString('hex')}`
      let clsendBytes
      const ch = tryChunk(payload)
      if (ch) {
        let full
        try {
          full = this.chunks.push(assemblyKey, ch)
        } catch {
          ws.send(crypto.noise())
          continue
        }
        if (full == null) continue
        clsendBytes = full
      } else {
        clsendBytes = payload
      }

      const clsend = unpackClsend(clsendBytes)
      if (!clsend) {
        ws.send(crypto.noise())
        continue
      }
      if (clsend.h !== expectedClsendHash(clsend.w, clsend.s)) {
        ws.send(crypto.noise())
        continue
      }

      const substate = clsend.s
      const newHash =
        substate != null ? computeHash(substate) : initialHash(clsend.w)

      let render
      try {
        render = await callPipeline(
          this.pipeline,
          clsend.a,
          sessionFp,
          clsend.w,
          userId,
        )
      } catch (e) {
        console.error(e)
        continue
      }

      const pack = { h: newHash, r: render, w: clsend.w }
      if (substate != null) pack.s = substate
      let frames
      try {
        const encoded = encode(pack)
        frames = await crypto.encryptSvsendChunked(encoded, key, requestId)
      } catch (e) {
        console.error(e)
        continue
      }
      try {
        for (const frame of frames) {
          if (ws.readyState !== WebSocket.OPEN) break
          await new Promise((resolve, reject) => {
            ws.send(frame, (err) => (err ? reject(err) : resolve()))
          })
        }
      } catch (e) {
        console.error('ws send SVsend failed', e)
        break
      }
    }
    ws.off('message', onMsg)
    ws.off('close', onClose)
    ws.off('error', onErr)
    while (waiters.length > 0) {
      const w = waiters.shift()
      clearTimeout(w.t)
      w.reject(new Error('closed'))
    }
    try {
      ws.close()
    } catch {
      /* ignore */
    }
  }

  listen(port) {
    const p = port ?? this.port
    this._http = http.createServer((req, res) => this.#onHttp(req, res))
    this._http.on('upgrade', async (req, socket, head) => {
      const path = new URL(req.url, 'http://x').pathname
      if (path !== '/w') {
        socket.destroy()
        return
      }
      const ip = clientIp(req)
      if (!this.wsLimit.allow(ip)) {
        socket.write('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n')
        socket.destroy()
        return
      }
      const raw = extractSessionCookie(req.headers.cookie)
      if (!raw) {
        write401Noise(socket)
        return
      }
      let token
      try {
        token = await crypto.decryptSessionToken(raw, this.masterSecret)
      } catch {
        write401Noise(socket)
        return
      }
      if (this.tokenRevoked(token)) {
        write401Noise(socket)
        return
      }
      this._wss.handleUpgrade(req, socket, head, (ws) => {
        this.#wsLoop(ws, token).catch(() => {
          try {
            ws.close()
          } catch {
            /* ignore */
          }
        })
      })
    })
    this._maintTimer = setInterval(() => {
      if (this.revocation?.reload) this.revocation.reload()
      this.hsLimit.purgeStale()
      this.wsLimit.purgeStale()
      this.refreshLimit.purgeStale()
      this.chunks.purgeStale(120)
    }, 60_000)
    this._http.listen(p, this.host, () => {
      console.log(`SIRA Node listening on http://${this.host}:${p}`)
    })
    return this._http
  }
}

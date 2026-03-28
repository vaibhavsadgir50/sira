import { describe, expect, it } from 'vitest'

import {
  decrypt,
  encrypt,
  encryptSessionToken,
  decryptSessionToken,
  newRequestId,
  noise,
} from '../src/crypto.js'
import { MESSAGE_SIZE } from '../src/types.js'

describe('roundtrip', () => {
  it('encrypt → decrypt wire', async () => {
    const key = Buffer.alloc(32, 42)
    const payload = Buffer.from('hello sst')
    const rid = newRequestId()
    const enc = await encrypt(payload, key, rid)
    expect(enc.length).toBe(MESSAGE_SIZE)
    const { requestId, payload: pt } = await decrypt(enc, key)
    expect(requestId.equals(rid)).toBe(true)
    expect(pt.equals(payload)).toBe(true)
  })

  it('wrong key fails decrypt', async () => {
    const key = Buffer.alloc(32, 42)
    const bad = Buffer.alloc(32, 99)
    const rid = newRequestId()
    const enc = await encrypt(Buffer.from('x'), key, rid)
    await expect(decrypt(enc, bad)).rejects.toThrow()
  })

  it('noise is 1024 bytes', () => {
    expect(noise().length).toBe(MESSAGE_SIZE)
  })

  it('session token cookie roundtrip', async () => {
    const master = Buffer.alloc(32, 7)
    const token = {
      key: Buffer.alloc(32, 3),
      created_at: Math.floor(Date.now() / 1000),
      persistent: false,
      user_id: null,
    }
    const s = await encryptSessionToken(token, master)
    const got = await decryptSessionToken(s, master)
    expect(got.key.equals(token.key)).toBe(true)
    expect(got.created_at).toBe(token.created_at)
    expect(got.persistent).toBe(false)
    expect(got.user_id).toBeNull()
  })

  it('session token wrong master fails', async () => {
    const masterA = Buffer.alloc(32, 1)
    const masterB = Buffer.alloc(32, 2)
    const token = {
      key: Buffer.alloc(32, 2),
      created_at: 1,
      persistent: true,
      user_id: null,
    }
    const s = await encryptSessionToken(token, masterA)
    await expect(decryptSessionToken(s, masterB)).rejects.toThrow()
  })
})

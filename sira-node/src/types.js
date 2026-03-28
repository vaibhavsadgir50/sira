/** SIRA protocol constants (match sira Rust types.rs). */

import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils'

export const MESSAGE_SIZE = 1024
export const IV_SIZE = 12
export const ID_SIZE = 16
export const CIPHERTEXT_SIZE = MESSAGE_SIZE - IV_SIZE
export const PAYLOAD_SIZE = CIPHERTEXT_SIZE - 16
export const DATA_SIZE = PAYLOAD_SIZE - ID_SIZE
export const MAX_ASSEMBLED = 8 * 1024 * 1024
export const MAX_CHUNK_COUNT = 16384
export const MAX_CHUNK_DATA = DATA_SIZE - 64

export const HKDF_INFO = new TextEncoder().encode('sst-aes-gcm-v1')
export const SESSION_TOKEN_HKDF_INFO = new TextEncoder().encode('sst-session-token-v1')

export const HEARTBEAT_INTERVAL = 30
export const HEARTBEAT_TIMEOUT = 60
export const COOKIE_MAX_AGE = 86400
export const COOKIE_MAX_AGE_PERSISTENT = 604800

export const HEARTBEAT_INTERVAL_SECS = HEARTBEAT_INTERVAL
export const HEARTBEAT_TIMEOUT_SECS = HEARTBEAT_TIMEOUT
export const COOKIE_MAX_AGE_SECS = COOKIE_MAX_AGE
export const COOKIE_MAX_AGE_PERSISTENT_SECS = COOKIE_MAX_AGE_PERSISTENT
export const MAX_ASSEMBLED_PAYLOAD = MAX_ASSEMBLED

export function nowUnix() {
  return Math.floor(Date.now() / 1000)
}

export function computeHash(substateBytes) {
  return bytesToHex(sha256(substateBytes))
}

export function initialHash(windowId) {
  return bytesToHex(sha256(concatBytes(utf8ToBytes('sst-initial-'), utf8ToBytes(windowId))))
}

export function expectedClsendHash(windowId, substate) {
  if (substate != null) return computeHash(substate)
  return initialHash(windowId)
}

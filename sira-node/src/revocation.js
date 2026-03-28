import fs from 'node:fs'
import path from 'node:path'

/** SIRA_REVOCATION_STORE — same semantics as sira Rust config.rs */
export class RevocationState {
  constructor(filePath) {
    this.path = path.resolve(filePath)
    this._cutoff = 0
    this.reload()
  }

  static fromEnv() {
    const p = process.env.SIRA_REVOCATION_STORE?.trim()
    if (!p) return null
    return new RevocationState(p)
  }

  reload() {
    this._cutoff = readRevocationCutoff(this.path)
  }

  isRevoked(createdAt) {
    const c = this._cutoff
    return c > 0 && createdAt <= c
  }
}

function readRevocationCutoff(filePath) {
  if (!fs.existsSync(filePath)) return 0
  const s = fs.readFileSync(filePath, 'utf8')
  let m = 0
  for (const line of s.split(/\r?\n/)) {
    const t = line.trim()
    if (!t || t.startsWith('#')) continue
    const v = parseInt(t, 10)
    if (Number.isFinite(v)) m = Math.max(m, v)
  }
  return m
}

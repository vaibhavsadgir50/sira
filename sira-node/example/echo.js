/**
 * Protocol smoke test: echoes the decoded action as JSON.
 * INTENTIONAL — not a dumb-terminal / IP-hiding app pattern.
 */
import { SiraServer } from '../src/index.js'

const secret = process.env.SIRA_MASTER_SECRET?.trim()
if (!secret || secret.length !== 64) {
  console.error('Set SIRA_MASTER_SECRET to 64 hex characters')
  process.exit(1)
}

let port = 3000
const pi = process.argv.indexOf('--port')
if (pi >= 0 && process.argv[pi + 1]) port = parseInt(process.argv[pi + 1], 10)

const server = new SiraServer({
  masterSecret: Buffer.from(secret, 'hex'),
  pipeline: async (action, { sessionId, windowId, userId }) => {
    const n = Math.min(16, sessionId.length)
    return {
      echo: action,
      session: sessionId.slice(0, n),
      window: windowId,
      user_id: userId ?? null,
      message: 'SIRA is working',
    }
  },
})

server.listen(port)
console.log(`SIRA Node server running on http://localhost:${port}`)

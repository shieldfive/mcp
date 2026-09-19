// Browser authorization: the connection string arrives without anyone copying it.
//
// This process listens on a random port on 127.0.0.1 and opens
//
//   https://shieldfive.com/files/settings/agents?connect=<state>&port=<port>&client=<hint>
//
// The owner signs in, unlocks, chooses the scope and clicks Authorize. The page
// creates the grant in the browser as it always does, then submits a form to
// http://127.0.0.1:<port>/callback carrying the state and the connection
// string. The page builds that address itself from the port; it accepts no
// callback URL, so a link someone else crafted can only deliver to the machine
// the browser runs on.
//
// What this listener accepts, and nothing else: one POST to /callback, Host
// exactly 127.0.0.1:<port> (defeats DNS rebinding), no Origin other than
// ShieldFive's (a POST from any other site is refused before its body is read),
// and a state that matches in constant time. The first valid delivery closes
// the listener.

import { randomBytes, timingSafeEqual } from 'node:crypto'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

import { parseConnectionString } from '@shieldfive/crypto/vault'

const MAX_BODY = 16 * 1024
export const CONNECT_TIMEOUT_MS = 10 * 60 * 1000

export const CLIENT_HINTS = ['claude-desktop', 'claude-code', 'cursor', 'chatgpt', 'local', 'other']

/** Map an MCP clientInfo.name to the hint the settings page understands. */
export function clientHintFor(name) {
  const n = String(name ?? '').toLowerCase()
  if (n.includes('claude-code') || n.includes('claude code')) return 'claude-code'
  if (n.includes('claude')) return 'claude-desktop'
  if (n.includes('cursor')) return 'cursor'
  if (n.includes('chatgpt') || n.includes('openai')) return 'chatgpt'
  return 'other'
}

/** Open a URL in the default browser without a shell. Resolves false on failure. */
export function openBrowser(url, platform = process.platform, spawnImpl = spawn) {
  const [cmd, args] =
    platform === 'darwin'
      ? ['open', [url]]
      : platform === 'win32'
        ? ['rundll32', ['url.dll,FileProtocolHandler', url]]
        : ['xdg-open', [url]]
  return new Promise((resolve) => {
    try {
      const child = spawnImpl(cmd, args, { stdio: 'ignore', detached: true })
      child.on('error', () => resolve(false))
      child.on('spawn', () => {
        child.unref()
        resolve(true)
      })
    } catch {
      resolve(false)
    }
  })
}

const PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

function page(title, body) {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    `<title>${title}</title><style>` +
    'body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;' +
    'background:#f7f7f8;color:#111}main{max-width:32rem;padding:2rem}h1{font-size:1.4rem;margin:0 0 .5rem}' +
    '@media (prefers-color-scheme:dark){body{background:#111;color:#eee}}' +
    `</style></head><body><main><h1>${title}</h1><p>${body}</p></main></body></html>`
  )
}

function send(res, status, title, body, onSent) {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': PAGE_CSP,
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  })
  res.end(page(title, body), onSent)
}

function sameSecret(a, b) {
  const x = Buffer.from(String(a))
  const y = Buffer.from(String(b))
  return x.length === y.length && timingSafeEqual(x, y)
}

export class ConnectError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'ConnectError'
    this.code = code
  }
}

/**
 * Start listening and build the authorization URL. `result` resolves with the
 * raw connection string, or rejects with a ConnectError (cancelled, timeout).
 */
export async function startConnectFlow({
  baseUrl,
  client = 'other',
  timeoutMs = CONNECT_TIMEOUT_MS,
  onDelivered,
} = {}) {
  const origin = new URL(baseUrl).origin
  const state = randomBytes(32).toString('base64url')
  let settle
  const result = new Promise((resolve, reject) => {
    settle = { resolve, reject }
  })
  // A flow can end (timeout) with nobody awaiting it; that is not a crash.
  result.catch(() => {})
  let done = false
  let port = 0

  const server = createServer((req, res) => {
    if (req.headers.host !== `127.0.0.1:${port}`) {
      send(res, 400, 'Not here', 'This address only accepts ShieldFive connections.')
      return
    }
    const path = new URL(req.url ?? '/', `http://127.0.0.1:${port}`).pathname
    if (path !== '/callback' || req.method !== 'POST') {
      send(res, 404, 'Not found', 'Return to your assistant.')
      return
    }
    // Browsers send ShieldFive's origin here; a few send "null" for a
    // navigation to plain http. Any OTHER site's origin is refused outright;
    // the 256-bit state is what actually authenticates the delivery.
    const from = req.headers.origin
    if (from !== undefined && from !== origin && from !== 'null') {
      send(res, 403, 'Refused', 'This connection did not come from ShieldFive.')
      return
    }
    if (done) {
      send(res, 409, 'Already connected', 'This request has already been used. Return to your assistant.')
      return
    }
    let size = 0
    const chunks = []
    req.on('data', (c) => {
      size += c.length
      if (size > MAX_BODY) req.destroy()
      else chunks.push(c)
    })
    req.on('end', () => {
      const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
      if (!sameSecret(form.get('state') ?? '', state)) {
        send(res, 403, 'Refused', 'This connection was meant for a different request.')
        return
      }
      if (form.get('error')) {
        done = true
        send(res, 200, 'Request denied', 'No connection was created. You can close this tab.', finish)
        settle.reject(new ConnectError('cancelled', 'The owner denied the connection request.'))
        return
      }
      const raw = (form.get('connection_string') ?? '').trim()
      try {
        parseConnectionString(raw)
      } catch {
        send(res, 400, 'Something went wrong', 'The connection could not be read. Try connecting again.')
        return
      }
      done = true
      send(
        res,
        200,
        'Connected',
        'Your assistant can now reach the folders you chose. You can close this tab and go back to it. ' +
          'Revoke the connection any time in ShieldFive → Settings → AI assistants.',
        finish,
      )
      onDelivered?.()
      settle.resolve(raw)
    })
  })
  server.headersTimeout = 10_000
  server.requestTimeout = 15_000

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  port = server.address().port

  const timer = setTimeout(() => {
    if (done) return
    done = true
    finish()
    settle.reject(new ConnectError('timeout', 'Nobody authorized the connection in time.'))
  }, timeoutMs)
  timer.unref?.()

  function finish() {
    clearTimeout(timer)
    server.close()
    server.closeAllConnections?.()
  }

  const url = new URL('/files/settings/agents', origin)
  url.searchParams.set('connect', state)
  url.searchParams.set('port', String(port))
  url.searchParams.set('client', CLIENT_HINTS.includes(client) ? client : 'other')

  return {
    url: url.toString(),
    port,
    result,
    cancel() {
      if (done) return
      done = true
      finish()
      settle.reject(new ConnectError('cancelled', 'Connection request cancelled.'))
    },
  }
}

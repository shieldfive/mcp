// The browser hand-off: what the loopback listener accepts, and what it refuses.
//
// The listener is the one inbound socket this package opens, so the refusals
// matter more than the happy path: a POST from another site, with another
// state, to another Host, or after the first delivery, must not hand anyone a
// connection string.

import assert from 'node:assert/strict'
import { request } from 'node:http'
import { describe, it } from 'node:test'

import {
  ConnectError,
  clientHintFor,
  openBrowser,
  startConnectFlow,
} from '../src/vault/connect.mjs'
import { loadGrantCredential } from '../src/vault/credential.mjs'
import { CONNECT_TOOL } from '../src/server.mjs'

const BASE = 'https://shieldfive.com'
// Shape only: parseConnectionString must accept it, and nothing here decrypts.
const GRANT =
  'sf-grant-v1:11111111-1111-4111-8111-111111111111.' +
  `${Buffer.alloc(32, 7).toString('base64url')}.${Buffer.alloc(32, 9).toString('base64url')}.${'a'.repeat(64)}`

function post(port, body, { origin = BASE, host, path = '/callback', method = 'POST' } = {}) {
  return new Promise((resolve, reject) => {
    const data = typeof body === 'string' ? body : new URLSearchParams(body).toString()
    const req = request(
      {
        host: '127.0.0.1',
        port,
        path,
        method,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(data),
          ...(origin === null ? {} : { origin }),
          ...(host ? { host } : {}),
        },
      },
      (res) => {
        let text = ''
        res.on('data', (c) => (text += c))
        res.on('end', () => resolve({ status: res.statusCode, text }))
      },
    )
    req.on('error', reject)
    req.end(data)
  })
}

const started = (opts) => startConnectFlow({ baseUrl: BASE, timeoutMs: 5_000, ...opts })

describe('the authorization URL', () => {
  it('points at the settings page with a 256-bit state and the loopback port', async () => {
    const flow = await started({ client: 'cursor' })
    try {
      const url = new URL(flow.url)
      assert.equal(url.origin, BASE)
      assert.equal(url.pathname, '/files/settings/agents')
      assert.match(url.searchParams.get('connect'), /^[A-Za-z0-9_-]{43}$/)
      assert.equal(url.searchParams.get('port'), String(flow.port))
      assert.equal(url.searchParams.get('client'), 'cursor')
      assert.ok(flow.port > 1024)
    } finally {
      flow.cancel()
    }
  })

  it('never passes an unknown client hint through', async () => {
    const flow = await started({ client: '../evil' })
    try {
      assert.equal(new URL(flow.url).searchParams.get('client'), 'other')
    } finally {
      flow.cancel()
    }
  })
})

describe('the loopback listener', () => {
  it('accepts one delivery with the right state and origin, then stops listening', async () => {
    const flow = await started()
    const state = new URL(flow.url).searchParams.get('connect')
    const res = await post(flow.port, { state, connection_string: GRANT })
    assert.equal(res.status, 200)
    assert.match(res.text, /Connected/)
    assert.equal(await flow.result, GRANT)
    // The listener is gone: the exact error depends on the platform (refused,
    // reset, hang up), so what is asserted is that nothing is accepted twice.
    const again = await post(flow.port, { state, connection_string: GRANT }).catch((err) => ({
      status: `closed: ${err.code ?? err.message}`,
    }))
    assert.notEqual(again.status, 200)
  })

  it('refuses a post from any other site', async () => {
    const flow = await started()
    const state = new URL(flow.url).searchParams.get('connect')
    const res = await post(flow.port, { state, connection_string: GRANT }, { origin: 'https://evil.example' })
    assert.equal(res.status, 403)
    const after = await Promise.race([flow.result, Promise.resolve('still waiting')])
    assert.equal(after, 'still waiting')
    flow.cancel()
  })

  it('refuses a post carrying the wrong state', async () => {
    const flow = await started()
    const res = await post(flow.port, { state: 'x'.repeat(43), connection_string: GRANT })
    assert.equal(res.status, 403)
    flow.cancel()
  })

  it('refuses a request whose Host is not the loopback address (DNS rebinding)', async () => {
    const flow = await started()
    const state = new URL(flow.url).searchParams.get('connect')
    const res = await post(flow.port, { state, connection_string: GRANT }, { host: 'attacker.example' })
    assert.equal(res.status, 400)
    flow.cancel()
  })

  it('refuses any other path or method', async () => {
    const flow = await started()
    const state = new URL(flow.url).searchParams.get('connect')
    assert.equal((await post(flow.port, { state }, { path: '/' })).status, 404)
    assert.equal((await post(flow.port, { state }, { method: 'GET' })).status, 404)
    flow.cancel()
  })

  it('refuses a value that is not a connection string, and keeps waiting', async () => {
    const flow = await started()
    const state = new URL(flow.url).searchParams.get('connect')
    const res = await post(flow.port, { state, connection_string: 'not-a-grant' })
    assert.equal(res.status, 400)
    const after = await Promise.race([flow.result, Promise.resolve('still waiting')])
    assert.equal(after, 'still waiting')
    flow.cancel()
  })

  it('survives an oversized body', async () => {
    const flow = await started()
    await post(flow.port, 'connection_string=' + 'a'.repeat(64 * 1024)).catch(() => {})
    const state = new URL(flow.url).searchParams.get('connect')
    assert.equal((await post(flow.port, { state, connection_string: GRANT })).status, 200)
    assert.equal(await flow.result, GRANT)
  })

  it('reports a denial as a cancellation', async () => {
    const flow = await started()
    const state = new URL(flow.url).searchParams.get('connect')
    assert.equal((await post(flow.port, { state, error: 'cancelled' })).status, 200)
    await assert.rejects(flow.result, (err) => err instanceof ConnectError && err.code === 'cancelled')
  })

  it('gives up when nobody authorizes', async () => {
    const flow = await started({ timeoutMs: 50 })
    await assert.rejects(flow.result, (err) => err.code === 'timeout')
  })
})

describe('opening the browser', () => {
  it('runs one fixed command per platform, with the URL as an argument and no shell', async () => {
    const calls = []
    const spawnStub = (cmd, args, opts) => {
      calls.push({ cmd, args, opts })
      return {
        on(event, fn) {
          if (event === 'spawn') queueMicrotask(fn)
        },
        unref() {},
      }
    }
    const url = 'https://shieldfive.com/files/settings/agents?connect=x&port=1'
    for (const platform of ['darwin', 'win32', 'linux']) {
      assert.equal(await openBrowser(url, platform, spawnStub), true)
    }
    assert.deepEqual(
      calls.map((c) => c.cmd),
      ['open', 'rundll32', 'xdg-open'],
    )
    for (const call of calls) {
      assert.ok(call.args.includes(url), 'the URL must be an argument, never interpolated')
      assert.equal(call.opts.shell, undefined)
    }
  })

  it('reports failure instead of throwing when no browser can be launched', async () => {
    const spawnStub = () => ({
      on(event, fn) {
        if (event === 'error') queueMicrotask(() => fn(new Error('ENOENT')))
      },
      unref() {},
    })
    assert.equal(await openBrowser('https://shieldfive.com', 'linux', spawnStub), false)
  })
})

describe('client hints', () => {
  it('maps the clients people actually use', () => {
    assert.equal(clientHintFor('claude-ai'), 'claude-desktop')
    assert.equal(clientHintFor('Claude Code'), 'claude-code')
    assert.equal(clientHintFor('claude-code'), 'claude-code')
    assert.equal(clientHintFor('cursor-vscode'), 'cursor')
    assert.equal(clientHintFor('ChatGPT'), 'chatgpt')
    assert.equal(clientHintFor('something else'), 'other')
    assert.equal(clientHintFor(undefined), 'other')
  })
})

describe('SHIELDFIVE_GRANT=none', () => {
  it('means no connection, and does not read the keychain', async () => {
    let read = 0
    const store = async () => {
      read += 1
      return GRANT
    }
    assert.equal(await loadGrantCredential({ SHIELDFIVE_GRANT: 'none' }, store), null)
    assert.equal(read, 0)
    assert.ok(await loadGrantCredential({}, store))
    assert.equal(read, 1)
  })
})

describe('the vault_connect tool', () => {
  const ctxFor = (root) => ({ ...root, root })

  function fakeRoot(overrides = {}) {
    const root = {
      apiBaseUrl: BASE,
      vault: null,
      connectWaitMs: 100,
      clientName: () => 'claude-ai',
      openBrowser: async () => true,
      writeKeychain: async () => {},
      makeVault: async (credential) => ({
        credential,
        api: { grant: async () => ({ grant: { id: '11111111-2222-4333-8444-555555555555', scopes: ['read'], scopeAll: true, scopeFolderIds: [], expiresAt: '2027-01-01T00:00:00Z' } }) },
        names: { close: async () => {} },
      }),
      ...overrides,
    }
    return root
  }

  it('reports that it is waiting when the user has not authorized yet, and keeps the request open', async () => {
    const root = fakeRoot()
    const first = await CONNECT_TOOL.handler(ctxFor(root), {})
    assert.match(first.content[0].text, /Authorize/)
    assert.ok(root.connectFlow, 'the listener must stay up between calls')
    const port = root.connectFlow.port
    const state = new URL(root.connectFlow.url).searchParams.get('connect')
    await post(port, { state, connection_string: GRANT })
    const second = await CONNECT_TOOL.handler(ctxFor(root), {})
    assert.match(second.content[0].text, /Connected/)
    assert.equal(root.connectFlow, null)
    assert.ok(root.vault, 'the vault tools need the new connection in place')
  })

  it('stores the connection and announces the tools once authorized', async () => {
    let stored = null
    let announced = 0
    const root = fakeRoot({
      // Long enough that the wait is ended by the delivery, not by the clock.
      connectWaitMs: 5_000,
      writeKeychain: async (raw) => {
        stored = raw
      },
      onConnected: () => (announced += 1),
    })
    const call = CONNECT_TOOL.handler(ctxFor(root), {})
    await new Promise((r) => setTimeout(r, 20))
    const state = new URL(root.connectFlow.url).searchParams.get('connect')
    await post(root.connectFlow.port, { state, connection_string: GRANT })
    const res = await call
    assert.equal(stored, GRANT)
    assert.equal(announced, 1)
    assert.match(res.content[0].text, /keychain/)
  })

  it('says so when the user denies the request', async () => {
    const root = fakeRoot({ connectWaitMs: 2_000 })
    const call = CONNECT_TOOL.handler(ctxFor(root), {}).then(
      (ok) => ({ ok }),
      (err) => ({ err }),
    )
    await new Promise((r) => setTimeout(r, 20))
    const state = new URL(root.connectFlow.url).searchParams.get('connect')
    await post(root.connectFlow.port, { state, error: 'cancelled' })
    assert.equal((await call).err?.code, 'cancelled')
    assert.equal(root.vault, null)
  })

  it('does not replace a working connection unless asked', async () => {
    const root = fakeRoot({
      vault: {
        api: {
          grant: async () => ({ grant: { id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', scopes: ['read', 'organize'], scopeAll: false, scopeFolderIds: ['x'], expiresAt: '2027-01-01T00:00:00Z' } }),
        },
      },
    })
    const res = await CONNECT_TOOL.handler(ctxFor(root), {})
    assert.match(res.content[0].text, /Already connected/)
    assert.equal(root.connectFlow, undefined)
  })

  it('connects again when the stored connection was revoked', async () => {
    const revoked = { api: { grant: async () => { const e = new Error('gone'); e.code = 'grant_invalid'; throw e } } }
    const root = fakeRoot({ vault: revoked })
    const res = await CONNECT_TOOL.handler(ctxFor(root), {})
    assert.match(res.content[0].text, /Authorize/)
    assert.ok(root.connectFlow)
    root.connectFlow.cancel()
  })
})

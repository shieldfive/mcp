// Where a connection is kept between restarts.
//
// The Claude Desktop bundle used to ship without a keychain binary for macOS
// and Windows, so the write was swallowed and every restart minted a new 7-day
// grant until ShieldFive refused new ones ("too many live grants"). Whatever
// the cause, a machine without a usable keychain must still keep the one
// connection it was given, in a file only this user can read, and say where.

import assert from 'node:assert/strict'
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'

import {
  connectionFilePath,
  deleteConnectionFile,
  loadGrantCredential,
  readStoredConnection,
  storeConnection,
} from '../src/vault/credential.mjs'
import { CONNECT_TOOL } from '../src/server.mjs'

const GRANT =
  'sf-grant-v1:11111111-1111-4111-8111-111111111111.' +
  `${Buffer.alloc(32, 7).toString('base64url')}.${Buffer.alloc(32, 9).toString('base64url')}.${'a'.repeat(64)}`

const dirs = []
async function configEnv() {
  const dir = await mkdtemp(join(tmpdir(), 'sf-mcp-cred-'))
  dirs.push(dir)
  return { SHIELDFIVE_MCP_CONFIG_DIR: join(dir, 'shieldfive-mcp') }
}
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true })
})

const noKeychain = async () => {
  throw new Error('Platform secure storage failure')
}
const emptyKeychain = async () => null
// What the server does at start-up, with no keychain on this machine.
const restart = (env) => loadGrantCredential(env, () => readStoredConnection(env, emptyKeychain))

describe('without a usable keychain', () => {
  it('keeps the connection in a file, so a restart reuses it instead of creating a new grant', async () => {
    const env = await configEnv()
    const where = await storeConnection(GRANT, { env, keychain: noKeychain })
    assert.equal(where.store, 'file')
    assert.equal(where.path, connectionFilePath(env))

    const loaded = await restart(env)
    assert.ok(loaded, 'the restarted server must find the stored connection')
    assert.equal(loaded.grantId, '11111111-1111-4111-8111-111111111111')
    assert.match(loaded.source, /^file /)
  })

  it('makes the file readable by this user only', { skip: process.platform === 'win32' }, async () => {
    const env = await configEnv()
    const { path } = await storeConnection(GRANT, { env, keychain: noKeychain })
    assert.equal((await stat(path)).mode & 0o777, 0o600)
    assert.equal((await stat(join(path, '..'))).mode & 0o777, 0o700)
  })

  it('tightens a file that already existed with looser permissions', { skip: process.platform === 'win32' }, async () => {
    const env = await configEnv()
    const path = connectionFilePath(env)
    await storeConnection('placeholder', { env, keychain: noKeychain })
    await writeFile(path, 'old', { mode: 0o644 })
    await storeConnection(GRANT, { env, keychain: noKeychain })
    assert.equal((await stat(path)).mode & 0o777, 0o600)
  })

  it('prefers the keychain, and removes a file left from when there was none', async () => {
    const env = await configEnv()
    await storeConnection(GRANT, { env, keychain: noKeychain })
    let kept = null
    const where = await storeConnection(GRANT, { env, keychain: async (raw) => (kept = raw) })
    assert.equal(where.store, 'keychain')
    assert.equal(kept, GRANT)
    assert.equal(await restart(env), null, 'no plaintext copy may outlive a keychain write')
  })

  it('reads the keychain before the file', async () => {
    const env = await configEnv()
    await storeConnection(GRANT, { env, keychain: noKeychain })
    const other = GRANT.replace('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222')
    const stored = await readStoredConnection(env, async () => other)
    assert.equal(stored.source, 'keychain')
    assert.equal(stored.raw, other)
  })

  it('logout removes the file', async () => {
    const env = await configEnv()
    await storeConnection(GRANT, { env, keychain: noKeychain })
    assert.equal(await deleteConnectionFile(env), true)
    assert.equal(await restart(env), null)
  })
})

describe('vault_connect reports where the connection went', () => {
  async function connectWith(storeConnection) {
    const { startConnectFlow } = await import('../src/vault/connect.mjs')
    const root = {
      apiBaseUrl: 'https://shieldfive.com',
      vault: null,
      connectWaitMs: 5_000,
      clientName: () => 'claude-ai',
      openBrowser: async () => true,
      storeConnection,
      makeVault: async (credential) => ({
        credential,
        api: { grant: async () => ({ grant: { id: '11111111-1111-4111-8111-111111111111', scopes: ['read'], scopeAll: true, scopeFolderIds: [], expiresAt: '2027-01-01T00:00:00Z' } }) },
        names: { close: async () => {} },
      }),
    }
    // Deliver the connection the way the browser does, without a browser.
    const started = await startConnectFlow({ baseUrl: root.apiBaseUrl, client: 'claude-desktop', label: 'test' })
    root.connectFlow = { ...started, opened: true }
    const state = new URL(started.url).searchParams.get('connect')
    const { request } = await import('node:http')
    const body = new URLSearchParams({ state, connection_string: GRANT }).toString()
    await new Promise((resolve, reject) => {
      const req = request(
        { host: '127.0.0.1', port: started.port, path: '/callback', method: 'POST', headers: { origin: root.apiBaseUrl, 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body) } },
        (res) => {
          res.resume()
          res.on('end', resolve)
        },
      )
      req.on('error', reject)
      req.end(body)
    })
    const res = await CONNECT_TOOL.handler({ root, ...root }, {})
    return { root, text: res.content[0].text }
  }

  it('names the file when there is no keychain, and the connection survives a restart', async () => {
    const env = await configEnv()
    const { root, text } = await connectWith((raw) => storeConnection(raw, { env, keychain: noKeychain }))
    assert.ok(root.vault)
    assert.ok(text.includes(connectionFilePath(env)), text)
    assert.match(text, /stays connected after restarts/)
    assert.ok(await restart(env))
  })

  it('tells the user how to keep it when nothing can be stored', async () => {
    const { text } = await connectWith(async () => {
      throw new Error('read-only home')
    })
    assert.match(text, /lasts until the assistant restarts/)
    assert.match(text, /connection string/)
    assert.match(text, /creates a new connection/)
  })
})

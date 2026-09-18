// The security boundary, asserted rather than described.
//
// Since 0.3.0 the server has two halves with different boundaries:
//
//   LOCAL tools touch only the directories passed at startup. They make no
//   network call and import nothing from the vault half, so a server started
//   without a grant behaves exactly as 0.2.0 did.
//
//   VAULT tools talk to one origin (ShieldFive's /api/agent/v1) with one
//   credential: an agent grant the user created, scoped, expiring and
//   revocable server-side. Decryption uses @shieldfive/crypto and happens only
//   in memory; the vault modules cannot write to disk because they do not
//   import the filesystem at all.
//
// What this cannot prove is stated where it matters: it proves what src/
// imports and calls, not what the dependency tree could do. The MCP SDK ships
// HTTP transports for other people's servers; the transport assertion below
// is what shows this one is stdio only.

import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { describe, it } from 'node:test'
import { extname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SRC = fileURLToPath(new URL('../src/', import.meta.url))
const ROOT = fileURLToPath(new URL('../', import.meta.url))

async function sourceFiles(dir = SRC, acc = []) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) await sourceFiles(full, acc)
    else if (extname(entry.name) === '.mjs') acc.push(full)
  }
  return acc
}

/** Source with comments stripped — a comment explaining `fetch` is not a call. */
function executable(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => (line.trim().startsWith('//') ? '' : line))
    .join('\n')
}

/**
 * Every module specifier a file imports.
 *
 * Matching specifiers rather than raw substrings matters: a bare-name check for
 * the `ws` package also matches the word "warnings", which is how a boundary
 * test starts failing for a reason that has nothing to do with the boundary.
 */
function importSpecifiers(code) {
  const found = new Set()
  const patterns = [
    /\bfrom\s+['"]([^'"]+)['"]/g,
    /\bimport\s+['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ]
  for (const re of patterns) for (const m of code.matchAll(re)) found.add(m[1])
  return found
}

const VAULT_FILES = /[\\/](vault[\\/][^\\/]+|tools[\\/]vault)\.mjs$/
const isVault = (file) => VAULT_FILES.test(file)

describe('network access is confined to the vault API client', () => {
  it('imports no networking module anywhere in src/', async () => {
    const forbidden = new Set([
      'node:http', 'node:https', 'node:net', 'node:tls', 'node:dgram', 'node:http2', 'node:dns',
      'http', 'https', 'net', 'tls', 'dgram', 'dns', 'undici', 'node-fetch', 'axios', 'got', 'ws',
    ])
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const spec of importSpecifiers(code)) {
        assert.ok(!forbidden.has(spec), `${file} imports ${spec}`)
      }
    }
  })

  it('calls fetch only in vault/api.mjs, and nothing else opens a connection', async () => {
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      if (!file.endsWith(join('vault', 'api.mjs'))) {
        assert.ok(!/\bfetch\b/.test(code), `${file} references fetch; only vault/api.mjs may`)
      }
      assert.ok(!/\bXMLHttpRequest\b/.test(code), `${file} references XMLHttpRequest`)
      assert.ok(!/\bnew\s+WebSocket\b/.test(code), `${file} opens a WebSocket`)
      assert.ok(!/\bnew\s+EventSource\b/.test(code), `${file} opens an EventSource`)
    }
  })

  it('refuses a non-https API origin other than localhost', async () => {
    const { createVaultApi } = await import('../src/vault/api.mjs')
    const credential = { token: new Uint8Array(32), secret: new Uint8Array(32), grantId: '00000000-0000-4000-8000-000000000000' }
    assert.throws(() => createVaultApi({ credential, baseUrl: 'http://evil.example' }), /https/)
    assert.doesNotThrow(() => createVaultApi({ credential, baseUrl: 'http://localhost:3000' }))
  })

  it('keeps the local tools free of every vault module', async () => {
    for (const file of await sourceFiles()) {
      if (isVault(file) || file.endsWith('server.mjs')) continue
      const code = executable(await readFile(file, 'utf8'))
      for (const spec of importSpecifiers(code)) {
        assert.ok(!/vault/.test(spec), `${file} imports ${spec}; local tools must not reach the vault half`)
        assert.ok(!spec.startsWith('@shieldfive/'), `${file} imports ${spec}`)
      }
    }
  })

  it('uses the stdio transport and no HTTP transport', async () => {
    const server = await readFile(join(SRC, 'server.mjs'), 'utf8')
    assert.ok(server.includes('server/stdio.js'), 'the stdio transport must be the one in use')
    for (const http of ['streamableHttp', 'sse.js', 'server/sse']) {
      assert.ok(!server.includes(http), `server.mjs must not import ${http}`)
    }
  })
})

describe('the only credential is an agent grant', () => {
  it('references no account credential, service key or vault key route', async () => {
    // SF_EMAIL / SF_PASSWORD are what @shieldfive/cli reads: inheriting them
    // would put the master password in this process. The grant is the only
    // credential this server may hold.
    const forbidden = [
      'SF_PASSWORD', 'SF_EMAIL', 'SF_TOTP_CODE', 'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_ANON_KEY',
      'rkWrappedByUk', 'vault-key', 'master', 'recoveryKey',
    ]
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const needle of forbidden) assert.ok(!code.includes(needle), `${file} references ${needle}`)
      if (!file.endsWith(join('vault', 'api.mjs'))) {
        assert.ok(!/authorization|Bearer /i.test(code), `${file} builds an Authorization header; only vault/api.mjs may`)
      }
    }
  })

  it('reads only its own configuration from the environment', async () => {
    const seen = new Set()
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const m of code.matchAll(/(?:process\.)?env\.([A-Z0-9_]+)/g)) seen.add(m[1])
    }
    assert.deepEqual([...seen].sort(), ['SHIELDFIVE_API_URL', 'SHIELDFIVE_GRANT', 'SHIELDFIVE_MCP_ROOTS'])
  })

  it('never spawns a subprocess', async () => {
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const needle of ['child_process', 'execSync', 'spawnSync', 'spawn(', 'exec(']) {
        assert.ok(!code.includes(needle), `${file} references ${needle}`)
      }
    }
  })
})

describe('cryptography comes from @shieldfive/crypto, and plaintext stays in memory', () => {
  it('imports @shieldfive/crypto only in the vault half, and no Supabase client anywhere', async () => {
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      if (!isVault(file)) assert.ok(!code.includes('@shieldfive/crypto'), `${file} imports @shieldfive/crypto`)
      assert.ok(!code.includes('@supabase/'), `${file} imports a Supabase client`)
    }
  })

  it('implements no cipher of its own: node:crypto is used for hashing and randomness only', async () => {
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const keyed of ['createCipheriv', 'createDecipheriv', 'createHmac', 'generateKey', 'subtle', 'pbkdf2', 'scrypt', 'hkdf']) {
        assert.ok(!code.includes(keyed), `${file} uses ${keyed}; primitives belong in @shieldfive/crypto`)
      }
    }
  })

  it('the vault modules cannot write to disk: they import no filesystem module', async () => {
    for (const file of await sourceFiles()) {
      if (!isVault(file)) continue
      const code = executable(await readFile(file, 'utf8'))
      for (const spec of importSpecifiers(code)) {
        assert.ok(!/^(node:)?fs(\/promises)?$/.test(spec), `${file} imports ${spec}; decrypted data must stay in memory`)
      }
    }
  })

  it('declares @shieldfive/crypto and no Supabase package', async () => {
    const pkg = JSON.parse(await readFile(join(ROOT, 'package.json'), 'utf8'))
    const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies }
    assert.ok(deps['@shieldfive/crypto'], '@shieldfive/crypto must be a dependency')
    for (const name of Object.keys(deps)) assert.ok(!name.startsWith('@supabase/'), `${name} must not be a dependency`)
  })
})

describe('the README does not drift from the code', () => {
  it('states the real test count', async () => {
    // The README quotes a number. A quoted number with nothing checking it is a
    // claim that goes stale on the next commit, which is the class of defect
    // this package is otherwise careful about.
    const readme = await readFile(join(ROOT, 'README.md'), 'utf8')
    const claimed = Number(readme.match(/`npm test` runs (\d+) tests/)?.[1])
    assert.ok(Number.isInteger(claimed), 'README must state a test count')

    let actual = 0
    for (const file of await readdir(join(ROOT, 'test'))) {
      if (!file.endsWith('.test.mjs')) continue
      const code = await readFile(join(ROOT, 'test', file), 'utf8')
      actual += [...code.matchAll(/^\s*it\(/gm)].length
    }
    assert.equal(claimed, actual, `README says ${claimed} tests; there are ${actual}`)
  })

  it('lists exactly the tools the server registers', async () => {
    const readme = await readFile(join(ROOT, 'README.md'), 'utf8')
    const server = await readFile(join(SRC, 'server.mjs'), 'utf8')
    const registered = [...server.matchAll(/^\s*name: '([a-z_]+)',$/gm)].map((m) => m[1])
    assert.equal(registered.length, 18)
    for (const name of registered) {
      assert.ok(readme.includes(`\`${name}\``), `README does not document ${name}`)
    }
  })

  it('describes the depth limit the walk applies: the root and 64 levels below it', async () => {
    // walk() skips a directory when depth > maxDepth with the root at depth 0,
    // so maxDepth 64 walks the root and 64 levels beneath it.
    const readme = await readFile(join(ROOT, 'README.md'), 'utf8')
    assert.match(readme, /root and 64 levels of subdirectories/)
    assert.doesNotMatch(readme, /64 directory levels/)
  })
})

describe('release hygiene', () => {
  it('takes the server version from package.json rather than keeping a second copy', async () => {
    const server = executable(await readFile(join(SRC, 'server.mjs'), 'utf8'))
    assert.doesNotMatch(server, /VERSION\s*=\s*['"`]\d/, 'a hardcoded version drifts from package.json')
    const { VERSION } = await import('../src/server.mjs')
    const pkg = JSON.parse(await readFile(join(ROOT, 'package.json'), 'utf8'))
    assert.equal(VERSION, pkg.version)
  })

  it('keeps no scratch scripts in the repository root', async () => {
    const stray = (await readdir(ROOT)).filter((name) => /\.(c|m)?js$/.test(name))
    assert.deepEqual(stray, [], 'scripts at the root of a public repository read as part of it')
  })
})

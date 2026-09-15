// The security boundary, asserted rather than described.
//
// README.md claims this server holds no credential, makes no network call and
// does not import @shieldfive/crypto. A claim in a README is worth what the
// test underneath it is worth, so these are the tests underneath it.
//
// What this can and cannot prove is worth stating. It proves that no file under
// src/ imports a network module, references a ShieldFive credential, or pulls
// in the crypto package. It does NOT prove the dependency tree is network-free:
// @modelcontextprotocol/sdk ships HTTP transports for other people's servers,
// and asserting otherwise would be a false claim. What closes that gap is the
// transport assertion below — src/ imports the stdio transport and nothing else
// — plus the fact that nothing in src/ ever calls into an HTTP one.

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

describe('the server makes no network calls', () => {
  it('imports no networking module anywhere in src/', async () => {
    const forbidden = new Set([
      'node:http',
      'node:https',
      'node:net',
      'node:tls',
      'node:dgram',
      'node:http2',
      'node:dns',
      'http',
      'https',
      'net',
      'tls',
      'dgram',
      'dns',
      'undici',
      'node-fetch',
      'axios',
      'got',
      'ws',
    ])

    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const spec of importSpecifiers(code)) {
        assert.ok(
          !forbidden.has(spec),
          `${file} imports ${spec}; this server must not reach the network`,
        )
      }
    }
  })

  it('never calls fetch, XMLHttpRequest, WebSocket or EventSource', async () => {
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      assert.ok(!/\bfetch\s*\(/.test(code), `${file} calls fetch()`)
      assert.ok(!/\bXMLHttpRequest\b/.test(code), `${file} references XMLHttpRequest`)
      assert.ok(!/\bnew\s+WebSocket\b/.test(code), `${file} opens a WebSocket`)
      assert.ok(!/\bnew\s+EventSource\b/.test(code), `${file} opens an EventSource`)
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

describe('the server holds no ShieldFive credential', () => {
  it('references no credential environment variable', async () => {
    // SF_EMAIL / SF_PASSWORD are what @shieldfive/cli reads. Inheriting them
    // through process.env would put the master password — one Argon2id call
    // from the root key — in this process's address space.
    const forbidden = [
      'SF_PASSWORD',
      'SF_EMAIL',
      'SF_TOTP_CODE',
      'SUPABASE_SERVICE_ROLE_KEY',
      'SUPABASE_ANON_KEY',
      'Authorization',
      'Bearer ',
      'rkWrappedByUk',
      'vault-key',
    ]

    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const needle of forbidden) {
        assert.ok(!code.includes(needle), `${file} references ${needle}`)
      }
    }
  })

  it('reads only its own configuration from the environment', async () => {
    const seen = new Set()
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const m of code.matchAll(/(?:process\.)?env\.([A-Z0-9_]+)/g)) seen.add(m[1])
    }
    assert.deepEqual([...seen].sort(), ['SHIELDFIVE_MCP_ROOTS'])
  })

  it('never spawns a subprocess', async () => {
    // Spawning `sf` would inherit the user's exported credentials whether or
    // not this code names them, which is why the ban is on spawning at all.
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      for (const needle of ['child_process', 'execSync', 'spawnSync', 'spawn(', 'exec(']) {
        assert.ok(!code.includes(needle), `${file} references ${needle}`)
      }
    }
  })
})

describe('the server does not import the crypto package', () => {
  it('has no @shieldfive/crypto import in src/', async () => {
    for (const file of await sourceFiles()) {
      const code = executable(await readFile(file, 'utf8'))
      assert.ok(!code.includes('@shieldfive/crypto'), `${file} imports @shieldfive/crypto`)
      assert.ok(!code.includes('@supabase/'), `${file} imports a Supabase client`)
    }
  })

  it('declares neither as a dependency', async () => {
    const pkg = JSON.parse(await readFile(join(ROOT, 'package.json'), 'utf8'))
    const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies }
    for (const name of Object.keys(deps)) {
      assert.ok(!name.startsWith('@shieldfive/'), `${name} must not be a dependency`)
      assert.ok(!name.startsWith('@supabase/'), `${name} must not be a dependency`)
    }
  })

  it('uses node:crypto only for content hashing', async () => {
    // SHA-256 over file bytes to prove two files are identical is not
    // cryptography in the sense § 1.2 of the handoff bans; it never touches a
    // key. This test pins the usage so that stays true.
    const scan = await readFile(join(SRC, 'scan.mjs'), 'utf8')
    assert.ok(scan.includes("createHash('sha256')"))
    for (const keyed of ['createCipheriv', 'createDecipheriv', 'createHmac', 'generateKey']) {
      assert.ok(!scan.includes(keyed), `scan.mjs uses ${keyed}; hashing only, please`)
    }
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
    assert.equal(registered.length, 9)
    for (const name of registered) {
      assert.ok(readme.includes(`\`${name}\``), `README does not document ${name}`)
    }
  })
})

describe('release hygiene', () => {
  it('keeps no scratch scripts in the repository root', async () => {
    const stray = (await readdir(ROOT)).filter((name) => /\.(c|m)?js$/.test(name))
    assert.deepEqual(stray, [], 'scripts at the root of a public repository read as part of it')
  })
})

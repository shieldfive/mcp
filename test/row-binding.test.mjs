// Row binding (audit 2026-09-30 crypto findings 3 and 4).
//
// Content: v1 and suite 0x03 headers carry the files-row UUID as file_id, and
// the key wraps carry no row AAD. A server that swaps ciphertext + key columns
// between two rows used to produce a clean decrypt of the wrong file. The
// reader now compares the header file_id with the row.
//
// Names: rows with a UUIDv7 id were written with a v6 (row-bound) name from
// the first insert, so a v4 name on such a row was copied from another row.
//
// Writer: uploads used a random header file_id, which mobile (and now web)
// refuse. They now seal both the name and the header to a UUIDv7 row id.

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { after, describe, it } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { parseHeader } from '@shieldfive/crypto'
import { deriveNameKey } from '@shieldfive/crypto/vault'

import { createLocalFileGateway } from '../src/localSource.mjs'
import { createPlanStore } from '../src/plans.mjs'
import { resolveRoots } from '../src/roots.mjs'
import { createServer, createVaultContext } from '../src/server.mjs'
import { createVaultApi } from '../src/vault/api.mjs'
import { loadGrantCredential } from '../src/vault/credential.mjs'
import { createNamePool } from '../src/vault/namePool.mjs'
import { isRowBoundId, newRowBoundId, uuidToBytes } from '../src/vault/rowBinding.mjs'
import { makeTree } from './helpers.mjs'
import { buildVault } from './vaultFixture.mjs'

const names = createNamePool({ size: 2 })
after(() => names.close())

async function connect(vault, tree = null) {
  const credential = await loadGrantCredential({ SHIELDFIVE_GRANT: vault.connectionString }, async () => null)
  const api = createVaultApi({ credential, baseUrl: 'https://shieldfive.test', fetchImpl: vault.fetchImpl })
  const ctx = {
    roots: tree ? await resolveRoots([tree.path('.')]).then((r) => r.roots) : [],
    noRootsMessage: 'no roots',
    now: () => Date.now(),
    plans: createPlanStore(),
    vault: await createVaultContext({}, { credential, api, names }),
  }
  ctx.localFiles = ctx.roots.length ? createLocalFileGateway(ctx) : null
  const server = createServer(ctx)
  const [a, b] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '1.0.0' })
  await Promise.all([server.connect(a), client.connect(b)])
  return async (name, args = {}) => {
    const res = await client.callTool({ name, arguments: args })
    const texts = res.content.map((c) => c.text)
    const jsonBlock = texts.find((t) => t.startsWith('{'))
    return { texts, data: jsonBlock ? JSON.parse(jsonBlock) : null, error: res.isError ? texts[0] : null }
  }
}

/** Swap everything a compromised server controls between two file rows. */
function swapRows(vault, a, b) {
  const fa = vault.files.get(a)
  const fb = vault.files.get(b)
  const cols = ['cskWrapped', 'cskIv', 'pqkFkWrapped', 'pqkFkIv', 'size', 'ciphertextSize']
  for (const c of cols) [fa[c], fb[c]] = [fb[c], fa[c]]
  const blobA = vault.blobs.get(a)
  vault.blobs.set(a, vault.blobs.get(b))
  vault.blobs.set(b, blobA)
}

/** A legacy v4 name envelope (no row AAD), as old clients wrote. */
async function v4Name(name, folderKey) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16))
  const iv = webcrypto.getRandomValues(new Uint8Array(12))
  const raw = await deriveNameKey(folderKey, salt, 'interactive')
  const k = await webcrypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt'])
  const out = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(name)))
  const b64 = (u) => Buffer.from(u).toString('base64')
  return JSON.stringify({
    v: 4, ct: b64(out.slice(0, -16)), iv: b64(iv), tag: b64(out.slice(-16)), salt: b64(salt), kdf: 'interactive',
  })
}

describe('content row binding', () => {
  it('refuses a post-quantum file whose ciphertext and keys were swapped with a sibling', async () => {
    const vault = await buildVault()
    swapRows(vault, vault.ids.taxPdf, vault.ids.notes)
    const call = await connect(vault)
    // notes.txt now carries return-signed.pdf's ciphertext and keys.
    const r = await call('vault_read_file', { file_id: vault.ids.notes })
    assert.ok(r.error, 'swapped file must not open: ' + JSON.stringify(r.texts).slice(0, 600))
    assert.match(r.error, /different file/)
    assert.ok(!r.texts.some((t) => t.includes('signed return')))
  })

  it('refuses a swapped AES-GCM v1 file too', async () => {
    const vault = await buildVault()
    const enc = (t) => new TextEncoder().encode(t)
    const a = await vault.file('a.txt', vault.ids.tax, enc('contents of a'), { version: 2 })
    const b = await vault.file('b.txt', vault.ids.tax, enc('contents of b'), { version: 2 })
    const call = await connect(vault)
    assert.equal((await call('vault_read_file', { file_id: a })).error, null)
    swapRows(vault, a, b)
    const r = await call('vault_read_file', { file_id: a })
    assert.ok(r.error, JSON.stringify(r.texts).slice(0, 400))
    assert.match(r.error, /different file/)
  })

  it('still opens files under their own rows', async () => {
    const vault = await buildVault()
    const call = await connect(vault)
    const r = await call('vault_read_file', { file_id: vault.ids.notes })
    assert.equal(r.error, null, r.error)
  })
})

describe('name row binding', () => {
  it('hides a v4 name on a row-bound (v7) row, keeps it on a legacy row', async () => {
    const vault = await buildVault()
    const taxKey = vault.folders.get(vault.ids.tax).fk
    const bound = await vault.file('bound.pdf', vault.ids.tax, new TextEncoder().encode('b'), { id: newRowBoundId() })
    const legacy = await vault.file('legacy.pdf', vault.ids.tax, new TextEncoder().encode('l'))
    // The server copies an unbound name onto each row.
    vault.files.get(bound).name = await v4Name('termination-letter.pdf', taxKey)
    vault.files.get(legacy).name = await v4Name('old-name.pdf', taxKey)
    const call = await connect(vault)
    const { data } = await call('vault_list_files')
    const paths = data.files.map((f) => f.path)
    assert.ok(!paths.some((p) => p.includes('termination-letter')), paths.join('\n'))
    assert.ok(paths.includes('/Documents/Tax 2025/old-name.pdf'), paths.join('\n'))
  })
})

describe('upload writes row-bound files', () => {
  it('uses a v7 row id and puts it in the header file_id', async () => {
    const vault = await buildVault({ scopes: ['read', 'organize', 'write'] })
    const tree = await makeTree({ 'a.txt': 'row binding\n'.repeat(50) })
    const call = await connect(vault, tree)
    const args = { path: tree.path('a.txt'), destination_folder_id: vault.ids.tax }
    const preview = await call('vault_upload', args)
    assert.equal(preview.error, null, preview.error)
    const done = await call('vault_upload', { ...args, confirm: true, plan_token: preview.data.plan_token })
    assert.equal(done.error, null, done.error)
    const id = done.data.uploaded
    assert.ok(isRowBoundId(id), id)
    const header = parseHeader(vault.state.uploadedBlobs.get(id).subarray(0, 4096))
    assert.deepEqual(Buffer.from(header.fileId), Buffer.from(uuidToBytes(id)))
    assert.equal(await vault.ownerName(id), 'a.txt')
  })
})

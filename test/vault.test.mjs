// The vault tools end to end, over the real MCP protocol, against an in-memory
// ShieldFive (vaultFixture.mjs) that serves the real API shapes and real
// ciphertext in every format the vault stores.
//
// What is proven here:
//   - files the web app encrypted decrypt in this process through grant keys only
//     (post-quantum, AES-GCM v1 and legacy v0), and names/paths are right;
//   - nothing outside the grant's scope is listed, readable or reachable;
//   - revocation and expiry fail the very next call;
//   - duplicates are found by content, never by name;
//   - writes re-seal names and keys so the OWNER'S keys still open them;
//   - a file telling the agent to trash everything comes back as fenced data,
//     and the trash cap still applies.

import assert from 'node:assert/strict'
import { after, beforeEach, describe, it } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createLocalFileGateway } from '../src/localSource.mjs'
import { createPlanStore } from '../src/plans.mjs'
import { createServer, createVaultContext } from '../src/server.mjs'
import { resolveRoots } from '../src/roots.mjs'
import { createVaultApi } from '../src/vault/api.mjs'
import { loadGrantCredential } from '../src/vault/credential.mjs'
import { createNamePool } from '../src/vault/namePool.mjs'
import { makeTree } from './helpers.mjs'
import { buildVault } from './vaultFixture.mjs'

const names = createNamePool({ size: 4 })
after(() => names.close())

let vault
let client

let tree
async function connect(opts = {}) {
  vault = await buildVault(opts)
  // Local roots, for the upload tool: a real directory this server may read.
  tree = opts.tree ? await makeTree(opts.tree) : null
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
  client = new Client({ name: 'test', version: '1.0.0' })
  await Promise.all([server.connect(a), client.connect(b)])
}

async function call(name, args = {}) {
  const res = await client.callTool({ name, arguments: args })
  const texts = res.content.map((c) => c.text)
  const jsonBlock = texts.find((t) => t.startsWith('{'))
  return { res, texts, data: jsonBlock ? JSON.parse(jsonBlock) : null, error: res.isError ? texts[0] : null }
}

async function confirmed(name, args) {
  const preview = await call(name, args)
  assert.equal(preview.error, null, preview.error)
  return call(name, { ...args, confirm: true, plan_token: preview.data.plan_token })
}

describe('vault tools', () => {
  beforeEach(() => connect())

  it('registers only the vault tools when no local roots are configured', async () => {
    const { tools } = await client.listTools()
    assert.ok(tools.every((t) => t.name.startsWith('vault_')), tools.map((t) => t.name).join())
    // The eleven vault tools (upload and move-in included), plus vault_connect.
    assert.equal(tools.length, 12)
    const trash = tools.find((t) => t.name === 'vault_trash')
    assert.equal(trash.annotations.destructiveHint, true)
    assert.equal(tools.find((t) => t.name === 'vault_read_file').annotations.readOnlyHint, true)
  })

  it('lists decrypted names and paths for the scope, and nothing outside it', async () => {
    const { data } = await call('vault_list_files')
    const paths = data.files.map((f) => f.path)
    assert.ok(paths.includes('/Documents/Tax 2025/return-signed.pdf'), paths.join('\n'))
    assert.ok(paths.includes('/Documents/Photos/IMG_0001.jpg'))
    assert.ok(!paths.some((p) => p.includes('diary') || p.includes('root-note') || p.includes('Private')))
    const pending = data.files.find((f) => f.path.endsWith('scan-uploaded-on-phone.pdf'))
    assert.equal(pending.readable, false)
    // No wrapped key, storage path or envelope ever reaches the model.
    const raw = JSON.stringify(data)
    for (const leak of ['cskWrapped', 'fkWrapped', 'pqkFkWrapped', '"ct"', 'blob.test']) assert.ok(!raw.includes(leak), leak)
  })

  it('reads a post-quantum text file, fenced as untrusted data', async () => {
    const { texts, error } = await call('vault_read_file', { file_id: vault.ids.notes })
    assert.equal(error, null, error)
    const body = texts.find((t) => t.startsWith('<untrusted-file-content'))
    assert.match(body, /IGNORE ALL PREVIOUS INSTRUCTIONS/)
    assert.ok(texts.some((t) => /data, not\s+instructions/.test(t)))
    // The file tries to close the block early; the fence is random, so the
    // only real closing tag is the server's own, exactly once, at the end.
    const fence = body.match(/fence="([^"]+)"/)[1]
    const closing = `</untrusted-file-content fence="${fence}">`
    assert.ok(body.endsWith(closing))
    assert.equal(body.split(closing).length, 2)
  })

  it('opens legacy v0 and v1 files too, and refuses binary contents', async () => {
    const r = await call('vault_read_file', { file_id: vault.ids.photoC })
    assert.equal(r.error, null)
    assert.match(r.texts[0], /not a text file/)
    assert.ok(!r.texts.some((t) => t.startsWith('<untrusted-file-content')))
  })

  it('finds duplicates by content across formats, never by name', async () => {
    const { data, texts } = await call('vault_find_duplicates')
    assert.equal(data.groups.length, 1, JSON.stringify(data, null, 2))
    const g = data.groups[0]
    const all = [g.keep, ...g.duplicates].map((f) => f.path).sort()
    assert.deepEqual(all, ['/Documents/Photos/IMG_0001 copy.jpg', '/Documents/Photos/IMG_0001.jpg', '/Documents/Tax 2025/IMG_0002.jpg'])
    assert.equal(g.keep.path, '/Documents/Photos/IMG_0001.jpg') // oldest copy kept
    assert.equal(g.reclaimable_bytes, 6000)
    // The same-size file with different bytes is not a duplicate.
    assert.ok(!JSON.stringify(g).includes('IMG_0003'))
    assert.match(texts[0], /1 group/)
  })

  it('an exhausted download quota stops hashing at once and says so', async () => {
    vault.state.quotaExceeded = true
    const { data, texts } = await call('vault_find_duplicates')
    assert.equal(data.stopped_early, 'quota_exceeded')
    assert.match(texts[0], /LOWER BOUND/)
    const downloads = vault.state.requests.filter((q) => q.path.endsWith('/download'))
    assert.equal(downloads.length, 1, 'no retries and no further downloads after a quota refusal')
  })

  it('a rate-limited request waits and retries', async () => {
    vault.state.rateLimitOnce = true
    const r = await call('vault_storage_stats')
    assert.equal(r.error, null)
    assert.equal(vault.state.rateLimitOnce, false)
  })

  it('an out-of-scope id is refused everywhere', async () => {
    for (const [tool, args] of [
      ['vault_read_file', { file_id: vault.ids.secret }],
      ['vault_rename', { item_id: vault.ids.secret, new_name: 'x.txt' }],
      ['vault_move', { item_id: vault.ids.secret, destination_folder_id: vault.ids.tax }],
      ['vault_move', { item_id: vault.ids.taxPdf, destination_folder_id: vault.ids.private }],
      ['vault_trash', { item_ids: [vault.ids.secret] }],
    ]) {
      const r = await call(tool, args)
      assert.match(r.error ?? '', /not_found/, `${tool} ${JSON.stringify(args)}`)
    }
    assert.ok(!vault.state.requests.some((q) => q.path.includes(vault.ids.secret)), 'never even asked the server')
  })

  it('revocation fails the very next call', async () => {
    assert.equal((await call('vault_list_files')).error, null)
    vault.state.revoked = true
    const r = await call('vault_list_files')
    assert.match(r.error, /grant_invalid.*revoked/)
    vault.state.revoked = false
    vault.state.expiresAt = new Date(Date.now() - 1000).toISOString()
    assert.match((await call('vault_storage_stats')).error, /grant_invalid/)
  })

  it('renames and moves re-seal so the owner’s own keys still open them', async () => {
    const rn = await confirmed('vault_rename', { item_id: vault.ids.taxPdf, new_name: '2025 tax return.pdf' })
    assert.equal(rn.error, null, rn.error)
    assert.equal(await vault.ownerName(vault.ids.taxPdf), '2025 tax return.pdf')

    const mv = await confirmed('vault_move', { item_id: vault.ids.taxPdf, destination_folder_id: vault.ids.photos })
    assert.equal(mv.error, null, mv.error)
    assert.equal(vault.files.get(vault.ids.taxPdf).folderId, vault.ids.photos)
    assert.equal(await vault.ownerName(vault.ids.taxPdf), '2025 tax return.pdf')
    // And the content still decrypts through the new parent.
    const read = await call('vault_read_file', { file_id: vault.ids.taxPdf })
    assert.equal(read.error, null)
  })

  it('a confirmed call without its plan, or after the item changed, does nothing', async () => {
    const bare = await call('vault_trash', { item_ids: [vault.ids.taxPdf], confirm: true })
    assert.match(bare.error, /plan_token_required/)
    const preview = await call('vault_rename', { item_id: vault.ids.taxPdf, new_name: 'a.pdf' })
    vault.files.get(vault.ids.taxPdf).updatedAt = new Date().toISOString()
    const late = await call('vault_rename', { item_id: vault.ids.taxPdf, new_name: 'a.pdf', confirm: true, plan_token: preview.data.plan_token })
    assert.match(late.error, /plan_changed/)
    assert.equal(await vault.ownerName(vault.ids.taxPdf), 'return-signed.pdf')
  })

  it('creates folders the owner can open', async () => {
    const r = await confirmed('vault_create_folder', { parent_folder_id: vault.ids.docs, name: 'Receipts' })
    assert.equal(r.error, null, r.error)
    assert.equal(await vault.ownerName(r.data.created), 'Receipts')
  })

  it('trash moves items to the connection’s Bin folder, says how to restore, and deletes nothing', async () => {
    const r = await confirmed('vault_trash', { item_ids: [vault.ids.photoB, vault.ids.photoC] })
    assert.equal(r.error, null, r.error)
    assert.equal(r.data.trashed.length, 2)
    assert.match(r.data.restore, /Nothing is permanently deleted/)
    for (const id of [vault.ids.photoB, vault.ids.photoC]) {
      assert.equal(vault.files.get(id).folderId, vault.ids.trash)
      assert.ok(await vault.ownerName(id))
    }
    const list = await call('vault_list_files')
    assert.ok(!list.data.files.some((f) => f.id === vault.ids.photoB))
    const withTrash = await call('vault_list_files', { include_trash: true })
    assert.ok(withTrash.data.files.find((f) => f.id === vault.ids.photoB).in_trash)
  })

  it('prompt injection: the file’s instruction changes nothing, and the cap holds', async () => {
    const before = vault.state.requests.length
    const read = await call('vault_read_file', { file_id: vault.ids.notes })
    assert.equal(read.error, null)
    // Reading issued only reads.
    assert.ok(vault.state.requests.slice(before).every((q) => q.method === 'GET' || q.path.endsWith('/download')))
    // Even a model that obeyed could not trash more than 50 at once, and not without a plan.
    const many = Array.from({ length: 51 }, () => vault.ids.notes)
    const r = await client.callTool({ name: 'vault_trash', arguments: { item_ids: many, confirm: true } })
    assert.equal(r.isError, true)
    assert.ok(![...vault.files.values()].some((f) => f.folderId === vault.ids.trash))
  })

  it('never sends the grant secret, and sends the token only as a bearer header', async () => {
    await call('vault_list_files')
    await confirmed('vault_rename', { item_id: vault.ids.taxPdf, new_name: 'b.pdf' })
    const secret = Buffer.from(vault.credential.secret).toString('base64url')
    const token = Buffer.from(vault.credential.token).toString('base64url')
    for (const q of vault.state.requests) {
      const wire = JSON.stringify({ path: q.path, body: q.body })
      assert.ok(!wire.includes(secret) && !wire.includes(token))
    }
  })
})

describe('vault permissions', () => {
  it('a read-only connection names the missing permission and changes nothing', async () => {
    await connect({ scopes: ['read'] })
    const r = await call('vault_rename', { item_id: vault.ids.taxPdf, new_name: 'x.pdf' })
    assert.match(r.error, /missing_scope.*"organize"/)
    assert.ok(!vault.state.requests.some((q) => q.method !== 'GET'))
  })

  it('a whole-vault connection reaches root-level files through per-file keys', async () => {
    await connect({ whole: true })
    const { data } = await call('vault_list_files')
    assert.ok(data.files.some((f) => f.path === '/root-note.txt'))
    const read = await call('vault_read_file', { file_id: vault.ids.rootFile })
    assert.match(read.texts.find((t) => t.startsWith('<untrusted')), /a note at the vault root/)
    const rn = await call('vault_rename', { item_id: vault.ids.rootFile, new_name: 'x.txt' })
    assert.match(rn.error, /fixed_item/)
  })

  it('names with control or bidi characters survive a move byte for byte, and new names cannot contain them', async () => {
    await connect()
    const rtl = `invoice${String.fromCharCode(0x202e)}fdp.exe`
    // The owner has such a name already (their own business); the agent moves it.
    const { encryptNameV6 } = await import('@shieldfive/crypto/vault')
    const f = vault.files.get(vault.ids.taxPdf)
    f.name = JSON.stringify(await encryptNameV6({ name: rtl, folderKey: vault.folders.get(vault.ids.tax).fk, rowId: f.id }))
    const listed = await call('vault_list_files')
    assert.ok(!JSON.stringify(listed.data).includes(String.fromCharCode(0x202e)), 'shown sanitized')
    const mv = await confirmed('vault_move', { item_id: vault.ids.taxPdf, destination_folder_id: vault.ids.photos })
    assert.equal(mv.error, null, mv.error)
    assert.equal(await vault.ownerName(vault.ids.taxPdf), rtl, 'the real name is preserved exactly')
    const bad = await call('vault_rename', { item_id: vault.ids.taxPdf, new_name: rtl })
    assert.match(bad.error, /invalid_name/)
  })

  it('a malformed connection string is refused without echoing it', async () => {
    await assert.rejects(
      loadGrantCredential({ SHIELDFIVE_GRANT: 'sf-grant-v1:not-really.secret-looking-value' }, async () => null),
      (err) => !err.message.includes('secret-looking-value'),
    )
  })
})

describe('vault_upload', () => {
  const WRITE = ['read', 'organize', 'write']
  const CONTENT = 'holiday photos and tax receipts\n'.repeat(200)

  const withFile = () =>
    connect({
      scopes: WRITE,
      tree: { 'photos/holiday.txt': CONTENT, 'photos/second.txt': 'x'.repeat(50) },
    })

  it('encrypts here, uploads, and verifies by reading it back', async () => {
    await withFile()
    const preview = await call('vault_upload', {
      path: tree.path('photos/holiday.txt'),
      destination_folder_id: vault.ids.tax,
    })
    assert.equal(preview.error, null, preview.error)
    assert.match(preview.texts[0], /Would encrypt/)
    assert.match(preview.texts[0], /local file is NOT removed/i)

    const done = await call('vault_upload', {
      path: tree.path('photos/holiday.txt'),
      destination_folder_id: vault.ids.tax,
      confirm: true,
      plan_token: preview.data.plan_token,
    })
    assert.equal(done.error, null, done.error)
    assert.equal(done.data.verified, true)
    assert.equal(done.data.bytes, CONTENT.length)

    // ShieldFive received ciphertext, never the plaintext.
    const stored = vault.state.uploadedBlobs.get(done.data.uploaded)
    assert.ok(stored.length > 0)
    assert.ok(!stored.includes(Buffer.from('holiday photos')))

    // The OWNER's own keys open the name — not just this connection's.
    assert.equal(await vault.ownerName(done.data.uploaded), 'holiday.txt')

    // And reading it back through the vault returns exactly what was on disk.
    const read = await call('vault_read_file', { file_id: done.data.uploaded })
    assert.ok(read.texts.some((t) => t.includes('holiday photos and tax receipts')))

    // The local file is still there: removing it is a separate, confirmed step.
    const local = await call('list_local', { path: tree.path('photos') })
    assert.ok(JSON.stringify(local.data).includes('holiday.txt'))
  })

  it('refuses a connection without the write scope', async () => {
    await connect({ tree: { 'a.txt': 'hello' } })
    const r = await call('vault_upload', {
      path: tree.path('a.txt'),
      destination_folder_id: vault.ids.tax,
    })
    assert.match(r.error ?? '', /cannot add files/)
  })

  it('refuses a destination outside the scope, and the Bin', async () => {
    await withFile()
    for (const dest of [vault.ids.private, vault.ids.bin, vault.ids.trash]) {
      const r = await call('vault_upload', {
        path: tree.path('photos/holiday.txt'),
        destination_folder_id: dest,
      })
      assert.ok(r.error, `expected a refusal for ${dest}`)
    }
  })

  it('refuses a path outside the allowed roots', async () => {
    await withFile()
    const r = await call('vault_upload', {
      path: '/etc/hosts',
      destination_folder_id: vault.ids.tax,
    })
    assert.ok(r.error)
  })

  it('refuses a confirmation whose file changed since the plan', async () => {
    await withFile()
    const preview = await call('vault_upload', {
      path: tree.path('photos/holiday.txt'),
      destination_folder_id: vault.ids.tax,
    })
    const { writeFile } = await import('node:fs/promises')
    await writeFile(tree.path('photos/holiday.txt'), 'something else entirely')
    const r = await call('vault_upload', {
      path: tree.path('photos/holiday.txt'),
      destination_folder_id: vault.ids.tax,
      confirm: true,
      plan_token: preview.data.plan_token,
    })
    assert.ok(r.error)
    assert.equal(vault.state.uploadedBlobs.size, 0)
  })

  it('stops when the owner’s upload budget is spent', async () => {
    await withFile()
    vault.state.writeBudget = 10
    const r = await confirmed('vault_upload', {
      path: tree.path('photos/holiday.txt'),
      destination_folder_id: vault.ids.tax,
    })
    assert.match(r.error ?? '', /upload allowance|budget/i)
  })

  it('refuses to encrypt to a public key that is not the one pinned in the connection', async () => {
    await withFile()
    const { generateMlKemKeypair } = await import('@shieldfive/crypto/pq-hybrid-v1')
    vault.state.servedPublicKey = generateMlKemKeypair().publicKey
    const r = await confirmed('vault_upload', {
      path: tree.path('photos/holiday.txt'),
      destination_folder_id: vault.ids.tax,
    })
    assert.match(r.error ?? '', /does not match/)
    assert.equal(vault.state.uploadedBlobs.size, 0)
  })

  it('never sends the vault credential to storage', async () => {
    await withFile()
    const r = await confirmed('vault_upload', {
      path: tree.path('photos/second.txt'),
      destination_folder_id: vault.ids.tax,
    })
    // The fixture fails the PUT outright if an Authorization header appears.
    assert.equal(r.error, null, r.error)
  })

  it('reports a storage failure without claiming anything was stored', async () => {
    await withFile()
    vault.state.storageRejects = true
    const r = await confirmed('vault_upload', {
      path: tree.path('photos/holiday.txt'),
      destination_folder_id: vault.ids.tax,
    })
    assert.ok(r.error)
    assert.match(r.error, /storage|upload/i)
  })

})

describe('vault_move_in', () => {
  const WRITE = ['read', 'organize', 'write']
  const A = 'receipt for the boiler service\n'.repeat(100)
  const B = 'scan of the passport, page 2\n'.repeat(80)

  const withFiles = () =>
    connect({ scopes: WRITE, tree: { 'Desktop/a.txt': A, 'Desktop/b.txt': B, 'Desktop/keep.txt': 'stay' } })

  const exists = async (p) => {
    const { lstat } = await import('node:fs/promises')
    return lstat(p).then(() => true, () => false)
  }

  it('uploads, verifies each file, then moves the originals to the local trash with one approval', async () => {
    await withFiles()
    const args = {
      paths: [tree.path('Desktop/a.txt'), tree.path('Desktop/b.txt')],
      destination_folder_id: vault.ids.tax,
    }
    const preview = await call('vault_move_in', args)
    assert.equal(preview.error, null, preview.error)
    assert.equal(preview.data.performed, false)
    assert.equal(preview.data.files.length, 2)
    assert.match(preview.texts[0], /Nothing is deleted/)
    // A preview uploads nothing and moves nothing.
    assert.equal(vault.state.uploadedBlobs.size, 0)
    assert.ok(await exists(tree.path('Desktop/a.txt')))

    const done = await call('vault_move_in', { ...args, confirm: true, plan_token: preview.data.plan_token })
    assert.equal(done.error, null, done.error)
    assert.equal(done.data.moved.length, 2)
    assert.equal(done.data.space_freed_bytes, 0)
    assert.equal(done.data.space_recoverable_bytes, A.length + B.length)

    for (const m of done.data.moved) {
      // Gone from where it was, present in the trash: moved, never deleted.
      assert.ok(!(await exists(m.source)), `${m.source} should have moved`)
      assert.ok(await exists(m.trashed_to), `${m.trashed_to} should exist`)
      assert.ok(m.trashed_to.includes('.shieldfive-mcp-trash'))
      // The owner's own keys open the vault copy's name.
      assert.equal(await vault.ownerName(m.vault_file_id), m.source.split('/').pop())
    }
    // The untouched file is untouched.
    assert.ok(await exists(tree.path('Desktop/keep.txt')))

    // The manifest names the vault copy of every original.
    const { readFile } = await import('node:fs/promises')
    const { dirname, join } = await import('node:path')
    const batchDir = dirname(done.data.moved[0].trashed_to).split('/Desktop')[0]
    const manifest = JSON.parse(await readFile(join(batchDir, 'manifest.json'), 'utf8'))
    assert.deepEqual(
      manifest.items.map((i) => i.vault_file_id).sort(),
      done.data.moved.map((m) => m.vault_file_id).sort(),
    )
  })

  it('refuses a connection without the write scope, before touching anything', async () => {
    await connect({ tree: { 'a.txt': 'hello' } })
    const r = await call('vault_move_in', { paths: [tree.path('a.txt')], destination_folder_id: vault.ids.tax })
    assert.match(r.error ?? '', /cannot add files/)
    assert.ok(await exists(tree.path('a.txt')))
  })

  it('refuses up front when the files cannot fit in the upload allowance', async () => {
    await withFiles()
    vault.state.writeBudget = A.length
    const r = await call('vault_move_in', {
      paths: [tree.path('Desktop/a.txt'), tree.path('Desktop/b.txt')],
      destination_folder_id: vault.ids.tax,
    })
    assert.match(r.error ?? '', /upload allowance/)
    assert.equal(vault.state.uploadedBlobs.size, 0)
  })

  it('leaves the original in place when the vault copy does not read back identical', async () => {
    await withFiles()
    vault.state.corruptStored = true
    const r = await confirmed('vault_move_in', {
      paths: [tree.path('Desktop/a.txt'), tree.path('Desktop/b.txt')],
      destination_folder_id: vault.ids.tax,
    })
    assert.ok(r.error)
    assert.match(r.error, /Stopped after 0 of 2/)
    assert.match(r.error, /NOT verified/)
    // Neither original moved, and the second was never even uploaded.
    assert.ok(await exists(tree.path('Desktop/a.txt')))
    assert.ok(await exists(tree.path('Desktop/b.txt')))
    assert.equal(vault.state.uploadedBlobs.size, 1)
  })

  it('stops at a storage failure and moves nothing', async () => {
    await withFiles()
    vault.state.storageRejects = true
    const r = await confirmed('vault_move_in', {
      paths: [tree.path('Desktop/a.txt')],
      destination_folder_id: vault.ids.tax,
    })
    assert.ok(r.error)
    assert.ok(await exists(tree.path('Desktop/a.txt')))
  })

  it('refuses a confirmation whose files changed since the plan', async () => {
    await withFiles()
    const args = { paths: [tree.path('Desktop/a.txt')], destination_folder_id: vault.ids.tax }
    const preview = await call('vault_move_in', args)
    const { writeFile } = await import('node:fs/promises')
    await writeFile(tree.path('Desktop/a.txt'), 'rewritten after the preview')
    const r = await call('vault_move_in', { ...args, confirm: true, plan_token: preview.data.plan_token })
    assert.ok(r.error)
    assert.equal(vault.state.uploadedBlobs.size, 0)
    assert.ok(await exists(tree.path('Desktop/a.txt')))
  })

  it('refuses two files that would share a name in the vault folder', async () => {
    await connect({ scopes: WRITE, tree: { 'one/x.txt': 'a', 'two/x.txt': 'b' } })
    const r = await call('vault_move_in', {
      paths: [tree.path('one/x.txt'), tree.path('two/x.txt')],
      destination_folder_id: vault.ids.tax,
    })
    assert.match(r.error ?? '', /both be named/)
  })

  it('refuses a folder: only files move', async () => {
    await withFiles()
    const r = await call('vault_move_in', { paths: [tree.path('Desktop')], destination_folder_id: vault.ids.tax })
    assert.ok(r.error)
    assert.ok(await exists(tree.path('Desktop/a.txt')))
  })

  it('will not trash a file that changed after it was read for upload', async () => {
    await withFiles()
    const roots = (await resolveRoots([tree.path('.')])).roots
    const gateway = createLocalFileGateway({ roots, now: () => Date.now() })
    const local = await gateway.describe(tree.path('Desktop/a.txt'))
    const { writeFile } = await import('node:fs/promises')
    await writeFile(tree.path('Desktop/a.txt'), 'edited after the upload read it')
    const trash = gateway.openTrash()
    await assert.rejects(trash.trash(local.path, local.entry, {}), /changed after it was uploaded/)
    assert.ok(await exists(tree.path('Desktop/a.txt')))
  })
})

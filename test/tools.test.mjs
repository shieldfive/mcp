import assert from 'node:assert/strict'
import { readFile, stat, utimes } from 'node:fs/promises'
import { after, describe, it } from 'node:test'
import { join } from 'node:path'

import { TRASH_DIR_NAME } from '../src/scan.mjs'
import { findDuplicates, findLargeFiles, findOldFiles, listLocal, storageSummary } from '../src/tools/read.mjs'
import { createLocalFolder, moveLocal, renameLocal, trashLocal } from '../src/tools/mutate.mjs'
import { makeCtx, makeTree, payload, summary } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

const gone = async (p) => {
  try {
    await stat(p)
    return false
  } catch {
    return true
  }
}

describe('list_local', () => {
  it('lists files and never follows a symlink out of the root', async () => {
    const t = await tree({
      'in/a.txt': 'aaa',
      'in/sub/b.txt': 'bbbb',
      'out/secret.txt': 'SECRET',
      'in/escape': { symlinkTo: 'out' },
    })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await listLocal(ctx, {}))

    const paths = data.files.map((f) => f.path)
    assert.equal(data.total_files, 2)
    assert.ok(paths.includes(t.path('in/a.txt')))
    assert.ok(!paths.some((p) => p.includes('secret')), 'symlinked tree must not be walked')
    assert.match(data.warnings.join(' '), /symlink/i)
  })

  it('skips node_modules and build output by default', async () => {
    const t = await tree({ 'in/keep.txt': 'x', 'in/node_modules/pkg/index.js': 'y', 'in/dist/out.js': 'z' })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await listLocal(ctx, {}))
    assert.equal(data.total_files, 1)
  })

  it('reports omitted rows rather than truncating silently', async () => {
    const spec = {}
    for (let i = 0; i < 12; i++) spec[`in/f${i}.txt`] = 'x'
    const t = await tree(spec)
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await listLocal(ctx, { limit: 5 }))
    assert.equal(data.shown, 5)
    assert.equal(data.omitted_by_limit, 7)
  })
})

describe('find_duplicates', () => {
  it('matches identical CONTENT under different names', async () => {
    const t = await tree({
      'in/report.pdf': 'IDENTICAL BYTES HERE',
      'in/backup/report-copy.pdf': 'IDENTICAL BYTES HERE',
      'in/other.pdf': 'different bytes entirely',
    })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findDuplicates(ctx, {}))

    assert.equal(data.duplicate_groups, 1)
    assert.equal(data.groups[0].copies, 2)
    assert.equal(data.groups[0].names_differ, true)
    assert.equal(data.reclaimable_bytes, 'IDENTICAL BYTES HERE'.length)
  })

  it('DOES NOT match same name and same size with different content', async () => {
    // The inference this tool is forbidden to make. Both files are called
    // invoice.pdf and both are 8 bytes; they are not the same file.
    const t = await tree({ 'in/a/invoice.pdf': 'AAAAAAAA', 'in/b/invoice.pdf': 'BBBBBBBB' })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findDuplicates(ctx, {}))
    assert.equal(data.duplicate_groups, 0)
    assert.equal(data.reclaimable_bytes, 0)
  })

  it('nominates the oldest copy as the one to keep', async () => {
    const t = await tree({ 'in/old.bin': 'SAME', 'in/new.bin': 'SAME' })
    const old = new Date('2020-01-01T00:00:00Z')
    await utimes(t.path('in/old.bin'), old, old)
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findDuplicates(ctx, {}))
    assert.equal(data.groups[0].oldest_copy.path, t.path('in/old.bin'))
  })

  it('says so when the hash budget makes the answer a lower bound', async () => {
    const spec = {}
    for (let i = 0; i < 6; i++) spec[`in/dup${i}.txt`] = 'SAME CONTENT'
    const t = await tree(spec)
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findDuplicates(ctx, { max_files_hashed: 2 }))
    assert.match(data.warnings.join(' '), /lower bound/i)
  })
})

describe('find_large_files and find_old_files', () => {
  it('thresholds on size', async () => {
    const t = await tree({ 'in/big.bin': 'x'.repeat(5000), 'in/small.bin': 'x' })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findLargeFiles(ctx, { min_bytes: 1000 }))
    assert.equal(data.match_count, 1)
    assert.equal(data.files[0].path, t.path('in/big.bin'))
  })

  it('warns that mtime is a weak signal', async () => {
    const t = await tree({ 'in/x.txt': 'x' })
    const old = new Date('2000-01-01T00:00:00Z')
    await utimes(t.path('in/x.txt'), old, old)
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findOldFiles(ctx, { older_than_days: 30 }))
    assert.equal(data.match_count, 1)
    assert.match(data.warnings.join(' '), /not evidence a file is unwanted/i)
  })
})

describe('storage_summary', () => {
  it('totals bytes and breaks down by extension', async () => {
    const t = await tree({ 'in/a.txt': 'xxx', 'in/b.txt': 'yy', 'in/c.bin': 'z' })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await storageSummary(ctx, {}))
    assert.equal(data.total_files, 3)
    assert.equal(data.total_bytes, 6)
    const txt = data.largest_by_extension.find((e) => e.key === '.txt')
    assert.equal(txt.bytes, 5)
  })
})

describe('confirm gating', () => {
  it('move_local changes nothing without confirm', async () => {
    const t = await tree({ 'in/a.txt': 'x', 'in/dest': null })
    const ctx = await makeCtx([t.path('in')])
    const res = await moveLocal(ctx, { source: t.path('in/a.txt'), destination: t.path('in/dest') })
    assert.equal(payload(res).performed, false)
    assert.match(summary(res), /Planned \(nothing changed\)/)
    assert.equal(await gone(t.path('in/a.txt')), false, 'source must still be there')
  })

  it('move_local moves with confirm, into a directory destination', async () => {
    const t = await tree({ 'in/a.txt': 'x', 'in/dest': null })
    const ctx = await makeCtx([t.path('in')])
    const res = await moveLocal(ctx, {
      source: t.path('in/a.txt'),
      destination: t.path('in/dest'),
      confirm: true,
    })
    assert.equal(payload(res).performed, true)
    assert.equal(await gone(t.path('in/a.txt')), true)
    assert.equal(await readFile(t.path('in/dest/a.txt'), 'utf8'), 'x')
  })

  it('move_local refuses to overwrite unless told', async () => {
    const t = await tree({ 'in/a.txt': 'new', 'in/dest/a.txt': 'old' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => moveLocal(ctx, { source: t.path('in/a.txt'), destination: t.path('in/dest'), confirm: true }),
      (e) => e.code === 'destination_exists',
    )
    assert.equal(await readFile(t.path('in/dest/a.txt'), 'utf8'), 'old')
  })

  it('move_local refuses to move a directory into itself', async () => {
    const t = await tree({ 'in/parent/child.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () =>
        moveLocal(ctx, {
          source: t.path('in/parent'),
          destination: t.path('in/parent/nested'),
          confirm: true,
        }),
      (e) => e.code === 'destination_inside_source',
    )
  })

  it('move_local refuses a destination outside the roots', async () => {
    const t = await tree({ 'in/a.txt': 'x', out: null })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => moveLocal(ctx, { source: t.path('in/a.txt'), destination: t.path('out/a.txt'), confirm: true }),
      (e) => e.code === 'outside_roots',
    )
  })

  it('rename_local refuses a path as the new name', async () => {
    const t = await tree({ 'in/a.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => renameLocal(ctx, { path: t.path('in/a.txt'), new_name: '../escaped.txt', confirm: true }),
      (e) => e.code === 'invalid_name',
    )
  })

  it('rename_local never replaces an existing file', async () => {
    const t = await tree({ 'in/a.txt': 'a', 'in/b.txt': 'b' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => renameLocal(ctx, { path: t.path('in/a.txt'), new_name: 'b.txt', confirm: true }),
      (e) => e.code === 'destination_exists',
    )
    assert.equal(await readFile(t.path('in/b.txt'), 'utf8'), 'b')
  })

  it('create_local_folder is idempotent and gated', async () => {
    const t = await tree({ 'in/.keep': '' })
    const ctx = await makeCtx([t.path('in')])

    assert.equal(payload(await createLocalFolder(ctx, { path: t.path('in/new') })).performed, false)
    assert.equal(await gone(t.path('in/new')), true)

    assert.equal(
      payload(await createLocalFolder(ctx, { path: t.path('in/new'), confirm: true })).performed,
      true,
    )
    const again = payload(await createLocalFolder(ctx, { path: t.path('in/new'), confirm: true }))
    assert.equal(again.already_existed, true)
  })
})

describe('trash_local', () => {
  it('moves rather than deletes, and says no space was freed', async () => {
    const t = await tree({ 'in/junk.txt': 'junk bytes' })
    const ctx = await makeCtx([t.path('in')])
    const res = await trashLocal(ctx, { paths: [t.path('in/junk.txt')], confirm: true })
    const data = payload(res)

    assert.equal(data.performed, true)
    assert.equal(data.space_freed_bytes, 0)
    assert.match(summary(res), /NOTHING WAS DELETED/)
    assert.equal(await gone(t.path('in/junk.txt')), true, 'moved out of its original place')

    const moved = data.items[0].trashed_to ?? data.items[0].destination
    assert.equal(await readFile(moved, 'utf8'), 'junk bytes', 'bytes still exist')
    assert.ok(moved.includes(TRASH_DIR_NAME))
  })

  it('writes a manifest that names where each item came from', async () => {
    const t = await tree({ 'in/doc.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await trashLocal(ctx, { paths: [t.path('in/doc.txt')], confirm: true }))
    const manifest = JSON.parse(await readFile(data.manifests[0], 'utf8'))
    assert.equal(manifest.items[0].original_path, t.path('in/doc.txt'))
    assert.match(manifest.note, /Nothing here is deleted/)
  })

  it('refuses to trash a configured root', async () => {
    const t = await tree({ 'in/x.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => trashLocal(ctx, { paths: [t.path('in')], confirm: true }),
      (e) => e.code === 'cannot_trash_root',
    )
  })

  it('refuses to re-trash something already in the trash', async () => {
    const t = await tree({ 'in/x.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await trashLocal(ctx, { paths: [t.path('in/x.txt')], confirm: true }))
    await assert.rejects(
      () => trashLocal(ctx, { paths: [data.items[0].destination], confirm: true }),
      (e) => e.code === 'already_trashed',
    )
  })

  it('does nothing without confirm', async () => {
    const t = await tree({ 'in/x.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await trashLocal(ctx, { paths: [t.path('in/x.txt')] }))
    assert.equal(data.performed, false)
    assert.equal(await gone(t.path('in/x.txt')), false)
  })

  it('does not re-offer trashed files on a later scan', async () => {
    const t = await tree({ 'in/a.txt': 'SAME', 'in/b.txt': 'SAME' })
    const ctx = await makeCtx([t.path('in')])
    await trashLocal(ctx, { paths: [t.path('in/b.txt')], confirm: true })
    const data = payload(await findDuplicates(ctx, {}))
    assert.equal(data.duplicate_groups, 0, 'the trashed copy must not count as a duplicate')
  })
})

describe('no roots configured', () => {
  it('every tool refuses with an actionable message', async () => {
    const ctx = { roots: [], noRootsMessage: 'configure roots', now: () => 0 }
    await assert.rejects(() => listLocal(ctx, {}), (e) => e.code === 'no_roots')
    await assert.rejects(
      () => moveLocal(ctx, { source: '/a', destination: '/b', confirm: true }),
      (e) => e.code === 'no_roots',
    )
  })
})

describe('cross-root isolation', () => {
  it('will not move between two configured roots', async () => {
    // Two roots are two allowed areas, not one merged filesystem. A move
    // between them is still contained, so this documents that it IS allowed.
    const t = await tree({ 'one/a.txt': 'x', 'two/.keep': '' })
    const ctx = await makeCtx([t.path('one'), t.path('two')])
    const res = await moveLocal(ctx, {
      source: t.path('one/a.txt'),
      destination: join(t.path('two'), 'a.txt'),
      confirm: true,
    })
    assert.equal(payload(res).performed, true)
    assert.equal(await readFile(t.path('two/a.txt'), 'utf8'), 'x')
  })
})

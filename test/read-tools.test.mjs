// The read tools report what acting on them would actually do.
//
// find_duplicates is the one read tool whose numbers a user acts on directly --
// "N bytes reclaimable" is what gets trashed -- so the budget, the keeper and
// the reclaimable figure each have a test that failed before its fix.

import assert from 'node:assert/strict'
import { link, utimes } from 'node:fs/promises'
import { after, describe, it } from 'node:test'

// A namespace import, so a function that does not exist yet fails its own test
// rather than the whole file.
import * as read from '../src/tools/read.mjs'
import { makeCtx, makeTree, payload } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

describe('find_duplicates reports what removing copies would actually free', () => {
  it('spends a tight budget on the most valuable group even when that group cannot be hashed whole', async () => {
    // Files over the 64 KiB head window cost two reads each, so this group's
    // worst case (12) is twice the budget. It used to be skipped outright while
    // the 1-byte pair behind it was hashed instead.
    const spec = {}
    for (let i = 0; i < 6; i++) spec[`in/big${i}.bin`] = 'B'.repeat(100_000)
    spec['in/small-a.bin'] = 'S'
    spec['in/small-b.bin'] = 'S'
    const t = await tree(spec)
    const ctx = await makeCtx([t.path('in')])

    const tight = payload(await read.findDuplicates(ctx, { max_files_hashed: 6 }))
    assert.ok(tight.hash_reads <= 6, `spent ${tight.hash_reads} reads of a budget of 6`)
    assert.equal(tight.groups[0]?.size, 100_000, 'the most valuable group must get the budget')
    assert.ok(tight.reclaimable_bytes >= 200_000, `found ${tight.reclaimable_bytes} bytes`)
    assert.equal(tight.groups_partially_hashed, 1)
    assert.match(tight.warnings.join(' '), /lower bound/i)
  })

  it('breaks an mtime tie deterministically, keeping the shorter path', async () => {
    // Finder's Duplicate keeps the modification time, so a tie is the common
    // case. The keeper used to be whichever copy the directory listed first.
    const t = await tree({ 'in/report.pdf': 'SAME BYTES', 'in/report copy.pdf': 'SAME BYTES' })
    const when = new Date('2024-05-01T10:00:00Z')
    await utimes(t.path('in/report.pdf'), when, when)
    await utimes(t.path('in/report copy.pdf'), when, when)
    const ctx = await makeCtx([t.path('in')])

    const data = payload(await read.findDuplicates(ctx, {}))
    assert.equal(data.groups[0].oldest_copy.path, t.path('in/report.pdf'))
  })

  it('orders copies by mtime, then path length, then path, whatever order they arrive in', () => {
    assert.equal(typeof read.compareKeeper, 'function', 'the keeper order must be a named, testable rule')
    const older = { path: '/r/a-much-longer-name-but-older.pdf', mtimeMs: 1 }
    const shortest = { path: '/r/report.pdf', mtimeMs: 5 }
    const a = { path: '/r/a/report.pdf', mtimeMs: 5 }
    const b = { path: '/r/b/report.pdf', mtimeMs: 5 }
    const dash = { path: '/r/report-2.pdf', mtimeMs: 5 }
    const expected = [older, shortest, a, b, dash].map((f) => f.path)

    for (const arrival of [
      [a, b, dash, shortest, older],
      [older, dash, b, a, shortest],
      [dash, older, shortest, b, a],
    ]) {
      assert.deepEqual([...arrival].sort(read.compareKeeper).map((f) => f.path), expected)
    }
  })

  it('does not count a second name for the same file as reclaimable space', async () => {
    const t = await tree({
      'in/a.bin': 'SAME-CONTENT',
      'in/c.bin': 'SAME-CONTENT',
      'in/solo.bin': 'ONLY ONE COPY',
    })
    await link(t.path('in/a.bin'), t.path('in/a-hardlink.bin'))
    await link(t.path('in/solo.bin'), t.path('in/solo-hardlink.bin'))
    const ctx = await makeCtx([t.path('in')])

    const data = payload(await read.findDuplicates(ctx, {}))
    assert.equal(data.duplicate_groups, 1, 'two names for one file are not a duplicate')
    assert.equal(data.groups[0].copies, 2)
    assert.equal(data.reclaimable_bytes, 'SAME-CONTENT'.length)

    const listed = [data.groups[0].oldest_copy, ...data.groups[0].other_copies]
    assert.equal(listed.length, 2, 'one entry per file on disk')
    assert.equal(
      listed.flatMap((c) => c.hardlinked_names ?? []).length,
      1,
      'the extra name is reported as a name, not as a copy',
    )
    assert.match(data.warnings.join(' '), /frees no space/i)
  })
})

describe('results describe the scan that actually ran', () => {
  it('lists only the roots it walked when the file budget runs out', async () => {
    const t = await tree({ 'one/a.txt': 'a', 'one/b.txt': 'b', 'two/c.txt': 'c' })
    const ctx = await makeCtx([t.path('one'), t.path('two')])

    const data = payload(await read.listLocal(ctx, { max_files: 1 }))

    assert.deepEqual(data.scanned, [t.path('one')])
    assert.deepEqual(data.not_scanned, [t.path('two')])
    assert.match(data.warnings.join(' '), new RegExp(escapeRegExp(t.path('two'))))
  })
})

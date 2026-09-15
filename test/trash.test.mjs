// The trash: where it is, what its manifest records, and what one call takes.
//
// trash_local and an overwriting move_local are the two operations that
// displace user data, and "nothing is deleted" rests on the trash directory
// being where it says, on the manifest being complete, and on a batch being
// planned before any of it moves. Each test here failed before its fix.

import assert from 'node:assert/strict'
import { chmod, mkdir, readdir, readFile, symlink, writeFile } from 'node:fs/promises'
import { after, describe, it } from 'node:test'
import { dirname, join } from 'node:path'

import { toolFailure } from '../src/format.mjs'
import { TRASH_DIR_NAME } from '../src/scan.mjs'
import { moveLocal, trashLocal, trashStamp } from '../src/tools/mutate.mjs'
import { makeCtx, makeTree, payload, withPatchedFs } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

describe('the trash directory is never followed out of the root', () => {
  it('refuses to trash anything while .shieldfive-mcp-trash is a symlink out of the root', async () => {
    // mkdir -p and rename both followed the link, so the user's files and the
    // manifest landed wherever it pointed.
    const t = await tree({ 'in/doc.txt': 'mine', 'outside/.keep': '' })
    await symlink(t.path('outside'), t.path(`in/${TRASH_DIR_NAME}`))
    const ctx = await makeCtx([t.path('in')])
    const unsafe = (e) => e.code === 'trash_unsafe'

    await assert.rejects(() => trashLocal(ctx, { paths: [t.path('in/doc.txt')] }), unsafe)
    await assert.rejects(() => trashLocal(ctx, { paths: [t.path('in/doc.txt')], confirm: true }), unsafe)

    assert.equal(await readFile(t.path('in/doc.txt'), 'utf8'), 'mine')
    assert.deepEqual(await readdir(t.path('outside')), ['.keep'], 'nothing may be written through the link')
  })

  it('refuses an overwriting move whose displaced item would go through that link', async () => {
    const t = await tree({ 'in/report.txt': 'new', 'in/dest/report.txt': 'old', 'outside/.keep': '' })
    await symlink(t.path('outside'), t.path(`in/${TRASH_DIR_NAME}`))
    const ctx = await makeCtx([t.path('in')])

    await assert.rejects(
      () =>
        moveLocal(ctx, {
          source: t.path('in/report.txt'),
          destination: t.path('in/dest'),
          overwrite: true,
          confirm: true,
        }),
      (e) => e.code === 'trash_unsafe',
    )
    assert.equal(await readFile(t.path('in/dest/report.txt'), 'utf8'), 'old')
    assert.equal(await readFile(t.path('in/report.txt'), 'utf8'), 'new')
    assert.deepEqual(await readdir(t.path('outside')), ['.keep'])
  })
})

describe('the trash manifest', () => {
  it('says what moved when a batch fails partway, and the client receives the detail', async () => {
    const t = await tree({ 'in/a.txt': 'a', 'in/b.txt': 'b' })
    const ctx = await makeCtx([t.path('in')])

    // The moment a.txt lands in the trash, make its batch directory read-only,
    // so the next write there fails: b.txt, or a manifest update. The old code
    // wrote the manifest after each move, and its message then said the moved
    // item "IS recorded in no manifest (nothing moved)".
    let lockedDir = null
    const lockAfterFirst =
      (original) =>
      async (from, to, ...rest) => {
        const out = await original(from, to, ...rest)
        if (!lockedDir && String(from) === t.path('in/a.txt') && String(to).includes(TRASH_DIR_NAME)) {
          lockedDir = dirname(String(to))
          await chmod(lockedDir, 0o555)
        }
        return out
      }

    let err
    try {
      await withPatchedFs({ rename: lockAfterFirst, link: lockAfterFirst }, async () => {
        err = await trashLocal(ctx, {
          paths: [t.path('in/a.txt'), t.path('in/b.txt')],
          confirm: true,
        }).then(
          () => null,
          (e) => e,
        )
      })
    } finally {
      if (lockedDir) await chmod(lockedDir, 0o755)
    }

    assert.ok(err, 'a partial failure must surface as an error')
    assert.equal(err.code, 'trash_partially_applied')
    assert.doesNotMatch(err.message, /nothing moved/i, 'one item did move')
    const trashedA = join(lockedDir, 'a.txt')
    assert.ok(err.message.includes(trashedA), `the message must say where a.txt went: ${err.message}`)

    const rendered = toolFailure(err)
    assert.equal(rendered.content.length, 2, 'the structured detail must reach the client')
    assert.equal(JSON.parse(rendered.content[1].text).moved.length, 1)

    const manifest = JSON.parse(await readFile(err.detail.manifests[0], 'utf8'))
    assert.ok(
      manifest.items.some((i) => i.original_path === t.path('in/a.txt') && i.trashed_to === trashedA),
      'the moved item must be in its manifest',
    )
    assert.equal(await readFile(t.path('in/b.txt'), 'utf8'), 'b')
  })

  it('records every item when concurrent calls share a timestamp', async () => {
    const spec = {}
    for (let i = 0; i < 8; i++) spec[`in/f${i}.txt`] = `file ${i}`
    const t = await tree(spec)
    // makeCtx's clock is fixed, so every call below gets the same timestamp.
    const ctx = await makeCtx([t.path('in')])
    const originals = Object.keys(spec).map((p) => t.path(p))

    const results = await Promise.all(originals.map((p) => trashLocal(ctx, { paths: [p], confirm: true })))

    const recorded = []
    for (const m of new Set(results.flatMap((r) => payload(r).manifests))) {
      recorded.push(...JSON.parse(await readFile(m, 'utf8')).items.map((i) => i.original_path))
    }
    assert.deepEqual(recorded.sort(), [...originals].sort())
  })

  it('never overwrites a manifest it did not write, even a corrupt one', async () => {
    const t = await tree({ 'in/doc.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    // Where the old code, with this clock, would have written its batch.
    const planted = join(t.path('in'), TRASH_DIR_NAME, trashStamp(ctx.now()), 'manifest.json')
    await mkdir(dirname(planted), { recursive: true })
    await writeFile(planted, '{ "items": [ not json')

    const data = payload(await trashLocal(ctx, { paths: [t.path('in/doc.txt')], confirm: true }))

    assert.equal(await readFile(planted, 'utf8'), '{ "items": [ not json', 'the planted manifest must be untouched')
    assert.notEqual(data.manifests[0], planted)
    const manifest = JSON.parse(await readFile(data.manifests[0], 'utf8'))
    assert.deepEqual(
      manifest.items.map((i) => i.original_path),
      [t.path('in/doc.txt')],
    )
  })
})

describe('trash_local takes each item once', () => {
  it('counts a path given twice once', async () => {
    const t = await tree({ 'in/a.txt': 'x'.repeat(1000) })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await trashLocal(ctx, { paths: [t.path('in/a.txt'), t.path('in/a.txt')] }))
    assert.equal(data.items.length, 1)
    assert.equal(
      data.items.reduce((n, i) => n + i.bytes, 0),
      1000,
    )
  })

  it('refuses a folder and something inside it in one call, before moving either', async () => {
    const t = await tree({ 'in/folder/inner.txt': 'inner', 'in/other.txt': 'other' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () =>
        trashLocal(ctx, {
          paths: [t.path('in/other.txt'), t.path('in/folder'), t.path('in/folder/inner.txt')],
          confirm: true,
        }),
      (e) => e.code === 'overlapping_paths',
    )
    assert.equal(await readFile(t.path('in/folder/inner.txt'), 'utf8'), 'inner')
    assert.equal(await readFile(t.path('in/other.txt'), 'utf8'), 'other')
  })
})

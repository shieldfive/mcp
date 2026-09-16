// Caller-supplied values are used exactly as given, and bounded before use.
//
// A model builds these arguments, sometimes by concatenation. Trimming turned
// "report " into "report", which is a different file, and nothing capped a
// name, a count or a list, so an oversized value either ran unbounded or came
// back whole in the refusal and landed in the model's context.

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { after, describe, it } from 'node:test'

import { findDuplicates, listLocal } from '../src/tools/read.mjs'
import { renameLocal, trashLocal } from '../src/tools/mutate.mjs'
import { apply, makeCtx, makeTree, payload } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

describe('paths and names are used exactly as given', () => {
  it('does not trash "report" when asked for "report "', async () => {
    const t = await tree({ 'in/report': 'keep me' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => apply(trashLocal, ctx, { paths: [`${t.path('in/report')} `]}),
      (e) => e.code === 'not_found',
    )
    assert.equal(await readFile(t.path('in/report'), 'utf8'), 'keep me')
  })

  it('keeps whitespace in new_name, so "b.txt " is not "b.txt"', async () => {
    const t = await tree({ 'in/a.txt': 'a', 'in/b.txt': 'b' })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(
      await apply(renameLocal, ctx, { path: t.path('in/a.txt'), new_name: 'b.txt '}),
    )
    assert.equal(data.to, t.path('in/b.txt '))
    assert.equal(await readFile(t.path('in/b.txt '), 'utf8'), 'a')
    assert.equal(await readFile(t.path('in/b.txt'), 'utf8'), 'b')
  })
})

describe('caller-supplied sizes are bounded', () => {
  it('refuses an overlong new_name without echoing all of it back', async () => {
    const t = await tree({ 'in/a.txt': 'a' })
    const ctx = await makeCtx([t.path('in')])

    const err = await renameLocal(ctx, { path: t.path('in/a.txt'), new_name: 'x'.repeat(100_000) }).then(
      () => null,
      (e) => e,
    )
    assert.equal(err?.code, 'invalid_name')
    assert.ok(err.message.length < 1000, `the refusal is ${err.message.length} characters long`)

    // 200 characters but 400 bytes: over the 255-byte name limit of APFS and ext4.
    await assert.rejects(
      () => renameLocal(ctx, { path: t.path('in/a.txt'), new_name: 'é'.repeat(200) }),
      (e) => e.code === 'invalid_name',
    )
  })

  it('refuses limit, max_files, max_files_hashed and paths beyond their caps', async () => {
    const t = await tree({ 'in/a.txt': 'a' })
    const ctx = await makeCtx([t.path('in')])
    const invalid = (e) => e.code === 'invalid_argument'

    await assert.rejects(() => listLocal(ctx, { limit: 10_000_001 }), invalid)
    await assert.rejects(() => listLocal(ctx, { max_files: 50_000_000 }), invalid)
    await assert.rejects(() => findDuplicates(ctx, { max_files_hashed: 50_000_000 }), invalid)
    await assert.rejects(() => trashLocal(ctx, { paths: Array(1001).fill(t.path('in/a.txt')) }), invalid)
  })
})

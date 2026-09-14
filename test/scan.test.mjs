import assert from 'node:assert/strict'
import { chmod, mkdir, writeFile } from 'node:fs/promises'
import { after, describe, it } from 'node:test'
import { join } from 'node:path'

import { hashFile, TRASH_DIR_NAME, walk } from '../src/scan.mjs'
import { makeTree } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

describe('walk', () => {
  it('reports truncation rather than stopping quietly', async () => {
    const spec = {}
    for (let i = 0; i < 20; i++) spec[`f${i}.txt`] = 'x'
    const t = await tree(spec)
    const { files, stats } = await walk(t.base, { maxFiles: 5 })
    assert.equal(files.length, 5)
    assert.equal(stats.truncated, true)
    assert.equal(stats.maxFiles, 5)
  })

  it('does not report truncation when everything fit', async () => {
    const t = await tree({ 'a.txt': 'x', 'b.txt': 'y' })
    const { stats } = await walk(t.base, { maxFiles: 100 })
    assert.equal(stats.truncated, false)
  })

  it('counts symlinks instead of following them', async () => {
    const t = await tree({ 'real/x.txt': 'x', 'link': { symlinkTo: 'real' } })
    const { files, stats } = await walk(t.base)
    assert.equal(stats.symlinksSkipped, 1)
    assert.equal(files.length, 1)
  })

  it('cannot loop on a self-referential symlink', async () => {
    const t = await tree({ 'a/x.txt': 'x', 'a/loop': { symlinkTo: 'a' } })
    const { files, stats } = await walk(t.base, { maxFiles: 50 })
    assert.equal(files.length, 1)
    assert.equal(stats.truncated, false)
  })

  it('skips its own trash directory', async () => {
    const t = await tree({ 'keep.txt': 'x' })
    await mkdir(join(t.base, TRASH_DIR_NAME, '2026'), { recursive: true })
    await writeFile(join(t.base, TRASH_DIR_NAME, '2026', 'old.txt'), 'y')
    const { files } = await walk(t.base)
    assert.deepEqual(
      files.map((f) => f.relativePath),
      ['keep.txt'],
    )
  })

  it('excludes hidden entries by default and includes them on request', async () => {
    const t = await tree({ 'visible.txt': 'x', '.hidden.txt': 'y' })
    const plain = await walk(t.base)
    assert.equal(plain.files.length, 1)
    assert.equal(plain.stats.hiddenSkipped, 1)

    const withHidden = await walk(t.base, { includeHidden: true })
    assert.equal(withHidden.files.length, 2)
  })

  it('records an unreadable directory instead of aborting the walk', async () => {
    const t = await tree({ 'ok/a.txt': 'x', 'locked/b.txt': 'y' })
    await chmod(t.path('locked'), 0o000)
    try {
      const { files, stats } = await walk(t.base)
      assert.equal(files.length, 1, 'the readable side still comes back')
      assert.equal(stats.unreadable.length, 1)
    } finally {
      await chmod(t.path('locked'), 0o755)
    }
  })

  it('stops descending past the depth limit and says which branch', async () => {
    const t = await tree({ 'a/b/c/d/deep.txt': 'x' })
    const { files, stats } = await walk(t.base, { maxDepth: 1 })
    assert.equal(files.length, 0)
    assert.ok(stats.depthLimited.length > 0)
  })
})

describe('hashFile', () => {
  it('gives the same digest for identical bytes and different for different', async () => {
    const t = await tree({ 'a.bin': 'SAME', 'b.bin': 'SAME', 'c.bin': 'DIFF' })
    const a = await hashFile(t.path('a.bin'))
    const b = await hashFile(t.path('b.bin'))
    const c = await hashFile(t.path('c.bin'))
    assert.equal(a, b)
    assert.notEqual(a, c)
  })

  it('honours a byte limit, so a prefix hash is a prefix hash', async () => {
    const t = await tree({ 'a.bin': 'PREFIX-aaaa', 'b.bin': 'PREFIX-bbbb' })
    assert.equal(await hashFile(t.path('a.bin'), { limit: 6 }), await hashFile(t.path('b.bin'), { limit: 6 }))
    assert.notEqual(await hashFile(t.path('a.bin')), await hashFile(t.path('b.bin')))
  })
})

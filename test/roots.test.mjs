// Containment is the whole security model, so it gets the most tests.

import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { join } from 'node:path'

import { isInside, resolveExisting, resolveRoots, resolveTarget, rootCandidatesFrom } from '../src/roots.mjs'
import { makeCtx, makeTree } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

describe('isInside', () => {
  it('treats a path as inside itself', () => {
    assert.equal(isInside('/a/b', '/a/b'), true)
  })

  it('accepts a genuine descendant', () => {
    assert.equal(isInside('/a/b/c.txt', '/a/b'), true)
  })

  it('rejects a sibling whose name merely starts with the root', () => {
    // The bug a naive startsWith() check ships with.
    assert.equal(isInside('/data/roots-evil/x', '/data/root'), false)
    assert.equal(isInside('/data/rootevil', '/data/root'), false)
  })

  it('rejects an ancestor', () => {
    assert.equal(isInside('/a', '/a/b'), false)
  })
})

describe('resolveRoots', () => {
  it('drops a non-absolute root with a reason', async () => {
    const { roots, rejected } = await resolveRoots(['relative/path'])
    assert.equal(roots.length, 0)
    assert.equal(rejected[0].reason, 'not an absolute path')
  })

  it('drops a root that does not exist', async () => {
    const { roots, rejected } = await resolveRoots(['/nope/definitely/not/here'])
    assert.equal(roots.length, 0)
    assert.equal(rejected[0].reason, 'does not exist')
  })

  it('drops a root that is a file', async () => {
    const t = await tree({ 'a.txt': 'x' })
    const { roots, rejected } = await resolveRoots([t.path('a.txt')])
    assert.equal(roots.length, 0)
    assert.equal(rejected[0].reason, 'not a directory')
  })

  it('drops a root nested inside another, keeping the outer one', async () => {
    const t = await tree({ 'outer/inner/x.txt': 'x' })
    const { roots, rejected } = await resolveRoots([t.path('outer'), t.path('outer/inner')])
    assert.equal(roots.length, 1)
    assert.equal(roots[0].realPath, t.path('outer'))
    assert.equal(rejected[0].reason, 'nested inside another configured root')
  })

  it('deduplicates two spellings of the same directory', async () => {
    const t = await tree({ 'a/x.txt': 'x' })
    const { roots } = await resolveRoots([t.path('a'), join(t.path('a'), '.', '')])
    assert.equal(roots.length, 1)
  })

  it('resolves a symlinked root to its real path', async () => {
    const t = await tree({ 'real/x.txt': 'x', link: { symlinkTo: 'real' } })
    const { roots } = await resolveRoots([t.path('link')])
    assert.equal(roots[0].realPath, t.path('real'))
  })
})

describe('rootCandidatesFrom', () => {
  it('reads argv and the environment, ignoring flags', () => {
    const got = rootCandidatesFrom(['/a', '--verbose', '/b'], { SHIELDFIVE_MCP_ROOTS: '/c' })
    assert.deepEqual(got.filter(Boolean), ['/a', '/b', '/c'])
  })
})

describe('resolveExisting', () => {
  it('refuses when no roots are configured', async () => {
    await assert.rejects(() => resolveExisting([], '/tmp'), (e) => e.code === 'no_roots')
  })

  it('refuses a relative path', async () => {
    const t = await tree({ 'a/x.txt': 'x' })
    const ctx = await makeCtx([t.path('a')])
    await assert.rejects(
      () => resolveExisting(ctx.roots, 'x.txt'),
      (e) => e.code === 'invalid_path',
    )
  })

  it('refuses a path outside every root', async () => {
    const t = await tree({ 'in/x.txt': 'x', 'out/y.txt': 'y' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => resolveExisting(ctx.roots, t.path('out/y.txt')),
      (e) => e.code === 'outside_roots',
    )
  })

  it('refuses a traversal that climbs out with ..', async () => {
    const t = await tree({ 'in/x.txt': 'x', 'out/y.txt': 'y' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => resolveExisting(ctx.roots, t.path('in/../out/y.txt')),
      (e) => e.code === 'outside_roots',
    )
  })

  it('REFUSES A SYMLINK THAT POINTS OUT OF THE ROOT', async () => {
    // The case a string-prefix check cannot catch: the path looks contained and
    // the bytes it reads are not.
    const t = await tree({
      'in/.keep': '',
      'out/secret.txt': 'secret',
      'in/escape': { symlinkTo: 'out/secret.txt' },
    })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => resolveExisting(ctx.roots, t.path('in/escape')),
      (e) => e.code === 'outside_roots',
    )
  })

  it('accepts a symlink that stays inside the root, returning the real path', async () => {
    const t = await tree({ 'in/real.txt': 'x', 'in/link': { symlinkTo: 'in/real.txt' } })
    const ctx = await makeCtx([t.path('in')])
    const got = await resolveExisting(ctx.roots, t.path('in/link'))
    assert.equal(got.realPath, t.path('in/real.txt'))
  })

  it('reports not_found for a missing path', async () => {
    const t = await tree({ 'in/.keep': '' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => resolveExisting(ctx.roots, t.path('in/nope.txt')),
      (e) => e.code === 'not_found',
    )
  })
})

describe('resolveTarget', () => {
  it('accepts a path that does not exist yet inside a root', async () => {
    const t = await tree({ 'in/.keep': '' })
    const ctx = await makeCtx([t.path('in')])
    const got = await resolveTarget(ctx.roots, t.path('in/new/deep/file.txt'))
    assert.equal(got.exists, false)
    assert.equal(got.realPath, t.path('in/new/deep/file.txt'))
  })

  it('REFUSES A NEW PATH UNDER A SYMLINKED PARENT THAT ESCAPES', async () => {
    // Writing through a symlinked directory is the write-side of the same hole.
    const t = await tree({ 'in/.keep': '', out: null, 'in/door': { symlinkTo: 'out' } })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => resolveTarget(ctx.roots, t.path('in/door/planted.txt')),
      (e) => e.code === 'outside_roots',
    )
  })

  it('reports exists: true for something already there', async () => {
    const t = await tree({ 'in/x.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    const got = await resolveTarget(ctx.roots, t.path('in/x.txt'))
    assert.equal(got.exists, true)
  })

  it('REFUSES A DANGLING SYMLINK, as the last component or one in the middle', async () => {
    // realpath fails on a dangling link exactly as it fails on a missing path,
    // so the link used to be treated as a free, contained name -- and a
    // cross-device copy then wrote through it to wherever it pointed.
    const t = await tree({ 'in/.keep': '', 'out/.keep': '', 'in/dangling': { symlinkTo: 'out/not-there' } })
    const ctx = await makeCtx([t.path('in')])
    const dangling = (e) => e.code === 'dangling_symlink'
    await assert.rejects(() => resolveTarget(ctx.roots, t.path('in/dangling')), dangling)
    await assert.rejects(() => resolveTarget(ctx.roots, t.path('in/dangling/child.txt')), dangling)
  })
})

describe('path arguments are used as given', () => {
  it('does not trim whitespace, so "report " is not "report"', async () => {
    const t = await tree({ 'in/report': 'plain', 'in/report ': 'trailing space' })
    const ctx = await makeCtx([t.path('in')])
    const got = await resolveExisting(ctx.roots, `${t.path('in/report')} `)
    assert.equal(got.realPath, t.path('in/report '))
    await assert.rejects(
      () => resolveExisting(ctx.roots, ` ${t.path('in/report')}`),
      (e) => e.code === 'invalid_path',
    )
  })

  it('bounds how much of an unusable path it echoes back', async () => {
    const t = await tree({ 'in/.keep': '' })
    const ctx = await makeCtx([t.path('in')])
    for (const input of [`relative/${'x'.repeat(20_000)}`, `/${'x'.repeat(20_000)}`]) {
      const err = await resolveExisting(ctx.roots, input).then(
        () => null,
        (e) => e,
      )
      assert.ok(err, 'must refuse')
      assert.ok(err.message.length < 1000, `a refusal of ${err.message.length} characters`)
    }
  })
})

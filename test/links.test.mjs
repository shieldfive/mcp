// Symlinks and names under the mutating tools.
//
// A mutating tool acts on the directory entry it was given. It does not follow
// a link to act on the target, it does not treat a dangling link as a free
// name, and "never replaces" holds even when something appears at the new name
// between the check and the change. Each of these used to be false.

import assert from 'node:assert/strict'
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises'
import { after, describe, it } from 'node:test'
import { join } from 'node:path'

import { moveLocal, renameLocal, trashLocal } from '../src/tools/mutate.mjs'
import { apply, makeCtx, makeTree, payload, withPatchedFs } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

/** True when nothing at all -- not even a dangling link -- is at `p`. */
const absent = (p) =>
  lstat(p).then(
    () => false,
    () => true,
  )

describe('a dangling symlink is an existing entry, not a free path', () => {
  it('previews it as displaced and refuses to move over it without overwrite', async () => {
    // realpath fails on a dangling link just as it fails on a missing path, and
    // the existence check followed links, so the preview said nothing was there
    // and a confirmed move replaced the link without a trash entry.
    const t = await tree({
      'in/report.txt': 'mine',
      'out/.keep': '',
      'in/dest/report.txt': { symlinkTo: 'out/planted.txt' },
    })
    const ctx = await makeCtx([t.path('in')])
    const args = { source: t.path('in/report.txt'), destination: t.path('in/dest') }

    const preview = payload(await moveLocal(ctx, { ...args, overwrite: true }))
    assert.equal(preview.replaces_existing, true)
    assert.equal(preview.displaced.kind, 'symlink')

    await assert.rejects(() => apply(moveLocal, ctx, { ...args}), (e) => e.code === 'destination_exists')
    assert.equal((await lstat(t.path('in/dest/report.txt'))).isSymbolicLink(), true, 'the link must survive')
    assert.equal(await readFile(t.path('in/report.txt'), 'utf8'), 'mine')
    assert.equal(await absent(t.path('out/planted.txt')), true)
  })
})

describe('mutating tools act on a symlink itself, never its target', () => {
  it('trash_local moves the link and leaves the tree it points to in place', async () => {
    const t = await tree({ 'in/photos/a.jpg': 'A', 'in/shortcut': { symlinkTo: 'in/photos' } })
    const ctx = await makeCtx([t.path('in')])

    const data = payload(await apply(trashLocal, ctx, { paths: [t.path('in/shortcut')]}))

    assert.equal(data.items[0].kind, 'symlink')
    assert.equal(await readFile(t.path('in/photos/a.jpg'), 'utf8'), 'A')
    assert.equal(await absent(t.path('in/shortcut')), true)
    assert.equal((await lstat(data.items[0].destination)).isSymbolicLink(), true)
  })

  it('rename_local renames the link, not the file it points to', async () => {
    const t = await tree({ 'in/real.txt': 'R', 'in/link': { symlinkTo: 'in/real.txt' } })
    const ctx = await makeCtx([t.path('in')])

    await apply(renameLocal, ctx, { path: t.path('in/link'), new_name: 'renamed-link'})

    assert.equal((await lstat(t.path('in/renamed-link'))).isSymbolicLink(), true)
    assert.equal(await readFile(t.path('in/real.txt'), 'utf8'), 'R')
  })

  it('move_local moves the link, leaving its target where it was', async () => {
    const t = await tree({ 'in/real.txt': 'R', 'in/link': { symlinkTo: 'in/real.txt' }, 'in/dest/.keep': '' })
    const ctx = await makeCtx([t.path('in')])

    await apply(moveLocal, ctx, { source: t.path('in/link'), destination: t.path('in/dest')})

    assert.equal((await lstat(t.path('in/dest/link'))).isSymbolicLink(), true)
    assert.equal(await readFile(t.path('in/real.txt'), 'utf8'), 'R')
    assert.equal(await absent(t.path('in/dest/real.txt')), true)
  })
})

describe('rename_local never replaces, even under a race', () => {
  it('refuses when a file appears at the new name between the check and the rename', async () => {
    const t = await tree({ 'in/a.txt': 'mine' })
    const ctx = await makeCtx([t.path('in')])
    const target = t.path('in/b.txt')
    const intrude =
      (original) =>
      async (from, to, ...rest) => {
        if (String(to) === target) await writeFile(target, 'someone else', { flag: 'wx' }).catch(() => {})
        return original(from, to, ...rest)
      }

    await withPatchedFs({ rename: intrude, link: intrude }, () =>
      assert.rejects(
        () => apply(renameLocal, ctx, { path: t.path('in/a.txt'), new_name: 'b.txt'}),
        (e) => e.code === 'destination_exists',
      ),
    )
    assert.equal(await readFile(target, 'utf8'), 'someone else')
    assert.equal(await readFile(t.path('in/a.txt'), 'utf8'), 'mine')
  })

  it('refuses a directory rename when the new name fills up at the last moment', async () => {
    const t = await tree({ 'in/album/1.jpg': 'one' })
    const ctx = await makeCtx([t.path('in')])
    const target = t.path('in/album-2')
    const intrude =
      (original) =>
      async (from, to, ...rest) => {
        if (String(to) === target) {
          await mkdir(target, { recursive: true })
          await writeFile(join(target, 'theirs.jpg'), 'theirs')
        }
        return original(from, to, ...rest)
      }

    await withPatchedFs({ rename: intrude }, () =>
      assert.rejects(
        () => apply(renameLocal, ctx, { path: t.path('in/album'), new_name: 'album-2'}),
        (e) => e.code === 'destination_exists',
      ),
    )
    assert.equal(await readFile(join(target, 'theirs.jpg'), 'utf8'), 'theirs')
    assert.equal(await readFile(t.path('in/album/1.jpg'), 'utf8'), 'one')
  })
})

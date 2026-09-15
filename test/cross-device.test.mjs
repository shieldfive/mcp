// Moves and the trash across two devices inside one configured root.
//
// A root is a directory, not a volume: /Volumes, or a home directory with an
// external drive mounted inside it, holds several filesystems. These tests
// mount a RAM disk inside their own temporary root so that is real, and skip
// visibly where that cannot be done.

import assert from 'node:assert/strict'
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import { after, before, describe, it } from 'node:test'
import { join, sep } from 'node:path'

import { TRASH_DIR_NAME } from '../src/scan.mjs'
import { trashLocal } from '../src/tools/mutate.mjs'
import { makeCtx, makeTree, mountScratchVolume, payload } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

describe('across two devices inside one root', () => {
  let root
  let vol
  let ctx
  let volume

  before(async () => {
    const t = await tree({ 'root/local/.keep': '', 'outside/.keep': '' })
    root = t.path('root')
    vol = t.path('root/vol')
    volume = await mountScratchVolume(vol)
    ctx = await makeCtx([root])
  })
  after(async () => {
    await volume?.detach()
  })

  const needVolume = (c) => {
    if (volume) return true
    c.skip('needs a second volume; see the [skip] line on stderr')
    return false
  }

  it('puts an item’s trash on the same volume as the item', async (c) => {
    // The trash lived at <root>/.shieldfive-mcp-trash whatever volume an item
    // was on, so trashing from a drive mounted inside the root copied the tree
    // onto the root's volume while the result said the bytes had not moved.
    if (!needVolume(c)) return
    await mkdir(join(vol, 'd7'))
    await writeFile(join(vol, 'd7/video.mov'), 'x'.repeat(4096))
    const volumeDevice = (await stat(vol)).dev

    const data = payload(await trashLocal(ctx, { paths: [join(vol, 'd7/video.mov')], confirm: true }))

    const [item] = data.items
    assert.ok(item.destination.startsWith(join(vol, TRASH_DIR_NAME) + sep), `trashed to ${item.destination}`)
    assert.equal((await stat(item.destination)).dev, volumeDevice)
    assert.equal(item.method, 'rename', 'a trash move is a rename, never a copy')
    for (const m of data.manifests) assert.equal((await stat(m)).dev, volumeDevice)
  })

  it('refuses to trash a mount point, which has nowhere on its own volume to go', async (c) => {
    if (!needVolume(c)) return
    const second = await mountScratchVolume(join(root, 'vol2'), { megabytes: 8 })
    if (!second) return c.skip('could not mount a second scratch volume')
    try {
      await writeFile(join(root, 'vol2/keep.txt'), 'keep')
      await assert.rejects(
        () => trashLocal(ctx, { paths: [join(root, 'vol2')], confirm: true }),
        (e) => e.code === 'trash_no_same_volume',
      )
      assert.equal(await readFile(join(root, 'vol2/keep.txt'), 'utf8'), 'keep')
    } finally {
      await second.detach()
    }
  })
})

// Moves and the trash across two devices inside one configured root.
//
// A root is a directory, not a volume: /Volumes, or a home directory with an
// external drive mounted inside it, holds several filesystems. These tests
// mount a RAM disk inside their own temporary root so that is real, and skip
// visibly where that cannot be done. Where a failure has to land at an exact
// moment -- a copy that arrives with a byte wrong, a source that grows while it
// is copied -- node:fs is patched for that one call.

import assert from 'node:assert/strict'
import { appendFile, lstat, mkdir, open, readdir, readFile, stat, symlink, writeFile } from 'node:fs/promises'
import { after, before, describe, it } from 'node:test'
import { dirname, join, sep } from 'node:path'

import { TRASH_DIR_NAME } from '../src/scan.mjs'
import { moveLocal, trashLocal } from '../src/tools/mutate.mjs'
import { makeCtx, makeFifo, makeTree, mountScratchVolume, payload, withPatchedFs } from './helpers.mjs'

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

describe('across two devices inside one root', () => {
  let root
  let vol
  let outside
  let ctx
  let volume

  before(async () => {
    const t = await tree({ 'root/local/.keep': '', 'outside/.keep': '' })
    root = t.path('root')
    vol = t.path('root/vol')
    outside = t.path('outside')
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

  it('moves a file across devices, keeping its bytes and leaving nothing behind', async (c) => {
    if (!needVolume(c)) return
    const source = join(root, 'local/plain/notes.txt')
    await mkdir(dirname(source), { recursive: true })
    await writeFile(source, 'plain notes')
    await mkdir(join(vol, 'plain'))

    const data = payload(await moveLocal(ctx, { source, destination: join(vol, 'plain'), confirm: true }))

    assert.equal(data.method, 'copy+remove')
    assert.equal(await readFile(join(vol, 'plain/notes.txt'), 'utf8'), 'plain notes')
    assert.equal(await absent(source), true)
    assert.deepEqual(await readdir(join(vol, 'plain')), ['notes.txt'])
  })

  it('never writes through a dangling symlink when the move crosses devices', async (c) => {
    // copyFile follows a link at its destination. The old fallback wrote the
    // file wherever the dangling link pointed, outside the root, and then
    // removed the source.
    if (!needVolume(c)) return
    await mkdir(join(vol, 'd2'))
    await writeFile(join(vol, 'd2/report.txt'), 'from the other volume')
    await mkdir(join(root, 'local/d2'), { recursive: true })
    await symlink(join(outside, 'planted.txt'), join(root, 'local/d2/report.txt'))
    const move = (extra) =>
      moveLocal(ctx, {
        source: join(vol, 'd2/report.txt'),
        destination: join(root, 'local/d2'),
        confirm: true,
        ...extra,
      })

    await assert.rejects(() => move({}), (e) => e.code === 'destination_exists')
    assert.equal(await absent(join(outside, 'planted.txt')), true, 'nothing may be written through the link')
    assert.equal(await readFile(join(vol, 'd2/report.txt'), 'utf8'), 'from the other volume')

    const data = payload(await move({ overwrite: true }))
    assert.equal(await absent(join(outside, 'planted.txt')), true)
    assert.equal((await lstat(join(root, 'local/d2/report.txt'))).isFile(), true)
    assert.equal(await readFile(join(root, 'local/d2/report.txt'), 'utf8'), 'from the other volume')
    assert.equal((await lstat(data.displaced_to)).isSymbolicLink(), true, 'the link itself goes to the trash')
  })

  it('never deletes a pre-existing entry that shares the old staging name', async (c) => {
    // The directory fallback began with rm -rf on `<destination>.shieldfive-mcp-incoming`,
    // whatever was there.
    if (!needVolume(c)) return
    await mkdir(join(root, 'local/d8a/album'), { recursive: true })
    await writeFile(join(root, 'local/d8a/album/1.jpg'), 'one')
    await mkdir(join(vol, 'd8a/album.shieldfive-mcp-incoming'), { recursive: true })
    await writeFile(join(vol, 'd8a/album.shieldfive-mcp-incoming/precious.txt'), 'not ours to delete')

    const data = payload(
      await moveLocal(ctx, {
        source: join(root, 'local/d8a/album'),
        destination: join(vol, 'd8a'),
        confirm: true,
      }),
    )

    assert.equal(data.method, 'copy+remove')
    assert.equal(
      await readFile(join(vol, 'd8a/album.shieldfive-mcp-incoming/precious.txt'), 'utf8'),
      'not ours to delete',
    )
    assert.equal(await readFile(join(vol, 'd8a/album/1.jpg'), 'utf8'), 'one')
    assert.equal(await absent(join(root, 'local/d8a/album')), true)
  })

  it('refuses a tree holding a FIFO instead of dropping it and removing the source', async (c) => {
    // The tree copy took files and directories only, and the source was then
    // removed whole, pipe and all.
    if (!needVolume(c)) return
    await mkdir(join(root, 'local/d8b/project'), { recursive: true })
    await writeFile(join(root, 'local/d8b/project/notes.txt'), 'notes')
    await makeFifo(join(root, 'local/d8b/project/pipe'))
    await mkdir(join(vol, 'd8b'))

    await assert.rejects(
      () =>
        moveLocal(ctx, {
          source: join(root, 'local/d8b/project'),
          destination: join(vol, 'd8b'),
          confirm: true,
        }),
      (e) => e.code === 'special_file_in_tree',
    )
    assert.equal((await lstat(join(root, 'local/d8b/project/pipe'))).isFIFO(), true)
    assert.equal(await readFile(join(root, 'local/d8b/project/notes.txt'), 'utf8'), 'notes')
    assert.deepEqual(await readdir(join(vol, 'd8b')), [], 'nothing, not even staging, is left behind')
  })

  it('keeps the source when the copy does not verify', async (c) => {
    if (!needVolume(c)) return
    const source = join(root, 'local/d8c/archive.bin')
    await mkdir(dirname(source), { recursive: true })
    await writeFile(source, 'A'.repeat(50_000))
    await mkdir(join(vol, 'd8c'))
    // A copy that lands with one byte wrong: the failure verification exists for.
    const corrupt =
      (original) =>
      async (from, to, ...rest) => {
        await original(from, to, ...rest)
        if (String(from) === source) {
          const fh = await open(to, 'r+')
          try {
            await fh.write('B', 0)
          } finally {
            await fh.close()
          }
        }
      }

    await withPatchedFs({ copyFile: corrupt }, () =>
      assert.rejects(
        () => moveLocal(ctx, { source, destination: join(vol, 'd8c'), confirm: true }),
        (e) => e.code === 'copy_verification_failed',
      ),
    )
    assert.equal(await readFile(source, 'utf8'), 'A'.repeat(50_000))
    assert.deepEqual(await readdir(join(vol, 'd8c')), [])
  })

  it('keeps the source when it changes while it is being copied', async (c) => {
    if (!needVolume(c)) return
    const source = join(root, 'local/d8e/log.txt')
    await mkdir(dirname(source), { recursive: true })
    await writeFile(source, 'first line\n')
    await mkdir(join(vol, 'd8e'))
    const grow =
      (original) =>
      async (from, to, ...rest) => {
        await original(from, to, ...rest)
        if (String(from) === source) await appendFile(source, 'written during the copy\n')
      }

    await withPatchedFs({ copyFile: grow }, () =>
      assert.rejects(
        () => moveLocal(ctx, { source, destination: join(vol, 'd8e'), confirm: true }),
        (e) => e.code === 'source_changed',
      ),
    )
    assert.equal(await readFile(source, 'utf8'), 'first line\nwritten during the copy\n')
    assert.deepEqual(await readdir(join(vol, 'd8e')), [])
  })

  it('leaves no partial file at the destination when the other volume fills up', async (c) => {
    if (!needVolume(c)) return
    const source = join(root, 'local/d8d/huge.bin')
    await mkdir(dirname(source), { recursive: true })
    await writeFile(source, Buffer.alloc(24 * 1024 * 1024, 7)) // bigger than the 20 MiB volume
    await mkdir(join(vol, 'd8d'))

    await assert.rejects(() => moveLocal(ctx, { source, destination: join(vol, 'd8d'), confirm: true }))

    assert.equal((await stat(source)).size, 24 * 1024 * 1024)
    assert.deepEqual(await readdir(join(vol, 'd8d')), [])
  })
})

// Where trashed items go, and the manifest that says where they came from.
//
// Three properties, each of which used to be false.
//
// 1. The trash is a real directory inside the root. `.shieldfive-mcp-trash`
//    was joined onto the root and handed to mkdir -p and rename(2), which both
//    follow a symlink, so a link planted at that name sent the user's files
//    and the manifest out of the root. The directory is now lstat'd before
//    anything is planned, created one level at a time without following
//    anything, and checked again before anything moves into it.
//
// 2. The trash is on the same volume as the item. It used to sit at the root
//    whatever volume an item was on, so for a root such as /Volumes, trashing
//    from an external drive copied the tree onto the boot volume while the
//    result said the bytes had stayed put. An item's trash is now in the
//    highest directory between it and its root that is on its own device, and
//    a move into the trash is a rename, never a copy.
//
// 3. The manifest is complete. Concurrent calls in one millisecond shared a
//    batch and a manifest, and the later write dropped the earlier entries; a
//    corrupt manifest was silently reset. Each call now gets a batch directory
//    of its own, created exclusively. Its manifest lists every item before any
//    of them moves, is written atomically and one write at a time, and no
//    manifest this server did not write is ever read, merged or replaced.

import { lstat, mkdir, open, readdir, realpath, rename, rmdir, unlink } from 'node:fs/promises'
import { dirname, join, relative, sep } from 'node:path'

import { quote } from './format.mjs'
import { renameNoReplace, syncDirectory } from './fsops.mjs'
import { isInside, ToolError } from './roots.mjs'
import { TRASH_DIR_NAME } from './scan.mjs'

const MANIFEST_NOTE =
  'Written by @shieldfive/mcp before anything in this batch was moved. Nothing here ' +
  'is deleted. To restore an entry, move trashed_to back to original_path. An entry ' +
  'whose trashed_to does not exist was planned but not moved.'

export function trashStamp(now) {
  return new Date(now).toISOString().replace(/[:.]/g, '-')
}

let batchCounter = 0

/**
 * A batch name no other call will use: the timestamp, this process and a
 * counter. The batch directory is also created exclusively, so a name another
 * process happens to pick is refused rather than shared.
 */
export function batchName(now) {
  batchCounter += 1
  return `${trashStamp(now)}-${process.pid}-${batchCounter}`
}

/** True when `path` is inside one of this server's trash directories below its root. */
export function inTrash(rootRealPath, path) {
  return relative(rootRealPath, path).split(sep).includes(TRASH_DIR_NAME)
}

/**
 * The directory whose trash an entry goes into: the highest directory between
 * the entry and its root that is on the entry's own device.
 */
export async function trashBaseFor(rootRealPath, entryPath, entryStats) {
  let base = null
  for (let dir = dirname(entryPath); isInside(dir, rootRealPath); dir = dirname(dir)) {
    if ((await lstat(dir)).dev !== entryStats.dev) break
    base = dir
    if (dir === rootRealPath) break
  }
  if (!base) {
    throw new ToolError(
      'trash_no_same_volume',
      `Refused: ${quote(entryPath)} is the top of a volume mounted inside the root ` +
        `${quote(rootRealPath)}, so no directory on that volume and inside the root can ` +
        'hold its trash. Putting it anywhere else would copy it onto another volume. ' +
        'Nothing was moved; trash what is inside it instead.',
    )
  }
  return base
}

/** Where an entry lands in a batch, and the batch's own paths. */
export function trashPaths(base, batch, entryPath) {
  const batchDir = join(base, TRASH_DIR_NAME, batch)
  return {
    batchDir,
    destination: join(batchDir, relative(base, entryPath)),
    manifest: join(batchDir, 'manifest.json'),
  }
}

function unsafe(path, why) {
  return new ToolError(
    'trash_unsafe',
    `Refused: ${quote(path)} ${why}. Trashed items and their manifest go inside it, so it ` +
      'must be a real directory in the root, and this server moves nothing through a link. ' +
      'Nothing was moved. Look at what is there and move it out of the way first.',
  )
}

async function requireRealDirectory(path, device) {
  const st = await lstat(path)
  if (st.isSymbolicLink()) throw unsafe(path, 'is a symlink')
  if (!st.isDirectory()) throw unsafe(path, 'is not a directory')
  if (st.dev !== device) throw unsafe(path, 'is on a different volume from the directory holding it')
  const real = await realpath(path)
  if (real !== path) throw unsafe(path, `resolves to ${quote(real)}`)
}

/**
 * Refuse, while planning, a trash directory that is not a real directory.
 *
 * Read-only, so a preview reports the refusal the confirmed call would hit.
 */
export async function inspectTrashDir(base) {
  const dir = join(base, TRASH_DIR_NAME)
  try {
    await lstat(dir)
  } catch (err) {
    if (err.code === 'ENOENT') return
    throw err
  }
  await requireRealDirectory(dir, (await lstat(base)).dev)
}

/**
 * Create, or check, the trash directory and create this call's batch in it.
 *
 * mkdir without `recursive` makes exactly one directory and fails when
 * anything, a link included, already has that name, so neither can be
 * redirected; both are checked afterwards regardless.
 */
export async function openBatch(base, batch) {
  const device = (await lstat(base)).dev
  const dir = join(base, TRASH_DIR_NAME)
  try {
    await mkdir(dir)
  } catch (err) {
    if (err.code !== 'EEXIST') throw err
  }
  await requireRealDirectory(dir, device)

  const { batchDir, manifest } = trashPaths(base, batch, base)
  try {
    await mkdir(batchDir)
  } catch (err) {
    if (err.code === 'EEXIST') {
      throw new ToolError(
        'trash_batch_exists',
        `Refused: a trash batch named ${quote(batchDir)} already exists, and this call will ` +
          'not share it. Nothing was moved; call again.',
      )
    }
    throw err
  }
  await requireRealDirectory(batchDir, device)
  return { base, dir: batchDir, manifest, device, entries: [], written: false }
}

/** Create the directories between a batch and one destination in it, following no link. */
export async function makeParents(batch, destination) {
  let dir = batch.dir
  for (const part of relative(batch.dir, dirname(destination)).split(sep).filter(Boolean)) {
    dir = join(dir, part)
    try {
      await mkdir(dir)
    } catch (err) {
      if (err.code !== 'EEXIST') throw err
    }
    await requireRealDirectory(dir, batch.device)
  }
}

/** Rename an entry into the trash. Never a copy: a move that crosses a device is refused. */
export async function moveIntoTrash(from, to, stats) {
  try {
    await renameNoReplace(from, to, stats)
  } catch (err) {
    if (err.code === 'EXDEV') {
      throw new ToolError(
        'trash_cross_device',
        `Refused: moving ${quote(from)} to ${quote(to)} would cross a filesystem boundary, ` +
          'and a move into the trash is never a copy. It was not moved.',
      )
    }
    throw err
  }
}

const manifestWrites = new Map()

/**
 * Write a batch's manifest from `batch.entries`.
 *
 * Serialised per manifest, so two writes never interleave. Atomic: the text
 * goes to a temporary file that is flushed and then renamed over the manifest,
 * so a crash leaves the old manifest or the new one and never half of either.
 * The first write refuses to replace anything at the manifest's name.
 */
export function writeManifest(batch, now) {
  const write = () => writeAtomically(batch, now)
  const previous = manifestWrites.get(batch.manifest) ?? Promise.resolve()
  const next = previous.then(write, write)
  manifestWrites.set(batch.manifest, next)
  const settle = () => {
    if (manifestWrites.get(batch.manifest) === next) manifestWrites.delete(batch.manifest)
  }
  next.then(settle, settle)
  return next
}

let tempCounter = 0

async function writeAtomically(batch, now) {
  const text = JSON.stringify(
    { format: 1, created: new Date(now).toISOString(), note: MANIFEST_NOTE, items: batch.entries },
    null,
    2,
  )
  tempCounter += 1
  const temp = `${batch.manifest}.${process.pid}-${tempCounter}.tmp`
  const handle = await open(temp, 'wx', 0o644)
  let flushed = false
  try {
    await handle.writeFile(text, 'utf8')
    await handle.sync()
    flushed = true
  } finally {
    await handle.close().catch(() => {})
    if (!flushed) await unlink(temp).catch(() => {})
  }
  try {
    if (batch.written) await rename(temp, batch.manifest)
    else await renameNoReplace(temp, batch.manifest)
  } catch (err) {
    await unlink(temp).catch(() => {})
    throw err
  }
  batch.written = true
  await syncDirectory(batch.dir)
}

/**
 * Take back a batch that nothing ended up in: its manifest and its empty
 * directories. Only what this call made, and a directory only if it is empty.
 */
export async function discardBatch(batch) {
  if (batch.written) await unlink(batch.manifest).catch(() => {})
  await removeEmptyDirectories(batch.dir)
}

async function removeEmptyDirectories(dir) {
  let entries = []
  try {
    entries = await readdir(dir, { withFileTypes: true })
  } catch {
    return
  }
  for (const e of entries) {
    if (e.isDirectory()) await removeEmptyDirectories(join(dir, e.name))
  }
  await rmdir(dir).catch(() => {})
}

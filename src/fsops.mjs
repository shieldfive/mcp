// Filesystem moves that never replace what is already there.
//
// rename(2) silently replaces a file, a symlink or an empty directory at its
// destination. Node exposes neither renameat2(RENAME_NOREPLACE) nor
// renamex_np(RENAME_EXCL), so a "never replaces" promise built on a check
// followed by rename() holds only until something appears in between. Every
// move in this server goes through renameNoReplace() instead, which uses an
// operation that fails when the destination exists wherever the platform has
// one, and says plainly where it does not.

import { constants } from 'node:fs'
import {
  copyFile,
  link,
  lstat,
  mkdir,
  open,
  readdir,
  readlink,
  rename,
  rmdir,
  symlink,
  unlink,
} from 'node:fs/promises'
import { dirname, join } from 'node:path'

import { quote } from './format.mjs'
import { isInside, ToolError } from './roots.mjs'
import { hashFile } from './scan.mjs'

/** Errors meaning "this filesystem cannot make that kind of name", rather than a real failure. */
const NAME_UNSUPPORTED = new Set(['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EMLINK', 'EINVAL'])

export function destinationExists(path) {
  return new ToolError(
    'destination_exists',
    `Refused: ${quote(path)} already exists, so nothing was moved and nothing was replaced.`,
  )
}

/**
 * Move `from` to `to`, refusing if anything at all is at `to`.
 *
 * - A regular file is hard-linked to the new name, which fails if anything --
 *   even a dangling symlink -- is already there, and only then unlinked from
 *   the old one.
 * - A symlink is recreated at the new name with the same target, and then the
 *   old one is removed. link(2) cannot be used for it: on macOS it follows the
 *   link and hard-links the target instead.
 * - A directory gets an empty placeholder made at the new name, and rename(2)
 *   replaces only that. Anything written into the placeholder in the gap makes
 *   the rename fail with ENOTEMPTY rather than be replaced. What remains is that
 *   an EMPTY directory created in place of the placeholder in that gap would be
 *   replaced, which loses nothing.
 * - FIFOs, sockets and device files, filesystems without hard links (FAT, exFAT
 *   and some network shares), and directories on Windows fall back to checking
 *   and then renaming, which leaves a window in which a file created at `to` by
 *   another process would be replaced. SECURITY.md records it.
 *
 * EXDEV propagates untouched, so the caller decides what a move across devices
 * means. `fromStats` is the lstat of `from`, when the caller already has it.
 */
export async function renameNoReplace(from, to, fromStats) {
  const stats = fromStats ?? (await lstat(from))

  if (stats.isFile()) {
    return swapName(from, to, () => link(from, to), async () => {
      const now = await lstat(to)
      return now.ino === stats.ino && now.dev === stats.dev
    })
  }
  if (stats.isSymbolicLink()) {
    const target = await readlink(from)
    return swapName(from, to, () => symlink(target, to), async () => {
      return (await lstat(to)).isSymbolicLink() && (await readlink(to)) === target
    })
  }
  if (stats.isDirectory() && process.platform !== 'win32') {
    return renameOverPlaceholder(from, to)
  }
  return renameChecked(from, to)
}

async function swapName(from, to, makeName, isOurs) {
  try {
    await makeName()
  } catch (err) {
    if (err.code === 'EEXIST') throw destinationExists(to)
    if (NAME_UNSUPPORTED.has(err.code)) return renameChecked(from, to)
    throw err
  }
  try {
    await unlink(from)
  } catch (err) {
    // The new name exists and the old one could not be removed. Take back the
    // name this call made -- only if it is still that name -- so a failure
    // leaves the item under exactly one name, the one it had.
    if (await isOurs().catch(() => false)) await unlink(to).catch(() => {})
    throw err
  }
}

async function renameOverPlaceholder(from, to) {
  try {
    await mkdir(to)
  } catch (err) {
    if (err.code === 'EEXIST') throw destinationExists(to)
    throw err
  }
  try {
    await rename(from, to)
  } catch (err) {
    // rmdir removes only an empty directory: the placeholder, and never
    // anything that landed inside it.
    await rmdir(to).catch(() => {})
    if (err.code === 'ENOTEMPTY' || err.code === 'EEXIST') throw destinationExists(to)
    throw err
  }
}

/**
 * Flush a directory, so a rename just made in it survives a power cut.
 *
 * Best effort. Not every platform lets a directory be opened and flushed, and a
 * failure here undoes nothing that has already happened.
 */
export async function syncDirectory(path) {
  let handle
  try {
    handle = await open(path, 'r')
    await handle.sync()
  } catch {
    // See above: nothing to report and nothing to undo.
  } finally {
    await handle?.close().catch(() => {})
  }
}

async function renameChecked(from, to) {
  let present = true
  try {
    await lstat(to)
  } catch (err) {
    if (err.code !== 'ENOENT') throw err
    present = false
  }
  if (present) throw destinationExists(to)
  await rename(from, to)
}

// Moves that cross a device.
//
// rename(2) cannot cross a filesystem boundary, so such a move is a copy
// followed by removing the source: the one place this server removes anything
// a user made. The old fallback began by rm -rf'ing whatever sat at its staging
// name, copied files and directories only -- so a FIFO, socket or device file
// in the tree was dropped -- and removed a file's source without flushing or
// checking the copy. The rules now:
//
// - Nothing that already exists is removed or replaced. A copy is made under a
//   fresh name, created exclusively, and put in place with renameNoReplace().
// - Only what a copy can carry is copied. A symlink or a special file in a tree
//   is refused before anything of the source is removed.
// - Every file is flushed to disk and verified -- same size and SHA-256, and a
//   source that has not changed since it was copied -- before anything goes.
// - The source is removed entry by entry: a file only if it is still the file
//   that was copied, a directory only once it is empty. Whatever appeared or
//   changed during the move stays where it is, and the caller is told.

let incomingCounter = 0

/** A name beside `to` that nothing else uses, for a copy on its way in. */
function incomingName(to) {
  incomingCounter += 1
  return join(dirname(to), `.shieldfive-mcp-incoming-${process.pid}-${incomingCounter}`)
}

/** Flush a file's bytes to disk. A read-only descriptor is enough, so a read-only copy can be flushed too. */
export async function syncFile(path) {
  const handle = await open(path, 'r')
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

function unchanged(before, now) {
  return (
    now.ino === before.ino &&
    now.dev === before.dev &&
    now.size === before.size &&
    now.mtimeMs === before.mtimeMs
  )
}

function describeSpecial(stats) {
  if (stats.isFIFO()) return 'named pipe (FIFO)'
  if (stats.isSocket()) return 'socket'
  if (stats.isBlockDevice() || stats.isCharacterDevice()) return 'device file'
  return 'special file'
}

async function verifyCopy(source, before, copy) {
  const changed = () =>
    new ToolError(
      'source_changed',
      `Refused: ${quote(source)} changed while it was being copied, so the copy cannot be ` +
        'trusted. The copy was discarded and the source was not removed; try again once ' +
        'nothing is writing to it.',
    )
  if (!unchanged(before, await lstat(source))) throw changed()

  const copied = await lstat(copy)
  const sourceDigest = await hashFile(source)
  const copyDigest = await hashFile(copy)
  if (!unchanged(before, await lstat(source))) throw changed()
  if (copied.size !== before.size || sourceDigest !== copyDigest) {
    throw new ToolError(
      'copy_verification_failed',
      `Refused: the copy of ${quote(source)} does not match it (` +
        (copied.size !== before.size
          ? `${copied.size} bytes instead of ${before.size}`
          : 'the same size, but a different SHA-256') +
        '). The copy was discarded and the source was not removed.',
    )
  }
}

/** Remove sources that have a verified copy, each only if it is still what was copied. */
async function removeCopied(copied) {
  const left = []
  for (const { source, stats } of copied) {
    let now
    try {
      now = await lstat(source)
    } catch {
      continue
    }
    if (!unchanged(stats, now)) {
      left.push(source)
      continue
    }
    try {
      await unlink(source)
    } catch {
      left.push(source)
    }
  }
  return left
}

/**
 * Move one regular file to another device.
 *
 * Returns the source paths left in place: empty, unless the source changed
 * after its copy was verified.
 */
export async function moveFileAcrossDevices(from, to, before) {
  const incoming = incomingName(to)
  try {
    await copyFile(from, incoming, constants.COPYFILE_EXCL)
    await syncFile(incoming)
    await verifyCopy(from, before, incoming)
    await renameNoReplace(incoming, to)
  } catch (err) {
    // The incoming name was created exclusively, so whatever is there is this
    // call's own partial or unverified copy -- unless the name was taken, and
    // then nothing is removed.
    if (err.code !== 'EEXIST') await unlink(incoming).catch(() => {})
    throw err
  }
  await syncDirectory(dirname(to))
  return removeCopied([{ source: from, stats: before }])
}

/**
 * Move a directory tree to another device.
 *
 * The tree is copied into a fresh staging directory beside the destination,
 * each file verified, and the staging directory renamed into place only once
 * all of it has landed. Returns the source paths left in place.
 */
export async function moveTreeAcrossDevices(from, to) {
  const staging = incomingName(to)
  await mkdir(staging)
  const made = { files: [], dirs: [staging] }
  const copied = []
  const sourceDirs = [from]
  try {
    await copyTreeVerified(from, staging, made, copied, sourceDirs)
    await renameNoReplace(staging, to)
  } catch (err) {
    for (const file of made.files) await unlink(file).catch(() => {})
    for (const dir of [...made.dirs].reverse()) await rmdir(dir).catch(() => {})
    throw err
  }
  await syncDirectory(dirname(to))

  const left = await removeCopied(copied)
  for (const dir of [...sourceDirs].reverse()) {
    try {
      await rmdir(dir)
    } catch {
      if (!left.some((p) => isInside(p, dir))) left.push(dir)
    }
  }
  return left
}

async function copyTreeVerified(fromDir, toDir, made, copied, sourceDirs) {
  for (const name of await readdir(fromDir)) {
    const source = join(fromDir, name)
    const target = join(toDir, name)
    const stats = await lstat(source)

    if (stats.isSymbolicLink()) {
      throw new ToolError(
        'symlink_in_tree',
        `Refused: ${quote(source)} is a symlink, and this move crosses a filesystem boundary, ` +
          'so it would have to be copied, and a copy cannot keep it a link. Nothing was ' +
          'removed and nothing is left at the destination. Move the link yourself or remove it first.',
      )
    }
    if (stats.isDirectory()) {
      await mkdir(target)
      made.dirs.push(target)
      sourceDirs.push(source)
      await copyTreeVerified(source, target, made, copied, sourceDirs)
      continue
    }
    if (!stats.isFile()) {
      throw new ToolError(
        'special_file_in_tree',
        `Refused: ${quote(source)} is a ${describeSpecial(stats)}, which cannot be copied to ` +
          'another filesystem. Nothing was removed and nothing is left at the destination. ' +
          'Move it yourself, or move the rest without it.',
      )
    }

    made.files.push(target)
    await copyFile(source, target, constants.COPYFILE_EXCL)
    await syncFile(target)
    await verifyCopy(source, stats, target)
    copied.push({ source, stats })
  }
}

export { describeSpecial }

// Filesystem moves that never replace what is already there.
//
// rename(2) silently replaces a file, a symlink or an empty directory at its
// destination. Node exposes neither renameat2(RENAME_NOREPLACE) nor
// renamex_np(RENAME_EXCL), so a "never replaces" promise built on a check
// followed by rename() holds only until something appears in between. Every
// move in this server goes through renameNoReplace() instead, which uses an
// operation that fails when the destination exists wherever the platform has
// one, and says plainly where it does not.

import { link, lstat, mkdir, readlink, rename, rmdir, symlink, unlink } from 'node:fs/promises'

import { quote } from './format.mjs'
import { ToolError } from './roots.mjs'

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

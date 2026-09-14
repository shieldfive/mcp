// The four tools that change the filesystem.
//
// Two rules hold across all of them, and they are the reason this server is
// safe to point at a real home directory.
//
// 1. Nothing happens without `confirm: true`. Called without it, each tool
//    resolves the paths, checks containment, reports exactly what it WOULD do —
//    including what it would displace — and returns.
//
// 2. Nothing is ever unlinked. Not by trash_local, and not by an overwriting
//    move. An earlier version of move_local called
//    `rm(finalPath, {recursive: true, force: true})` when overwrite was set,
//    which made "this server deletes nothing" false in the one case where it
//    mattered most: overwriting a directory destroyed every file underneath it,
//    unrecoverably, with only the SOURCE's byte count shown in the preview.
//    Overwriting now MOVES the existing destination into the trash first, so
//    the bytes survive and the manifest records where they were.
//
// The only `rm` calls left are in the cross-device copy fallback, where they
// remove a source whose bytes have already been written to the destination.

import { copyFile, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import { basename, dirname, join, relative, sep } from 'node:path'

import { formatBytes, toolResult } from '../format.mjs'
import { isInside, resolveExisting, resolveTarget, ToolError } from '../roots.mjs'
import { TRASH_DIR_NAME } from '../scan.mjs'

/** Total bytes and file count beneath a path, for reporting before a move. */
async function measure(path) {
  let st
  try {
    st = await stat(path)
  } catch {
    return { files: 0, bytes: 0, kind: 'missing', symlinks: [] }
  }
  if (st.isFile()) return { files: 1, bytes: st.size, kind: 'file', symlinks: [] }

  let files = 0
  let bytes = 0
  const symlinks = []
  const queue = [path]
  while (queue.length) {
    const dir = queue.shift()
    let entries
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const e of entries) {
      const full = join(dir, e.name)
      if (e.isSymbolicLink()) {
        symlinks.push(full)
        continue
      }
      if (e.isDirectory()) queue.push(full)
      else if (e.isFile()) {
        try {
          const s = await stat(full)
          files++
          bytes += s.size
        } catch {
          // Undercounts silently, as does the readdir catch above, which skips
          // a whole subtree. These figures go into the move and trash previews
          // the user approves, so a permission-denied subtree makes a move look
          // smaller than it is. It never makes one look safer: nothing is
          // deleted either way.
        }
      }
    }
  }
  return { files, bytes, kind: 'directory', symlinks }
}

/** rename(2), falling back to copy+remove when the move crosses a device. */
async function relocate(from, to) {
  try {
    await rename(from, to)
    return 'rename'
  } catch (err) {
    if (err.code !== 'EXDEV') throw err
  }

  const st = await stat(from)
  if (st.isFile()) {
    await copyFile(from, to)
    await rm(from)
    return 'copy+remove'
  }

  // Stage the copy beside the target and rename it into place only once the
  // whole tree has landed. Copying straight into `to` left a partial tree there
  // when anything threw mid-walk -- and the source was already torn in half by
  // the older interleaved copy+remove. Now a failure leaves the source
  // untouched and nothing at the destination.
  const staging = `${to}.shieldfive-mcp-incoming`
  await rm(staging, { recursive: true, force: true })
  try {
    await copyTree(from, staging)
  } catch (err) {
    await rm(staging, { recursive: true, force: true })
    throw err
  }
  await rename(staging, to)
  await rm(from, { recursive: true })
  return 'copy+remove'
}

async function copyTree(from, to) {
  await mkdir(to, { recursive: true })
  for (const e of await readdir(from, { withFileTypes: true })) {
    if (e.isSymbolicLink()) {
      throw new ToolError(
        'symlink_in_tree',
        `Refused: ${join(from, e.name)} is a symlink, and this move crosses a ` +
          'filesystem boundary so it cannot be preserved. Nothing has been ' +
          'removed. Move it yourself or remove the link first.',
      )
    }
    if (e.isDirectory()) await copyTree(join(from, e.name), join(to, e.name))
    else if (e.isFile()) await copyFile(join(from, e.name), join(to, e.name))
  }
}

async function exists(path) {
  try {
    await stat(path)
    return true
  } catch {
    return false
  }
}

export function trashStamp(now) {
  return new Date(now).toISOString().replace(/[:.]/g, '-')
}

/**
 * Where an item goes when it is trashed.
 *
 * The root is passed in rather than recovered from the destination string. The
 * previous version derived it with
 * `destination.indexOf(sep + TRASH_DIR_NAME + sep)`, which finds the FIRST
 * occurrence — so a user whose root path happens to contain a directory named
 * `.shieldfive-mcp-trash` had the manifest written outside their root.
 */
export function trashDestination(rootRealPath, itemRealPath, stamp) {
  return join(rootRealPath, TRASH_DIR_NAME, stamp, relative(rootRealPath, itemRealPath))
}

/** Append to the manifest for one trash batch, creating it if absent. */
async function recordInManifest(rootRealPath, stamp, entries, now) {
  const manifestPath = join(rootRealPath, TRASH_DIR_NAME, stamp, 'manifest.json')

  let existing = []
  try {
    existing = JSON.parse(await readFile(manifestPath, 'utf8')).items ?? []
  } catch {
    /* first write of this batch */
  }

  await mkdir(dirname(manifestPath), { recursive: true })
  await writeFile(
    manifestPath,
    JSON.stringify(
      {
        created: new Date(now).toISOString(),
        note:
          'Written by @shieldfive/mcp. Nothing here is deleted. To restore an ' +
          'entry, move trashed_to back to original_path.',
        items: [...existing, ...entries],
      },
      null,
      2,
    ),
    'utf8',
  )
  return manifestPath
}

export async function moveLocal(ctx, args) {
  const source = await resolveExisting(ctx.roots, args.source, { what: 'source' })
  const dest = await resolveTarget(ctx.roots, args.destination, { what: 'destination' })

  // Resolve the final path before any guard runs. Checking the destination
  // argument alone missed the worst case: moving /root/sub onto its parent
  // /root gives a final path of /root/sub — the source itself — which the old
  // guard passed and the old overwrite branch then deleted.
  const destIsDirectory = dest.exists && (await stat(dest.realPath)).isDirectory()
  const finalPath = destIsDirectory ? join(dest.realPath, basename(source.realPath)) : dest.realPath

  if (finalPath === source.realPath) {
    throw new ToolError(
      'destination_is_source',
      `Refused: that resolves to ${finalPath}, which is the source itself. ` +
        'Nothing to do.',
    )
  }
  if (isInside(finalPath, source.realPath)) {
    throw new ToolError(
      'destination_inside_source',
      `Refused: ${finalPath} is inside ${source.realPath}. Moving a directory ` +
        'into its own subtree is not a move.',
    )
  }

  const finalResolved = await resolveTarget(ctx.roots, finalPath, { what: 'destination' })
  const collision = await exists(finalPath)

  if (collision && !args.overwrite) {
    throw new ToolError(
      'destination_exists',
      `Refused: ${finalPath} already exists. Pass overwrite: true to move it to ` +
        'the trash and take its place, or choose a different destination.',
    )
  }

  const size = await measure(source.realPath)
  const displaced = collision
    ? await measure(finalPath)
    : { files: 0, bytes: 0, kind: 'none', symlinks: [] }
  const stamp = trashStamp(ctx.now())

  // A symlink inside the source cannot survive a cross-device move, and
  // relocate() throws when it reaches one. Refusing HERE rather than there is
  // the difference between a clean refusal and one raised after the existing
  // destination has already been displaced. Checked for every move, not only
  // cross-device ones, because whether two paths share a device is not
  // something the caller can see and a refusal that depends on it is worse
  // than one that does not.
  if (size.symlinks?.length && collision) {
    throw new ToolError(
      'symlink_in_tree',
      `Refused before changing anything: ${source.realPath} contains ` +
        `${size.symlinks.length} symlink(s), starting with ${size.symlinks[0]}. ` +
        'A move that also displaces an existing destination is not attempted with ' +
        'links in the tree, because a failure partway would leave both sides ' +
        'disturbed. Move the links yourself, or move to a destination that is empty.',
    )
  }

  const plan = {
    action: 'move',
    source: source.realPath,
    destination: finalPath,
    kind: size.kind,
    files: size.files,
    bytes: size.bytes,
    bytes_human: formatBytes(size.bytes),
    replaces_existing: collision,
    displaced: collision
      ? {
          kind: displaced.kind,
          files: displaced.files,
          bytes: displaced.bytes,
          bytes_human: formatBytes(displaced.bytes),
          moved_to_trash: trashDestination(finalResolved.root.realPath, finalPath, stamp),
        }
      : null,
  }

  if (!args.confirm) {
    return toolResult(
      `Planned (nothing changed): move ${size.kind} ${source.realPath} → ${finalPath} ` +
        `(${formatBytes(size.bytes)})` +
        (collision
          ? `. This DISPLACES an existing ${displaced.kind} of ${displaced.files} file(s), ` +
            `${formatBytes(displaced.bytes)}, which would be moved to the trash, not deleted`
          : '') +
        '. Call again with confirm: true to perform it.',
      { performed: false, ...plan },
    )
  }

  // Re-resolve immediately before the write. It does not close the
  // time-of-check/time-of-use window — nothing path-based can, and SECURITY.md
  // says so — but it narrows it from "however long measure() took on a large
  // tree" to the gap between these two statements.
  await resolveTarget(ctx.roots, finalPath, { what: 'destination' })

  let displacedTo = null
  if (collision) {
    displacedTo = trashDestination(finalResolved.root.realPath, finalPath, stamp)
    await mkdir(dirname(displacedTo), { recursive: true })
    await relocate(finalPath, displacedTo)
    await recordInManifest(
      finalResolved.root.realPath,
      stamp,
      [{ original_path: finalPath, trashed_to: displacedTo, bytes: displaced.bytes, reason: 'displaced by a move' }],
      ctx.now(),
    )
  }

  await mkdir(dirname(finalPath), { recursive: true })
  let method
  try {
    method = await relocate(source.realPath, finalPath)
  } catch (err) {
    // The destination was displaced a moment ago and the replacement did not
    // arrive. Put it back rather than leaving the user with an empty
    // destination and an error that reads as though nothing happened.
    if (displacedTo) {
      try {
        await relocate(displacedTo, finalPath)
        throw new ToolError(
          'move_failed_destination_restored',
          `The move failed (${err.message}). The item that was at ${finalPath} has ` +
            'been put back, and the source is untouched.',
        )
      } catch (restoreErr) {
        if (restoreErr instanceof ToolError && restoreErr.code === 'move_failed_destination_restored') {
          throw restoreErr
        }
        throw new ToolError(
          'move_failed_destination_in_trash',
          `The move failed (${err.message}) and the item that was at ${finalPath} ` +
            `could not be put back (${restoreErr.message}). It is NOT lost -- it is at ` +
            `${displacedTo} and recorded in the manifest beside it.`,
        )
      }
    }
    throw err
  }

  return toolResult(
    `Moved ${size.kind} ${source.realPath} → ${finalPath} (${formatBytes(size.bytes)}).` +
      (displacedTo
        ? ` The ${displaced.kind} that was there (${displaced.files} file(s), ` +
          `${formatBytes(displaced.bytes)}) was moved to ${displacedTo}, not deleted.`
        : ''),
    { performed: true, method, displaced_to: displacedTo, ...plan },
  )
}

export async function renameLocal(ctx, args) {
  const source = await resolveExisting(ctx.roots, args.path, { what: 'path' })
  const newName = String(args.new_name ?? '').trim()

  if (!newName || newName === '.' || newName === '..') {
    throw new ToolError('invalid_name', 'new_name must be a non-empty filename.')
  }
  if (newName.includes(sep) || newName.includes('/') || newName.includes('\0')) {
    throw new ToolError(
      'invalid_name',
      `new_name must be a bare filename, not a path; got ${JSON.stringify(newName)}. ` +
        'Use move_local to change a location.',
    )
  }

  const finalPath = join(dirname(source.realPath), newName)
  await resolveTarget(ctx.roots, finalPath, { what: 'new name' })

  if (await exists(finalPath)) {
    throw new ToolError(
      'destination_exists',
      `Refused: ${finalPath} already exists. Rename never replaces another file; ` +
        'move it out of the way first.',
    )
  }

  const plan = { action: 'rename', from: source.realPath, to: finalPath }
  if (!args.confirm) {
    return toolResult(
      `Planned (nothing changed): rename ${basename(source.realPath)} → ${newName} ` +
        `in ${dirname(source.realPath)}. Call again with confirm: true.`,
      { performed: false, ...plan },
    )
  }

  await rename(source.realPath, finalPath)
  return toolResult(`Renamed to ${finalPath}.`, { performed: true, ...plan })
}

export async function createLocalFolder(ctx, args) {
  const dest = await resolveTarget(ctx.roots, args.path, { what: 'folder' })

  if (dest.exists) {
    const st = await stat(dest.realPath)
    if (st.isDirectory()) {
      return toolResult(`${dest.realPath} already exists and is a directory.`, {
        performed: false,
        action: 'create_folder',
        path: dest.realPath,
        already_existed: true,
      })
    }
    throw new ToolError(
      'destination_exists',
      `Refused: ${dest.realPath} exists and is not a directory.`,
    )
  }

  const plan = { action: 'create_folder', path: dest.realPath }
  if (!args.confirm) {
    return toolResult(
      `Planned (nothing changed): create directory ${dest.realPath}. ` +
        'Call again with confirm: true.',
      { performed: false, ...plan },
    )
  }

  await mkdir(dest.realPath, { recursive: true })
  return toolResult(`Created ${dest.realPath}.`, { performed: true, ...plan })
}

/**
 * Move items into a trash directory inside their own root.
 *
 * Not a delete. The bytes stay on the same volume, which means this does not
 * free space until the user empties the trash themselves — stated in the
 * result, because a tool whose purpose is reclaiming space must not let anyone
 * believe it already has.
 */
export async function trashLocal(ctx, args) {
  const inputs = Array.isArray(args.paths) ? args.paths : [args.paths]
  if (!inputs.length) throw new ToolError('invalid_path', 'At least one path is required.')

  const stamp = trashStamp(ctx.now())
  const planned = []

  for (const input of inputs) {
    const item = await resolveExisting(ctx.roots, input, { what: 'path' })

    if (item.realPath === item.root.realPath) {
      throw new ToolError(
        'cannot_trash_root',
        `Refused: ${item.realPath} is a configured root. Trashing a root would ` +
          'move the whole allowed tree into a directory inside itself.',
      )
    }
    if (isInside(item.realPath, join(item.root.realPath, TRASH_DIR_NAME))) {
      throw new ToolError(
        'already_trashed',
        `Refused: ${item.realPath} is already in this server's trash.`,
      )
    }

    const size = await measure(item.realPath)
    planned.push({
      source: item.realPath,
      root: item.root.realPath,
      destination: trashDestination(item.root.realPath, item.realPath, stamp),
      kind: size.kind,
      files: size.files,
      bytes: size.bytes,
      bytes_human: formatBytes(size.bytes),
    })
  }

  const totalBytes = planned.reduce((n, p) => n + p.bytes, 0)
  const totalFiles = planned.reduce((n, p) => n + p.files, 0)

  if (!args.confirm) {
    return toolResult(
      `Planned (nothing changed): move ${planned.length} item(s), ${totalFiles} file(s), ` +
        `${formatBytes(totalBytes)} into ${TRASH_DIR_NAME}/${stamp}. Nothing is deleted ` +
        'and no space is freed until you empty that directory yourself. ' +
        'Call again with confirm: true.',
      { performed: false, action: 'trash', trash_stamp: stamp, items: planned },
    )
  }

  // The manifest is written after EACH item, not once at the end. Writing it
  // only after the loop meant a failure on item 2 left item 1 moved with no
  // record of where it came from — the one situation the manifest exists for.
  const moved = []
  const manifests = new Set()
  try {
    for (const p of planned) {
      await mkdir(dirname(p.destination), { recursive: true })
      const method = await relocate(p.source, p.destination)
      moved.push({ ...p, method })
      manifests.add(
        await recordInManifest(
          p.root,
          stamp,
          [{ original_path: p.source, trashed_to: p.destination, bytes: p.bytes }],
          ctx.now(),
        ),
      )
    }
  } catch (err) {
    throw new ToolError(
      'trash_partially_applied',
      `Stopped after moving ${moved.length} of ${planned.length} item(s): ` +
        `${err.message}. What was already moved IS recorded in ` +
        `${[...manifests].join(', ') || 'no manifest (nothing moved)'} and can be ` +
        'restored from there. Nothing was deleted.',
      { moved, manifests: [...manifests] },
    )
  }

  return toolResult(
    `Moved ${moved.length} item(s), ${totalFiles} file(s), ${formatBytes(totalBytes)} into ` +
      `${TRASH_DIR_NAME}/${stamp}. NOTHING WAS DELETED and no disk space has been ` +
      'freed — the files are still on the same volume. Delete that directory in ' +
      'your file manager when you are satisfied. A manifest.json beside them records ' +
      'where each came from.',
    {
      performed: true,
      action: 'trash',
      trash_stamp: stamp,
      space_freed_bytes: 0,
      space_recoverable_bytes: totalBytes,
      manifests: [...manifests],
      items: moved,
    },
  )
}

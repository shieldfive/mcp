// The four tools that change the filesystem.
//
// Three rules hold across all of them, and they are the reason this server is
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
//    the bytes survive and the manifest records where they were. trash.mjs
//    keeps the trash a real directory, on the item's own volume, with a
//    manifest written before anything moves.
//
// 3. A tool acts on the entry it was given. A symlink passed as the thing to
//    move, rename or trash is moved, renamed or trashed itself; its target is
//    never touched.
//
// The only thing of the user's ever removed is the source of a move that
// crosses a device, and only once its copy has been flushed and verified; see
// fsops.mjs. Everything else removed is this server's own temporary state.

import { lstat, mkdir, readdir } from 'node:fs/promises'
import { basename, dirname, join, sep } from 'node:path'

import { formatBytes, quote, toolResult } from '../format.mjs'
import {
  describeSpecial,
  moveFileAcrossDevices,
  moveTreeAcrossDevices,
  renameNoReplace,
} from '../fsops.mjs'
import { boundedList, LIMITS } from '../limits.mjs'
import { isInside, resolveDestination, resolveEntry, resolveTarget, ToolError } from '../roots.mjs'
import { TRASH_DIR_NAME } from '../scan.mjs'
import {
  batchName,
  discardBatch,
  inspectTrashDir,
  inTrash,
  makeParents,
  moveIntoTrash,
  openBatch,
  trashBaseFor,
  trashPaths,
  writeManifest,
} from '../trash.mjs'

export { trashStamp } from '../trash.mjs'

/** What an lstat says an entry is, in the words the previews use. */
function kindOf(stats) {
  if (stats.isSymbolicLink()) return 'symlink'
  if (stats.isDirectory()) return 'directory'
  if (stats.isFile()) return 'file'
  return 'special'
}

/**
 * Total bytes and file count beneath a path, for reporting before a move.
 *
 * lstat throughout: an item that is a symlink is measured as the link that
 * will move, not as the tree it points to.
 */
async function measure(path) {
  let st
  try {
    st = await lstat(path)
  } catch {
    return { files: 0, bytes: 0, kind: 'missing', symlinks: [], special: [] }
  }
  if (!st.isDirectory()) {
    return {
      files: st.isFile() ? 1 : 0,
      bytes: st.isFile() ? st.size : 0,
      kind: kindOf(st),
      symlinks: [],
      special: [],
    }
  }

  let files = 0
  let bytes = 0
  const symlinks = []
  const special = []
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
      else if (!e.isFile()) special.push(full)
      else {
        try {
          const s = await lstat(full)
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
  return { files, bytes, kind: 'directory', symlinks, special }
}

/**
 * Move without replacing anything, and across a device only by a verified copy.
 *
 * Returns how the item moved and, after a copy, the source entries left in
 * place because they changed once they had been copied.
 */
async function relocate(from, to, stats) {
  try {
    await renameNoReplace(from, to, stats)
    return { method: 'rename', leftInPlace: [] }
  } catch (err) {
    if (err.code !== 'EXDEV') throw err
  }
  if (stats.isFile()) {
    return { method: 'copy+remove', leftInPlace: await moveFileAcrossDevices(from, to, stats) }
  }
  if (stats.isDirectory()) {
    return { method: 'copy+remove', leftInPlace: await moveTreeAcrossDevices(from, to) }
  }
  throw new ToolError(
    'special_file',
    `Refused: ${quote(from)} is a ${describeSpecial(stats)}, and this move crosses a filesystem ` +
      'boundary, where it would have to be copied. Nothing was moved.',
  )
}

/** The device of `path`, or of its nearest existing ancestor. */
async function nearestDevice(path) {
  for (let dir = path; ; dir = dirname(dir)) {
    try {
      return (await lstat(dir)).dev
    } catch (err) {
      if (dirname(dir) === dir) throw err
    }
  }
}

export async function moveLocal(ctx, args) {
  const source = await resolveEntry(ctx.roots, args.source, { what: 'source' })
  const dest = await resolveDestination(ctx.roots, args.destination, { what: 'destination' })

  // A real directory at the destination means "move into it". A symlink there
  // is an entry in its own right: the source can replace the link, with
  // overwrite, but never lands wherever the link points.
  //
  // The final path is resolved before any guard runs. Checking the destination
  // argument alone missed the worst case: moving /root/sub onto its parent
  // /root gives a final path of /root/sub — the source itself — which the old
  // guard passed and the old overwrite branch then deleted.
  const finalPath = dest.stats?.isDirectory()
    ? join(dest.realPath, basename(source.realPath))
    : dest.realPath

  if (finalPath === source.realPath) {
    throw new ToolError(
      'destination_is_source',
      `Refused: that resolves to ${quote(finalPath)}, which is the source itself. ` +
        'Nothing to do.',
    )
  }
  if (isInside(finalPath, source.realPath)) {
    throw new ToolError(
      'destination_inside_source',
      `Refused: ${quote(finalPath)} is inside ${quote(source.realPath)}. Moving a directory ` +
        'into its own subtree is not a move.',
    )
  }

  const final = await resolveDestination(ctx.roots, finalPath, { what: 'destination' })
  const collision = final.stats !== null

  if (collision && !args.overwrite) {
    throw new ToolError(
      'destination_exists',
      `Refused: ${quote(finalPath)} already exists` +
        (final.stats.isSymbolicLink()
          ? ' as a symlink. The link itself would be replaced, not what it points to; to ' +
            'move into a directory a link points to, give that directory’s real path'
          : '') +
        '. Pass overwrite: true to move it to the trash and take its place, or choose a ' +
        'different destination.',
    )
  }

  const size = await measure(source.realPath)
  const displaced = collision
    ? await measure(finalPath)
    : { files: 0, bytes: 0, kind: 'none', symlinks: [] }

  // Where a displaced item would go, checked now so that an unsafe trash
  // directory is a refusal in the preview and not a failure halfway through.
  let trash = null
  if (collision) {
    const base = await trashBaseFor(final.root.realPath, finalPath, final.stats)
    await inspectTrashDir(base)
    const batch = batchName(ctx.now())
    trash = { base, batch, destination: trashPaths(base, batch, finalPath).destination }
  }

  // A symlink or a special file inside the source cannot survive a
  // cross-device move, and the copy refuses when it reaches one. Refusing HERE
  // is the difference between a clean refusal and one raised partway through.
  // It is checked for every move that displaces a destination, not only
  // cross-device ones, because whether two paths share a device is not
  // something the caller can see; and for any move that is known to cross one.
  const crossesDevice = source.stats.dev !== (await nearestDevice(dirname(finalPath)))
  const uncopyable = size.symlinks.length
    ? { code: 'symlink_in_tree', what: 'symlink(s)', list: size.symlinks }
    : size.special.length
      ? { code: 'special_file_in_tree', what: 'FIFO(s), socket(s) or device file(s)', list: size.special }
      : null
  if (uncopyable && (collision || crossesDevice)) {
    throw new ToolError(
      uncopyable.code,
      `Refused before changing anything: ${quote(source.realPath)} contains ` +
        `${uncopyable.list.length} ${uncopyable.what}, starting with ${quote(uncopyable.list[0])}. ` +
        (crossesDevice
          ? 'This move crosses a filesystem boundary, where it has to be a copy, and a copy ' +
            'cannot carry those. '
          : 'A move that also displaces an existing destination is not attempted with them ' +
            'in the tree, because a failure partway would leave both sides disturbed. ') +
        'Move them yourself, or move the rest without them.',
    )
  }
  if (crossesDevice && size.kind === 'special') {
    throw new ToolError(
      'special_file',
      `Refused: ${quote(source.realPath)} is a ${describeSpecial(source.stats)}, and this move ` +
        'crosses a filesystem boundary, where it would have to be copied. Nothing was moved.',
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
          moved_to_trash: trash.destination,
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
  const current = await resolveDestination(ctx.roots, finalPath, { what: 'destination' })
  if ((current.stats !== null) !== collision) {
    throw new ToolError(
      'destination_changed',
      `Refused: ${quote(finalPath)} ${collision ? 'disappeared' : 'appeared'} while this move ` +
        'was being planned. Nothing was moved; call again to see the new plan.',
    )
  }

  let displacedTo = null
  let batch = null
  if (collision) {
    // The manifest entry is written before the displaced item moves, so there
    // is no moment at which it is in the trash and recorded nowhere.
    batch = await openBatch(trash.base, trash.batch)
    batch.entries = [
      {
        original_path: finalPath,
        trashed_to: trash.destination,
        kind: displaced.kind,
        bytes: displaced.bytes,
        reason: 'displaced by a move',
      },
    ]
    try {
      await writeManifest(batch, ctx.now())
      await makeParents(batch, trash.destination)
      await moveIntoTrash(finalPath, trash.destination, current.stats)
    } catch (err) {
      await discardBatch(batch)
      throw err
    }
    displacedTo = trash.destination
  }

  await mkdir(dirname(finalPath), { recursive: true })
  let outcome
  try {
    outcome = await relocate(source.realPath, finalPath, source.stats)
  } catch (err) {
    // The destination was displaced a moment ago and the replacement did not
    // arrive. Put it back rather than leaving the user with an empty
    // destination and an error that reads as though nothing happened.
    if (displacedTo) {
      try {
        await renameNoReplace(displacedTo, finalPath, current.stats)
        await discardBatch(batch)
        throw new ToolError(
          'move_failed_destination_restored',
          `The move failed (${err.message}). The item that was at ${quote(finalPath)} has ` +
            'been put back, and the source is untouched.',
        )
      } catch (restoreErr) {
        if (restoreErr instanceof ToolError && restoreErr.code === 'move_failed_destination_restored') {
          throw restoreErr
        }
        throw new ToolError(
          'move_failed_destination_in_trash',
          `The move failed (${err.message}) and the item that was at ${quote(finalPath)} ` +
            `could not be put back (${restoreErr.message}). It is NOT lost -- it is at ` +
            `${quote(displacedTo)} and recorded in the manifest beside it.`,
        )
      }
    }
    throw err
  }

  const left = outcome.leftInPlace
  return toolResult(
    `Moved ${size.kind} ${source.realPath} → ${finalPath} (${formatBytes(size.bytes)}).` +
      (outcome.method === 'copy+remove'
        ? ' It crossed a filesystem boundary, so it was copied, and every file was flushed and ' +
          'verified by SHA-256 before its original was removed.'
        : '') +
      (left.length
        ? ` ${left.length} source item(s) changed or appeared during the move and were left ` +
          `where they were, starting with ${left[0]}.`
        : '') +
      (displacedTo
        ? ` The ${displaced.kind} that was there (${displaced.files} file(s), ` +
          `${formatBytes(displaced.bytes)}) was moved to ${displacedTo}, not deleted.`
        : ''),
    {
      performed: true,
      method: outcome.method,
      source_left_in_place: left,
      displaced_to: displacedTo,
      ...plan,
    },
  )
}

/**
 * new_name, exactly as given.
 *
 * Not trimmed: "b.txt " is a different name from "b.txt", and trimming turned a
 * rename to the first into a refusal about the second -- or, where no "b.txt"
 * existed, into a rename nobody asked for. Bounded in bytes, because a name
 * longer than any filesystem accepts used to come back whole in the error.
 */
function requireName(value) {
  if (typeof value !== 'string' || value === '' || value === '.' || value === '..') {
    throw new ToolError('invalid_name', 'new_name must be a non-empty filename.')
  }
  const bytes = Buffer.byteLength(value, 'utf8')
  if (bytes > LIMITS.nameBytes) {
    throw new ToolError(
      'invalid_name',
      `new_name is ${bytes.toLocaleString('en-US')} bytes; filesystems accept at most ` +
        `${LIMITS.nameBytes}. It starts ${quote(value, 60)}.`,
    )
  }
  if (value.includes(sep) || value.includes('/') || value.includes('\0')) {
    throw new ToolError(
      'invalid_name',
      `new_name must be a bare filename, not a path; got ${quote(value)}. ` +
        'Use move_local to change a location.',
    )
  }
  return value
}

export async function renameLocal(ctx, args) {
  const source = await resolveEntry(ctx.roots, args.path, { what: 'path' })
  const newName = requireName(args.new_name)

  const finalPath = join(dirname(source.realPath), newName)
  const final = await resolveDestination(ctx.roots, finalPath, { what: 'new name' })

  if (final.stats) {
    throw new ToolError(
      'destination_exists',
      `Refused: ${quote(finalPath)} already exists. Rename never replaces another file; ` +
        'move it out of the way first.',
    )
  }

  const plan = { action: 'rename', from: source.realPath, to: finalPath, kind: kindOf(source.stats) }
  if (!args.confirm) {
    return toolResult(
      `Planned (nothing changed): rename ${basename(source.realPath)} → ${newName} ` +
        `in ${dirname(source.realPath)}. Call again with confirm: true.`,
      { performed: false, ...plan },
    )
  }

  // The check above is for the preview. This is what keeps the promise: it
  // refuses if anything has appeared at the new name since.
  await renameNoReplace(source.realPath, finalPath, source.stats)
  return toolResult(`Renamed to ${finalPath}.`, { performed: true, ...plan })
}

export async function createLocalFolder(ctx, args) {
  const dest = await resolveTarget(ctx.roots, args.path, { what: 'folder' })

  if (dest.exists) {
    const st = await lstat(dest.realPath)
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
      `Refused: ${quote(dest.realPath)} exists and is not a directory.`,
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
 * Refuse a trash call that lists a path inside another path it also lists.
 *
 * The preview counted such an item twice, and a confirmed call moved the
 * folder and then failed on the file that had already gone with it.
 */
function refuseOverlaps(entries) {
  const listed = new Set(entries.map((e) => e.realPath))
  for (const e of entries) {
    for (let dir = dirname(e.realPath); isInside(dir, e.root.realPath); dir = dirname(dir)) {
      if (listed.has(dir)) {
        throw new ToolError(
          'overlapping_paths',
          `Refused before moving anything: ${quote(e.realPath)} is inside ${quote(dir)}, ` +
            'which is also listed. Trashing a folder takes everything in it; list one or the other.',
        )
      }
      if (dir === e.root.realPath) break
    }
  }
}

/**
 * Move items into this server's trash.
 *
 * Not a delete. The bytes stay on the same volume, which means this does not
 * free space until the user empties the trash themselves — stated in the
 * result, because a tool whose purpose is reclaiming space must not let anyone
 * believe it already has.
 */
export async function trashLocal(ctx, args) {
  const inputs = boundedList(args.paths, { name: 'paths', max: LIMITS.paths })
  const batch = batchName(ctx.now())

  // Every path is resolved before any is planned. A path given twice is taken
  // once.
  const entries = []
  const seen = new Set()
  for (const input of inputs) {
    const entry = await resolveEntry(ctx.roots, input, { what: 'path' })
    if (seen.has(entry.realPath)) continue
    seen.add(entry.realPath)
    entries.push(entry)
  }
  refuseOverlaps(entries)

  const planned = []
  for (const entry of entries) {
    if (entry.realPath === entry.root.realPath) {
      throw new ToolError(
        'cannot_trash_root',
        `Refused: ${quote(entry.realPath)} is a configured root. Trashing a root would ` +
          'move the whole allowed tree into a directory inside itself.',
      )
    }
    if (inTrash(entry.root.realPath, entry.realPath)) {
      throw new ToolError(
        'already_trashed',
        `Refused: ${quote(entry.realPath)} is already in this server's trash.`,
      )
    }
    const base = await trashBaseFor(entry.root.realPath, entry.realPath, entry.stats)
    await inspectTrashDir(base)
    planned.push({
      entry,
      base,
      destination: trashPaths(base, batch, entry.realPath).destination,
      size: await measure(entry.realPath),
    })
  }

  const items = planned.map((p) => ({
    source: p.entry.realPath,
    root: p.entry.root.realPath,
    trash_directory: join(p.base, TRASH_DIR_NAME),
    destination: p.destination,
    kind: p.size.kind,
    files: p.size.files,
    bytes: p.size.bytes,
    bytes_human: formatBytes(p.size.bytes),
  }))
  const totalBytes = items.reduce((n, i) => n + i.bytes, 0)
  const totalFiles = items.reduce((n, i) => n + i.files, 0)
  const repeated = inputs.length - entries.length
  const places = [...new Set(items.map((i) => i.trash_directory))]

  if (!args.confirm) {
    return toolResult(
      `Planned (nothing changed): move ${items.length} item(s), ${totalFiles} file(s), ` +
        `${formatBytes(totalBytes)} into a new batch in ${places.join(', ')}. Nothing is ` +
        'deleted and no space is freed until you empty that directory yourself.' +
        (repeated ? ` ${repeated} repeated path(s) are counted once.` : '') +
        ' Call again with confirm: true.',
      {
        performed: false,
        action: 'trash',
        trash_stamp: batch,
        repeated_paths_ignored: repeated,
        items,
        note:
          'The batch directory is named when the move is performed, so a confirmed ' +
          'call puts items in a batch with a different name from the one shown here.',
      },
    )
  }

  // One batch per trash directory, each with a manifest that lists its items
  // before any of them moves.
  const batches = new Map()
  const moved = []
  let failure = null
  for (const p of planned) {
    try {
      let b = batches.get(p.base)
      if (!b) {
        b = await openBatch(p.base, batch)
        batches.set(p.base, b)
        b.entries = planned.filter((q) => q.base === p.base).map(manifestEntry)
        await writeManifest(b, ctx.now())
      }
      await makeParents(b, p.destination)
      await moveIntoTrash(p.entry.realPath, p.destination, p.entry.stats)
      moved.push(p)
    } catch (err) {
      failure = err
      break
    }
  }

  if (failure) throw await trashFailure(failure, planned, moved, batches, ctx)

  return toolResult(
    `Moved ${moved.length} item(s), ${totalFiles} file(s), ${formatBytes(totalBytes)} into ` +
      `${TRASH_DIR_NAME}/${batch}${places.length > 1 ? ` in ${places.join(', ')}` : ''}. ` +
      'NOTHING WAS DELETED and no disk space has been freed — the files are still on the ' +
      'same volume. Delete that directory in your file manager when you are satisfied. A ' +
      'manifest.json beside them records where each came from.',
    {
      performed: true,
      action: 'trash',
      trash_stamp: batch,
      space_freed_bytes: 0,
      space_recoverable_bytes: totalBytes,
      repeated_paths_ignored: repeated,
      manifests: [...batches.values()].map((b) => b.manifest),
      items: items.map((i) => ({ ...i, trashed_to: i.destination, method: 'rename' })),
    },
  )
}

function manifestEntry(p) {
  return { original_path: p.entry.realPath, trashed_to: p.destination, kind: p.size.kind, bytes: p.size.bytes }
}

/**
 * The error for a trash call that stopped partway, after the manifests have
 * been brought into line with what moved.
 *
 * It says what moved and where, and `detail` carries the same as JSON. The old
 * message could say that a moved item "IS recorded in no manifest (nothing
 * moved)", and the detail never reached the client.
 */
async function trashFailure(failure, planned, moved, batches, ctx) {
  const stale = []
  for (const b of batches.values()) {
    const here = moved.filter((p) => p.base === b.base)
    try {
      if (here.length === 0) {
        await discardBatch(b)
      } else if (here.length !== b.entries.length) {
        b.entries = here.map(manifestEntry)
        await writeManifest(b, ctx.now())
      }
    } catch {
      stale.push(b.manifest)
    }
  }

  const manifests = [...batches.values()]
    .filter((b) => moved.some((p) => p.base === b.base))
    .map((b) => b.manifest)
  const detail = {
    moved: moved.map((p) => ({ original_path: p.entry.realPath, trashed_to: p.destination })),
    not_moved: planned.filter((p) => !moved.includes(p)).map((p) => p.entry.realPath),
    manifests,
  }

  if (moved.length === 0) {
    return new ToolError(
      failure instanceof ToolError ? failure.code : 'trash_failed',
      `Nothing was moved to the trash: ${failure.message}`,
      detail,
    )
  }

  const shown = detail.moved.slice(0, 10).map((m) => `${m.original_path} → ${m.trashed_to}`)
  return new ToolError(
    'trash_partially_applied',
    `Stopped after moving ${moved.length} of ${planned.length} item(s): ${failure.message}. ` +
      `Moved, and recorded in ${manifests.join(', ')}: ${shown.join('; ')}` +
      `${moved.length > shown.length ? `; and ${moved.length - shown.length} more` : ''}. ` +
      (stale.length
        ? `${stale.join(', ')} could not be brought up to date and also lists items that ` +
          'were not moved; an entry whose trashed_to does not exist was not moved. '
        : '') +
      'Nothing was deleted, and the items that were not moved are where they were.',
    detail,
  )
}

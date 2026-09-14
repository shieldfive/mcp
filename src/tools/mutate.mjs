// The four tools that change the filesystem.
//
// Two rules hold across all of them, and they are the reason this server is
// safe to point at a real home directory.
//
// 1. Nothing happens without `confirm: true`. Called without it, each tool
//    resolves the paths, checks containment, reports exactly what it WOULD do,
//    and returns. That preview is not advisory — it is the same code path, so a
//    plan that reports a refusal is a refusal.
//
// 2. Nothing is ever unlinked. `trash_local` MOVES into a trash directory
//    inside the same root and writes a manifest that names where each item came
//    from. Deleting for real stays a decision the user makes in their own file
//    manager, with their own undo.

import { copyFile, mkdir, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import { basename, dirname, join, relative, sep } from 'node:path'

import { formatBytes, toolResult } from '../format.mjs'
import { isInside, resolveExisting, resolveTarget, ToolError } from '../roots.mjs'
import { TRASH_DIR_NAME } from '../scan.mjs'

/** Total bytes and file count beneath a path, for reporting before a move. */
async function measure(path) {
  const st = await stat(path)
  if (st.isFile()) return { files: 1, bytes: st.size, kind: 'file' }

  let files = 0
  let bytes = 0
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
      if (e.isSymbolicLink()) continue
      if (e.isDirectory()) queue.push(full)
      else if (e.isFile()) {
        try {
          const s = await stat(full)
          files++
          bytes += s.size
        } catch {
          /* counted as unreadable by the caller's scan, not here */
        }
      }
    }
  }
  return { files, bytes, kind: 'directory' }
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

  await mkdir(to, { recursive: true })
  const entries = await readdir(from, { withFileTypes: true })
  for (const e of entries) {
    if (e.isSymbolicLink()) {
      throw new ToolError(
        'symlink_in_tree',
        `Refused: ${join(from, e.name)} is a symlink, and this move crosses a ` +
          'filesystem boundary so it cannot be preserved. Move it yourself or ' +
          'remove the link first.',
      )
    }
    await relocate(join(from, e.name), join(to, e.name))
  }
  await rm(from, { recursive: true })
  return 'copy+remove'
}

async function exists(path) {
  try {
    await stat(path)
    return true
  } catch {
    return false
  }
}

export async function moveLocal(ctx, args) {
  const source = await resolveExisting(ctx.roots, args.source, { what: 'source' })
  const dest = await resolveTarget(ctx.roots, args.destination, { what: 'destination' })

  // Moving a directory into itself silently destroys it on some platforms.
  if (isInside(dest.realPath, source.realPath)) {
    throw new ToolError(
      'destination_inside_source',
      `Refused: ${args.destination} is inside ${args.source}. Moving a directory ` +
        'into its own subtree is not a move.',
    )
  }

  const finalPath = dest.exists && (await stat(dest.realPath)).isDirectory()
    ? join(dest.realPath, basename(source.realPath))
    : dest.realPath

  // Re-check: joining a basename onto a directory produced a new path.
  await resolveTarget(ctx.roots, finalPath, { what: 'destination' })

  const collision = await exists(finalPath)
  if (collision && !args.overwrite) {
    throw new ToolError(
      'destination_exists',
      `Refused: ${finalPath} already exists. Pass overwrite: true to replace it, ` +
        'or choose a different destination.',
    )
  }

  const size = await measure(source.realPath)
  const plan = {
    action: 'move',
    source: source.realPath,
    destination: finalPath,
    kind: size.kind,
    files: size.files,
    bytes: size.bytes,
    bytes_human: formatBytes(size.bytes),
    replaces_existing: collision,
  }

  if (!args.confirm) {
    return toolResult(
      `Planned (nothing changed): move ${size.kind} ${source.realPath} → ${finalPath}` +
        `${collision ? ', REPLACING what is there' : ''}. ` +
        'Call again with confirm: true to perform it.',
      { performed: false, ...plan },
    )
  }

  if (collision && args.overwrite) await rm(finalPath, { recursive: true, force: true })
  await mkdir(dirname(finalPath), { recursive: true })
  const method = await relocate(source.realPath, finalPath)

  return toolResult(
    `Moved ${size.kind} ${source.realPath} → ${finalPath} (${formatBytes(size.bytes)}).`,
    { performed: true, method, ...plan },
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

  const collision = await exists(finalPath)
  if (collision) {
    throw new ToolError(
      'destination_exists',
      `Refused: ${finalPath} already exists. Rename is never allowed to replace ` +
        'another file; move it out of the way first.',
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
 * Not a delete. The bytes are still on the same volume, which means this does
 * not free space until the user empties the trash themselves — stated in the
 * result, because a tool whose whole purpose is reclaiming space must not let
 * anyone believe it already has.
 */
export async function trashLocal(ctx, args) {
  const inputs = Array.isArray(args.paths) ? args.paths : [args.paths]
  if (!inputs.length) throw new ToolError('invalid_path', 'At least one path is required.')

  const stamp = new Date(ctx.now()).toISOString().replace(/[:.]/g, '-')
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

    const trashBase = join(item.root.realPath, TRASH_DIR_NAME, stamp)
    if (isInside(item.realPath, join(item.root.realPath, TRASH_DIR_NAME))) {
      throw new ToolError(
        'already_trashed',
        `Refused: ${item.realPath} is already in this server's trash.`,
      )
    }

    const size = await measure(item.realPath)
    planned.push({
      source: item.realPath,
      destination: join(trashBase, relative(item.root.realPath, item.realPath)),
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

  const moved = []
  for (const p of planned) {
    await mkdir(dirname(p.destination), { recursive: true })
    const method = await relocate(p.source, p.destination)
    moved.push({ ...p, method })
  }

  // The manifest is what makes this reversible without this server.
  const manifests = new Map()
  for (const m of moved) {
    const trashRoot = m.destination.slice(0, m.destination.indexOf(sep + TRASH_DIR_NAME + sep))
    const manifestPath = join(trashRoot, TRASH_DIR_NAME, stamp, 'manifest.json')
    const list = manifests.get(manifestPath) ?? []
    list.push({ original_path: m.source, trashed_to: m.destination, bytes: m.bytes })
    manifests.set(manifestPath, list)
  }
  for (const [path, items] of manifests) {
    await writeFile(
      path,
      JSON.stringify(
        {
          created: new Date(ctx.now()).toISOString(),
          note:
            'Written by @shieldfive/mcp trash_local. Nothing here is deleted. ' +
            'To restore an entry, move trashed_to back to original_path.',
          items,
        },
        null,
        2,
      ),
      'utf8',
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
      manifests: [...manifests.keys()],
      items: moved,
    },
  )
}

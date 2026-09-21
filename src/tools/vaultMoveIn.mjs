// vault_move_in — the whole "free up space" move, with one approval.
//
// For each file, in order:
//   1. encrypt it here and upload it (vault_upload's own path);
//   2. READ IT BACK out of the vault, decrypt it and compare the SHA-256 to the
//      bytes that were read off disk;
//   3. only then move the local original into this server's trash — the same
//      .shieldfive-mcp-trash directory and manifest trash_local uses — after
//      checking it is still the file that was read (same inode, size, mtime).
//
// NOTHING IS DELETED. The original sits in the local trash, on its own volume,
// with a manifest naming where it came from and which vault file holds its
// verified copy; the user frees the space by emptying that directory. That is
// the same line every local tool in this server holds, and it is what makes
// "the assistant cleaned up my disk" safe to say yes to.
//
// The first failure stops the batch. Files before it are done (uploaded,
// verified, trashed); the failing file and every file after it are left where
// they are. A file whose upload verified but whose trash move failed is
// reported as such: it is safely in the vault AND still on disk.

import { displayName } from '../vault/session.mjs'
import { formatBytes, quote } from '../format.mjs'
import { requireApprovedPlan } from '../plans.mjs'
import { ToolError } from '../roots.mjs'
import {
  destinationFolder,
  refuseTooLarge,
  requireWriteView,
  result,
  uploadVerified,
  validName,
} from './vaultUpload.mjs'

/** Most files one approval covers. Each is a full upload and read-back. */
export const MOVE_MAX_FILES = 50

async function plan(ctx, view, args) {
  if (!Array.isArray(args.paths) || args.paths.length === 0) {
    throw new ToolError('bad_request', 'Name at least one file to move.')
  }
  if (args.paths.length > MOVE_MAX_FILES) {
    throw new ToolError(
      'too_many_items',
      `At most ${MOVE_MAX_FILES} files per call; split the rest into another call.`,
    )
  }
  const { folder, folderKey } = destinationFolder(view, args.destination_folder_id)

  const items = []
  const seenPaths = new Set()
  const seenNames = new Map()
  for (const input of args.paths) {
    const local = await ctx.localFiles.describe(input)
    if (seenPaths.has(local.path)) continue
    seenPaths.add(local.path)
    refuseTooLarge(local)
    const name = validName(undefined, local.name)
    // Two files with one name would land as two indistinguishable entries in
    // the folder. Refused here rather than renamed behind the user's back.
    if (seenNames.has(name)) {
      throw new ToolError(
        'duplicate_name',
        `${quote(local.path)} and ${quote(seenNames.get(name))} would both be named ` +
          `${quote(name)} in the vault folder. Move them in separate calls or rename one first.`,
      )
    }
    seenNames.set(name, local.path)
    const { trashDirectory } = await ctx.localFiles.trashPlan(local.path)
    items.push({
      source: local.path,
      entry: local.entry,
      bytes: local.size,
      name,
      vault_path: `${folder.path}/${displayName(name)}`,
      trash_directory: trashDirectory,
    })
  }

  const totalBytes = items.reduce((n, i) => n + i.bytes, 0)
  // Ciphertext is a little larger than the file, so this is a floor: over it
  // is certain to fail, under it may still run out near the end.
  const budget = view.grant.writeBudget
  const remaining = budget ? budget.bytes - budget.usedBytes : null
  if (remaining !== null && totalBytes > remaining) {
    throw new ToolError(
      'write_budget_exhausted',
      `These files total ${formatBytes(totalBytes)}, and this connection has ` +
        `${formatBytes(Math.max(0, remaining))} of its upload allowance left. Nothing was ` +
        'moved. Move fewer files, or ask the owner for a connection with a larger allowance.',
    )
  }

  return {
    folder,
    folderKey,
    items,
    totalBytes,
    remaining,
    fingerprint: {
      op: 'vault_move_in',
      destination: folder.id,
      items: items.map(({ source, entry, bytes, name, trash_directory }) => ({
        source,
        entry,
        bytes,
        name,
        trash_directory,
      })),
    },
  }
}

export async function vaultMoveIn(ctx, args) {
  const view = await requireWriteView(ctx)
  const p = await plan(ctx, view, args)
  const places = [...new Set(p.items.map((i) => i.trash_directory))]

  if (!args.confirm) {
    return result(
      `Would move ${p.items.length} file(s), ${formatBytes(p.totalBytes)}, into ${p.folder.path}: ` +
        'each is encrypted on this machine, uploaded, read back and compared byte for byte, and ' +
        `only then moved to the local trash in ${places.join(', ')}. Nothing is deleted; the space ` +
        'is freed when the user empties that directory. A file that fails stops the batch and ' +
        'stays where it is. Show this to the user, then call again with confirm: true and this plan_token.',
      {
        performed: false,
        destination: p.folder.path,
        files: p.items.map(({ source, bytes, vault_path, trash_directory }) => ({
          source,
          bytes,
          bytes_human: formatBytes(bytes),
          vault_path,
          trash_directory,
        })),
        total_bytes: p.totalBytes,
        ...(p.remaining !== null ? { upload_allowance_left_bytes: p.remaining } : {}),
        plan_token: ctx.plans.issue(p.fingerprint),
      },
    )
  }
  requireApprovedPlan(ctx, args.plan_token, p.fingerprint)

  const trash = ctx.localFiles.openTrash()
  const moved = []
  let inVaultStillLocal = null
  let failure = null
  let failedAt = null
  const total = p.items.length * 4
  for (const [i, item] of p.items.entries()) {
    if (ctx.signal?.aborted) {
      failure = new ToolError('cancelled', 'The request was cancelled.')
      failedAt = i
      break
    }
    let up = null
    try {
      const local = await ctx.localFiles.describe(item.source)
      if (local.entry !== item.entry) {
        throw new ToolError(
          'changed',
          `${quote(item.source)} changed since the plan was made. It was not uploaded.`,
        )
      }
      up = await uploadVerified(
        ctx,
        view,
        { local, folder: p.folder, folderKey: p.folderKey, name: item.name },
        (n, label) => ctx.progress?.(i * 4 + n, total, `${item.name}: ${label}`),
      )
      const t = await trash.trash(local.path, item.entry, {
        vault_file_id: up.fileId,
        vault_path: item.vault_path,
        sha256: up.sha256,
      })
      moved.push({
        source: item.source,
        bytes: item.bytes,
        vault_file_id: up.fileId,
        vault_path: item.vault_path,
        sha256: up.sha256,
        trashed_to: t.trashedTo,
      })
    } catch (err) {
      failure = err
      failedAt = i
      if (up) {
        inVaultStillLocal = {
          source: item.source,
          vault_file_id: up.fileId,
          vault_path: item.vault_path,
        }
      }
      break
    }
  }

  const freedLater = moved.reduce((n, m) => n + m.bytes, 0)
  const report = {
    performed: moved.length > 0,
    moved,
    trash_batch: trash.batch,
    space_freed_bytes: 0,
    space_recoverable_bytes: freedLater,
  }
  if (!failure) {
    return result(
      `Moved ${moved.length} file(s), ${formatBytes(freedLater)}, into ${p.folder.path}. Every one was ` +
        'read back from the vault and matched the file on disk byte for byte before its original was ' +
        `moved to the local trash (${places.join(', ')}, batch ${trash.batch}). NOTHING WAS DELETED: ` +
        `the ${formatBytes(freedLater)} is freed when the user empties that directory. A manifest.json ` +
        'there records where each file came from and which vault file holds its copy.',
      report,
    )
  }

  const untouched = p.items.slice(failedAt + (inVaultStillLocal ? 1 : 0)).map((i) => i.source)
  throw new ToolError(
    failure.code ?? 'move_failed',
    `Stopped after ${moved.length} of ${p.items.length} file(s): ${failure.message} ` +
      (inVaultStillLocal
        ? `${quote(inVaultStillLocal.source)} IS in the vault and verified, but its original was not ` +
          'moved to the trash and is still on disk. '
        : '') +
      `${untouched.length} file(s) were left exactly where they were.` +
      (moved.length
        ? ` The ${moved.length} moved before it are verified in the vault and in the local trash.`
        : ''),
    { ...report, in_vault_and_still_on_disk: inVaultStillLocal, untouched },
  )
}

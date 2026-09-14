// The five read-only tools. None of these writes anything.

import { basename, dirname } from 'node:path'

import { daysAgo, formatBytes, formatDate, scanWarnings, toolResult } from '../format.mjs'
import { resolveExisting, ToolError } from '../roots.mjs'
import { hashFile, walkRoots } from '../scan.mjs'

/** Resolve an optional `path` argument to the set of trees to walk. */
async function targets(ctx, path) {
  if (!path) {
    if (!ctx.roots.length) throw new ToolError('no_roots', ctx.noRootsMessage)
    return ctx.roots
  }
  const { realPath } = await resolveExisting(ctx.roots, path, { what: 'path' })
  return [{ realPath, configured: path }]
}

function scanOptions(args) {
  return {
    includeHidden: args.include_hidden ?? false,
    maxFiles: args.max_files ?? 200_000,
  }
}

export async function listLocal(ctx, args) {
  const roots = await targets(ctx, args.path)
  const { files, perRoot } = await walkRoots(roots, scanOptions(args))

  const sorted = files.sort((a, b) =>
    args.sort_by === 'size'
      ? b.size - a.size
      : args.sort_by === 'modified'
        ? b.mtimeMs - a.mtimeMs
        : a.path.localeCompare(b.path),
  )
  const limit = args.limit ?? 200
  const shown = sorted.slice(0, limit)
  const totalBytes = files.reduce((n, f) => n + f.size, 0)
  const warnings = scanWarnings(perRoot)

  return toolResult(
    `${files.length.toLocaleString()} file(s), ${formatBytes(totalBytes)}. ` +
      `Showing ${shown.length}${files.length > shown.length ? ` of ${files.length} (limit ${limit})` : ''}.` +
      (warnings.length ? ` ${warnings.join(' ')}` : ''),
    {
      scanned: roots.map((r) => r.realPath),
      total_files: files.length,
      total_bytes: totalBytes,
      shown: shown.length,
      omitted_by_limit: Math.max(0, files.length - shown.length),
      warnings,
      files: shown.map((f) => ({
        path: f.path,
        size: f.size,
        size_human: formatBytes(f.size),
        modified: formatDate(f.mtimeMs),
      })),
    },
  )
}

export async function findLargeFiles(ctx, args) {
  const roots = await targets(ctx, args.path)
  const threshold = args.min_bytes ?? 100_000_000
  const { files, perRoot } = await walkRoots(roots, scanOptions(args))

  const big = files.filter((f) => f.size >= threshold).sort((a, b) => b.size - a.size)
  const limit = args.limit ?? 100
  const shown = big.slice(0, limit)
  const warnings = scanWarnings(perRoot)

  return toolResult(
    `${big.length} file(s) at or above ${formatBytes(threshold)}, ` +
      `${formatBytes(big.reduce((n, f) => n + f.size, 0))} in total.` +
      (warnings.length ? ` ${warnings.join(' ')}` : ''),
    {
      scanned: roots.map((r) => r.realPath),
      threshold_bytes: threshold,
      match_count: big.length,
      matched_bytes: big.reduce((n, f) => n + f.size, 0),
      shown: shown.length,
      omitted_by_limit: Math.max(0, big.length - shown.length),
      warnings,
      files: shown.map((f) => ({
        path: f.path,
        size: f.size,
        size_human: formatBytes(f.size),
        modified: formatDate(f.mtimeMs),
      })),
    },
  )
}

export async function findOldFiles(ctx, args) {
  const roots = await targets(ctx, args.path)
  const days = args.older_than_days ?? 365
  const now = ctx.now()
  const cutoff = now - days * 86_400_000
  const { files, perRoot } = await walkRoots(roots, scanOptions(args))

  const old = files.filter((f) => f.mtimeMs < cutoff).sort((a, b) => a.mtimeMs - b.mtimeMs)
  const limit = args.limit ?? 100
  const shown = old.slice(0, limit)
  const warnings = scanWarnings(perRoot)
  warnings.push(
    'Modification time is not evidence a file is unwanted, and on some copy ' +
      'operations it is reset to the copy date. Treat this as a shortlist to review.',
  )

  return toolResult(
    `${old.length} file(s) unmodified for more than ${days} day(s), ` +
      `${formatBytes(old.reduce((n, f) => n + f.size, 0))} in total.`,
    {
      scanned: roots.map((r) => r.realPath),
      older_than_days: days,
      match_count: old.length,
      matched_bytes: old.reduce((n, f) => n + f.size, 0),
      shown: shown.length,
      omitted_by_limit: Math.max(0, old.length - shown.length),
      warnings,
      files: shown.map((f) => ({
        path: f.path,
        size: f.size,
        size_human: formatBytes(f.size),
        modified: formatDate(f.mtimeMs),
        days_since_modified: daysAgo(f.mtimeMs, now),
      })),
    },
  )
}

export async function storageSummary(ctx, args) {
  const roots = await targets(ctx, args.path)
  const { files, perRoot } = await walkRoots(roots, scanOptions(args))

  const byExtension = new Map()
  const byDirectory = new Map()
  for (const f of files) {
    const ext = f.extension || '(no extension)'
    const e = byExtension.get(ext) ?? { count: 0, bytes: 0 }
    e.count++
    e.bytes += f.size
    byExtension.set(ext, e)

    const dir = dirname(f.path)
    const d = byDirectory.get(dir) ?? { count: 0, bytes: 0 }
    d.count++
    d.bytes += f.size
    byDirectory.set(dir, d)
  }

  const top = (map, n) =>
    [...map.entries()]
      .sort((a, b) => b[1].bytes - a[1].bytes)
      .slice(0, n)
      .map(([key, v]) => ({
        key,
        count: v.count,
        bytes: v.bytes,
        bytes_human: formatBytes(v.bytes),
      }))

  const totalBytes = files.reduce((n, f) => n + f.size, 0)
  const warnings = scanWarnings(perRoot)

  return toolResult(
    `${files.length.toLocaleString()} file(s), ${formatBytes(totalBytes)} across ` +
      `${roots.length} location(s).` + (warnings.length ? ` ${warnings.join(' ')}` : ''),
    {
      scanned: roots.map((r) => r.realPath),
      total_files: files.length,
      total_bytes: totalBytes,
      total_bytes_human: formatBytes(totalBytes),
      warnings,
      per_root: perRoot.map((r) => ({
        root: r.root,
        files: r.files,
        directories: r.directories,
        truncated: r.truncated,
      })),
      largest_by_extension: top(byExtension, args.limit ?? 15),
      largest_directories: top(byDirectory, args.limit ?? 15),
      note:
        'Sizes are what the filesystem reports for file contents. They exclude ' +
        'directory overhead and do not account for filesystem compression, ' +
        'sparse files or APFS clones, so this will not match a disk utility exactly.',
    },
  )
}

/**
 * Duplicate detection.
 *
 * Three passes, narrowing: group by size, then by a hash of the first 64 KiB,
 * then by a full-content hash. Only the full hash decides. Name is never an
 * input — two files with the same name and size are routinely different files,
 * and acting on that guess deletes the wrong copy.
 */
export async function findDuplicates(ctx, args) {
  const roots = await targets(ctx, args.path)
  const minSize = args.min_bytes ?? 1
  const { files, perRoot } = await walkRoots(roots, scanOptions(args))

  const candidates = files.filter((f) => f.size >= minSize && f.size > 0)

  const bySize = new Map()
  for (const f of candidates) {
    const list = bySize.get(f.size) ?? []
    list.push(f)
    bySize.set(f.size, list)
  }
  const sizeGroups = [...bySize.values()].filter((g) => g.length > 1)

  const hashBudget = args.max_files_hashed ?? 20_000
  let hashed = 0
  let hashBudgetHit = false
  const unreadable = []

  const headGroups = []
  for (const group of sizeGroups) {
    if (hashed + group.length > hashBudget) {
      hashBudgetHit = true
      continue
    }
    const byHead = new Map()
    for (const f of group) {
      let head
      try {
        head = await hashFile(f.path, { limit: 65_536 })
      } catch (err) {
        unreadable.push({ path: f.path, code: err.code ?? 'EREAD' })
        continue
      }
      hashed++
      const list = byHead.get(head) ?? []
      list.push(f)
      byHead.set(head, list)
    }
    for (const g of byHead.values()) if (g.length > 1) headGroups.push(g)
  }

  const byFull = new Map()
  for (const group of headGroups) {
    for (const f of group) {
      let full
      try {
        full = await hashFile(f.path)
      } catch (err) {
        unreadable.push({ path: f.path, code: err.code ?? 'EREAD' })
        continue
      }
      const list = byFull.get(full) ?? []
      list.push(f)
      byFull.set(full, list)
    }
  }

  const duplicates = [...byFull.entries()]
    .filter(([, group]) => group.length > 1)
    .map(([digest, group]) => {
      const ordered = [...group].sort((a, b) => a.mtimeMs - b.mtimeMs)
      const [keep, ...redundant] = ordered
      return {
        sha256: digest,
        size: keep.size,
        size_human: formatBytes(keep.size),
        copies: ordered.length,
        reclaimable_bytes: keep.size * redundant.length,
        oldest_copy: { path: keep.path, modified: formatDate(keep.mtimeMs) },
        other_copies: redundant.map((f) => ({
          path: f.path,
          modified: formatDate(f.mtimeMs),
        })),
        names_differ: new Set(ordered.map((f) => basename(f.path))).size > 1,
      }
    })
    .sort((a, b) => b.reclaimable_bytes - a.reclaimable_bytes)

  const reclaimable = duplicates.reduce((n, d) => n + d.reclaimable_bytes, 0)
  const warnings = scanWarnings(perRoot)
  if (hashBudgetHit) {
    warnings.push(
      `The hash budget of ${hashBudget.toLocaleString()} files was reached, so some ` +
        'same-size groups were never hashed and are NOT represented below. This ' +
        'result is a lower bound — raise max_files_hashed for a complete answer.',
    )
  }
  if (unreadable.length) {
    warnings.push(`${unreadable.length} file(s) could not be read and were not compared.`)
  }

  const limit = args.limit ?? 100
  return toolResult(
    `${duplicates.length} duplicate group(s), ${formatBytes(reclaimable)} reclaimable ` +
      `by keeping one copy of each. Every match is confirmed by a full SHA-256 of the ` +
      `file contents.` + (warnings.length ? ` ${warnings.join(' ')}` : ''),
    {
      scanned: roots.map((r) => r.realPath),
      files_considered: candidates.length,
      files_hashed: hashed,
      duplicate_groups: duplicates.length,
      reclaimable_bytes: reclaimable,
      reclaimable_human: formatBytes(reclaimable),
      shown: Math.min(limit, duplicates.length),
      omitted_by_limit: Math.max(0, duplicates.length - limit),
      warnings,
      unreadable,
      method:
        'Grouped by exact byte size, then by SHA-256 of the first 64 KiB, then ' +
        'confirmed by SHA-256 of the entire file. Filenames are not used to decide ' +
        'identity; `names_differ` is reported only so you can see when copies were renamed.',
      groups: duplicates.slice(0, limit),
    },
  )
}

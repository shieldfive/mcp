// The read-only tools. Mutations live in mutate.mjs.

import { basename, dirname } from 'node:path'

import { daysAgo, formatBytes, formatDate, scanWarnings, toolResult } from '../format.mjs'
import { isInside, resolveExisting, ToolError } from '../roots.mjs'
import { hashFile, walkRoots } from '../scan.mjs'

/** Resolve an optional `path` argument to the set of trees to walk. */
async function targets(ctx, path) {
  // `path === ''` used to take the same branch as an omitted path and scan
  // EVERY root. A model that builds the argument by concatenation and produces
  // '' would get a whole-machine scan reported as the narrow one it asked for.
  if (path === '') {
    throw new ToolError(
      'invalid_path',
      'path was an empty string. Omit it to scan every configured root, or give ' +
        'an absolute path; an empty string is not a request for either.',
    )
  }
  if (!path) {
    if (!ctx.roots.length) throw new ToolError('no_roots', ctx.noRootsMessage)
    return ctx.roots
  }
  const { realPath } = await resolveExisting(ctx.roots, path, { what: 'path' })
  return [{ realPath, configured: path }]
}

function scanOptions(args, ctx) {
  return {
    includeHidden: args.include_hidden ?? false,
    maxFiles: args.max_files ?? 200_000,
    // Plumbed so a cancelled request stops the walk. Without it the SDK's abort
    // signal was accepted and dropped, and a cancelled scan of a large tree ran
    // to completion burning CPU nobody was waiting for.
    signal: ctx?.signal,
  }
}

export async function listLocal(ctx, args) {
  const roots = await targets(ctx, args.path)
  const { files, perRoot } = await walkRoots(roots, scanOptions(args, ctx))

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
  const { files, perRoot } = await walkRoots(roots, scanOptions(args, ctx))

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
  const { files, perRoot } = await walkRoots(roots, scanOptions(args, ctx))

  const old = files.filter((f) => f.mtimeMs < cutoff).sort((a, b) => a.mtimeMs - b.mtimeMs)
  const limit = args.limit ?? 100
  const shown = old.slice(0, limit)
  const warnings = scanWarnings(perRoot)
  warnings.push(
    'Modification time is not evidence a file is unwanted, and on some copy ' +
      'operations it is reset to the copy date. Treat this as a shortlist to review.',
  )

  // Every other read tool appends its warnings to the summary line. This one
  // did not, so a truncated scan AND its own "mtime is a weak signal" caveat
  // reached only the JSON payload -- not the line a model actually quotes.
  return toolResult(
    `${old.length} file(s) unmodified for more than ${days} day(s), ` +
      `${formatBytes(old.reduce((n, f) => n + f.size, 0))} in total.` +
      (warnings.length ? ` ${warnings.join(' ')}` : ''),
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
  const { files, perRoot } = await walkRoots(roots, scanOptions(args, ctx))

  const byExtension = new Map()
  const byDirectory = new Map()
  for (const f of files) {
    const ext = f.extension || '(no extension)'
    const e = byExtension.get(ext) ?? { count: 0, bytes: 0 }
    e.count++
    e.bytes += f.size
    byExtension.set(ext, e)

    // Credit every ancestor up to the root, not just the immediate parent.
    // Crediting only dirname() answers "which leaf folder holds the most bytes",
    // so a 900 MB Movies/ split across nine subfolders never appeared while a
    // single flat 200 MB folder ranked first -- the opposite of the question a
    // storage summary is asked.
    const root = f.root ?? roots[0].realPath
    let dir = dirname(f.path)
    for (;;) {
      const d = byDirectory.get(dir) ?? { count: 0, bytes: 0 }
      d.count++
      d.bytes += f.size
      byDirectory.set(dir, d)
      if (dir === root || !isInside(dir, root)) break
      const parent = dirname(dir)
      if (parent === dir) break
      dir = parent
    }
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
        'sparse files or APFS clones, so this will not match a disk utility exactly. ' +
        'largest_directories counts each file against every ancestor directory, so ' +
        'a parent and its child both appear and their totals overlap by design.',
    },
  )
}

/**
 * Duplicate detection.
 *
 * Narrowing passes: group by exact size, then — for files large enough for it
 * to mean anything — by a hash of the first 64 KiB, then confirm every survivor
 * with a full-content hash. Only the full hash decides. Name is never an input:
 * two files with the same name and size are routinely different files, and
 * acting on that guess deletes the wrong copy.
 *
 * The hashing budget counts EVERY read, head and full. It used to count only
 * the head pass, so a budget of 300 permitted 300 head reads of 64 KiB plus 300
 * unbounded whole-file reads — on 4 MB files, 61x the work the number implied.
 *
 * Groups are processed in descending order of what they could reclaim, and the
 * budget is spent per file rather than per group. The old all-or-nothing gate
 * skipped a group entirely if it did not fit, and since a group is large
 * precisely because it has many copies, the budget was biased against the
 * groups worth the most.
 */
export async function findDuplicates(ctx, args) {
  const HEAD_WINDOW = 65_536
  const roots = await targets(ctx, args.path)
  const minSize = args.min_bytes ?? 1
  const { files, perRoot } = await walkRoots(roots, scanOptions(args, ctx))

  // A zero-byte file is identical to every other zero-byte file, which is true
  // and useless. Excluded unless min_bytes: 0 asks for them explicitly, and
  // said out loud either way rather than silently overridden.
  const candidates = files.filter((f) => f.size >= minSize && (minSize === 0 || f.size > 0))

  const bySize = new Map()
  for (const f of candidates) {
    const list = bySize.get(f.size) ?? []
    list.push(f)
    bySize.set(f.size, list)
  }

  const sizeGroups = [...bySize.values()]
    .filter((g) => g.length > 1)
    .sort((a, b) => b[0].size * (b.length - 1) - a[0].size * (a.length - 1))

  const budget = args.max_files_hashed ?? 20_000
  let reads = 0
  const skippedGroups = []
  const unreadable = []

  const hash = async (f, limit) => {
    reads++
    return hashFile(f.path, limit ? { limit, signal: ctx?.signal } : { signal: ctx?.signal })
  }

  const byFull = new Map()

  for (const group of sizeGroups) {
    ctx?.signal?.throwIfAborted?.()

    // Worst case for this group: a head read and a full read per file. Small
    // files skip the head pass because it would read the very same bytes.
    const needsHead = group[0].size > HEAD_WINDOW
    const worstCase = group.length * (needsHead ? 2 : 1)
    if (reads + worstCase > budget) {
      skippedGroups.push({ size: group[0].size, copies: group.length })
      continue
    }

    let survivors = group
    if (needsHead) {
      const byHead = new Map()
      for (const f of group) {
        let head
        try {
          head = await hash(f, HEAD_WINDOW)
        } catch (err) {
          unreadable.push({ path: f.path, code: err.code ?? 'EREAD' })
          continue
        }
        const list = byHead.get(head) ?? []
        list.push(f)
        byHead.set(head, list)
      }
      survivors = [...byHead.values()].filter((g) => g.length > 1).flat()
    }

    for (const f of survivors) {
      let full
      try {
        full = await hash(f)
      } catch (err) {
        unreadable.push({ path: f.path, code: err.code ?? 'EREAD' })
        continue
      }
      const list = byFull.get(full) ?? []
      list.push(f)
      byFull.set(full, list)
    }
  }

  const COPIES_SHOWN = 50
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
        // Bounded. `limit` caps the number of GROUPS; without this a single
        // 12,000-copy group produced a multi-megabyte payload regardless of it.
        other_copies: redundant.slice(0, COPIES_SHOWN).map((f) => ({
          path: f.path,
          modified: formatDate(f.mtimeMs),
        })),
        other_copies_omitted: Math.max(0, redundant.length - COPIES_SHOWN),
        names_differ: new Set(ordered.map((f) => basename(f.path))).size > 1,
      }
    })
    .sort((a, b) => b.reclaimable_bytes - a.reclaimable_bytes)

  const reclaimable = duplicates.reduce((n, d) => n + d.reclaimable_bytes, 0)
  const warnings = scanWarnings(perRoot)
  if (skippedGroups.length) {
    const unchecked = skippedGroups.reduce((n, g) => n + g.size * (g.copies - 1), 0)
    warnings.push(
      `The hashing budget of ${budget.toLocaleString()} reads was reached, so ` +
        `${skippedGroups.length} same-size group(s) covering up to ` +
        `${formatBytes(unchecked)} were never hashed and are absent below. This result ` +
        'is a lower bound — raise max_files_hashed for a complete answer.',
    )
  }
  if (unreadable.length) {
    warnings.push(`${unreadable.length} file(s) could not be read and were not compared.`)
  }
  if (minSize === 0) {
    warnings.push('min_bytes: 0 was given, so empty files are included; every empty file matches every other.')
  }

  const limit = args.limit ?? 100
  return toolResult(
    `${duplicates.length} duplicate group(s), ${formatBytes(reclaimable)} reclaimable ` +
      'by keeping one copy of each. Every match is confirmed by a full SHA-256 of the ' +
      'file contents.' + (warnings.length ? ` ${warnings.join(' ')}` : ''),
    {
      scanned: roots.map((r) => r.realPath),
      files_considered: candidates.length,
      hash_reads: reads,
      hash_budget: budget,
      groups_skipped_for_budget: skippedGroups.length,
      duplicate_groups: duplicates.length,
      reclaimable_bytes: reclaimable,
      reclaimable_human: formatBytes(reclaimable),
      shown: Math.min(limit, duplicates.length),
      omitted_by_limit: Math.max(0, duplicates.length - limit),
      warnings,
      unreadable,
      method:
        'Grouped by exact byte size, then (for files over 64 KiB) by SHA-256 of the ' +
        'first 64 KiB, then confirmed by SHA-256 of the entire file. Filenames are not ' +
        'used to decide identity; `names_differ` is reported only so you can see when ' +
        'copies were renamed. Empty files are excluded unless min_bytes: 0.',
      groups: duplicates.slice(0, limit),
    },
  )
}

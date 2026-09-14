// Directory walking and content hashing.
//
// Symlinks are never followed. Every entry is inspected with lstat, and a link
// is counted and skipped rather than traversed. That is a containment decision
// before it is a loop-avoidance one: following a link is exactly how a walk
// leaves the configured root, and roots.mjs cannot re-check a path the walk
// never surfaced.
//
// Nothing here is silently truncated. When a cap is hit the result says so and
// names the number, because a listing that quietly stops is read as a complete
// listing and the conclusions drawn from it are wrong in a way nobody notices.

import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { opendir, lstat } from 'node:fs/promises'
import { extname, join, relative } from 'node:path'

/** Where trash_local moves things. Never walked; see DEFAULT_SKIP_DIRS. */
export const TRASH_DIR_NAME = '.shieldfive-mcp-trash'

/** Entries whose names are noise in every report. */
const ALWAYS_SKIP = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini'])

/**
 * Directories excluded from every walk: build output, package caches and VCS
 * metadata.
 *
 * `build`, `dist` and `target` are ordinary folder names outside a code tree,
 * so this list can hide real user data. Every exclusion is counted and reported
 * in the scan warnings, and there is no way to override the list yet.
 */
const DEFAULT_SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  '.cache',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  '.turbo',
  'dist',
  'build',
  'target',
  'Pods',
  '.gradle',
  '.tox',
  '.mypy_cache',
  '.pytest_cache',
  // This server's own trash. Walking it would offer already-trashed files back
  // as fresh candidates on the next scan.
  TRASH_DIR_NAME,
])

/**
 * Walk one directory tree, breadth-first.
 *
 * Every field of `stats` is read by name elsewhere: scanWarnings() in format.mjs
 * turns the counters into the sentences a user sees, and read.mjs copies a few
 * into its payloads. Adding a field is safe; renaming one silently drops a
 * warning.
 *
 * @returns {Promise<{
 *   files: Array<{path, relativePath, size, mtimeMs, extension, hardlinked}>,
 *   stats: {
 *     directories: number, symlinksSkipped: number, hiddenSkipped: number,
 *     skippedDirectories: string[], hardlinked: string[],
 *     unreadable: Array<{path, code}>, depthLimited: string[],
 *     truncated: boolean, maxFiles: number,
 *   },
 * }>}
 */
export async function walk(
  startRealPath,
  {
    maxFiles = 200_000,
    maxDepth = 64,
    includeHidden = false,
    skipDirs = DEFAULT_SKIP_DIRS,
    signal,
  } = {},
) {
  const files = []
  const stats = {
    directories: 0,
    symlinksSkipped: 0,
    hiddenSkipped: 0,
    skippedDirectories: [],
    hardlinked: [],
    unreadable: [],
    depthLimited: [],
    truncated: false,
    maxFiles,
  }

  const queue = [{ dir: startRealPath, depth: 0 }]

  while (queue.length) {
    signal?.throwIfAborted()
    const { dir, depth } = queue.shift()

    if (depth > maxDepth) {
      stats.depthLimited.push(dir)
      continue
    }

    let handle
    try {
      handle = await opendir(dir)
    } catch (err) {
      stats.unreadable.push({ path: dir, code: err.code })
      continue
    }
    stats.directories++

    try {
      for await (const entry of handle) {
        if (files.length >= maxFiles) {
          stats.truncated = true
          break
        }
        if (ALWAYS_SKIP.has(entry.name)) continue

        const full = join(dir, entry.name)

        // lstat before any name-based branch. The hidden check used to
        // run on the dirent, so a dot-named symlink was consumed as "hidden"
        // and never reached the symlink branch -- two links on disk, one
        // reported. Trust lstat, not the dirent flags: a dirent can report
        // DT_UNKNOWN on some filesystems, and isSymbolicLink() has to be
        // authoritative here.
        let st
        try {
          st = await lstat(full)
        } catch (err) {
          stats.unreadable.push({ path: full, code: err.code })
          continue
        }

        if (st.isSymbolicLink()) {
          stats.symlinksSkipped++
          continue
        }

        const hidden = entry.name.startsWith('.')

        if (st.isDirectory()) {
          if (skipDirs.has(entry.name)) {
            stats.skippedDirectories.push(full)
            continue
          }
          if (!includeHidden && hidden) {
            stats.hiddenSkipped++
            continue
          }
          queue.push({ dir: full, depth: depth + 1 })
          continue
        }

        if (!includeHidden && hidden) {
          stats.hiddenSkipped++
          continue
        }

        if (!st.isFile()) continue

        // nlink > 1 means this inode is reachable by another name, possibly
        // one outside every root. realpath resolves symlinks but not hardlinks,
        // so containment cannot see that second name. Counting them is the
        // honest response: it is reported, not silently trusted.
        if (st.nlink > 1) stats.hardlinked.push(full)

        files.push({
          path: full,
          relativePath: relative(startRealPath, full),
          size: st.size,
          mtimeMs: st.mtimeMs,
          extension: extname(entry.name).toLowerCase(),
          hardlinked: st.nlink > 1,
        })
      }
    } finally {
      // `for await` closes the handle on normal completion; an early `break`
      // leaves it open, and an unclosed dir handle is a real leak on a long-
      // lived stdio server.
      await handle.close().catch(() => {})
    }

    if (stats.truncated) break
  }

  return { files, stats }
}

/** Walk every root, tagging each file with the root it came from. */
export async function walkRoots(rootSet, options = {}) {
  const files = []
  const perRoot = []
  const budget = options.maxFiles ?? 200_000

  for (const root of rootSet) {
    // A shared budget, decremented per root. Passing the same maxFiles to each
    // walk made the documented cap a PER-ROOT cap, so N roots returned up to N
    // times the number the caller asked for.
    const remaining = Math.max(0, budget - files.length)
    const result = await walk(root.realPath, { ...options, maxFiles: remaining })

    for (const f of result.files) {
      f.root = root.realPath
      // NOT files.push(...result.files): spreading an array as call arguments
      // exceeds V8's argument limit at roughly 125,000 elements and throws
      // RangeError, which made every scanning tool crash on a large root well
      // below the 200,000-file cap the schema advertises.
      files.push(f)
    }

    const exhausted = remaining === 0 || result.stats.truncated
    perRoot.push({
      root: root.realPath,
      ...result.stats,
      truncated: exhausted,
      maxFiles: budget,
      files: result.files.length,
    })
    if (exhausted) break
  }

  return { files, perRoot }
}

/**
 * SHA-256 of a file's bytes, optionally only the first `limit` bytes.
 *
 * Content identity is established by hashing content. Nothing in this server
 * treats matching name and size as evidence that two files are the same — that
 * inference is wrong often enough to delete the wrong copy, which is the one
 * mistake this tool must never make.
 */
export function hashFile(path, { limit = Infinity, signal } = {}) {
  return new Promise((resolvePromise, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(path, {
      end: Number.isFinite(limit) ? limit - 1 : undefined,
      signal,
    })
    stream.on('error', reject)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolvePromise(hash.digest('hex')))
  })
}

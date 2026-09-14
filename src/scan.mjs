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

/** Directories that are build output or package caches, not user data. */
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
 * Walk one directory tree.
 *
 * @returns {Promise<{files: Array, stats: object}>}
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
        if (!includeHidden && entry.name.startsWith('.') && !entry.isDirectory()) {
          stats.hiddenSkipped++
          continue
        }

        const full = join(dir, entry.name)

        // Trust lstat, not the dirent flags: a dirent can report DT_UNKNOWN on
        // some filesystems, and isSymbolicLink() must be authoritative here.
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

        if (st.isDirectory()) {
          if (skipDirs.has(entry.name)) {
            stats.skippedDirectories.push(full)
            continue
          }
          if (!includeHidden && entry.name.startsWith('.')) {
            stats.hiddenSkipped++
            continue
          }
          queue.push({ dir: full, depth: depth + 1 })
          continue
        }

        if (!st.isFile()) continue

        files.push({
          path: full,
          relativePath: relative(startRealPath, full),
          size: st.size,
          mtimeMs: st.mtimeMs,
          extension: extname(entry.name).toLowerCase(),
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

  for (const root of rootSet) {
    const result = await walk(root.realPath, options)
    for (const f of result.files) f.root = root.realPath
    files.push(...result.files)
    perRoot.push({ root: root.realPath, ...result.stats, files: result.files.length })
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

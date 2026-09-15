// Path containment — the security core of this server.
//
// Every path that reaches the filesystem passes through here first. One rule:
// a path is usable only if its real path, with every symlink resolved, sits
// inside one of the roots the user configured at startup. Nothing else grants
// access, and there is no override flag.
//
// Why realpath rather than string prefixing. A string check on the path the
// caller supplied is defeated by `..`, and a check after `path.resolve` is still
// defeated by a symlink: `/allowed/link -> /etc` resolves to a string under
// /allowed while reading /etc. Resolving symlinks first is what closes that, and
// it is why the directory walk in scan.mjs uses lstat and never follows a link.
//
// The boundary test is separator-aware. `/data/roots-evil` must not match the
// root `/data/root` just because the string starts with it.

import { realpath, lstat } from 'node:fs/promises'
import { delimiter, isAbsolute, join, resolve, sep } from 'node:path'

import { quote } from './format.mjs'

/** A refusal the model is meant to read and act on, not a crash. */
export class ToolError extends Error {
  constructor(code, message, detail = undefined) {
    super(message)
    this.name = 'ToolError'
    this.code = code
    if (detail !== undefined) this.detail = detail
  }
}

/**
 * The longest path argument accepted: PATH_MAX on Linux, and more than macOS
 * accepts. The cap is not about the filesystem. Without it a 5 MB path argument
 * was reflected verbatim into the error and into the model's context.
 */
export const MAX_PATH_CHARS = 4096

export const NO_ROOTS_MESSAGE =
  'No allowed roots are configured, so this server can read nothing. ' +
  'Start it with one or more directories: `shieldfive-mcp /Users/you/Documents ' +
  '/Volumes/Archive`, or set SHIELDFIVE_MCP_ROOTS to a ' +
  `${JSON.stringify(delimiter)}-separated list. Roots are the only paths this ` +
  'server may touch; it has no default and will not guess one.'

/**
 * Resolve configured roots to real paths.
 *
 * A root that does not exist, or is not a directory, is dropped with a reason
 * rather than silently ignored — a typo in a client config should be visible,
 * not just produce an empty file listing.
 *
 * Root candidates are trimmed, unlike tool arguments: they come from a config
 * file or a shell variable a person typed, where stray whitespace around a
 * separator is common, and every rejection is logged at startup.
 */
export async function resolveRoots(candidates) {
  const roots = []
  const rejected = []

  for (const raw of candidates) {
    const trimmed = String(raw).trim()
    if (!trimmed) continue

    if (!isAbsolute(trimmed)) {
      rejected.push({ path: trimmed, reason: 'not an absolute path' })
      continue
    }

    let real
    try {
      real = await realpath(trimmed)
    } catch (err) {
      rejected.push({
        path: trimmed,
        reason: err.code === 'ENOENT' ? 'does not exist' : `unreadable (${err.code})`,
      })
      continue
    }

    let stats
    try {
      stats = await lstat(real)
    } catch (err) {
      rejected.push({ path: trimmed, reason: `unreadable (${err.code})` })
      continue
    }
    if (!stats.isDirectory()) {
      rejected.push({ path: trimmed, reason: 'not a directory' })
      continue
    }

    if (roots.some((r) => r.realPath === real)) continue
    roots.push({ configured: trimmed, realPath: real })
  }

  // Drop a root nested inside another so a file is never reported twice and
  // containment has a single answer.
  const kept = roots.filter(
    (r) => !roots.some((other) => other !== r && isInside(r.realPath, other.realPath)),
  )
  for (const r of roots) {
    if (!kept.includes(r)) {
      rejected.push({
        path: r.configured,
        reason: 'nested inside another configured root',
      })
    }
  }

  return { roots: kept, rejected }
}

/** True when `child` is `parent` itself or sits beneath it. Separator-aware. */
export function isInside(child, parent) {
  if (child === parent) return true
  return child.startsWith(parent.endsWith(sep) ? parent : parent + sep)
}

/** Read root candidates from argv and the environment. */
export function rootCandidatesFrom(argv, env) {
  const fromArgs = argv.filter((a) => !a.startsWith('-'))
  const fromEnv = (env.SHIELDFIVE_MCP_ROOTS ?? '').split(delimiter)
  return [...fromArgs, ...fromEnv]
}

/**
 * Resolve a caller-supplied path that must already exist.
 *
 * Returns the REAL path, so every downstream operation acts on the resolved
 * target rather than on a link the caller chose.
 */
export async function resolveExisting(rootSet, input, { what = 'path' } = {}) {
  assertRoots(rootSet)
  const requested = requireAbsolute(input, what)

  let real
  try {
    real = await realpath(requested)
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new ToolError('not_found', `No such ${what}: ${quote(requested)}`)
    }
    throw new ToolError('unreadable', `Cannot read ${what} ${quote(requested)} (${err.code})`)
  }

  return { realPath: real, root: requireContained(rootSet, real, requested, what) }
}

/**
 * Resolve a path that may not exist yet — a move destination, a new folder.
 *
 * The nearest existing ancestor is realpath'd and the remaining segments are
 * re-appended, so a destination under a symlinked parent is caught before the
 * write rather than after it.
 */
export async function resolveTarget(rootSet, input, { what = 'destination' } = {}) {
  assertRoots(rootSet)
  const requested = requireAbsolute(input, what)

  const trailing = []
  let probe = requested
  for (;;) {
    try {
      const real = await realpath(probe)
      const full = trailing.length ? join(real, ...trailing) : real
      return {
        realPath: full,
        root: requireContained(rootSet, full, requested, what),
        exists: trailing.length === 0,
      }
    } catch (err) {
      // A containment refusal is raised from inside this try by
      // requireContained. Re-wrapping it as an I/O error would relabel the one
      // failure that matters most here, so it passes through untouched.
      if (err instanceof ToolError) throw err
      if (err.code !== 'ENOENT') {
        throw new ToolError('unreadable', `Cannot resolve ${what} ${quote(requested)} (${err.code})`)
      }
      const parent = resolve(probe, '..')
      if (parent === probe) {
        throw new ToolError('not_found', `No existing ancestor for ${quote(requested)}`)
      }
      trailing.unshift(probe.slice(parent.length + (parent.endsWith(sep) ? 0 : 1)))
      probe = parent
    }
  }
}

function assertRoots(rootSet) {
  if (!rootSet || rootSet.length === 0) {
    throw new ToolError('no_roots', NO_ROOTS_MESSAGE)
  }
}

/**
 * A path argument, exactly as given.
 *
 * Nothing is trimmed. "report " and "report" are different files, and trimming
 * made a request for the first act on the second.
 */
function requireAbsolute(input, what) {
  if (typeof input !== 'string' || input === '') {
    throw new ToolError('invalid_path', `A ${what} is required.`)
  }
  if (input.length > MAX_PATH_CHARS) {
    throw new ToolError(
      'invalid_path',
      `${what} is ${input.length.toLocaleString('en-US')} characters long, more than any ` +
        `filesystem accepts. It starts ${quote(input, 80)}.`,
    )
  }
  if (input.includes('\0')) {
    throw new ToolError('invalid_path', `${what} contains a NUL byte, which no path can: ${quote(input)}.`)
  }
  if (!isAbsolute(input)) {
    throw new ToolError(
      'invalid_path',
      `${what} must be an absolute path; got ${quote(input)}. ` +
        'This server resolves nothing against a working directory, because it has ' +
        'no meaningful one.',
    )
  }
  return resolve(input)
}

function requireContained(rootSet, real, requested, what) {
  const root = rootSet.find((r) => isInside(real, r.realPath))
  if (!root) {
    throw new ToolError(
      'outside_roots',
      `Refused: ${what} ${quote(requested)} resolves to ${quote(real)}, which is outside ` +
        `every configured root (${rootSet.map((r) => r.realPath).join(', ')}). ` +
        'Add the directory at startup if this is intended; there is no override.',
    )
  }
  return root
}

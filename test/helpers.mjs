import fs from 'node:fs'
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { resolveRoots } from '../src/roots.mjs'

/**
 * A temporary tree.
 *
 * The root is realpath'd because macOS hands out /var/folders/... which is a
 * symlink to /private/var/folders/... — exactly the case containment has to get
 * right, and a source of tests that pass for the wrong reason.
 */
export async function makeTree(spec) {
  const base = await realpath(await mkdtemp(join(tmpdir(), 'sf-mcp-')))

  for (const [relPath, content] of Object.entries(spec)) {
    const full = join(base, relPath)
    if (content === null) {
      await mkdir(full, { recursive: true })
      continue
    }
    if (typeof content === 'object' && content.symlinkTo) {
      await mkdir(dirname(full), { recursive: true })
      await symlink(join(base, content.symlinkTo), full)
      continue
    }
    await mkdir(dirname(full), { recursive: true })
    await writeFile(full, content)
  }

  return {
    base,
    path: (p) => join(base, p),
    cleanup: () => rm(base, { recursive: true, force: true }),
  }
}

/** A context object shaped like the one server.mjs builds. */
export async function makeCtx(rootPaths, { now = () => Date.UTC(2026, 8, 14) } = {}) {
  const { roots } = await resolveRoots(rootPaths)
  return { roots, noRootsMessage: 'no roots', now }
}

/** The JSON payload a tool returned. */
export function payload(result) {
  return JSON.parse(result.content[1].text)
}

export function summary(result) {
  return result.content[0].text
}

/**
 * Run `fn` with some node:fs/promises functions replaced.
 *
 * For faults that have to land at an exact moment -- a copy that arrives with a
 * byte wrong, a file that appears between a check and a rename -- instead of a
 * race the test would lose most of the time. syncBuiltinESMExports() is what
 * makes the replacement visible to modules that imported the function by name.
 */
export async function withPatchedFs(patches, fn) {
  const originals = {}
  for (const [name, wrap] of Object.entries(patches)) {
    originals[name] = fs.promises[name]
    fs.promises[name] = wrap(originals[name])
  }
  syncBuiltinESMExports()
  try {
    return await fn()
  } finally {
    Object.assign(fs.promises, originals)
    syncBuiltinESMExports()
  }
}

async function run(command, args) {
  const { execFile } = await import('node:child_process')
  const { promisify } = await import('node:util')
  return promisify(execFile)(command, args)
}

/**
 * A second filesystem, mounted at `mountPoint`, for tests that need a real EXDEV.
 *
 * A RAM disk formatted HFS+ and mounted inside the test's own temporary tree, so
 * one configured root can span two devices without anything touching /Volumes.
 * macOS only. Returns null where it cannot be done, after saying so on stderr,
 * so the caller skips visibly instead of passing for the wrong reason.
 */
export async function mountScratchVolume(mountPoint, { megabytes = 20 } = {}) {
  if (process.platform !== 'darwin') {
    console.error(`[skip] no second volume at ${mountPoint}: only macOS is supported by this helper`)
    return null
  }
  let disk
  try {
    const { stdout } = await run('hdiutil', ['attach', '-nomount', `ram://${megabytes * 2048}`])
    disk = stdout.trim().split(/\s+/)[0]
    await run('newfs_hfs', ['-v', 'sf-mcp-test', disk])
    await mkdir(mountPoint, { recursive: true })
    await run('diskutil', ['mount', '-mountPoint', mountPoint, disk])
  } catch (err) {
    if (disk) await run('hdiutil', ['detach', disk, '-force']).catch(() => {})
    console.error(`[skip] could not mount a scratch volume at ${mountPoint}: ${err.message}`)
    return null
  }
  return {
    mountPoint,
    disk,
    detach: () => run('hdiutil', ['detach', disk, '-force']).catch(() => {}),
  }
}

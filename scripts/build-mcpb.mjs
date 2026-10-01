// Build dist/shieldfive.mcpb: the manifest, this package's src and its
// production dependencies, packed with the official MCPB CLI. Run from a clean
// checkout after `npm ci`; nothing outside dist/ is touched.
//
// The bundle is built once (on Linux in CI) and installed on macOS, Windows and
// Linux. `npm ci` installs a native package only for the platform it runs on,
// and @napi-rs/keyring ships its binary as one optional package per platform,
// so a plain `npm ci` on the runner produced a bundle with a Linux keychain
// binary and nothing for the people who actually install .mcpb files. Without
// a keychain the connection was never saved and every restart minted a new
// grant. Every target's binary is therefore added explicitly below, from the
// exact tarball package-lock.json pins (integrity checked), and the build
// fails if any is missing.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// The MCPB packer, pinned: an unpinned `npx -y` would run whatever was
// published last inside the release job.
const MCPB_CLI = '@anthropic-ai/mcpb@2.1.2'

// Every platform the manifest declares, by the package napi-rs loads there.
export const KEYRING_TARGETS = [
  'darwin-arm64',
  'darwin-x64',
  'win32-x64-msvc',
  'win32-arm64-msvc',
  'linux-x64-gnu',
  'linux-arm64-gnu',
]

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const stage = join(root, 'dist', 'mcpb')
const server = join(stage, 'server')

function sri(bytes) {
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`
}

/** Add one platform's keyring binary to the staged node_modules, as the lockfile pins it. */
async function addKeyringBinary(lock, target) {
  const name = `@napi-rs/keyring-${target}`
  const dest = join(server, 'node_modules', name)
  if (existsSync(dest)) return // npm ci already installed the host's own
  const entry = lock.packages[`node_modules/${name}`]
  if (!entry?.resolved || !entry?.integrity) {
    throw new Error(`${name} is not pinned in package-lock.json; run npm install on a lockfile that lists it`)
  }
  if (!entry.resolved.startsWith('https://registry.npmjs.org/')) {
    throw new Error(`${name} resolves outside the npm registry: ${entry.resolved}`)
  }
  const res = await fetch(entry.resolved)
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status} fetching ${entry.resolved}`)
  const tgz = Buffer.from(await res.arrayBuffer())
  if (sri(tgz) !== entry.integrity) throw new Error(`${name}: tarball integrity does not match package-lock.json`)
  const tmp = join(root, 'dist', `${target}.tgz`)
  writeFileSync(tmp, tgz)
  mkdirSync(dest, { recursive: true })
  execFileSync('tar', ['-xzf', tmp, '-C', dest, '--strip-components=1'], { stdio: 'inherit' })
  rmSync(tmp)
}

/** Fail the build unless every target has its binary, at the version the loader expects. */
export function assertKeyringBinaries(serverDir) {
  const base = join(serverDir, 'node_modules', '@napi-rs')
  const want = JSON.parse(readFileSync(join(base, 'keyring', 'package.json'), 'utf8')).version
  const missing = []
  for (const target of KEYRING_TARGETS) {
    const dir = join(base, `keyring-${target}`)
    const ok =
      existsSync(dir) &&
      readdirSync(dir).some((f) => f.endsWith('.node')) &&
      JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version === want
    if (!ok) missing.push(target)
  }
  if (missing.length) throw new Error(`bundle is missing keyring binaries for: ${missing.join(', ')}`)
}

async function main() {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'))
  const manifest = JSON.parse(readFileSync(join(root, 'mcpb', 'manifest.json'), 'utf8'))
  if (manifest.version !== pkg.version) {
    throw new Error(`mcpb/manifest.json is ${manifest.version}, package.json is ${pkg.version}`)
  }

  rmSync(stage, { recursive: true, force: true })
  mkdirSync(server, { recursive: true })
  writeFileSync(join(stage, 'manifest.json'), JSON.stringify(manifest, null, 2))
  if (manifest.icon) cpSync(join(root, 'mcpb', manifest.icon), join(stage, manifest.icon))
  cpSync(join(root, 'src'), join(server, 'src'), { recursive: true })
  for (const f of ['package.json', 'package-lock.json', 'README.md', 'LICENSE', 'SECURITY.md']) {
    cpSync(join(root, f), join(server, f))
  }
  // No dependency needs an install script (native code arrives prebuilt), so
  // none is run inside a job that can publish.
  execFileSync('npm', ['ci', '--omit=dev', '--ignore-scripts'], { cwd: server, stdio: 'inherit' })
  for (const target of KEYRING_TARGETS) await addKeyringBinary(lock, target)
  assertKeyringBinaries(server)

  execFileSync('npx', ['-y', MCPB_CLI, 'pack', stage, join(root, 'dist', 'shieldfive.mcpb')], { stdio: 'inherit' })
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main()

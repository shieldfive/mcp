// Where the grant's connection string comes from, and nothing else.
//
// A connection string holds the bearer token AND the grant secret that opens
// the grant's keys. It is looked up in this order:
//
//   1. SHIELDFIVE_GRANT in the environment — for CI and headless use. Anything
//      that can read this process's environment can read it; say so in docs.
//   2. The OS keychain (macOS Keychain, Windows Credential Manager, the Secret
//      Service on Linux), written by `npx @shieldfive/mcp login` or vault_connect.
//   3. Only when no keychain is usable: a file readable by this user alone
//      (0600, in a 0700 directory, under the user's config directory). Without
//      it, a machine with no keychain minted a new grant on every restart until
//      ShieldFive's cap on live grants refused new connections. The file is not
//      encrypted: any key to encrypt it would sit on the same disk, readable by
//      the same user, and would add nothing but the appearance of protection.
//      It has the same exposure as the assistant's own config file holding
//      SHIELDFIVE_GRANT, and users are told where it is.
//
// The value is never logged, and never included in a tool result or an error
// message. parseConnectionString's errors describe the shape, not the value.

import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

import { parseConnectionString, VaultCryptoError } from '@shieldfive/crypto/vault'

export const KEYCHAIN_SERVICE = 'shieldfive-mcp'
export const KEYCHAIN_ACCOUNT = 'grant'

async function keychainEntry() {
  const { Entry } = await import('@napi-rs/keyring')
  return new Entry(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
}

export async function readKeychain() {
  try {
    const entry = await keychainEntry()
    return entry.getPassword() ?? null
  } catch {
    // No keychain on this machine (headless Linux without a Secret Service),
    // or no entry: both mean "not configured here".
    return null
  }
}

export async function writeKeychain(connectionString) {
  const entry = await keychainEntry()
  entry.setPassword(connectionString)
}

export async function deleteKeychain() {
  try {
    const entry = await keychainEntry()
    return entry.deletePassword()
  } catch {
    return false
  }
}

/**
 * Where the no-keychain fallback lives. SHIELDFIVE_MCP_CONFIG_DIR overrides the
 * directory (tests, portable installs).
 */
export function connectionFilePath(env = process.env, platform = process.platform) {
  if (env.SHIELDFIVE_MCP_CONFIG_DIR) return join(env.SHIELDFIVE_MCP_CONFIG_DIR, 'connection')
  const home = env.HOME || env.USERPROFILE || homedir()
  let base
  if (platform === 'win32') base = env.APPDATA || join(home, 'AppData', 'Roaming')
  else if (platform === 'darwin') base = join(home, 'Library', 'Application Support')
  else base = env.XDG_CONFIG_HOME || join(home, '.config')
  return join(base, KEYCHAIN_SERVICE, 'connection')
}

export async function readConnectionFile(env = process.env) {
  try {
    return (await readFile(connectionFilePath(env), 'utf8')).trim() || null
  } catch {
    return null
  }
}

export async function writeConnectionFile(connectionString, env = process.env) {
  const file = connectionFilePath(env)
  const dir = join(file, '..')
  await mkdir(dir, { recursive: true, mode: 0o700 })
  await chmod(dir, 0o700).catch(() => {})
  // Written under a temporary name created 0600, then renamed over the old one,
  // so the value is never in a file anyone else can open, even for a moment.
  const tmp = `${file}.${process.pid}.tmp`
  await writeFile(tmp, `${connectionString}\n`, { mode: 0o600, flag: 'w' })
  await chmod(tmp, 0o600).catch(() => {})
  await rename(tmp, file)
  return file
}

export async function deleteConnectionFile(env = process.env) {
  const file = connectionFilePath(env)
  const existed = (await readConnectionFile(env)) !== null
  await rm(file, { force: true })
  return existed
}

/**
 * Store a connection so it survives a restart: the keychain when there is one,
 * otherwise the 0600 file. Returns where it went ({ store: 'keychain' } or
 * { store: 'file', path }). Throws only if neither works.
 */
export async function storeConnection(connectionString, { env = process.env, keychain = writeKeychain } = {}) {
  try {
    await keychain(connectionString)
    // A connection stored in the file earlier, while the keychain was not
    // usable, must not outlive this one.
    await rm(connectionFilePath(env), { force: true }).catch(() => {})
    return { store: 'keychain' }
  } catch {
    const path = await writeConnectionFile(connectionString, env)
    return { store: 'file', path }
  }
}

/** The stored connection: keychain first, then the fallback file. */
export async function readStoredConnection(env = process.env, keychain = readKeychain) {
  const fromKeychain = (await keychain())?.trim()
  if (fromKeychain) return { raw: fromKeychain, source: 'keychain' }
  const fromFile = await readConnectionFile(env)
  if (fromFile) return { raw: fromFile, source: `file ${connectionFilePath(env)}` }
  return null
}

/** Remove the connection from every place this package stores it. */
export async function deleteStoredConnection(env = process.env) {
  const keychain = await deleteKeychain()
  const file = await deleteConnectionFile(env).catch(() => false)
  return { keychain: Boolean(keychain), file }
}

/**
 * The configured grant, parsed, or null when none is configured. A malformed
 * value is an error with a fixed message; the value itself never appears.
 *
 * SHIELDFIVE_GRANT=none means "no vault here": nothing stored is read at all.
 * That is how one client stays local-only on a machine where another client is
 * connected, and how the tests avoid depending on the developer's keychain.
 *
 * `readStore` returns the stored string (taken to be from the keychain) or
 * { raw, source }.
 */
export async function loadGrantCredential(env = process.env, readStore = () => readStoredConnection(env)) {
  const configured = env.SHIELDFIVE_GRANT?.trim()
  if (configured === 'none') return null
  let raw = configured || null
  let source = 'env'
  if (!raw) {
    const stored = await readStore()
    if (typeof stored === 'string') {
      raw = stored.trim() || null
      source = 'keychain'
    } else if (stored?.raw) {
      raw = stored.raw.trim() || null
      source = stored.source
    }
  }
  if (!raw) return null
  try {
    return { ...parseConnectionString(raw), source }
  } catch (err) {
    if (err instanceof VaultCryptoError) {
      throw new Error(
        'The configured ShieldFive connection string is not valid. Create a new ' +
          'connection in ShieldFive → Settings → AI assistants, or run ' +
          '`npx @shieldfive/mcp login` again.',
      )
    }
    throw err
  }
}

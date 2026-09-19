// Where the grant's connection string comes from, and nothing else.
//
// A connection string holds the bearer token AND the grant secret that opens
// the grant's keys. It is looked up in this order:
//
//   1. SHIELDFIVE_GRANT in the environment — for CI and headless use. Anything
//      that can read this process's environment can read it; say so in docs.
//   2. The OS keychain (macOS Keychain, Windows Credential Manager, the Secret
//      Service on Linux), written by `npx @shieldfive/mcp login`.
//
// It is never written to a file by this package, never logged, and never
// included in a tool result or an error message. parseConnectionString's
// errors describe the shape, not the value.

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
 * The configured grant, parsed, or null when none is configured. A malformed
 * value is an error with a fixed message; the value itself never appears.
 */
export async function loadGrantCredential(env = process.env, readStore = readKeychain) {
  const raw = env.SHIELDFIVE_GRANT?.trim() || (await readStore())?.trim() || null
  if (!raw) return null
  try {
    return { ...parseConnectionString(raw), source: env.SHIELDFIVE_GRANT ? 'env' : 'keychain' }
  } catch (err) {
    if (err instanceof VaultCryptoError) {
      throw new Error(
        'The configured ShieldFive connection string is not valid. Create a new ' +
          'connection in ShieldFive → Settings → AI assistants and run ' +
          '`npx @shieldfive/mcp login` again.',
      )
    }
    throw err
  }
}

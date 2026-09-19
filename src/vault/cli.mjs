// `npx @shieldfive/mcp login [--paste] | logout | status`
//
// login opens ShieldFive in the browser, where the owner chooses the scope and
// clicks Authorize; the connection string comes back to this process over
// 127.0.0.1 (connect.mjs). `login --paste` reads it from the terminal instead,
// without echoing it. Either way it is checked against the server (so a
// revoked grant is caught now, not in the middle of a conversation) and stored
// in the OS keychain. Nothing is written to a file and the value is never
// printed.

import { parseConnectionString } from '@shieldfive/crypto/vault'

import { createVaultApi, DEFAULT_API_URL } from './api.mjs'
import { openBrowser, startConnectFlow } from './connect.mjs'
import { deleteKeychain, loadGrantCredential, writeKeychain } from './credential.mjs'

const out = (s) => process.stderr.write(`${s}\n`)

function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin
    if (!stdin.isTTY) {
      let data = ''
      stdin.setEncoding('utf8')
      stdin.on('data', (c) => (data += c))
      stdin.on('end', () => resolve(data.trim()))
      stdin.on('error', reject)
      return
    }
    process.stderr.write(prompt)
    let value = ''
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding('utf8')
    const onData = (chunk) => {
      for (const ch of chunk) {
        const code = ch.charCodeAt(0)
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false)
          stdin.pause()
          stdin.off('data', onData)
          process.stderr.write('\n')
          resolve(value.trim())
          return
        }
        if (code === 3) {
          stdin.setRawMode(false)
          process.stderr.write('\n')
          reject(new Error('cancelled'))
          return
        }
        if (code === 127 || code === 8) value = value.slice(0, -1)
        else if (code >= 32) value += ch
      }
    }
    stdin.on('data', onData)
  })
}

export function describeGrant(grant) {
  const scope = grant.scopeAll ? 'whole vault' : `${grant.scopeFolderIds.length} folder(s)`
  return `connection ${grant.id.slice(0, 8)}…: ${grant.scopes.join(' + ')}, ${scope}, expires ${grant.expiresAt}`
}

async function describe(credential, env) {
  const api = createVaultApi({ credential, baseUrl: env.SHIELDFIVE_API_URL || DEFAULT_API_URL })
  const { grant } = await api.grant()
  return describeGrant(grant)
}

async function authorizeInBrowser(env, open) {
  const flow = await startConnectFlow({ baseUrl: env.SHIELDFIVE_API_URL || DEFAULT_API_URL, client: 'other' })
  const opened = await open(flow.url)
  out(
    opened
      ? 'Opened ShieldFive in your browser. Choose what the assistant may reach and click Authorize.'
      : 'Open this link in your browser, choose what the assistant may reach and click Authorize:',
  )
  out(`  ${flow.url}`)
  out('Waiting (up to 10 minutes; Ctrl+C to stop)…')
  return flow.result
}

export async function runCli(command, env = process.env, args = [], { open = openBrowser } = {}) {
  if (command === 'login') {
    let raw
    if (args.includes('--paste')) {
      raw = await readHidden('Paste the ShieldFive connection string (input hidden): ')
    } else {
      try {
        raw = await authorizeInBrowser(env, open)
      } catch (err) {
        out(
          err?.code === 'cancelled'
            ? 'The request was denied in ShieldFive. Nothing was connected.'
            : 'Nobody authorized the connection in time. Run the command again, or use --paste.',
        )
        return 1
      }
    }
    let credential
    try {
      credential = parseConnectionString(raw)
    } catch {
      out('That is not a ShieldFive connection string. Copy it again from Settings → AI assistants.')
      return 1
    }
    try {
      out(`Checking with ShieldFive… ${await describe(credential, env)}`)
    } catch (err) {
      out(`ShieldFive did not accept it: ${err?.message ?? 'unknown error'}`)
      return 1
    }
    try {
      await writeKeychain(raw)
    } catch {
      out(
        'No system keychain is available here. Set SHIELDFIVE_GRANT in the MCP server’s ' +
          'environment instead (anything that can read that environment can read the connection).',
      )
      return 1
    }
    out('Saved to the system keychain. Restart your AI assistant to pick it up.')
    return 0
  }
  if (command === 'logout') {
    const removed = await deleteKeychain()
    out(removed ? 'Removed the connection from the system keychain.' : 'No connection was stored in the keychain.')
    out('To cut off access everywhere, revoke the connection in ShieldFive → Settings → AI assistants.')
    return 0
  }
  if (command === 'status') {
    const credential = await loadGrantCredential(env).catch((e) => {
      out(e.message)
      return null
    })
    if (!credential) {
      out('No ShieldFive connection configured. Vault tools are off; local tools work as before.')
      return 0
    }
    try {
      out(`Configured from ${credential.source}: ${await describe(credential, env)}`)
    } catch (err) {
      out(`Configured from ${credential.source}, but ShieldFive refused it: ${err?.message ?? 'unknown error'}`)
      return 1
    }
    return 0
  }
  return null
}

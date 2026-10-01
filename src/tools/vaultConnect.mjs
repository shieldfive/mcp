// vault_connect: connect this server to a ShieldFive vault from inside the
// conversation. It opens ShieldFive in the user's browser; they choose what the
// assistant may reach and click Authorize; the connection is delivered to this
// process over 127.0.0.1 (vault/connect.mjs) and stored in the OS keychain, or
// where there is none, in a file only this user can read (vault/credential.mjs).
// Storing it is what stops every restart from minting a new grant.
//
// A tool call cannot wait ten minutes (clients time out after about a minute),
// so the call waits briefly and, if the user has not finished yet, says so. The
// listener keeps running; calling vault_connect again picks up the result.

import { parseConnectionString } from '@shieldfive/crypto/vault'

import { ToolError } from '../roots.mjs'
import { describeGrant } from '../vault/cli.mjs'
import { clientHintFor, connectLabel, openBrowser, startConnectFlow } from '../vault/connect.mjs'
import { storeConnection } from '../vault/credential.mjs'

export const CONNECT_WAIT_MS = 45_000
export const REVOKE_WAIT_MS = 10_000

/**
 * Best-effort: end the grant a reconnect replaced, using that grant's own
 * credentials. Never blocks the new connection; returns a sentence for the
 * user whenever the old grant may still be live, so it is never left behind
 * silently.
 */
async function retirePrevious(previous, nextGrantId, signal) {
  const old = previous?.credential
  if (!old?.grantId || old.grantId === nextGrantId) return ''
  const id = `${old.grantId.slice(0, 8)}…`
  if (old.source === 'env') {
    // Revoking it would break the SHIELDFIVE_GRANT the user configured, which
    // still wins after a restart. Their call, so say so instead.
    return (
      ` The previous connection (${id}, from SHIELDFIVE_GRANT) was left live because it is in the ` +
      'assistant’s settings; revoke it in ShieldFive → Settings → AI assistants if it is no longer wanted.'
    )
  }
  if (typeof previous.api?.revoke !== 'function') return ''
  // Bounded: a slow or rate-limited server must not hold up the new connection.
  const timeout = AbortSignal.timeout(REVOKE_WAIT_MS)
  try {
    await previous.api.revoke(signal ? AbortSignal.any([signal, timeout]) : timeout)
    return ` The previous connection (${id}) was revoked.`
  } catch (err) {
    // 401: already revoked or expired, so nothing is left live. Anything else
    // (including a 404 from a server without this endpoint) is reported.
    if (err?.code === 'grant_invalid') return ''
    return (
      ` The previous connection (${id}) could not be revoked automatically and is still live until it ` +
      'expires; ask the user to revoke it in ShieldFive → Settings → AI assistants.'
    )
  }
}

function text(summary) {
  return { content: [{ type: 'text', text: summary }] }
}

/** Resolve with {value} / {error}, or {pending} after `ms`; never rejects. */
function waitFor(promise, ms, ctx) {
  return new Promise((resolve) => {
    let ticks = 0
    const tick = setInterval(() => ctx.progress?.(++ticks, undefined, 'Waiting for you to authorize in the browser'), 5_000)
    const stop = (outcome) => {
      clearInterval(tick)
      clearTimeout(timer)
      resolve(outcome)
    }
    const timer = setTimeout(() => stop({ pending: true }), ms)
    ctx.signal?.addEventListener('abort', () => stop({ pending: true }), { once: true })
    promise.then(
      (value) => stop({ value }),
      (error) => stop({ error }),
    )
  })
}

export async function vaultConnect(ctx, args) {
  const root = ctx.root
  if (root.vault && !args.reconnect) {
    try {
      const { grant } = await root.vault.api.grant(ctx.signal)
      return text(
        `Already connected (${describeGrant(grant)}). The vault_* tools are ready. ` +
          'Call vault_connect with reconnect: true only if the user wants a different connection.',
      )
    } catch (err) {
      if (err?.code !== 'grant_invalid') throw err
      // Expired or revoked: fall through and connect again.
    }
  }

  let flow = root.connectFlow
  if (!flow) {
    const name = root.clientName?.()
    const started = await startConnectFlow({
      baseUrl: root.apiBaseUrl,
      client: clientHintFor(name),
      label: connectLabel(name),
    })
    flow = { ...started, opened: await (root.openBrowser ?? openBrowser)(started.url) }
    // Kept until a call consumes its outcome: a user who authorizes after the
    // call returned is picked up by the next vault_connect.
    root.connectFlow = flow
  }

  const outcome = await waitFor(flow.result, root.connectWaitMs ?? CONNECT_WAIT_MS, ctx)
  if (outcome.pending) {
    return text(
      (flow.opened
        ? 'ShieldFive is open in the user’s browser. '
        : 'The browser could not be opened automatically. Ask the user to open this link: ' +
          `${flow.url} — `) +
        'Ask them to sign in if needed, choose which folders the assistant may use, and click Authorize. ' +
        'Then call vault_connect again to finish. The request stays open for 10 minutes.',
    )
  }
  root.connectFlow = null
  if (outcome.error) {
    const code = outcome.error.code === 'cancelled' ? 'cancelled' : 'connect_failed'
    throw new ToolError(
      code,
      code === 'cancelled'
        ? 'The user denied the connection request in ShieldFive. Nothing was connected.'
        : 'Nobody authorized the connection within 10 minutes. Call vault_connect to try again.',
    )
  }

  const raw = outcome.value
  const credential = { ...parseConnectionString(raw), source: 'browser' }
  const next = await root.makeVault(credential)
  let grant
  try {
    ;({ grant } = await next.api.grant(ctx.signal))
  } catch (err) {
    await next.names?.close?.()
    throw err
  }
  let stored = null
  try {
    stored = await (root.storeConnection ?? storeConnection)(raw)
  } catch {
    stored = null
  }
  const previous = root.vault
  root.vault = next
  const retired = await retirePrevious(previous, grant?.id ?? credential.grantId, ctx.signal)
  await previous?.names?.close?.()
  root.onConnected?.()

  const envNote = root.envGrant
    ? ' SHIELDFIVE_GRANT in the assistant’s MCP settings still takes precedence after a restart; ' +
      'remove it there to use this one.'
    : ''
  let persistence
  if (stored?.store === 'file') {
    persistence =
      `No system keychain is available, so the connection was saved to ${stored.path}, readable only by ` +
      'this user account, and stays connected after restarts. Tell the user where it is; deleting that file ' +
      '(or `npx @shieldfive/mcp logout`) forgets it, and revoking it in ShieldFive cuts off access.' +
      envNote
  } else if (stored) {
    persistence = root.envGrant
      ? `Saved in the system keychain.${envNote}`
      : 'Saved in the system keychain, so it stays connected after restarts.'
  } else {
    persistence =
      'It could not be saved on this computer (no system keychain and no writable config directory), so ' +
      'it lasts until the assistant restarts. To keep it, the user can paste a connection string from ' +
      'ShieldFive → Settings → AI assistants into this server’s connection setting (SHIELDFIVE_GRANT, or ' +
      '“ShieldFive connection string” in Claude Desktop’s extension settings). Do not call vault_connect ' +
      'again after a restart without telling the user: each call creates a new connection.'
  }
  return text(
    `Connected (${describeGrant(grant)}). ${persistence}${retired} The vault_* tools are ready to use now.`,
  )
}

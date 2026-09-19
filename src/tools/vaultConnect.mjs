// vault_connect: connect this server to a ShieldFive vault from inside the
// conversation. It opens ShieldFive in the user's browser; they choose what the
// assistant may reach and click Authorize; the connection is delivered to this
// process over 127.0.0.1 (vault/connect.mjs) and stored in the OS keychain.
//
// A tool call cannot wait ten minutes (clients time out after about a minute),
// so the call waits briefly and, if the user has not finished yet, says so. The
// listener keeps running; calling vault_connect again picks up the result.

import { parseConnectionString } from '@shieldfive/crypto/vault'

import { ToolError } from '../roots.mjs'
import { describeGrant } from '../vault/cli.mjs'
import { clientHintFor, openBrowser, startConnectFlow } from '../vault/connect.mjs'
import { writeKeychain } from '../vault/credential.mjs'

export const CONNECT_WAIT_MS = 45_000

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
    const started = await startConnectFlow({
      baseUrl: root.apiBaseUrl,
      client: clientHintFor(root.clientName?.()),
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
  let stored = true
  try {
    await (root.writeKeychain ?? writeKeychain)(raw)
  } catch {
    stored = false
  }
  const previous = root.vault
  root.vault = next
  await previous?.names?.close?.()
  root.onConnected?.()

  const persistence = stored
    ? root.envGrant
      ? 'Saved in the system keychain, but SHIELDFIVE_GRANT in the assistant’s MCP settings still takes ' +
        'precedence after a restart; remove it there to use this one.'
      : 'Saved in the system keychain, so it stays connected after restarts.'
    : 'No system keychain is available, so this connection lasts until the assistant restarts.'
  return text(`Connected (${describeGrant(grant)}). ${persistence} The vault_* tools are ready to use now.`)
}

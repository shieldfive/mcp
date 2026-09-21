// The grant-authenticated ShieldFive API (/api/agent/v1).
//
// Every call goes to the server: nothing here caches a response, so an expired
// or revoked grant fails on the very next tool call (the server re-checks it on
// every request). Scope checks in this process are a courtesy that produces a
// clearer error; the server is the boundary.

import { grantBearerToken } from '@shieldfive/crypto/vault'

import { ToolError } from '../roots.mjs'

export const DEFAULT_API_URL = 'https://shieldfive.com'
const TIMEOUT_MS = 30_000

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms)
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(t)
        reject(signal.reason)
      },
      { once: true },
    )
  })
}

export function createVaultApi({ credential, baseUrl = DEFAULT_API_URL, fetchImpl = fetch }) {
  const bearer = grantBearerToken(credential)
  const origin = new URL(baseUrl)
  if (origin.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(origin.hostname)) {
    throw new Error('SHIELDFIVE_API_URL must be https (or localhost for development).')
  }

  // A rate-limited request waits and retries (at most 3 times, honouring
  // Retry-After and cancellation). A quota refusal does not: it will not clear
  // by waiting, so it surfaces at once.
  async function call(method, path, body, signal) {
    for (let attempt = 0; ; attempt++) {
      try {
        return await once(method, path, body, signal)
      } catch (err) {
        if (err?.code !== 'rate_limited' || attempt >= 3 || signal?.aborted) throw err
        await sleep(Math.min(60_000, (err.retryAfterSeconds ?? 15 * (attempt + 1)) * 1000), signal)
      }
    }
  }

  async function once(method, path, body, signal) {
    const url = new URL(`/api/agent/v1${path}`, origin)
    const timeout = AbortSignal.timeout(TIMEOUT_MS)
    let res
    try {
      res = await fetchImpl(url, {
        method,
        headers: {
          authorization: `Bearer ${bearer}`,
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
        cache: 'no-store',
      })
    } catch (err) {
      if (signal?.aborted) throw err
      throw new ToolError('network_error', 'Could not reach ShieldFive. Nothing was changed.')
    }
    if (res.ok) return res.json().catch(() => ({}))
    return failure(res)
  }

  async function failure(res) {
    const data = await res.json().catch(() => ({}))
    // The server's code is echoed to the model, so only a plain identifier passes.
    const code =
      typeof data.code === 'string' && /^[a-z_]{1,40}$/.test(data.code) ? data.code : `http_${res.status}`
    if (res.status === 401) {
      throw new ToolError(
        'grant_invalid',
        'This ShieldFive connection is expired or has been revoked. Call vault_connect to ' +
          'connect again (it opens ShieldFive in the browser to authorize).',
      )
    }
    if (res.status === 403 && code === 'missing_scope') {
      throw new ToolError(
        'missing_scope',
        `This connection does not include the "${data.scope === 'read' ? 'read' : 'organize'}" permission. ` +
          'The vault owner can create a connection with it in Settings → AI assistants.',
      )
    }
    if (res.status === 404) {
      throw new ToolError('not_found', 'That item is not in this connection’s scope, or no longer exists.')
    }
    if (res.status === 409) {
      throw new ToolError('conflict', 'That item changed since it was listed. List again and retry.')
    }
    if (res.status === 429 && code === 'write_budget_exhausted') {
      // Not a rate limit: waiting will not clear it. Only the vault owner can
      // raise it, by creating a connection with a larger upload allowance.
      throw new ToolError(
        'write_budget_exhausted',
        'This connection has used its upload allowance. Nothing was uploaded. The vault owner ' +
          'sets the allowance when authorizing a connection in ShieldFive → Settings → AI assistants.',
      )
    }
    if (res.status === 429 && (code === 'transfer_limit' || code === 'egress_cap' || data.reason === 'egress_cap')) {
      throw new ToolError(
        'quota_exceeded',
        'The vault owner’s download quota is used up for now (daily egress or monthly transfer). ' +
          'Downloads resume when it resets; listing and organizing still work.',
      )
    }
    if (res.status === 429) {
      const err = new ToolError('rate_limited', 'ShieldFive is rate-limiting this connection. Wait a minute and retry.')
      const retry = Number(res.headers.get('retry-after'))
      if (Number.isFinite(retry) && retry > 0) err.retryAfterSeconds = retry
      throw err
    }
    throw new ToolError(code, `ShieldFive refused the request (${res.status}). Nothing was changed.`)
  }

  // A download that fails is reported through the same error mapping as every
  // other call (401 revoked, 429 quota, …); a success is the byte stream.
  async function rawDownload(id, signal) {
    for (let attempt = 0; ; attempt++) {
      const url = new URL(`/api/agent/v1/files/${id}/download`, origin)
      const res = await fetchImpl(url, {
        method: 'POST',
        headers: { authorization: `Bearer ${bearer}` },
        signal,
        cache: 'no-store',
      }).catch((err) => {
        if (signal?.aborted) throw err
        throw new ToolError('network_error', 'Could not reach ShieldFive.')
      })
      if (res.ok && res.body) return res
      try {
        await failure(res)
      } catch (err) {
        if (err?.code !== 'rate_limited' || attempt >= 3 || signal?.aborted) throw err
        await sleep(Math.min(60_000, (err.retryAfterSeconds ?? 15 * (attempt + 1)) * 1000), signal)
      }
    }
  }

  async function listAll(path, key, signal) {
    const out = []
    let after = null
    for (let page = 0; page < 1000; page++) {
      const q = `?limit=1000${after ? `&after=${after}` : ''}`
      const data = await call('GET', `${path}${q}`, undefined, signal)
      out.push(...(data[key] ?? []))
      if (!data.next) return out
      after = data.next
    }
    throw new ToolError('too_large', 'The listing did not finish within 1,000 pages.')
  }

  return {
    grant: (signal) => call('GET', '/grant', undefined, signal),
    folders: (signal) => listAll('/folders', 'folders', signal),
    files: (signal) => listAll('/files', 'files', signal),
    stats: (signal) => call('GET', '/stats', undefined, signal),
    /**
     * The file's ciphertext, streamed through ShieldFive (no storage URL is ever
     * handed out). Refused past `maxBytes` without buffering the rest.
     */
    async download(id, maxBytes, signal) {
      const res = await rawDownload(id, signal)
      const len = Number(res.headers.get('content-length') ?? 0)
      if (len && len > maxBytes) throw new ToolError('too_large', 'File exceeds the size cap.')
      const reader = res.body.getReader()
      const parts = []
      let total = 0
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        total += value.length
        if (total > maxBytes) {
          await reader.cancel()
          throw new ToolError('too_large', 'File exceeds the size cap.')
        }
        parts.push(value)
      }
      const out = new Uint8Array(total)
      let off = 0
      for (const p of parts) {
        out.set(p, off)
        off += p.length
      }
      return out
    },
    patchFile: (id, body, signal) => call('PATCH', `/files/${id}`, body, signal),
    /** Reserve an upload: scope, destination and byte budget are checked server-side. */
    startUpload: (body, signal) => call('POST', '/files', body, signal),
    finalizeUpload: (id, body, signal) =>
      call('POST', `/files/${id}/finalize`, body, signal),
    /**
     * PUT the ciphertext at the presigned URL the reserve step returned.
     *
     * This is the one request that does not go to ShieldFive: the URL is
     * storage's, signed for exactly this object key, this method and a short
     * window. The bearer token is NOT sent with it — a storage URL must never
     * carry the vault credential.
     */
    async putCiphertext(uploadUrl, bytes, contentType, signal) {
      const target = new URL(uploadUrl)
      if (target.protocol !== 'https:') {
        throw new ToolError('network_error', 'Storage returned an insecure upload URL.')
      }
      let res
      try {
        res = await fetchImpl(target, {
          method: 'PUT',
          headers: {
            'content-type': contentType,
            'content-length': String(bytes.length),
          },
          body: bytes,
          signal,
        })
      } catch (err) {
        if (signal?.aborted) throw err
        throw new ToolError(
          'network_error',
          'The encrypted file could not be sent to storage. Nothing was changed.',
        )
      }
      if (!res.ok) {
        throw new ToolError(
          'upload_failed',
          `Storage refused the upload (${res.status}). Nothing was changed.`,
        )
      }
    },
    patchFolder: (id, body, signal) => call('PATCH', `/folders/${id}`, body, signal),
    createFolder: (body, signal) => call('POST', '/folders', body, signal),
    trash: (items, signal) => call('POST', '/trash', { items }, signal),
  }
}

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

export function createVaultApi({ credential, baseUrl = DEFAULT_API_URL, fetchImpl = fetch }) {
  const bearer = grantBearerToken(credential)
  const origin = new URL(baseUrl)
  if (origin.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(origin.hostname)) {
    throw new Error('SHIELDFIVE_API_URL must be https (or localhost for development).')
  }

  async function call(method, path, body, signal) {
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
    const data = await res.json().catch(() => ({}))
    if (res.ok) return data
    const code = typeof data.code === 'string' ? data.code : `http_${res.status}`
    if (res.status === 401) {
      throw new ToolError(
        'grant_invalid',
        'This ShieldFive connection is expired or has been revoked. Create a new one in ' +
          'ShieldFive → Settings → AI assistants and run `npx @shieldfive/mcp login`.',
      )
    }
    if (res.status === 403 && code === 'missing_scope') {
      throw new ToolError(
        'missing_scope',
        `This connection does not include the "${data.scope ?? 'organize'}" permission. ` +
          'The vault owner can create a connection with it in Settings → AI assistants.',
      )
    }
    if (res.status === 404) {
      throw new ToolError('not_found', 'That item is not in this connection’s scope, or no longer exists.')
    }
    if (res.status === 409) {
      throw new ToolError('conflict', 'That item changed since it was listed. List again and retry.')
    }
    if (res.status === 429) {
      throw new ToolError('rate_limited', 'ShieldFive is rate-limiting this connection. Wait a minute and retry.')
    }
    throw new ToolError(code, `ShieldFive refused the request (${res.status}). Nothing was changed.`)
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
    downloadUrl: (id, signal) => call('POST', `/files/${id}/download`, {}, signal),
    patchFile: (id, body, signal) => call('PATCH', `/files/${id}`, body, signal),
    patchFolder: (id, body, signal) => call('PATCH', `/folders/${id}`, body, signal),
    createFolder: (body, signal) => call('POST', '/folders', body, signal),
    trash: (items, signal) => call('POST', '/trash', { items }, signal),
    /** Ciphertext from a signed URL. The URL is not logged or returned. */
    async ciphertext(url, maxBytes, signal) {
      const res = await fetchImpl(url, { signal })
      if (!res.ok) throw new ToolError('download_failed', `Download failed (${res.status}).`)
      const len = Number(res.headers.get('content-length') ?? 0)
      if (len && len > maxBytes) throw new ToolError('too_large', 'File exceeds the size cap.')
      const buf = new Uint8Array(await res.arrayBuffer())
      if (buf.length > maxBytes) throw new ToolError('too_large', 'File exceeds the size cap.')
      return buf
    },
  }
}

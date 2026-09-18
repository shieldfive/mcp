// Opening a file's contents in memory. Nothing here writes plaintext, keys or
// ciphertext to disk; buffers are dropped when the call returns.

import { createHash } from 'node:crypto'

import { base64ToBytes } from '@shieldfive/crypto'
import { decryptToBytes as decryptV1 } from '@shieldfive/crypto/aes-gcm-v1'
import { decryptV0 } from '@shieldfive/crypto/legacy-v0'
import { decryptStreamPqHybridV1 } from '@shieldfive/crypto/streams/pq-hybrid-v1'
import { unwrapChainKey } from '@shieldfive/crypto/vault'

import { ToolError } from '../roots.mjs'

/**
 * The key that opens a file's content, from the keys this grant holds:
 *   cipher_version 3 (suite 0x03): the combined key K, from the aux wrap under
 *     the parent folder key, or the grant's file_pq wrap for a root-level file;
 *   cipher_version 1/2: the content key under the parent folder key, or the
 *     grant's file wrap for a root-level file.
 */
export async function contentKey(file, view) {
  const row = file.raw
  if (row.folderId) {
    const fk = view.folderKeys.get(row.folderId)
    if (!fk) return null
    if (row.cipherVersion === 3) {
      if (!row.pqkFkWrapped) return null
      return unwrapChainKey(fk, { wrapped: row.pqkFkWrapped, iv: row.pqkFkIv })
    }
    if (!row.cskWrapped) return null
    return unwrapChainKey(fk, { wrapped: row.cskWrapped, iv: row.cskIv })
  }
  return (row.cipherVersion === 3 ? view.wraps.file_pq : view.wraps.file).get(row.id) ?? null
}

/** The key csk_wrapped holds (classical envelope key for v3) — what a move re-wraps. */
export async function classicalKey(file, view) {
  const row = file.raw
  if (!row.folderId) return view.wraps.file.get(row.id) ?? null
  const fk = view.folderKeys.get(row.folderId)
  if (!fk || !row.cskWrapped) return null
  return unwrapChainKey(fk, { wrapped: row.cskWrapped, iv: row.cskIv })
}

export async function decryptContent(file, view, api, { maxBytes, signal }) {
  const key = await contentKey(file, view)
  if (!key) {
    throw new ToolError(
      'pending_owner_unlock',
      'This file cannot be opened by this connection yet. Post-quantum files become ' +
        'readable after the owner next opens ShieldFive on a device with their full keys.',
    )
  }
  const { url } = await api.downloadUrl(file.id, signal)
  const ciphertext = await api.ciphertext(url, maxBytes + 1024 * 1024, signal)
  const blob = new Blob([ciphertext])
  const row = file.raw
  let out
  try {
    if (row.cipherVersion === 3) {
      const { plaintext } = decryptStreamPqHybridV1(blob.stream(), { combinedKey: key })
      out = new Uint8Array(await new Response(plaintext).arrayBuffer())
    } else if (row.cipherVersion === 2) {
      out = await decryptV1({ blob, contentKey: key })
    } else if (row.cipherVersion === 1) {
      const plain = await decryptV0({
        blob,
        contentKey: key,
        noncePrefix: base64ToBytes(row.cipherNoncePrefix),
        chunkSize: row.cipherChunkSize,
      })
      out = new Uint8Array(await plain.arrayBuffer())
    }
  } catch {
    throw new ToolError(
      'decrypt_failed',
      'The file did not decrypt. It may be damaged or tampered with; nothing was changed.',
    )
  }
  if (!out) {
    throw new ToolError('unsupported', `Unsupported file format (cipher_version ${row.cipherVersion}).`)
  }
  if (out.length > maxBytes) throw new ToolError('too_large', 'File exceeds the size cap.')
  return out
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

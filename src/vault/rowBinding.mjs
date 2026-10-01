// Row binding: a files row's ciphertext and name are tied to the row's UUID,
// so a backend that can rewrite rows cannot move one file's content or name
// onto another row. Mirrors shieldfive/web utils/fileRowBinding.ts.
//
// Content: every v1 (cipher_version 2) and suite 0x03 (cipher_version 3)
// writer puts the row UUID in the header file_id, which the header MAC covers.
// The content-key wraps carry no row AAD, so the reader must compare.
//
// Names: rows with a UUIDv7 id were created with a v6 (row-bound) name from
// the first insert; any other envelope on such a row was copied from another
// row. Rows with older (v4) ids keep accepting v4 names.

import { webcrypto } from 'node:crypto'

import { parseHeader } from '@shieldfive/crypto'

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function isRowBoundId(rowId) {
  return typeof rowId === 'string' && UUID_V7.test(rowId)
}

/** RFC 9562 UUIDv7: 48-bit ms timestamp, version 7, 74 random bits. */
export function newRowBoundId(now = Date.now()) {
  const b = new Uint8Array(16)
  webcrypto.getRandomValues(b)
  let ts = Math.floor(now)
  for (let i = 5; i >= 0; i--) {
    b[i] = ts % 256
    ts = Math.floor(ts / 256)
  }
  b[6] = (b[6] & 0x0f) | 0x70
  b[8] = (b[8] & 0x3f) | 0x80
  const h = Buffer.from(b).toString('hex')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

export function uuidToBytes(uuid) {
  const hex = String(uuid).replace(/-/g, '').toLowerCase()
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error('not a uuid')
  return new Uint8Array(Buffer.from(hex, 'hex'))
}

/** True when the ciphertext's header file_id is this row's UUID. */
export function headerMatchesRow(ciphertext, rowId) {
  let parsed
  try {
    parsed = parseHeader(ciphertext.subarray(0, Math.min(ciphertext.length, 4096)))
  } catch {
    return false
  }
  const expected = uuidToBytes(rowId)
  if (parsed.fileId.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ parsed.fileId[i]
  return diff === 0
}

/** A row-bound row takes only a v6 name envelope. */
export function nameFitsRow(envelope, rowId) {
  return !isRowBoundId(rowId) || envelope?.v === 6
}

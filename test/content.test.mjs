// Reading file contents and connection strings against @shieldfive/crypto 1.0.1.
//
//   - A legacy v0 (cipher_version 1) file has no length binding: dropping whole
//     trailing chunks leaves every remaining chunk authentic. The reader must
//     compare against the ciphertext size the server recorded, as the web does.
//   - 1.0.1 rejects non-canonical connection strings, so one grant has exactly
//     one string form. 1.0.0-rc.6 accepted them.

import assert from 'node:assert/strict'
import { randomBytes, randomUUID, webcrypto } from 'node:crypto'
import { describe, it } from 'node:test'

import { createGrantCredential, formatConnectionString, wrapChainKey } from '@shieldfive/crypto/vault'
import { generateMlKemKeypair } from '@shieldfive/crypto/pq-hybrid-v1'

import { decryptContent } from '../src/vault/content.mjs'
import { loadGrantCredential } from '../src/vault/credential.mjs'

const CHUNK = 64
const TAG = 16

async function encryptV0(plaintext, contentKey, prefix) {
  const k = await webcrypto.subtle.importKey('raw', contentKey, 'AES-GCM', false, ['encrypt'])
  const parts = []
  for (let i = 0, c = 0; i < Math.max(plaintext.length, 1); i += CHUNK, c++) {
    const iv = new Uint8Array(12)
    iv.set(prefix, 0)
    new DataView(iv.buffer).setBigUint64(4, BigInt(c))
    parts.push(new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, plaintext.slice(i, i + CHUNK))))
  }
  return new Uint8Array(Buffer.concat(parts))
}

async function v0File(plaintext) {
  const folderKey = new Uint8Array(randomBytes(32))
  const csk = new Uint8Array(randomBytes(32))
  const prefix = new Uint8Array(randomBytes(4))
  const ciphertext = await encryptV0(plaintext, csk, prefix)
  const w = await wrapChainKey(folderKey, csk)
  const folderId = randomUUID()
  const row = {
    id: randomUUID(), folderId, cipherVersion: 1, cskWrapped: w.wrapped, cskIv: w.iv,
    cipherNoncePrefix: Buffer.from(prefix).toString('base64'), cipherChunkSize: CHUNK,
    size: plaintext.length, ciphertextSize: ciphertext.length,
  }
  const view = { folderKeys: new Map([[folderId, folderKey]]), wraps: { file: new Map(), file_pq: new Map() } }
  return { file: { id: row.id, raw: row }, view, ciphertext, row }
}

const apiServing = (bytes) => ({ download: async () => bytes })

describe('legacy v0 contents', () => {
  const plaintext = new Uint8Array(randomBytes(CHUNK * 6 + 10)) // 7 chunks

  it('opens an intact v0 file', async () => {
    const { file, view, ciphertext } = await v0File(plaintext)
    const out = await decryptContent(file, view, apiServing(ciphertext), { maxBytes: 1 << 20 })
    assert.deepEqual(out, plaintext)
  })

  it('refuses a v0 file whose trailing chunks were dropped, instead of returning a short file', async () => {
    const { file, view, ciphertext } = await v0File(plaintext)
    // Drop the short last chunk and one full chunk: what remains ends on a clean
    // chunk boundary, so every remaining AES-GCM tag still verifies.
    const cut = ciphertext.slice(0, (CHUNK + TAG) * 5)
    await assert.rejects(
      decryptContent(file, view, apiServing(cut), { maxBytes: 1 << 20 }),
      (err) => err.code === 'decrypt_failed',
    )
  })

  it('still opens a v0 row with no recorded ciphertext size (legacy rows)', async () => {
    const { file, view, ciphertext, row } = await v0File(plaintext)
    row.ciphertextSize = null
    const out = await decryptContent(file, view, apiServing(ciphertext), { maxBytes: 1 << 20 })
    assert.deepEqual(out, plaintext)
  })
})

describe('connection strings (@shieldfive/crypto 1.0.1)', () => {
  const credential = createGrantCredential({ grantId: randomUUID(), mlKemPublicKey: generateMlKemKeypair().publicKey })
  const canonical = formatConnectionString(credential)

  it('accepts the canonical form', async () => {
    const loaded = await loadGrantCredential({ SHIELDFIVE_GRANT: canonical }, async () => null)
    assert.equal(loaded.grantId, credential.grantId)
  })

  it('rejects a non-canonical spelling of the same grant', async () => {
    // A 32-byte value is 43 base64url chars; the last one carries 2 unused bits.
    // Setting one of them decodes to the same bytes but is a second string form.
    const parts = canonical.split('.')
    const token = parts[1]
    const last = token.at(-1)
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    parts[1] = token.slice(0, -1) + alphabet[alphabet.indexOf(last) ^ 1]
    const variant = parts.join('.')
    assert.notEqual(variant, canonical)
    await assert.rejects(loadGrantCredential({ SHIELDFIVE_GRANT: variant }, async () => null), /not valid/)
  })
})

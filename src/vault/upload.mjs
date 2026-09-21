// Encrypting a local file INTO the vault.
//
// The bytes are encrypted here, on this machine, before anything leaves it.
// ShieldFive receives ciphertext and a wrapped key it cannot open, exactly as
// it does from the apps.
//
// Post-quantum (cipher_version 3) is the only format written. It needs the
// owner's PUBLIC ML-KEM key, which the server serves to a write-capable
// connection — and which is CHECKED HERE against the fingerprint pinned in the
// connection string the owner handed this machine. That check is what stops a
// malicious or compromised server from having an assistant encrypt the user's
// files to a recipient the user never chose: substitute a key, and the
// fingerprint no longer matches, and nothing is uploaded.
//
// Nothing on disk is touched by this module. Deleting the local copy is the
// caller's decision, taken only after the upload has been read back and
// compared byte-for-byte (tools/vault.mjs).

import { createHash, webcrypto } from 'node:crypto'
import { Readable } from 'node:stream'

import { base64ToBytes, bytesToBase64 } from '@shieldfive/crypto'
import { encryptStreamPqHybridV1 } from '@shieldfive/crypto/streams/pq-hybrid-v1'
import {
  buildUploadProofV3,
  publicKeyFingerprint,
  wrapChainKey,
} from '@shieldfive/crypto/vault'

import { ToolError } from '../roots.mjs'

/** Refused above this; the server refuses it too (AGENT_MAX_UPLOAD_BYTES). */
export const MAX_UPLOAD_BYTES = 512 * 1024 * 1024

/**
 * The recipient key for this vault, verified against the connection string.
 *
 * `pkfp` is part of the credential the owner's browser produced, so it was
 * fixed before this process ever spoke to the server.
 */
export function recipientPublicKey(grant, credential) {
  const b64 = grant?.mlKemPublicKey
  if (typeof b64 !== 'string' || b64.length === 0) {
    throw new ToolError(
      'no_recipient_key',
      'This vault has no post-quantum key on record yet. Open ShieldFive once on a device with your keys, then try again.',
    )
  }
  let bytes
  try {
    bytes = base64ToBytes(b64)
  } catch {
    throw new ToolError('no_recipient_key', 'The vault’s public key could not be read.')
  }
  const fp = publicKeyFingerprint(bytes)
  if (!credential.publicKeyFingerprint || fp !== credential.publicKeyFingerprint) {
    throw new ToolError(
      'key_mismatch',
      'The public key ShieldFive served does not match the one in this connection. ' +
        'Nothing was uploaded. Create a new connection; if it happens again, stop and report it.',
    )
  }
  return bytes
}

/** AES-GCM under the folder key, the same wrap shape every other key uses. */
async function wrapUnderFolderKey(folderKey, keyBytes) {
  const { wrapped, iv } = await wrapChainKey(folderKey, keyBytes)
  return { wrapped, iv }
}

/**
 * Encrypt one local file for `folderKey`, in memory, and return everything the
 * server needs plus the plaintext hash the verification step compares against.
 */
export async function encryptForVault({
  // A ReadableStream of the plaintext, opened by the caller: this module does
  // not touch the filesystem, so nothing here can write decrypted bytes to it.
  source,
  size,
  folderKey,
  recipientPublicKey: pk,
}) {
  if (!Number.isInteger(size) || size <= 0) {
    throw new ToolError('empty_file', 'There is nothing in that file to upload.')
  }
  if (size > MAX_UPLOAD_BYTES) {
    throw new ToolError(
      'too_large',
      `That file is larger than the ${Math.floor(MAX_UPLOAD_BYTES / 1024 / 1024)} MB limit for an assistant upload.`,
    )
  }

  // The envelope key is the classical half: csk_wrapped holds it, and the
  // owner's own client opens the file with it plus their ML-KEM secret.
  const envelopeKey = new Uint8Array(32)
  webcrypto.getRandomValues(envelopeKey)

  const plaintextHash = createHash('sha256')
  const hashing = source.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        plaintextHash.update(chunk)
        controller.enqueue(chunk)
      },
    }),
  )

  const { ciphertext, combinedKey } = await encryptStreamPqHybridV1(hashing, {
    recipientPublicKey: pk,
    envelopeKey,
    plaintextSize: size,
  })

  const bytes = new Uint8Array(await new Response(ciphertext).arrayBuffer())

  // csk_wrapped: the classical envelope key, as every client writes it.
  // pqk_fk_wrapped: the combined key K, so this connection (and any other
  // holder of the folder key) can read the file back immediately — which is
  // what makes "verify it arrived" possible without the owner unlocking.
  const csk = await wrapUnderFolderKey(folderKey, envelopeKey)
  const pqk = await wrapUnderFolderKey(folderKey, combinedKey)

  envelopeKey.fill(0)
  combinedKey.fill(0)

  return {
    ciphertext: bytes,
    cskWrapped: csk.wrapped,
    cskIv: csk.iv,
    pqkFkWrapped: pqk.wrapped,
    pqkFkIv: pqk.iv,
    cipherVersion: 3,
    plaintextSha256: plaintextHash.digest('hex'),
  }
}

// The proof frame lives in @shieldfive/crypto (buildUploadProofV3): the web app
// produces the same bytes, and the server verifies exactly one frame.
export async function uploadProof(proofKeyHex, ciphertext) {
  return buildUploadProofV3({ proofKeyHex, ciphertext })
}

export { bytesToBase64 }

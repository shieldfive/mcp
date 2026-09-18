// Worker for name decryption. Argon2id costs ~70 ms per name at the web app's
// "interactive" level, so names are opened on a small pool of threads. Keys
// arrive over the in-process message channel; nothing touches disk.

import { parentPort } from 'node:worker_threads'

import { decryptName, decryptNameWithKey, parseNameEnvelope } from '@shieldfive/crypto/vault'

parentPort.on('message', async ({ id, raw, key, rowId, direct }) => {
  try {
    const envelope = parseNameEnvelope(raw)
    if (!envelope) {
      parentPort.postMessage({ id, ok: false })
      return
    }
    const name = direct
      ? await decryptNameWithKey({ envelope, nameKey: key, rowId })
      : await decryptName({ envelope, folderKey: key, rowId })
    parentPort.postMessage({ id, ok: true, name })
  } catch {
    parentPort.postMessage({ id, ok: false })
  }
})

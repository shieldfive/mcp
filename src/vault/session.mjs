// One view of the vault as this grant can see it, rebuilt on every tool call.
//
// Every call re-fetches the grant, its wraps and the in-scope listing from the
// server. That is what makes revocation and expiry take effect on the next
// call: nothing here outlives a request except (a) the grant wrap key derived
// from the connection string and (b) decrypted names, cached by envelope. Both
// live only in this process's memory.
//
// Keys come from exactly two places: the grant's own wraps (opened with the
// grant secret) and the folder-key chain below them. Nothing here can derive a
// key the grant was not given; a folder or file whose key does not open is
// reported as unreadable, never guessed.

import {
  deriveGrantWrapKey,
  unwrapChainKey,
  unwrapKeyForGrant,
} from '@shieldfive/crypto/vault'

import { ToolError } from '../roots.mjs'

// C0/C1 controls, line/paragraph separators and bidi overrides/isolates: a
// decrypted name is attacker-influenced text headed for a model's context.
const UNSAFE = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u2028-\\u2029\\u202a-\\u202e\\u2066-\\u2069]', 'g')

/** A name as it may be shown to a model: no control or bidi characters, bounded. */
export function displayName(name) {
  if (typeof name !== 'string') return null
  const clean = name.replace(UNSAFE, String.fromCharCode(0xfffd))
  return clean.length > 255 ? `${clean.slice(0, 255)}…` : clean
}

export const TRASH_LABEL = 'ShieldFive Bin (this connection)'

export function createVaultSession({ credential, api, names }) {
  let wrapKey = null

  async function grantWrapKey() {
    wrapKey ??= await deriveGrantWrapKey(credential.secret, credential.grantId)
    return wrapKey
  }

  /** Fetch and open everything this grant can see right now. */
  async function load(signal, onProgress) {
    const { grant, keys } = await api.grant(signal)
    if (grant.id !== credential.grantId) {
      throw new ToolError(
        'grant_mismatch',
        'The server answered for a different connection. Nothing was read.',
      )
    }
    const gk = await grantWrapKey()
    const wraps = { folder: new Map(), file: new Map(), file_pq: new Map(), name: new Map() }
    for (const k of keys) {
      if (!wraps[k.kind]) continue
      try {
        wraps[k.kind].set(
          k.objectId,
          await unwrapKeyForGrant({
            grantWrapKey: gk,
            grantId: grant.id,
            kind: k.kind,
            objectId: k.objectId,
            wrapped: k,
          }),
        )
      } catch {
        // A wrap that does not open under this grant's key was not made for
        // this grant, or was tampered with. Ignored, never trusted.
      }
    }

    const [folderRows, fileRows] = await Promise.all([api.folders(signal), api.files(signal)])

    // Folder keys: the grant's wraps for its roots, then the chain downwards.
    const folderKeys = new Map(wraps.folder)
    let grew = true
    while (grew) {
      grew = false
      for (const f of folderRows) {
        if (folderKeys.has(f.id) || f.isScopeRoot || !f.parentId || !f.fkWrapped) continue
        const parentKey = folderKeys.get(f.parentId)
        if (!parentKey) continue
        try {
          folderKeys.set(f.id, await unwrapChainKey(parentKey, { wrapped: f.fkWrapped, iv: f.fkIv }))
          grew = true
        } catch {
          // Unopenable branch; its contents are reported as unreadable.
        }
      }
    }

    // Names, in parallel on the worker pool.
    const total = folderRows.length + fileRows.length
    let done = 0
    // Raw names are what writes re-seal; display names are what the model sees.
    const nameOf = async (row, parentId, isRoot) => {
      let name = null
      if (row.id === grant.trashFolderId) name = TRASH_LABEL
      else if (isRoot || !parentId) {
        const k = wraps.name.get(row.id)
        if (k) name = await names.decrypt({ raw: row.name, key: k, rowId: row.id, direct: true })
      } else {
        const k = folderKeys.get(parentId)
        if (k) name = await names.decrypt({ raw: row.name, key: k, rowId: row.id })
      }
      onProgress?.(++done, total)
      return name
    }
    const folderNames = await Promise.all(folderRows.map((f) => nameOf(f, f.parentId, f.isScopeRoot)))
    const fileNames = await Promise.all(fileRows.map((f) => nameOf(f, f.folderId, false)))

    const folders = new Map()
    folderRows.forEach((f, i) => {
      folders.set(f.id, {
        id: f.id,
        name: displayName(folderNames[i]),
        rawName: folderNames[i],
        parentId: f.isScopeRoot ? null : f.parentId,
        isScopeRoot: f.isScopeRoot,
        inTrash: f.inTrash,
        updatedAt: f.updatedAt,
        raw: f,
      })
    })
    const pathOf = (folderId) => {
      const parts = []
      let cur = folderId ? folders.get(folderId) : null
      for (let depth = 0; cur && depth < 256; depth++) {
        parts.unshift(cur.name ?? '[name unavailable]')
        cur = cur.parentId ? folders.get(cur.parentId) : null
      }
      return `/${parts.join('/')}`
    }
    for (const f of folders.values()) f.path = pathOf(f.id)

    const files = new Map()
    fileRows.forEach((f, i) => {
      const name = displayName(fileNames[i])
      files.set(f.id, {
        id: f.id,
        name,
        rawName: fileNames[i],
        path: `${f.folderId ? pathOf(f.folderId) : ''}/${name ?? '[name unavailable]'}`,
        folderId: f.folderId,
        size: f.size ?? null,
        ciphertextSize: f.ciphertextSize ?? null,
        createdAt: f.createdAt,
        updatedAt: f.updatedAt,
        contentType: typeof f.contentType === 'string' ? displayName(f.contentType.slice(0, 100)) : null,
        cipherVersion: f.cipherVersion,
        inTrash: f.inTrash,
        readable: contentKeyAvailable(f, folderKeys, wraps),
        raw: f,
      })
    })

    return { grant, folders, files, folderKeys, wraps }
  }

  return { load, grantWrapKey }
}

function contentKeyAvailable(f, folderKeys, wraps) {
  if (f.folderId) {
    if (!folderKeys.has(f.folderId)) return false
    return f.cipherVersion === 3 ? Boolean(f.pqkFkWrapped) : Boolean(f.cskWrapped)
  }
  return f.cipherVersion === 3 ? wraps.file_pq.has(f.id) : wraps.file.has(f.id)
}

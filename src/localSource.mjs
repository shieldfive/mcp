// The local half of an upload: the only place that opens a file on this
// machine for the vault path to read.
//
// It exists so the vault modules keep their boundary — they import no
// filesystem module at all, which is what makes "decrypted data cannot be
// written to disk" a fact about the code rather than a promise. Reading a local
// plaintext file is the one direction upload needs, and it happens here, under
// the same root rules every local tool obeys: a path outside the configured
// roots, or reached through a symlink that leaves them, is refused before it is
// opened.
//
// It also holds the one local WRITE the vault side may ask for: moving a file
// whose upload has been verified into this server's own trash — the same
// directory, rules and manifest trash_local uses. Never a delete.

import { createReadStream } from 'node:fs'
import { join } from 'node:path'
import { Readable } from 'node:stream'

import { quote } from './format.mjs'
import { entryId } from './plans.mjs'
import { resolveEntry, ToolError } from './roots.mjs'
import { TRASH_DIR_NAME } from './scan.mjs'
import {
  batchName,
  discardBatch,
  inspectTrashDir,
  inTrash,
  makeParents,
  moveIntoTrash,
  openBatch,
  trashBaseFor,
  trashPaths,
  writeManifest,
} from './trash.mjs'

/**
 * A gateway over the allowed roots, handed to the vault upload tool through
 * ctx. Nothing here decrypts, and nothing here talks to the network.
 */
export function createLocalFileGateway(ctx) {
  return {
    /** Resolve inside the roots and describe the file. Never opens it. */
    async describe(input) {
      // resolveEntry, not resolveExisting: the last component is NOT followed,
      // so a symlink is the thing named rather than whatever it points at.
      // Uploading through a link would read a file the roots never allowed.
      const entry = await resolveEntry(ctx.roots, input, { what: 'path' })
      if (!entry.stats.isFile()) {
        throw new ToolError(
          'not_a_file',
          entry.stats.isSymbolicLink()
            ? 'That path is a symbolic link. Point at the file itself.'
            : 'Only a single file can be uploaded; point at a file, not a folder.',
        )
      }
      return {
        path: entry.realPath,
        name: entry.realPath.split('/').pop() ?? 'file',
        size: entry.stats.size,
        // The inode identity, so the confirmed call can prove it is uploading
        // the file the preview described and not one swapped in since.
        entry: entryId(entry.stats),
        root: entry.root.realPath,
      }
    },

    /** A byte stream of the plaintext, for encryption in memory. */
    open(realPath) {
      return Readable.toWeb(createReadStream(realPath))
    },

    /**
     * Where a file would go in the local trash. Read-only, for a preview: it
     * refuses now what the move would refuse later.
     */
    async trashPlan(realPath) {
      const entry = await resolveEntry(ctx.roots, realPath, { what: 'path' })
      if (inTrash(entry.root.realPath, entry.realPath)) {
        throw new ToolError(
          'already_trashed',
          `Refused: ${quote(entry.realPath)} is already in this server's trash.`,
        )
      }
      const base = await trashBaseFor(entry.root.realPath, entry.realPath, entry.stats)
      await inspectTrashDir(base)
      return { trashDirectory: join(base, TRASH_DIR_NAME) }
    },

    /**
     * One call's trash: a batch per trash directory, opened on first use.
     *
     * Each file is added to its batch's manifest BEFORE it moves (with whatever
     * the caller records about it, such as where its vault copy is), and taken
     * out again if the move fails, so the manifest never names a file that is
     * not there and never misses one that is.
     */
    openTrash() {
      const batch = batchName(ctx.now())
      const batches = new Map()
      return {
        batch,
        async trash(realPath, expectedEntry, record = {}) {
          const entry = await resolveEntry(ctx.roots, realPath, { what: 'path' })
          // The same file, unchanged since it was read for upload: a file
          // rewritten or swapped since then is not the one that was verified.
          if (entryId(entry.stats) !== expectedEntry) {
            throw new ToolError(
              'changed',
              `${quote(realPath)} changed after it was uploaded, so the verified copy is not ` +
                'this file any more. It was left where it is.',
            )
          }
          const base = await trashBaseFor(entry.root.realPath, entry.realPath, entry.stats)
          let b = batches.get(base)
          if (!b) {
            b = await openBatch(base, batch)
            batches.set(base, b)
          }
          const destination = trashPaths(base, batch, entry.realPath).destination
          b.entries.push({
            original_path: entry.realPath,
            trashed_to: destination,
            kind: 'file',
            bytes: entry.stats.size,
            ...record,
          })
          await writeManifest(b, ctx.now())
          try {
            await makeParents(b, destination)
            await moveIntoTrash(entry.realPath, destination, entry.stats)
          } catch (err) {
            b.entries.pop()
            if (b.entries.length) {
              await writeManifest(b, ctx.now()).catch(() => {})
            } else {
              await discardBatch(b).catch(() => {})
              batches.delete(base)
            }
            throw err
          }
          return { trashedTo: destination, trashDirectory: join(base, TRASH_DIR_NAME) }
        },
      }
    },

  }
}

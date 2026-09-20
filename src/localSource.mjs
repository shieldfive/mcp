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

import { createReadStream } from 'node:fs'
import { Readable } from 'node:stream'

import { entryId } from './plans.mjs'
import { resolveEntry, ToolError } from './roots.mjs'

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

  }
}

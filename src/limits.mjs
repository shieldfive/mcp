// Upper bounds on what a caller may ask for.
//
// The MCP schema in server.mjs applies these before a handler runs, and the
// handlers apply them again, so a handler reached any other way enforces the
// same bounds. Before they existed, limit, max_files, max_files_hashed, paths
// and new_name had no upper bound: a caller could ask for a ten-million-row
// payload, a scan with no effective cap, or a name longer than any filesystem
// accepts, which then came back whole in the refusal.

import { quote } from './format.mjs'
import { MAX_PATH_CHARS, ToolError } from './roots.mjs'

export const LIMITS = Object.freeze({
  /** Rows a listing returns. */
  limit: 10_000,
  /** Files one scan may walk, across every root. The default is 200,000. */
  maxFiles: 1_000_000,
  /** Hash reads find_duplicates may spend. The default is 20,000. */
  maxFilesHashed: 1_000_000,
  /** Paths one trash_local call may take. */
  paths: 1_000,
  /** Characters in a path argument. */
  pathChars: MAX_PATH_CHARS,
  /** UTF-8 bytes in a file name: NAME_MAX on APFS, ext4 and most others. */
  nameBytes: 255,
})

/** An optional positive whole-number argument, defaulted and bounded. */
export function boundedInt(value, { name, max, fallback }) {
  if (value === undefined || value === null) return fallback
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new ToolError(
      'invalid_argument',
      `${name} must be a whole number from 1 to ${max.toLocaleString('en-US')}; ` +
        `got ${quote(value, 40)}.`,
    )
  }
  return value
}

/** A list argument with at least one and at most `max` entries. */
export function boundedList(value, { name, max }) {
  const list = Array.isArray(value) ? value : value === undefined ? [] : [value]
  if (list.length === 0) {
    throw new ToolError('invalid_path', `At least one entry in ${name} is required.`)
  }
  if (list.length > max) {
    throw new ToolError(
      'invalid_argument',
      `${name} may hold at most ${max.toLocaleString('en-US')} entries; got ` +
        `${list.length.toLocaleString('en-US')}. Split the call.`,
    )
  }
  return list
}

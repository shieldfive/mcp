#!/usr/bin/env node
// @shieldfive/mcp — a Model Context Protocol server for local file management.
//
// WHAT THIS SERVER DOES NOT DO, AND WHY THAT IS THE DESIGN
//
// It holds no ShieldFive credential, makes no network request, and does not
// import @shieldfive/crypto. That is not a gap to be filled later; it is the
// security boundary, expressed as an absence.
//
// The alternative was to authenticate with a full ShieldFive account JWT. That
// token also opens /api/vault-key — the wrapped root key and an ML-KEM public
// key — and every content-download route, and none of it can be scoped away,
// because no scoped vault credential exists. A server holding that token would
// be DECLINING to read your files rather than being UNABLE to, with the
// difference resting on a client-side denylist and on the token file not being
// read by anything else on the machine. A server holding no token cannot read
// them at all. See docs/mcp-v1-step0-discovery.md in shieldfive/web for the
// full argument, and README.md § "What this cannot do" for the consequences.
//
// The cost is honest: v1 cannot tell you whether a local file is already backed
// up. It will not guess, either — matching a filename and a size against a
// vault listing is how a tool deletes the only copy of something.

import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'

import { toolFailure } from './format.mjs'
import { NO_ROOTS_MESSAGE, resolveRoots, rootCandidatesFrom } from './roots.mjs'
import {
  findDuplicates,
  findLargeFiles,
  findOldFiles,
  listLocal,
  storageSummary,
} from './tools/read.mjs'
import { createLocalFolder, moveLocal, renameLocal, trashLocal } from './tools/mutate.mjs'

export const VERSION = '0.1.0'

/** stdout is the protocol channel. Everything human goes to stderr. */
const log = (...parts) => process.stderr.write(`[shieldfive-mcp] ${parts.join(' ')}\n`)

// 4096 is PATH_MAX on Linux and far above anything macOS accepts. The cap is
// not about the filesystem: without it a 5 MB path argument was reflected
// verbatim into the error message and landed 1:1 in the model's context.
const pathArg = z
  .string()
  .max(4096, 'path is longer than any filesystem accepts')
  .describe('Absolute path. Must resolve inside a configured root; relative paths are refused.')

const scanArgs = {
  path: pathArg.optional().describe('Directory to scan. Omit to scan every configured root.'),
  include_hidden: z.boolean().optional().describe('Include dotfiles and dot-directories.'),
  max_files: z
    .number()
    .int()
    .positive()
    .optional()
    .describe('Stop after this many files. The result says so when the cap is hit.'),
  limit: z.number().int().positive().optional().describe('Maximum rows to return.'),
}

const TOOLS = [
  {
    name: 'list_local',
    title: 'List local files',
    description:
      'List files in an allowed local directory, with sizes and modification dates. ' +
      'Never follows symlinks and never leaves the configured roots.',
    inputSchema: { ...scanArgs, sort_by: z.enum(['path', 'size', 'modified']).optional() },
    annotations: { readOnlyHint: true, openWorldHint: false },
    handler: listLocal,
  },
  {
    name: 'find_duplicates',
    title: 'Find duplicate files',
    description:
      'Find files with byte-identical contents. Identity is decided by a full SHA-256 ' +
      'of each file, never by matching names or sizes. Reports how much space keeping ' +
      'one copy of each would reclaim.',
    inputSchema: {
      ...scanArgs,
      min_bytes: z
        .number()
        .int()
        .nonnegative()
        .optional()
        .describe('Ignore files smaller than this. Default 1.'),
      max_files_hashed: z
        .number()
        .int()
        .positive()
        .optional()
        .describe('Hashing budget. When reached, the result says it is a lower bound.'),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    handler: findDuplicates,
  },
  {
    name: 'find_large_files',
    title: 'Find large files',
    description: 'List files at or above a size threshold, largest first.',
    inputSchema: {
      ...scanArgs,
      min_bytes: z.number().int().positive().optional().describe('Default 100 MB.'),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    handler: findLargeFiles,
  },
  {
    name: 'find_old_files',
    title: 'Find stale files',
    description:
      'List files not modified for a given number of days. Modification time is a weak ' +
      'signal and the result says so; treat the output as a shortlist to review.',
    inputSchema: {
      ...scanArgs,
      older_than_days: z.number().int().positive().optional().describe('Default 365.'),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    handler: findOldFiles,
  },
  {
    name: 'storage_summary',
    title: 'Summarise local storage',
    description:
      'Total file count and bytes for the allowed roots, broken down by file extension ' +
      'and by directory. Reports file-content sizes, which will not match a disk ' +
      'utility exactly.',
    inputSchema: scanArgs,
    annotations: { readOnlyHint: true, openWorldHint: false },
    handler: storageSummary,
  },
  {
    name: 'move_local',
    title: 'Move a file or folder',
    description:
      'Move a file or directory to another location inside the allowed roots. Without ' +
      'confirm: true this only reports what it would do. Refuses to overwrite unless ' +
      'overwrite: true is also passed.',
    inputSchema: {
      source: pathArg,
      destination: pathArg.describe(
        'Absolute destination. If it is an existing directory, the source is moved into it.',
      ),
      overwrite: z.boolean().optional().describe('Replace the destination if it exists.'),
      confirm: z.boolean().optional().describe('Required to actually move anything.'),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    handler: moveLocal,
  },
  {
    name: 'rename_local',
    title: 'Rename a file or folder',
    description:
      'Rename an item in place. new_name must be a bare filename, not a path. Never ' +
      'replaces an existing file. Without confirm: true this only reports the plan.',
    inputSchema: {
      path: pathArg,
      new_name: z.string().describe('The new filename, with no directory separators.'),
      confirm: z.boolean().optional().describe('Required to actually rename.'),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    handler: renameLocal,
  },
  {
    name: 'create_local_folder',
    title: 'Create a folder',
    description:
      'Create a directory (and any missing parents) inside the allowed roots. ' +
      'Without confirm: true this only reports the plan.',
    inputSchema: {
      path: pathArg,
      confirm: z.boolean().optional().describe('Required to actually create it.'),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    handler: createLocalFolder,
  },
  {
    name: 'trash_local',
    title: 'Move files to this server’s trash',
    description:
      'Move files or folders into a .shieldfive-mcp-trash directory inside their own ' +
      'root, with a manifest recording where each came from. NOTHING IS DELETED and no ' +
      'disk space is freed — the bytes stay on the same volume until you empty that ' +
      'directory yourself. Without confirm: true this only reports the plan.',
    inputSchema: {
      paths: z.array(pathArg).min(1).describe('Absolute paths to move into the trash.'),
      confirm: z.boolean().optional().describe('Required to actually move anything.'),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    handler: trashLocal,
  },
]

export function createServer(ctx) {
  const server = new McpServer(
    { name: 'shieldfive-mcp', version: VERSION },
    {
      instructions:
        'Local file management for the directories the user allowed at startup. ' +
        'This server has no ShieldFive credential and makes no network calls, so it ' +
        'cannot see, list or verify anything in a ShieldFive vault. Do not tell the ' +
        'user a local file is backed up: this server cannot know that, and guessing ' +
        'from a filename and size is how the only copy of something gets deleted. ' +
        'Mutating tools do nothing until called with confirm: true — show the user ' +
        'the plan first.',
    },
  )

  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      },
      async (args, extra) => {
        try {
          // extra.signal is aborted when the client cancels the request. It was
          // previously discarded, so a cancelled scan of a large tree kept
          // hashing to completion.
          return await tool.handler({ ...ctx, signal: extra?.signal }, args ?? {})
        } catch (err) {
          if (err?.name === 'AbortError' || extra?.signal?.aborted) {
            return toolFailure(new Error('Cancelled.'))
          }
          if (err?.name !== 'ToolError') {
            log(`${tool.name} failed:`, err?.stack ?? String(err))
          }
          return toolFailure(err)
        }
      },
    )
  }

  return server
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  const { roots, rejected } = await resolveRoots(rootCandidatesFrom(argv, env))

  for (const r of rejected) log(`ignoring root ${r.path}: ${r.reason}`)
  if (roots.length) {
    log(`serving ${roots.length} root(s):`, roots.map((r) => r.realPath).join(', '))
  } else {
    log('NO ROOTS CONFIGURED — every tool will refuse.')
    log(NO_ROOTS_MESSAGE)
  }

  const ctx = { roots, noRootsMessage: NO_ROOTS_MESSAGE, now: () => Date.now() }
  const server = createServer(ctx)
  await server.connect(new StdioServerTransport())
  log('ready on stdio.')
  return server
}

/**
 * Is this module the program, rather than something someone imported?
 *
 * Both sides must be realpath'd. npm installs the `bin` as a SYMLINK — argv[1]
 * is `node_modules/.bin/shieldfive-mcp` while `import.meta.url` is the resolved
 * `node_modules/@shieldfive/mcp/src/server.mjs`. Comparing them unresolved is
 * false for every installed copy, so the server exits silently the moment it is
 * run the way an actual user runs it. `import.meta.main` would avoid this but
 * is Node 24+, and this package supports 20.
 */
function isMain() {
  if (!process.argv[1]) return false
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
}

if (isMain()) {
  main().catch((err) => {
    log('fatal:', err?.stack ?? String(err))
    process.exit(1)
  })
}

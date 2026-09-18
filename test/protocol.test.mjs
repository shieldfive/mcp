// End-to-end over a real stdio transport.
//
// The unit tests call handlers directly, which proves the logic and proves
// nothing about whether this is a working MCP server. This spawns the published
// entry point and talks to it with the real client.

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

import { makeTree } from './helpers.mjs'

const ENTRY = fileURLToPath(new URL('../src/server.mjs', import.meta.url))

let tree
let client

before(async () => {
  tree = await makeTree({
    'vault/a.txt': 'IDENTICAL',
    'vault/nested/a-copy.txt': 'IDENTICAL',
    'vault/unique.txt': 'something else',
  })

  client = new Client({ name: 'test', version: '1.0.0' })
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [ENTRY, tree.path('vault')],
      stderr: 'pipe',
    }),
  )
})

after(async () => {
  await client?.close()
  await tree?.cleanup()
})

describe('MCP protocol', () => {
  it('registers exactly the nine local tools', async () => {
    const { tools } = await client.listTools()
    assert.deepEqual(
      tools.map((t) => t.name).sort(),
      [
        'create_local_folder',
        'find_duplicates',
        'find_large_files',
        'find_old_files',
        'list_local',
        'move_local',
        'rename_local',
        'storage_summary',
        'trash_local',
      ],
    )
  })

  it('registers no vault tool', async () => {
    // v1 holds no credential, so a vault tool would be one that cannot work.
    // The discovery doc's rule is that such a tool is not registered at all
    // rather than registered and thrown from.
    const { tools } = await client.listTools()
    const vaultish = tools.filter((t) => /vault|upload|remote|cloud|sync/i.test(t.name))
    assert.deepEqual(vaultish, [])
  })

  it('marks the read-only tools read-only and closed-world', async () => {
    const { tools } = await client.listTools()
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]))
    for (const name of ['list_local', 'find_duplicates', 'find_large_files', 'find_old_files', 'storage_summary']) {
      assert.equal(byName[name].annotations?.readOnlyHint, true, `${name} must be read-only`)
    }
    for (const t of tools) {
      assert.equal(t.annotations?.openWorldHint, false, `${t.name} must declare a closed world`)
    }
  })

  it('finds the duplicate pair over the wire', async () => {
    const res = await client.callTool({ name: 'find_duplicates', arguments: {} })
    const data = JSON.parse(res.content[1].text)
    assert.equal(data.duplicate_groups, 1)
    assert.equal(data.groups[0].copies, 2)
  })

  it('returns a readable refusal for a path outside the root', async () => {
    const res = await client.callTool({
      name: 'list_local',
      arguments: { path: '/etc' },
    })
    assert.equal(res.isError, true)
    assert.match(res.content[0].text, /outside_roots/)
  })

  it('previews a mutation instead of performing it', async () => {
    const res = await client.callTool({
      name: 'create_local_folder',
      arguments: { path: tree.path('vault/brand-new') },
    })
    assert.match(res.content[0].text, /Planned \(nothing changed\)/)
  })

  it('reports the version in package.json', async () => {
    const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
    assert.equal(client.getServerVersion()?.version, pkg.version)
  })

  it('rejects out-of-range arguments at the schema, before doing any work', async () => {
    const limit = await client.callTool({ name: 'list_local', arguments: { limit: 10_000_001 } })
    assert.equal(limit.isError, true, 'limit above its cap must be refused')
    assert.match(limit.content[0].text, /10000/)

    const paths = await client.callTool({
      name: 'trash_local',
      arguments: { paths: Array.from({ length: 1001 }, () => tree.path('vault/a.txt')) },
    })
    assert.equal(paths.isError, true, 'more than 1000 paths must be refused')
    assert.match(paths.content[0].text, /1000/)

    const name = await client.callTool({
      name: 'rename_local',
      arguments: { path: tree.path('vault/a.txt'), new_name: 'x'.repeat(5000) },
    })
    assert.equal(name.isError, true)
    assert.ok(name.content[0].text.length < 1000, 'an oversized name must not be echoed back whole')
  })

  it('carries instructions telling the model not to claim a backup', async () => {
    const instructions = client.getInstructions()
    assert.match(instructions, /cannot see the ShieldFive vault/i)
    assert.match(instructions, /backed up/i)
  })

  it('STARTS WHEN INVOKED THROUGH A SYMLINK, as npm installs it', async () => {
    // npm links `bin` into node_modules/.bin, so argv[1] is the symlink while
    // import.meta.url is the resolved real path. Comparing them unresolved is
    // false for every installed copy, and the server exits silently — working
    // perfectly from a source checkout and not at all once published. This is
    // the only invocation that catches it.
    const linkDir = await mkdtemp(join(tmpdir(), 'sf-mcp-bin-'))
    const link = join(linkDir, 'shieldfive-mcp')
    await symlink(ENTRY, link)

    const viaLink = new Client({ name: 'via-link', version: '1.0.0' })
    try {
      await viaLink.connect(
        new StdioClientTransport({
          command: process.execPath,
          args: [link, tree.path('vault')],
          stderr: 'pipe',
        }),
      )
      const { tools } = await viaLink.listTools()
      assert.equal(tools.length, 9, 'the server must start when run through its bin symlink')
    } finally {
      await viaLink.close().catch(() => {})
      await rm(linkDir, { recursive: true, force: true })
    }
  })
})

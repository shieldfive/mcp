// Cancellation of the mutating tools.
//
// A cancelled request reached the mutating tools as a signal none of them
// looked at, so a move or a trash the user had already called off ran to
// completion. Nothing now starts once the request is cancelled, a trash batch
// stops between items, and the server records what did happen -- the SDK sends
// no response to a cancelled request, so the log is the only place left to
// say it.

import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { lstat, readFile } from 'node:fs/promises'
import { after, describe, it } from 'node:test'

import { ToolError } from '../src/roots.mjs'
import { createLocalFolder, moveLocal, renameLocal, trashLocal } from '../src/tools/mutate.mjs'
import { apply, makeCtx, makeTree } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

/** True when nothing at all -- not even a dangling link -- is at `p`. */
const absent = (p) =>
  lstat(p).then(
    () => false,
    () => true,
  )

/** An AbortSignal that has already fired, as a cancelled MCP request hands a handler. */
function abortedSignal() {
  const controller = new AbortController()
  controller.abort()
  return controller.signal
}

describe('cancellation', () => {
  it('changes nothing once the request is cancelled, in every mutating tool', async () => {
    const t = await tree({ 'in/a.txt': 'a', 'in/b.txt': 'b', 'in/dest/.keep': '' })
    const ctx = { ...(await makeCtx([t.path('in')])), signal: abortedSignal() }
    const cancelled = (e) => e.code === 'cancelled'

    await assert.rejects(
      () => apply(moveLocal, ctx, { source: t.path('in/a.txt'), destination: t.path('in/dest')}),
      cancelled,
    )
    await assert.rejects(
      () => apply(renameLocal, ctx, { path: t.path('in/a.txt'), new_name: 'renamed.txt'}),
      cancelled,
    )
    await assert.rejects(() => apply(createLocalFolder, ctx, { path: t.path('in/new-folder')}), cancelled)
    await assert.rejects(() => apply(trashLocal, ctx, { paths: [t.path('in/b.txt')]}), cancelled)

    assert.equal(await readFile(t.path('in/a.txt'), 'utf8'), 'a')
    assert.equal(await readFile(t.path('in/b.txt'), 'utf8'), 'b')
    assert.equal(await absent(t.path('in/new-folder')), true)
    assert.equal(await absent(t.path('in/dest/a.txt')), true)
    assert.equal(await absent(t.path('in/renamed.txt')), true)
  })

  it('stops a trash batch between items when cancelled, and says exactly what moved', async () => {
    const t = await tree({ 'in/a.txt': 'a', 'in/b.txt': 'b', 'in/c.txt': 'c' })
    const first = t.path('in/a.txt')
    // A cancellation that arrives the moment the first item has left its place.
    const signal = {
      get aborted() {
        return !existsSync(first)
      },
      reason: new Error('cancelled'),
      throwIfAborted() {
        if (this.aborted) throw Object.assign(new Error('cancelled'), { name: 'AbortError' })
      },
    }
    const ctx = { ...(await makeCtx([t.path('in')])), signal }

    const err = await apply(trashLocal, ctx, {
      paths: [first, t.path('in/b.txt'), t.path('in/c.txt')]
    }).then(
      () => null,
      (e) => e,
    )

    assert.ok(err, 'a cancelled batch must not report success')
    assert.equal(err.code, 'cancelled_partially_applied')
    assert.equal(err.detail.moved.length, 1)
    assert.equal(await readFile(t.path('in/b.txt'), 'utf8'), 'b')
    assert.equal(await readFile(t.path('in/c.txt'), 'utf8'), 'c')
    const manifest = JSON.parse(await readFile(err.detail.manifests[0], 'utf8'))
    assert.deepEqual(
      manifest.items.map((i) => i.original_path),
      [first],
    )
  })

  it('the server reports what a cancelled mutation did instead of masking it', async () => {
    // The wrapper turned any error raised after cancellation into "Cancelled.",
    // including a partial trash with its record of what had moved, and the SDK
    // then dropped even that.
    const server = await import('../src/server.mjs')
    assert.equal(typeof server.runTool, 'function', 'the tool wrapper must be testable')

    const logs = []
    const tool = {
      name: 'trash_local',
      annotations: { readOnlyHint: false },
      handler: async () => {
        throw new ToolError('trash_partially_applied', 'Stopped after moving 1 of 2 item(s).', {
          moved: [{ original_path: '/r/a' }],
        })
      },
    }
    const res = await server.runTool(tool, {}, {}, { signal: abortedSignal() }, (...parts) =>
      logs.push(parts.join(' ')),
    )

    assert.match(res.content[0].text, /trash_partially_applied/)
    assert.equal(JSON.parse(res.content[1].text).moved.length, 1)
    assert.ok(
      logs.some((l) => /cancel/i.test(l) && l.includes('trash_partially_applied')),
      'the SDK drops the response to a cancelled request, so the outcome must be logged',
    )
  })
})

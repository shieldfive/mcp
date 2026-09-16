// A confirmed call is bound to the preview the user approved (D3).
//
// Before this, the two calls were unrelated: the preview measured the tree, the
// user said yes, and the confirmed call measured it again and acted on whatever
// it found. These tests are the difference — a plan that no longer describes
// the filesystem is refused, and refused before anything is written.

import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { readFile, rm, writeFile } from 'node:fs/promises'
import { after, describe, it } from 'node:test'

import { createPlanStore, entryId, PLAN_TTL_MS } from '../src/plans.mjs'
import { createLocalFolder, moveLocal, renameLocal, trashLocal } from '../src/tools/mutate.mjs'
import { apply, makeCtx, makeTree, payload, planToken, summary } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

const changed = (e) => e.code === 'plan_changed'

describe('a preview hands back a token', () => {
  it('every mutating tool returns one, and still changes nothing', async () => {
    const t = await tree({ 'in/a.txt': 'x', 'in/dest': null, 'in/junk.txt': 'j' })
    const ctx = await makeCtx([t.path('in')])

    const move = payload(await moveLocal(ctx, { source: t.path('in/a.txt'), destination: t.path('in/dest') }))
    const rename = payload(await renameLocal(ctx, { path: t.path('in/a.txt'), new_name: 'b.txt' }))
    const folder = payload(await createLocalFolder(ctx, { path: t.path('in/new') }))
    const trash = payload(await trashLocal(ctx, { paths: [t.path('in/junk.txt')] }))

    for (const [name, data] of Object.entries({ move, rename, folder, trash })) {
      assert.match(data.plan_token ?? '', /^plan_[0-9a-f]{32}$/, `${name} must issue a token`)
      assert.equal(data.performed, false)
    }
    assert.equal(await readFile(t.path('in/a.txt'), 'utf8'), 'x')
    assert.equal(existsSync(t.path('in/new')), false)
  })

  it('says how to use it', async () => {
    const t = await tree({ 'in/a.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    const res = await renameLocal(ctx, { path: t.path('in/a.txt'), new_name: 'b.txt' })
    assert.match(summary(res), /plan_token/)
  })
})

describe('a confirmed call without the token', () => {
  it('is refused, and nothing is moved', async () => {
    const t = await tree({ 'in/a.txt': 'x', 'in/dest': null })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => moveLocal(ctx, { source: t.path('in/a.txt'), destination: t.path('in/dest'), confirm: true }),
      (e) => e.code === 'plan_token_required',
    )
    assert.equal(await readFile(t.path('in/a.txt'), 'utf8'), 'x')
  })

  it('is refused for a trash call too, the one that moves the most at once', async () => {
    const t = await tree({ 'in/a.txt': 'a', 'in/b.txt': 'b' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () => trashLocal(ctx, { paths: [t.path('in/a.txt'), t.path('in/b.txt')], confirm: true }),
      (e) => e.code === 'plan_token_required',
    )
    assert.equal(await readFile(t.path('in/a.txt'), 'utf8'), 'a')
  })

  it('is refused when the token was never issued by this server', async () => {
    const t = await tree({ 'in/a.txt': 'x' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(
      () =>
        renameLocal(ctx, {
          path: t.path('in/a.txt'),
          new_name: 'b.txt',
          confirm: true,
          plan_token: 'plan_deadbeefdeadbeefdeadbeefdeadbeef',
        }),
      (e) => e.code === 'unknown_plan_token',
    )
    assert.equal(existsSync(t.path('in/b.txt')), false)
  })
})

describe('a token approves one plan, once', () => {
  it('cannot be replayed', async () => {
    const t = await tree({ 'in/.keep': '' })
    const ctx = await makeCtx([t.path('in')])
    const token = await planToken(createLocalFolder, ctx, { path: t.path('in/new') })
    const args = { path: t.path('in/new'), confirm: true, plan_token: token }
    assert.equal(payload(await createLocalFolder(ctx, args)).performed, true)

    // Put the tree back exactly as the plan described it. The token is still
    // spent: an approval performs one change, not one change per state.
    await rm(t.path('in/new'), { recursive: true })
    await assert.rejects(() => createLocalFolder(ctx, args), (e) => e.code === 'unknown_plan_token')
    assert.equal(existsSync(t.path('in/new')), false)
  })

  it('cannot approve a different call', async () => {
    const t = await tree({ 'in/keep.txt': 'keep', 'in/junk.txt': 'junk' })
    const ctx = await makeCtx([t.path('in')])
    const token = await planToken(trashLocal, ctx, { paths: [t.path('in/junk.txt')] })

    await assert.rejects(
      () => trashLocal(ctx, { paths: [t.path('in/keep.txt')], confirm: true, plan_token: token }),
      changed,
    )
    assert.equal(await readFile(t.path('in/keep.txt'), 'utf8'), 'keep')
  })

  it('is spent on a cancelled call only if the call got as far as changing something', async () => {
    const t = await tree({ 'in/a.txt': 'x' })
    const controller = new AbortController()
    controller.abort()
    const base = await makeCtx([t.path('in')])
    const token = await planToken(renameLocal, base, { path: t.path('in/a.txt'), new_name: 'b.txt' })

    await assert.rejects(
      () =>
        renameLocal(
          { ...base, signal: controller.signal },
          { path: t.path('in/a.txt'), new_name: 'b.txt', confirm: true, plan_token: token },
        ),
      (e) => e.code === 'cancelled',
    )
    // The cancelled call changed nothing, so the approval is still good.
    const res = await renameLocal(base, {
      path: t.path('in/a.txt'),
      new_name: 'b.txt',
      confirm: true,
      plan_token: token,
    })
    assert.equal(payload(res).performed, true)
  })
})

describe('a plan that no longer describes the tree', () => {
  it('refuses a trash whose directory grew between the plan and the call', async () => {
    const t = await tree({ 'in/box/one.txt': '1' })
    const ctx = await makeCtx([t.path('in')])
    const token = await planToken(trashLocal, ctx, { paths: [t.path('in/box')] })

    await writeFile(t.path('in/box/two.txt'), '2')
    await assert.rejects(
      () => trashLocal(ctx, { paths: [t.path('in/box')], confirm: true, plan_token: token }),
      changed,
    )
    assert.equal(existsSync(t.path('in/box/two.txt')), true, 'nothing may be trashed')
    assert.equal(existsSync(t.path('in/box/one.txt')), true)
  })

  it('refuses when the file behind the path was replaced by another file', async () => {
    const t = await tree({ 'in/a.txt': 'original', 'in/dest': null })
    const ctx = await makeCtx([t.path('in')])
    const token = await planToken(moveLocal, ctx, {
      source: t.path('in/a.txt'),
      destination: t.path('in/dest'),
    })

    // Same name, same length, different entry: this is the substitution the
    // token exists for, and byte counts alone would not notice it.
    await rm(t.path('in/a.txt'))
    await writeFile(t.path('in/a.txt'), 'different')
    await assert.rejects(
      () =>
        moveLocal(ctx, {
          source: t.path('in/a.txt'),
          destination: t.path('in/dest'),
          confirm: true,
          plan_token: token,
        }),
      changed,
    )
    assert.equal(await readFile(t.path('in/a.txt'), 'utf8'), 'different')
    assert.equal(existsSync(t.path('in/dest/a.txt')), false)
  })

  it('refuses when a destination appeared that the plan said was free', async () => {
    const t = await tree({ 'in/a.txt': 'new', 'in/dest': null })
    const ctx = await makeCtx([t.path('in')])
    const token = await planToken(moveLocal, ctx, {
      source: t.path('in/a.txt'),
      destination: t.path('in/dest/a.txt'),
    })

    await writeFile(t.path('in/dest/a.txt'), 'appeared')
    await assert.rejects(
      () =>
        moveLocal(ctx, {
          source: t.path('in/a.txt'),
          destination: t.path('in/dest/a.txt'),
          confirm: true,
          overwrite: true,
          plan_token: token,
        }),
      changed,
    )
    assert.equal(await readFile(t.path('in/dest/a.txt'), 'utf8'), 'appeared')
  })

  it('names what changed, so the model can show a new plan instead of guessing', async () => {
    const t = await tree({ 'in/box/one.txt': '1' })
    const ctx = await makeCtx([t.path('in')])
    const token = await planToken(trashLocal, ctx, { paths: [t.path('in/box')] })
    await writeFile(t.path('in/box/two.txt'), '2')

    await assert.rejects(
      () => trashLocal(ctx, { paths: [t.path('in/box')], confirm: true, plan_token: token }),
      (e) => /items changed between the plan and this call/.test(e.message),
    )
  })

  it('refuses an approval older than the time limit', async () => {
    const t = await tree({ 'in/a.txt': 'x' })
    let clock = Date.UTC(2026, 8, 16)
    const ctx = await makeCtx([t.path('in')], { now: () => clock })
    const token = await planToken(renameLocal, ctx, { path: t.path('in/a.txt'), new_name: 'b.txt' })

    clock += PLAN_TTL_MS + 1
    await assert.rejects(
      () =>
        renameLocal(ctx, { path: t.path('in/a.txt'), new_name: 'b.txt', confirm: true, plan_token: token }),
      (e) => e.code === 'plan_expired',
    )
    assert.equal(existsSync(t.path('in/b.txt')), false)
  })
})

describe('an unchanged plan still performs', () => {
  it('moves, renames, creates and trashes through a preview', async () => {
    const t = await tree({ 'in/a.txt': 'x', 'in/dest': null, 'in/junk.txt': 'j' })
    const ctx = await makeCtx([t.path('in')])

    assert.equal(payload(await apply(moveLocal, ctx, { source: t.path('in/a.txt'), destination: t.path('in/dest') })).performed, true)
    assert.equal(payload(await apply(renameLocal, ctx, { path: t.path('in/dest/a.txt'), new_name: 'b.txt' })).performed, true)
    assert.equal(payload(await apply(createLocalFolder, ctx, { path: t.path('in/new') })).performed, true)
    assert.equal(payload(await apply(trashLocal, ctx, { paths: [t.path('in/junk.txt')] })).performed, true)

    assert.equal(await readFile(t.path('in/dest/b.txt'), 'utf8'), 'x')
    assert.equal(existsSync(t.path('in/new')), true)
    assert.equal(existsSync(t.path('in/junk.txt')), false)
  })

  it('tolerates a touch that changes nothing the plan described', async () => {
    const t = await tree({ 'in/box/one.txt': '1' })
    const ctx = await makeCtx([t.path('in')])
    const token = await planToken(trashLocal, ctx, { paths: [t.path('in/box')] })
    // Reading a file is not a change to the plan.
    await readFile(t.path('in/box/one.txt'))
    const res = await trashLocal(ctx, { paths: [t.path('in/box')], confirm: true, plan_token: token })
    assert.equal(payload(res).performed, true)
  })
})

describe('the store itself', () => {
  it('issues opaque tokens that cannot be derived from the plan', () => {
    const store = createPlanStore()
    const a = store.issue({ action: 'trash', items: [] })
    const b = store.issue({ action: 'trash', items: [] })
    assert.notEqual(a, b, 'two identical plans must not share a token')
  })

  it('forgets the oldest plans rather than growing without a bound', () => {
    let clock = 0
    const store = createPlanStore({ now: () => (clock += 1), capacity: 3 })
    const tokens = [1, 2, 3, 4, 5].map((n) => store.issue({ n }))
    assert.ok(store.size <= 3)
    assert.equal(store.take(tokens[0]).ok, false)
    assert.equal(store.take(tokens[4]).ok, true)
  })

  it('distinguishes two entries that look alike but are not the same file', async () => {
    const t = await tree({ 'in/a.txt': 'same', 'in/b.txt': 'same' })
    const { lstat } = await import('node:fs/promises')
    assert.notEqual(entryId(await lstat(t.path('in/a.txt'))), entryId(await lstat(t.path('in/b.txt'))))
  })

  it('reports absence, so a destination that appears is a different plan', () => {
    assert.equal(entryId(null), 'absent')
  })
})

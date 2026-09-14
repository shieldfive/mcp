// One test per defect found by the pre-release adversarial review.
//
// Each mirrors the reproduction that was demonstrated against the real module,
// so a regression fails here rather than on someone's disk.

import assert from 'node:assert/strict'
import { chmod, mkdir, readFile, stat, utimes, writeFile } from 'node:fs/promises'
import { after, describe, it } from 'node:test'
import { join } from 'node:path'

import { formatBytes } from '../src/format.mjs'
import { TRASH_DIR_NAME, walk, walkRoots } from '../src/scan.mjs'
import { findDuplicates, findOldFiles, listLocal, storageSummary } from '../src/tools/read.mjs'
import { moveLocal, trashLocal } from '../src/tools/mutate.mjs'
import { makeCtx, makeTree, payload, summary } from './helpers.mjs'

const trees = []
async function tree(spec) {
  const t = await makeTree(spec)
  trees.push(t)
  return t
}
after(async () => {
  for (const t of trees) await t.cleanup()
})

const gone = async (p) => {
  try {
    await stat(p)
    return false
  } catch {
    return true
  }
}

describe('move_local must never delete', () => {
  it('DISPLACES an overwritten directory to the trash instead of rm -rf', async () => {
    // The critical finding: `rm(finalPath, {recursive: true, force: true})`
    // destroyed every file under the destination, unrecoverably, while the
    // README said the server deletes nothing.
    const t = await tree({
      'in/src/one.txt': 'new',
      'in/dest/src/IRREPLACEABLE.txt': 'must survive',
      'in/dest/src/deep/also.txt': 'must also survive',
    })
    const ctx = await makeCtx([t.path('in')])

    const res = await moveLocal(ctx, {
      source: t.path('in/src'),
      destination: t.path('in/dest'),
      overwrite: true,
      confirm: true,
    })
    const data = payload(res)

    assert.equal(data.performed, true)
    assert.ok(data.displaced_to, 'the displaced directory must be recorded')
    assert.ok(data.displaced_to.includes(TRASH_DIR_NAME))

    const survivor = join(data.displaced_to, 'IRREPLACEABLE.txt')
    assert.equal(await readFile(survivor, 'utf8'), 'must survive')
    assert.equal(await readFile(join(data.displaced_to, 'deep', 'also.txt'), 'utf8'), 'must also survive')
    assert.match(summary(res), /not deleted/i)
  })

  it('reports what it would DESTROY in the preview, not only what it moves', async () => {
    // The preview used to show the source's 3 bytes while silently planning to
    // remove two irreplaceable files.
    const t = await tree({
      'in/src/one.txt': 'abc',
      'in/dest/src/big-a.txt': 'x'.repeat(5000),
      'in/dest/src/big-b.txt': 'y'.repeat(5000),
    })
    const ctx = await makeCtx([t.path('in')])

    const res = await moveLocal(ctx, {
      source: t.path('in/src'),
      destination: t.path('in/dest'),
      overwrite: true,
    })
    const data = payload(res)

    assert.equal(data.performed, false)
    assert.equal(data.displaced.files, 2)
    assert.equal(data.displaced.bytes, 10_000)
    assert.match(summary(res), /DISPLACES/)
    assert.equal(await readFile(t.path('in/dest/src/big-a.txt'), 'utf8').then((s) => s.length), 5000)
  })

  it('REFUSES a directory moved onto its own parent', async () => {
    // finalPath resolved to the source itself, the guard passed, and the
    // overwrite branch then deleted the source outright.
    const t = await tree({
      'in/sub/important-a.txt': 'a',
      'in/sub/important-b.txt': 'b',
      'in/sub/nested/c.txt': 'c',
    })
    const ctx = await makeCtx([t.path('in')])

    await assert.rejects(
      () =>
        moveLocal(ctx, {
          source: t.path('in/sub'),
          destination: t.path('in'),
          overwrite: true,
          confirm: true,
        }),
      (e) => e.code === 'destination_is_source',
    )

    assert.equal(await readFile(t.path('in/sub/important-a.txt'), 'utf8'), 'a')
    assert.equal(await readFile(t.path('in/sub/nested/c.txt'), 'utf8'), 'c')
  })
})

describe('scanning does not crash or silently under-report', () => {
  it('does not spread the file array as call arguments', async () => {
    // 130,000 files threw RangeError from `files.push(...result.files)` — below
    // the 200,000 cap the schema advertises. Building the fixture is too slow
    // for this suite, so the mechanism is asserted at the source level, the way
    // the other structural guarantees in this package are.
    const src = await readFile(new URL('../src/scan.mjs', import.meta.url), 'utf8')
    // Comments first: the comment explaining this fix quotes the broken call,
    // and a raw scan matches the explanation instead of the code.
    const code = src
      .split('\n')
      .map((line) => (line.trim().startsWith('//') ? '' : line))
      .join('\n')
    assert.ok(
      !/files\.push\(\s*\.\.\./.test(code),
      'walkRoots must not spread the per-root array into push()',
    )
  })

  it('applies max_files as a budget ACROSS roots, not per root', async () => {
    const t = await tree({
      'one/a.txt': 'x',
      'one/b.txt': 'x',
      'one/c.txt': 'x',
      'two/d.txt': 'x',
      'two/e.txt': 'x',
    })
    const ctx = await makeCtx([t.path('one'), t.path('two')])
    const data = payload(await listLocal(ctx, { max_files: 3 }))
    assert.ok(data.total_files <= 3, `expected at most 3 files, got ${data.total_files}`)
    assert.match(data.warnings.join(' '), /PARTIAL/)
  })

  it('counts a dot-named symlink as a symlink, not as a hidden entry', async () => {
    const t = await tree({
      'real/x.txt': 'x',
      '.link': { symlinkTo: 'real' },
      'visible-link': { symlinkTo: 'real' },
    })
    const { stats } = await walk(t.base)
    assert.equal(stats.symlinksSkipped, 2, 'both links must be reported as links')
  })

  it('WARNS that hidden files and build directories are excluded from totals', async () => {
    // storage_summary reported 1.0 KB of a 10 MB tree with warnings: [].
    const t = await tree({
      'in/visible.bin': 'x'.repeat(1000),
      'in/node_modules/huge.bin': 'x'.repeat(50_000),
      'in/dist/bundle.bin': 'x'.repeat(30_000),
      'in/.hiddendir/a.bin': 'x'.repeat(20_000),
      'in/.hiddenfile.bin': 'x'.repeat(7000),
    })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await storageSummary(ctx, {}))

    assert.equal(data.total_files, 1)
    const joined = data.warnings.join(' ')
    assert.match(joined, /hidden item\(s\) excluded/i)
    assert.match(joined, /build\/cache director/i)
  })
})

describe('warnings reach the line a model reads', () => {
  it('find_old_files puts its warnings in the summary, like every other tool', async () => {
    const spec = {}
    for (let i = 0; i < 12; i++) spec[`in/f${i}.txt`] = 'x'
    const t = await tree(spec)
    const old = new Date('2000-01-01T00:00:00Z')
    for (let i = 0; i < 12; i++) await utimes(t.path(`in/f${i}.txt`), old, old)

    const ctx = await makeCtx([t.path('in')])
    const res = await findOldFiles(ctx, { max_files: 5, older_than_days: 30 })
    assert.match(summary(res), /PARTIAL/, 'truncation must be on the summary line')
    assert.match(summary(res), /not evidence a file is unwanted/i)
  })
})

describe('formatBytes promotes units after rounding', () => {
  it('renders 999,999 bytes as 1.0 MB rather than 1000 KB', () => {
    assert.equal(formatBytes(999_500), '1.0 MB')
    assert.equal(formatBytes(999_999), '1.0 MB')
    assert.equal(formatBytes(999_999_999), '1.0 GB')
  })

  it('still renders ordinary values normally', () => {
    assert.equal(formatBytes(0), '0 B')
    assert.equal(formatBytes(999), '999 B')
    assert.equal(formatBytes(1000), '1.0 KB')
    assert.equal(formatBytes(1500), '1.5 KB')
    assert.equal(formatBytes(-1), 'unknown')
  })
})

describe('find_duplicates budget', () => {
  it('does not abandon the most valuable group when the budget is tight', async () => {
    // The old all-or-nothing gate skipped a group entirely if it did not fit,
    // and a group is large precisely because it has many copies — so the budget
    // was biased against the groups worth the most.
    const spec = {}
    for (let i = 0; i < 6; i++) spec[`in/big${i}.bin`] = 'B'.repeat(4000)
    spec['in/small-a.bin'] = 'S'
    spec['in/small-b.bin'] = 'S'
    const t = await tree(spec)
    const ctx = await makeCtx([t.path('in')])

    const generous = payload(await findDuplicates(ctx, {}))
    assert.equal(generous.duplicate_groups, 2)
    assert.equal(generous.reclaimable_bytes, 4000 * 5 + 1)

    // The largest group must be the one that survives a tight budget.
    const tight = payload(await findDuplicates(ctx, { max_files_hashed: 6 }))
    assert.ok(tight.reclaimable_bytes >= 4000 * 5, 'the biggest group must be hashed first')
    assert.match(tight.warnings.join(' '), /lower bound/i)
  })

  it('counts every hash read against the budget, head and full', async () => {
    const spec = {}
    for (let i = 0; i < 4; i++) spec[`in/f${i}.bin`] = 'x'.repeat(100_000)
    const t = await tree(spec)
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findDuplicates(ctx, {}))
    // 4 files over the 64 KiB head window: 4 head reads + 4 full reads.
    assert.equal(data.hash_reads, 8)
  })

  it('skips the head pass for files at or under the head window', async () => {
    // For a small file the head hash reads the same bytes as the full hash, so
    // it filtered nothing and doubled the I/O.
    const t = await tree({ 'in/a.bin': 'x'.repeat(1000), 'in/b.bin': 'x'.repeat(1000) })
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findDuplicates(ctx, {}))
    assert.equal(data.hash_reads, 2, 'two small files should cost two reads, not four')
    assert.equal(data.duplicate_groups, 1)
  })

  it('bounds other_copies so one huge group cannot blow up the payload', async () => {
    const spec = {}
    for (let i = 0; i < 60; i++) spec[`in/c${i}.txt`] = 'SAME'
    const t = await tree(spec)
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await findDuplicates(ctx, { limit: 1 }))
    assert.equal(data.groups[0].copies, 60)
    assert.equal(data.groups[0].other_copies.length, 50)
    assert.equal(data.groups[0].other_copies_omitted, 9)
  })

  it('honours min_bytes: 0 and says what it did', async () => {
    const t = await tree({ 'in/e1.txt': '', 'in/e2.txt': '', 'in/a.txt': 'SAME', 'in/b.txt': 'SAME' })
    const ctx = await makeCtx([t.path('in')])

    const without = payload(await findDuplicates(ctx, {}))
    assert.equal(without.files_considered, 2)

    const with0 = payload(await findDuplicates(ctx, { min_bytes: 0 }))
    assert.equal(with0.files_considered, 4)
    assert.match(with0.warnings.join(' '), /empty files are included/i)
  })
})

describe('storage_summary answers the question it is asked', () => {
  it('rolls bytes up to ancestor directories, not just the immediate parent', async () => {
    const spec = { 'in/Downloads/one.bin': 'x'.repeat(2000) }
    for (let i = 0; i < 9; i++) spec[`in/Movies/trip${i}/clip.bin`] = 'x'.repeat(1000)
    const t = await tree(spec)
    const ctx = await makeCtx([t.path('in')])
    const data = payload(await storageSummary(ctx, { limit: 20 }))

    const movies = data.largest_directories.find((d) => d.key === t.path('in/Movies'))
    const downloads = data.largest_directories.find((d) => d.key === t.path('in/Downloads'))
    assert.ok(movies, 'the parent directory must appear at all')
    assert.equal(movies.bytes, 9000)
    assert.ok(movies.bytes > downloads.bytes, 'the 9 KB tree must outrank the 2 KB folder')
  })
})

describe('path arguments', () => {
  it('refuses an empty path instead of scanning every root', async () => {
    const t = await tree({ 'in/a.txt': 'x', 'in/b.txt': 'y' })
    const ctx = await makeCtx([t.path('in')])
    await assert.rejects(() => listLocal(ctx, { path: '' }), (e) => e.code === 'invalid_path')
  })
})

describe('trash_local robustness', () => {
  it('writes the manifest for items already moved when a later one fails', async () => {
    const t = await tree({ 'in/keep/a.txt': 'a', 'in/locked/b.txt': 'b' })
    const ctx = await makeCtx([t.path('in')])
    await chmod(t.path('in/locked'), 0o555)

    try {
      let err
      try {
        await trashLocal(ctx, {
          paths: [t.path('in/keep/a.txt'), t.path('in/locked/b.txt')],
          confirm: true,
        })
      } catch (e) {
        err = e
      }
      assert.ok(err, 'the failing item must surface as an error')
      assert.equal(err.code, 'trash_partially_applied')
      assert.equal(err.detail.moved.length, 1)

      const manifest = JSON.parse(await readFile(err.detail.manifests[0], 'utf8'))
      assert.equal(manifest.items[0].original_path, t.path('in/keep/a.txt'))
      assert.equal(await gone(t.path('in/keep/a.txt')), true)
      assert.equal(await readFile(manifest.items[0].trashed_to, 'utf8'), 'a')
    } finally {
      await chmod(t.path('in/locked'), 0o755)
    }
  })

  it('keeps the manifest inside the root even when the root path contains the trash name', async () => {
    // trashRoot was derived with indexOf(sep + TRASH_DIR_NAME + sep), which
    // finds the FIRST occurrence — so this root put the manifest outside itself.
    const t = await tree({ [`${TRASH_DIR_NAME}/vault/file.txt`]: 'x' })
    const root = t.path(`${TRASH_DIR_NAME}/vault`)
    const ctx = await makeCtx([root])

    const data = payload(await trashLocal(ctx, { paths: [join(root, 'file.txt')], confirm: true }))
    for (const m of data.manifests) {
      assert.ok(m.startsWith(root + '/'), `manifest ${m} escaped the root ${root}`)
    }
    assert.equal(JSON.parse(await readFile(data.manifests[0], 'utf8')).items.length, 1)
  })
})

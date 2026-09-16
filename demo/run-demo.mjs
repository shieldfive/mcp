#!/usr/bin/env node
// A synthetic demonstration of what this server does, on files it creates
// itself in a temporary directory. Nothing outside that directory is read,
// written or listed, and the directory is removed at the end unless you pass
// --keep.
//
// It exists so the tools can be shown to someone without pointing them at a
// real machine, and so the claims in the README — duplicates found by content,
// previews before writes, a trash you can undo — are demonstrable rather than
// only asserted in tests.
//
//   node demo/run-demo.mjs [--keep]

import {
  mkdtemp,
  mkdir,
  realpath,
  rm,
  utimes,
  writeFile,
  readdir,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createPlanStore } from '../src/plans.mjs'
import { resolveRoots } from '../src/roots.mjs'
import {
  findDuplicates,
  findLargeFiles,
  findOldFiles,
  storageSummary,
} from '../src/tools/read.mjs'
import { trashLocal } from '../src/tools/mutate.mjs'

const keep = process.argv.includes('--keep')
const MB = 1024 * 1024

const summary = (result) => result.content[0].text
const payload = (result) => JSON.parse(result.content[1].text)

function heading(text) {
  console.log(`\n── ${text} ${'─'.repeat(Math.max(0, 62 - text.length))}`)
}

async function buildFixture() {
  const root = await mkdtemp(join(tmpdir(), 'shieldfive-mcp-demo-'))
  await mkdir(join(root, 'photos/2019'), { recursive: true })
  await mkdir(join(root, 'archive'), { recursive: true })

  // The same bytes under two different names, in two different folders: the
  // case name matching gets wrong and a content hash gets right.
  const holiday = Buffer.alloc(256 * 1024, 7)
  await writeFile(join(root, 'photos/holiday.jpg'), holiday)
  await writeFile(join(root, 'photos/2019/holiday-copy.jpg'), holiday)
  // Same size, different bytes — a name-and-size tool would call this a copy.
  await writeFile(join(root, 'photos/2019/beach.jpg'), Buffer.alloc(256 * 1024, 9))

  await writeFile(join(root, 'archive/backup.bin'), Buffer.alloc(12 * MB, 3))

  const stale = join(root, 'archive/quarterly-report.pdf')
  await writeFile(stale, Buffer.alloc(4096, 1))
  const twoYearsAgo = Date.now() / 1000 - 730 * 24 * 60 * 60
  await utimes(stale, twoYearsAgo, twoYearsAgo)

  return root
}

async function main() {
  const root = await buildFixture()
  const { roots } = await resolveRoots([root])
  const now = () => Date.now()
  const ctx = { roots, noRootsMessage: 'no roots', now, plans: createPlanStore({ now }) }
  // macOS resolves /var to /private/var, and the tools report resolved paths,
  // so strip both spellings when printing.
  const realRoot = await realpath(root)
  const short = (p) => String(p).replace(realRoot, '.').replace(root, '.')

  console.log(`Root: ${root}`)
  console.log('Five files: two with identical contents, one same-size decoy,')
  console.log('one 12 MB archive, one PDF last modified two years ago.')

  heading('storage_summary')
  const stored = await storageSummary(ctx, {})
  console.log(summary(stored))

  heading('find_duplicates — by content, not by name')
  const dupes = await findDuplicates(ctx, {})
  console.log(summary(dupes))
  for (const group of payload(dupes).groups ?? []) {
    const paths = [group.oldest_copy, ...(group.other_copies ?? [])].map((c) =>
      short(c.path),
    )
    console.log(`  ${paths.join('  =  ')}`)
    console.log(`  sha256 ${group.sha256.slice(0, 16)}…, names differ: ${group.names_differ}`)
  }
  console.log('  beach.jpg is the same size as holiday.jpg and is not in the group.')

  heading('find_large_files — min_bytes 5 MB')
  const large = await findLargeFiles(ctx, { min_bytes: 5 * MB })
  console.log(summary(large))

  heading('find_old_files — older_than_days 365')
  const old = await findOldFiles(ctx, { older_than_days: 365 })
  console.log(summary(old))

  heading('trash_local — preview first, nothing written')
  const target = join(root, 'photos/2019/holiday-copy.jpg')
  const preview = await trashLocal(ctx, { paths: [target] })
  console.log(summary(preview))
  const stillThere = await readdir(join(root, 'photos/2019'))
  console.log(`  photos/2019 still holds: ${stillThere.join(', ')}`)

  heading('trash_local — confirmed with the plan the preview issued')
  // The confirmed call carries the token from that preview. Without it, or if
  // the directory had changed since, this refuses instead of acting on a plan
  // nobody saw.
  const done = await trashLocal(ctx, {
    paths: [target],
    confirm: true,
    plan_token: payload(preview).plan_token,
  })
  console.log(summary(done))
  const after = await readdir(join(root, 'photos/2019'))
  console.log(`  photos/2019 now holds: ${after.join(', ')}`)
  const trashed = payload(done)
  for (const entry of trashed.moved ?? []) {
    console.log(
      `  ${short(entry.original_path)} → ${short(entry.trashed_to)}`,
    )
  }
  for (const manifest of trashed.manifests ?? []) {
    console.log(`  manifest: ${short(manifest)}`)
  }
  console.log('  the manifest records where each item came from, so the move can')
  console.log('  be undone by hand. Nothing was deleted.')

  if (keep) {
    console.log(`\nKept: ${root}`)
  } else {
    await rm(root, { recursive: true, force: true })
    console.log('\nTemporary directory removed.')
  }
}

main().catch((err) => {
  console.error(err)
  process.exitCode = 1
})

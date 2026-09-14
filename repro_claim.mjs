import { makeTree, makeCtx, payload, summary } from './test/helpers.mjs'
import { moveLocal } from './src/tools/mutate.mjs'

// The reporter's scenario: a move whose destination is a DIRECTORY holding two
// irreplaceable files, source is a tiny 3-byte file.
const tree = await makeTree({
  'src/thing': 'abc',                      // 3 bytes, the source
  'dst/thing/irreplaceable-a.txt': 'A'.repeat(50000),
  'dst/thing/deep/irreplaceable-b.txt': 'B'.repeat(70000),
})
const ctx = await makeCtx([tree.base])

const res = await moveLocal(ctx, {
  source: tree.path('src/thing'),
  destination: tree.path('dst/thing'),
  overwrite: true,
  // no confirm -> preview
})

console.log('--- SUMMARY (content[0]) ---')
console.log(summary(res))
console.log('--- PAYLOAD (content[1]) ---')
console.log(JSON.stringify(payload(res), null, 2))

const p = payload(res)
console.log('\n--- ASSERTIONS AGAINST THE CLAIM ---')
console.log('claim: preview never measures destination tree  ->', p.displaced == null ? 'TRUE (defect)' : 'FALSE, displaced =' + JSON.stringify(p.displaced))
console.log('claim: preview reports only a bare boolean      ->', (p.replaces_existing === true && p.displaced == null) ? 'TRUE (defect)' : 'FALSE')
console.log('displaced file count reported:', p.displaced?.files, 'bytes:', p.displaced?.bytes, '(actual on disk: 2 files, 120000 bytes)')
console.log('summary names what is there?  ->', /DISPLACES an existing/.test(summary(res)))
console.log('summary names trash dest?     ->', p.displaced?.moved_to_trash)

await tree.cleanup()

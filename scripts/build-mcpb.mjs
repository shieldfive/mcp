// Build dist/shieldfive.mcpb: the manifest, this package's src and its
// production dependencies, packed with the official MCPB CLI. Run from a clean
// checkout after `npm ci`; nothing outside dist/ is touched.

import { execFileSync } from 'node:child_process'
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const stage = join(root, 'dist', 'mcpb')
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const manifest = JSON.parse(readFileSync(join(root, 'mcpb', 'manifest.json'), 'utf8'))
if (manifest.version !== pkg.version) {
  throw new Error(`mcpb/manifest.json is ${manifest.version}, package.json is ${pkg.version}`)
}

rmSync(stage, { recursive: true, force: true })
mkdirSync(join(stage, 'server'), { recursive: true })
writeFileSync(join(stage, 'manifest.json'), JSON.stringify(manifest, null, 2))
cpSync(join(root, 'src'), join(stage, 'server', 'src'), { recursive: true })
for (const f of ['package.json', 'package-lock.json', 'README.md', 'LICENSE', 'SECURITY.md']) {
  cpSync(join(root, f), join(stage, 'server', f))
}
execFileSync('npm', ['ci', '--omit=dev', '--ignore-scripts=false'], { cwd: join(stage, 'server'), stdio: 'inherit' })
execFileSync('npx', ['-y', '@anthropic-ai/mcpb', 'pack', stage, join(root, 'dist', 'shieldfive.mcpb')], { stdio: 'inherit' })

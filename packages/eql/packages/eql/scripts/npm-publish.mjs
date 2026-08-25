#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const pkg = JSON.parse(
  readFileSync(resolve(packageRoot, 'package.json'), 'utf8'),
)
// Dist-tag policy. Before 3.0.0 GA this was `true` so `latest` tracked the
// alphas. GA shipped (npm `latest` is 3.0.5), so prereleases now go to their
// channel tag and `latest` stays on finals — otherwise the next alpha would
// move `latest` off the GA release and `npm install @cipherstash/eql` would
// resolve to it.
const PRE_GA_LATEST = false

const prerelease = pkg.version.match(/-(alpha|beta|rc)\./)
const tag = prerelease && !PRE_GA_LATEST ? prerelease[1] : 'latest'

console.log(`publishing ${pkg.name}@${pkg.version} with npm dist-tag '${tag}'`)

// The bundled-SQL freshness guard lives in prepublishOnly
// (scripts/verify-release-assets.mjs), which `npm publish` runs for every
// publish path — including `changeset publish` on the production side.
const result = spawnSync(
  'npm',
  [
    'publish',
    '--access',
    'public',
    '--provenance',
    '--tag',
    tag,
    ...process.argv.slice(2),
  ],
  { cwd: packageRoot, stdio: 'inherit' },
)

process.exit(result.status ?? 1)

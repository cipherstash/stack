#!/usr/bin/env node
// prepublishOnly gate: the package bundles the exact-version SQL it was
// generated against, so publishing with a stale/placeholder bundle is a
// correctness bug in the published artifact. npm runs prepublishOnly for every
// publish path — `changeset publish` (production) and scripts/npm-publish.mjs
// (prerelease) both shell out to `npm publish` — so this guards both.
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const pkg = JSON.parse(readFileSync(resolve(packageRoot, 'package.json'), 'utf8'))

const manifestPath = resolve(packageRoot, 'sql/release-manifest.json')
if (!existsSync(manifestPath)) {
  console.error(
    `refusing to publish: ${manifestPath} is missing — run 'mise run release:prepare_bindings_assets --version ${pkg.version}' first`,
  )
  process.exit(1)
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
if (manifest.eqlVersion !== pkg.version) {
  console.error(
    `refusing to publish: sql/release-manifest.json eqlVersion ('${manifest.eqlVersion}') does not match package.json version ('${pkg.version}') — the bundled SQL was not prepared for this release. Run 'mise run release:prepare_bindings_assets --version ${pkg.version}' and rebuild.`,
  )
  process.exit(1)
}

const installSql = readFileSync(resolve(packageRoot, 'sql/cipherstash-encrypt.sql'), 'utf8')
if (!installSql.includes('eql_v3')) {
  console.error(
    'refusing to publish: sql/cipherstash-encrypt.sql looks like the DEV placeholder — the bundled SQL was not prepared for this release.',
  )
  process.exit(1)
}

console.log(`release assets verified for ${pkg.name}@${pkg.version}`)

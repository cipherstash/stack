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
const pkg = JSON.parse(
  readFileSync(resolve(packageRoot, 'package.json'), 'utf8'),
)

// mise finds config from the cwd and its parents, and there is no mise config
// at the repository root — the EQL subtree carries its own. A bare `mise run`
// from where these messages are read fails with a TRUST error that reads like
// a broken toolchain, so the `cd` is part of the instruction, not decoration.
const REPAIR = `(cd packages/eql && mise run release:prepare_bindings_assets --version ${pkg.version})`

const manifestPath = resolve(packageRoot, 'sql/release-manifest.json')
if (!existsSync(manifestPath)) {
  console.error(
    `refusing to publish: ${manifestPath} is missing — run '${REPAIR}' first`,
  )
  process.exit(1)
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
if (manifest.eqlVersion !== pkg.version) {
  console.error(
    `refusing to publish: sql/release-manifest.json eqlVersion ('${manifest.eqlVersion}') does not match package.json version ('${pkg.version}') — the bundled SQL was not prepared for this release. Run '${REPAIR}' and rebuild.`,
  )
  process.exit(1)
}

const installSql = readFileSync(
  resolve(packageRoot, 'sql/cipherstash-encrypt.sql'),
  'utf8',
)
// THE STAMP, not the schema name. This read `installSql.includes('eql_v3')`
// until it was found unable to fire: `eql_v3` appears ~23,000 times in every
// bundle, and a DEV build is no exception — `tasks/build.sh` substitutes only
// `$RELEASE_VERSION`, which lands in this one COMMENT. So the check passed on
// any input at all, including the placeholder it names.
//
// The manifest comparison above cannot cover this either. Both files are
// regenerated together by `release:prepare_bindings_assets`, so a bundle built
// under the wrong version arrives with a manifest that agrees with it. The
// COMMENT is the only record of which build produced these bytes. Same
// reasoning, and the same predicate, as the guard in `release-plz.yml`.
if (!installSql.includes(`COMMENT ON SCHEMA eql_v3 IS '${pkg.version}'`)) {
  const stamped = installSql.match(/COMMENT ON SCHEMA eql_v3 IS '[^']*'/)?.[0]
  console.error(
    `refusing to publish: sql/cipherstash-encrypt.sql was not built for ${pkg.version} — it carries ${stamped ?? 'no version stamp'}. Run '${REPAIR}' and rebuild.`,
  )
  process.exit(1)
}

console.log(`release assets verified for ${pkg.name}@${pkg.version}`)

import { cpSync, existsSync, readFileSync } from 'node:fs'
import { defineConfig } from 'tsup'
import { RELEASE_TRAIN_MANIFESTS } from './src/release-train.js'

/**
 * Build-time value for the embedded PostHog project key (see
 * `src/telemetry/index.ts`). Only the release workflow sets `STASH_POSTHOG_KEY`
 * (from a public repo variable), so every other build — dev, forks, CI — bakes
 * in an empty string and the CLI ships telemetry-dormant. Applied to both bundles
 * because either may inline the telemetry module. The value must be a JS
 * expression string, hence `JSON.stringify`.
 */
const posthogKeyDefine = {
  __STASH_POSTHOG_KEY__: JSON.stringify(process.env.STASH_POSTHOG_KEY ?? ''),
}

/**
 * Build-time embed of the runtime-package versions from this release train
 * (see `src/runtime-versions.ts` and #661): `stash init` pins the packages it
 * installs to the versions this CLI was built alongside, instead of trusting
 * npm dist-tags (which lag, or point at placeholders, during pre-release
 * windows). The package list is the shared `RELEASE_TRAIN_MANIFESTS`
 * (`src/release-train.ts`) — the same constant the runtime cross-checks its
 * adapter list against — and versions are read straight from the sibling
 * workspace manifests so the embed can never disagree with what Changesets is
 * about to publish. A missing/broken manifest throws at build time — a
 * silently absent embed would quietly reintroduce unpinned installs. Unlike
 * the PostHog key this needs no env var, so EVERY build embeds it. The double
 * `JSON.stringify` makes the define value a string literal that
 * `runtime-versions.ts` parses and validates (throwing on a malformed embed
 * rather than degrading to unpinned).
 */
function workspaceVersion(relPkgJson: string): string {
  const manifest: unknown = JSON.parse(
    readFileSync(new URL(relPkgJson, import.meta.url), 'utf8'),
  )
  const version = (manifest as { version?: unknown }).version
  if (typeof version !== 'string' || version.length === 0)
    throw new Error(`tsup: no version in ${relPkgJson}`)
  return version
}
const runtimeVersionsDefine = {
  __STASH_RUNTIME_VERSIONS__: JSON.stringify(
    JSON.stringify(
      Object.fromEntries(
        Object.entries(RELEASE_TRAIN_MANIFESTS).map(([pkg, manifest]) => [
          pkg,
          workspaceVersion(manifest),
        ]),
      ),
    ),
  ),
}

// One shared define object spread into BOTH build entries — a define added to
// one entry but not the other would leave that bundle silently degraded (both
// consumers typeof-guard their identifier).
const buildDefines = { ...posthogKeyDefine, ...runtimeVersionsDefine }

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    sourcemap: true,
    dts: true,
    clean: true,
    target: 'es2022',
    tsconfig: './tsconfig.json',
    // `@cipherstash/eql` is external so `readInstallSql()` resolves the real
    // installed package (and its `dist/sql/*.sql`) at runtime rather than
    // getting flattened into the bundle. `pg` is a native-ish dep, kept external.
    external: ['pg', '@cipherstash/eql', '@cipherstash/eql/sql'],
    esbuildOptions(options) {
      // Suppress import.meta warning in CJS — we guard with typeof checks at runtime
      options.logOverride = {
        ...options.logOverride,
        'empty-import-meta': 'silent',
      }
      options.define = { ...options.define, ...buildDefines }
    },
    onSuccess: async () => {
      // Copy bundled SQL files into dist so they ship with the package
      cpSync('src/sql', 'dist/sql', { recursive: true })
      // Skills live at the monorepo root and ship inside the CLI tarball so
      // `stash init` can copy them into the user's `.claude/skills/` or
      // `.codex/skills/` directory at handoff time. Mirror of
      // packages/wizard/tsup.config.ts:24.
      if (existsSync('../../skills')) {
        cpSync('../../skills', 'dist/skills', { recursive: true })
      }
      // The AGENTS.md doctrine fragment is read at handoff time and
      // wrapped in a sentinel block. The runtime resolver in
      // src/commands/init/lib/build-agents-md.ts walks up looking for a
      // sibling `doctrine/` dir, so mirror the source layout under dist.
      cpSync('src/commands/init/doctrine', 'dist/commands/init/doctrine', {
        recursive: true,
      })
    },
  },
  {
    entry: ['src/bin/stash.ts'],
    outDir: 'dist/bin',
    format: ['esm'],
    platform: 'node',
    target: 'es2022',
    banner: {
      js: `#!/usr/bin/env node
import { createRequire as __createRequire } from 'module';
var require = __createRequire(import.meta.url);`,
    },
    dts: false,
    sourcemap: true,

    skipNodeModulesBundle: true,
    esbuildOptions(options) {
      options.define = { ...options.define, ...buildDefines }
    },
  },
])

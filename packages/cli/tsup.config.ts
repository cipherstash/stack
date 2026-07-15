import { cpSync, existsSync } from 'node:fs'
import { defineConfig } from 'tsup'

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

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    sourcemap: true,
    dts: true,
    clean: true,
    target: 'es2022',
    tsconfig: './tsconfig.json',
    external: ['pg'],
    esbuildOptions(options) {
      // Suppress import.meta warning in CJS — we guard with typeof checks at runtime
      options.logOverride = {
        ...options.logOverride,
        'empty-import-meta': 'silent',
      }
      options.define = { ...options.define, ...posthogKeyDefine }
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
      options.define = { ...options.define, ...posthogKeyDefine }
    },
  },
])

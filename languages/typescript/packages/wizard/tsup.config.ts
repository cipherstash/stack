import { cpSync, existsSync } from 'node:fs'
import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/bin/wizard.ts'],
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
  clean: true,
  skipNodeModulesBundle: true,
  onSuccess: async () => {
    // Skills live at the monorepo root and ship inside the wizard tarball so
    // the agent can install them into the user's `.claude/skills` directory
    // (CIP-2992). The cli used to ship these too — they belong with the
    // wizard now.
    if (existsSync('../../skills')) {
      cpSync('../../skills', 'dist/skills', { recursive: true })
    }
  },
})

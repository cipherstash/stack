import { defineConfig } from 'tsup'

export default defineConfig([
  {
    // Keyed entry-object form: a flat array of two `index.ts` basenames would
    // collide both onto dist/pg/index.js. The keyed form pins the output paths so
    // src/pg/v3/index.ts lands at dist/pg/v3/index.js (not dist/pg/index.js).
    entry: {
      index: 'src/pg/index.ts',
      'v3/index': 'src/pg/v3/index.ts',
    },
    outDir: 'dist/pg',
    format: ['cjs', 'esm'],
    sourcemap: true,
    dts: true,
  },
  {
    entry: ['src/bin/generate-eql-migration.ts'],
    outDir: 'dist/bin',
    format: ['cjs', 'esm'],
    target: 'esnext',
    clean: true,
    splitting: true,
    minify: true,
    shims: true,
    banner: {
      js: '#!/usr/bin/env node',
    },
  },
])

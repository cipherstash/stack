import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    'src/exports/codec-types.ts',
    'src/exports/column-types.ts',
    'src/exports/control.ts',
    'src/exports/operation-types.ts',
    'src/exports/pack.ts',
    'src/exports/runtime.ts',
    'src/exports/stack.ts',
    'src/exports/v3.ts',
  ],
  outDir: 'dist',
  format: ['esm'],
  sourcemap: true,
  dts: true,
  clean: true,
  splitting: true,
})

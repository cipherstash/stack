import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/clerk/index.ts'],
  format: ['cjs', 'esm'],
  sourcemap: true,
  dts: true,
})

import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/schema.ts', 'src/sql.ts'],
  format: ['cjs', 'esm'],
  sourcemap: true,
  dts: true,
  clean: true,
  external: ['node:fs', 'node:path', 'node:url'],
  async onSuccess() {
    const { copyAssets } = await import('./scripts/copy-assets.mjs')
    await copyAssets()
  },
})

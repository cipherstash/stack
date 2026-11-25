import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/testing.ts'],
  format: ['cjs', 'esm'],
  // One copy of each class across the two entries, in CommonJS too, so a
  // cipher from `./testing` is the `Cipher` the root entry exports.
  splitting: true,
  // `import.meta.url` in the CommonJS build, for the addon's path.
  shims: true,
  sourcemap: true,
  dts: true,
  clean: true,
  target: 'es2022',
  platform: 'node',
  tsconfig: './tsconfig.json',
})

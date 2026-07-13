import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/v3/index.ts'],
  outDir: 'dist',
  format: ['cjs', 'esm'],
  sourcemap: true,
  dts: true,
  clean: false,
  target: 'es2022',
  tsconfig: './tsconfig.json',
  external: ['@cipherstash/stack', '@cipherstash/protect-ffi', 'drizzle-orm'],
})

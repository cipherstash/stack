import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  outDir: 'dist',
  format: ['cjs', 'esm'],
  sourcemap: true,
  dts: true,
  clean: false,
  target: 'es2022',
  tsconfig: './tsconfig.json',
  // Core + the Postgres/Supabase clients stay external — they are the
  // consumer's (peer) dependencies, not bundled into the adapter.
  external: [
    '@cipherstash/stack',
    '@cipherstash/protect-ffi',
    '@supabase/supabase-js',
    '@supabase/postgrest-js',
    'pg',
  ],
})

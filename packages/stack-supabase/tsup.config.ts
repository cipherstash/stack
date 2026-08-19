import { defineConfig } from 'tsup'

// Core + the Postgres/Supabase clients stay external — they are the
// consumer's (peer) dependencies, not bundled into the adapter.
const external = [
  '@cipherstash/stack',
  '@cipherstash/protect-ffi',
  '@supabase/supabase-js',
  '@supabase/postgrest-js',
  'pg',
]

export default defineConfig([
  {
    entry: ['src/index.ts'],
    outDir: 'dist',
    format: ['cjs', 'esm'],
    sourcemap: true,
    dts: true,
    clean: false,
    target: 'es2022',
    tsconfig: './tsconfig.json',
    external,
  },
  // The edge entry (#708). A SEPARATE build, not another entry on the one
  // above, for two reasons: it is ESM-only (matching
  // `@cipherstash/stack/wasm-inline`, which has no `require` condition), and
  // emitting it alongside the native entry would let esbuild hoist their
  // shared code into a chunk that both import — putting the native
  // `@cipherstash/stack` specifier back into the edge graph, which is the one
  // thing this entry exists to keep out.
  {
    entry: { 'wasm-inline': 'src/wasm-inline.ts' },
    outDir: 'dist',
    format: ['esm'],
    sourcemap: true,
    dts: true,
    clean: false,
    target: 'es2022',
    tsconfig: './tsconfig.json',
    external: [...external, '@cipherstash/stack/wasm-inline'],
  },
])

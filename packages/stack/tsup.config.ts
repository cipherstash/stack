import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/client.ts',
    'src/types-public.ts',
    'src/identity/index.ts',
    'src/secrets/index.ts',
    'src/schema/index.ts',
    'src/drizzle/index.ts',
    'src/dynamodb/index.ts',
    'src/supabase/index.ts',
    'src/encryption/index.ts',
    'src/errors/index.ts',
    'src/wasm-inline.ts',
  ],
  format: ['cjs', 'esm'],
  sourcemap: true,
  dts: true,
  clean: true,
  target: 'es2022',
  tsconfig: './tsconfig.json',
  external: ['drizzle-orm', '@supabase/supabase-js'],
  // zod + @byteslice/result are bundled so dist/wasm-inline.js carries no
  // bare-specifier transitive imports — important for Deno / Edge /
  // browser consumers whose runtime won't resolve npm names without an
  // explicit import map. Both are small (zod ~50 KB, result ~3 KB) and
  // dependency-free, so bundling them into the Node entries too is fine.
  noExternal: ['evlog', 'uuid', 'zod', '@byteslice/result'],
  // Drop dist/wasm-inline.cjs after bundling — the protect-ffi
  // wasm-inline runtime it transitively requires is ESM-only and
  // crashes a Node CJS consumer with ERR_REQUIRE_ESM. The runtimes
  // that need /wasm-inline (Deno, Bun, Workers, Supabase Edge, browsers)
  // are ESM-first anyway, and package.json's exports map omits the
  // `require` branch for ./wasm-inline so npm consumers never reach
  // this path. The dual ESM + CJS d.ts pair stays so type-only CJS
  // imports of stack's public surface still resolve.
  onSuccess: async () => {
    const { rm } = await import('node:fs/promises')
    for (const file of [
      'dist/wasm-inline.cjs',
      'dist/wasm-inline.cjs.map',
    ]) {
      await rm(file, { force: true })
    }
  },
})

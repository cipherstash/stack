import { defineConfig } from 'tsup'

// Two configs run in parallel inside tsup. They share the same `dist/`
// output dir, so neither uses `clean: true` — a parallel-run race could
// otherwise wipe the other config's output. The pre-tsup `rimraf dist`
// in `package.json`'s build script clears the dir once before either
// starts.
export default defineConfig([
  // Main entries — dual ESM + CJS bundles.
  {
    entry: [
      'src/index.ts',
      'src/client.ts',
      'src/types-public.ts',
      'src/identity/index.ts',
      'src/secrets/index.ts',
      'src/schema/index.ts',
      'src/eql/v3/index.ts',
      'src/drizzle/index.ts',
      'src/dynamodb/index.ts',
      'src/supabase/index.ts',
      'src/encryption/index.ts',
      'src/encryption/v3.ts',
      'src/errors/index.ts',
    ],
    format: ['cjs', 'esm'],
    sourcemap: true,
    dts: true,
    clean: false,
    target: 'es2022',
    tsconfig: './tsconfig.json',
    external: ['drizzle-orm', '@supabase/supabase-js'],
    // zod + @byteslice/result are bundled so dist/wasm-inline.js carries
    // no bare-specifier transitive imports — important for Deno / Edge /
    // browser consumers whose runtime won't resolve npm names without an
    // explicit import map.
    noExternal: ['evlog', 'uuid', 'zod', '@byteslice/result'],
  },
  // WASM-inline entry — ESM only. The protect-ffi wasm-inline bundle is
  // an ESM module that dynamically imports the inlined base64 WASM blob;
  // it cannot be loaded via Node CJS `require()` (ERR_REQUIRE_ESM), and
  // the only runtimes that need wasm-inline (Deno, Bun, Workers,
  // Supabase Edge, browsers) are ESM-first anyway. `package.json`'s
  // `./wasm-inline` export deliberately omits the `require` branch to
  // match.
  {
    entry: { 'wasm-inline': 'src/wasm-inline.ts' },
    format: ['esm'],
    sourcemap: true,
    dts: { entry: { 'wasm-inline': 'src/wasm-inline.ts' } },
    clean: false,
    target: 'es2022',
    tsconfig: './tsconfig.json',
    external: ['drizzle-orm', '@supabase/supabase-js'],
    noExternal: ['evlog', 'uuid', 'zod', '@byteslice/result'],
  },
])

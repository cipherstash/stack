import { defineConfig } from 'tsup'

// Three configs run in parallel inside tsup. They share the same `dist/`
// output dir, so none uses `clean: true` — a parallel-run race could
// otherwise wipe another config's output. The pre-tsup `rimraf dist`
// in `package.json`'s build script clears the dir once before any
// starts.
export default defineConfig([
  // Main entries — dual ESM + CJS bundles.
  {
    entry: [
      'src/index.ts',
      'src/types-public.ts',
      'src/identity/index.ts',
      'src/schema/index.ts',
      'src/eql/v3/index.ts',
      'src/dynamodb/index.ts',
      'src/encryption/index.ts',
      'src/encryption/v3.ts',
      'src/errors/index.ts',
      'src/adapter-kit.ts',
    ],
    format: ['cjs', 'esm'],
    sourcemap: true,
    dts: true,
    clean: false,
    target: 'es2022',
    tsconfig: './tsconfig.json',
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
    noExternal: ['evlog', 'uuid', 'zod', '@byteslice/result'],
  },
  // Diagnostics entry — its own config rather than another `entry` in the
  // main one, because what it must NOT reach is the whole point of it.
  // `splitting` is on for ESM in the main config, and a shared chunk is
  // exactly how `@cipherstash/auth` would arrive here: the probe would then
  // fail on auth's binary while reporting the encryption engine, which is the
  // bug this entry exists to fix. `splitting: false` makes that structural
  // rather than a property of today's module graph.
  //
  // Nothing is bundled in (no `noExternal`): `@cipherstash/protect-ffi` has to
  // stay a bare specifier so the load goes through the installed package's own
  // loader, which is the thing under test.
  {
    entry: { diagnostics: 'src/diagnostics.ts' },
    format: ['cjs', 'esm'],
    splitting: false,
    sourcemap: true,
    dts: { entry: { diagnostics: 'src/diagnostics.ts' } },
    clean: false,
    target: 'es2022',
    tsconfig: './tsconfig.json',
  },
])

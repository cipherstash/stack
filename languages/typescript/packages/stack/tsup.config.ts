import { defineConfig } from 'tsup'

// Three configs run in parallel inside tsup. They share the same `dist/`
// output dir, so none uses `clean: true` — a parallel-run race could
// otherwise wipe another config's output. The pre-tsup `rimraf dist`
// in `package.json`'s build script clears the dir once before any
// starts.

// The dual-format entries. Named so the `dts` list below can be derived from it
// rather than repeated — a second hand-maintained copy would silently drop the
// types for any subpath added to one list and not the other.
const mainEntry = [
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
]

export default defineConfig([
  // Main entries — dual ESM + CJS bundles.
  {
    entry: mainEntry,
    format: ['cjs', 'esm'],
    sourcemap: true,
    // `wasm-inline` is listed here for TYPES ONLY — its JS is emitted by the
    // ESM-only config below, which sets `dts: false`. The two configs are
    // separate rollup runs, so a `dts` built down there gets its own inlined
    // copy of every column class, and `EncryptedV3Column` carries `private`
    // members, which TypeScript compares by declaration origin rather than
    // structurally. Two copies meant a table authored from
    // `@cipherstash/stack/wasm-inline` was a COMPILE error against every
    // first-party adapter's `schemas` ("Types have separate declarations of a
    // private property 'columnName'"), even though the runtime accepted it.
    // Emitting these types here shares the `types-public-*.d.ts` chunk with
    // `./eql/v3` and `./adapter-kit`, so every entry yields one declaration.
    // This is the type-level half of the same two-copies-of-a-class hazard
    // `isV3ColumnLike` fixed at runtime; `dist-types/wasm-inline-type-identity.ts`
    // and `dist-types/node16/wasm-inline.mts` hold it in place.
    //
    // Side effect: this config is dual-format, so the wasm-inline entry now also
    // gets a `dist/wasm-inline.d.cts`. Nothing resolves it — `./wasm-inline` has
    // no `require` branch in `exports` and there is no `wasm-inline.cjs` for it
    // to describe. It is unreferenced ballast in the tarball, accepted because
    // tsup cannot scope a `dts` entry to one format, and one shared declaration
    // is worth more than the bytes.
    dts: { entry: [...mainEntry, 'src/wasm-inline.ts'] },
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
  // Supabase Edge — all server-side; the entry requires a workspace
  // secret, so it is not browser-safe, see #804) are ESM-first anyway.
  // `package.json`'s `./wasm-inline` export deliberately omits the
  // `require` branch to match.
  {
    entry: { 'wasm-inline': 'src/wasm-inline.ts' },
    format: ['esm'],
    sourcemap: true,
    // Types come from the main config above so they share its chunks — see the
    // comment there. Emitting them here as well would restore the second copy
    // of every column class and re-break the `wasm-inline` authoring path for
    // TypeScript consumers. JS emission stays here: only types moved.
    dts: false,
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

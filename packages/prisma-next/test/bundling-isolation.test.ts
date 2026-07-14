/**
 * Control vs runtime/middleware byte-level subpath isolation.
 *
 * The cipherstash extension publishes three runtime-relevant subpath
 * entries: `./control` (contract-space authoring + the codec lifecycle
 * hook), `./runtime` (envelope + SDK + codec runtime), and
 * `./middleware` (bulk-encrypt middleware). Each entry must compose
 * tree-shakably so a consumer pulling `./runtime` does not drag in the
 * EQL bundle SQL, the cipherstash baseline migration, or the codec
 * lifecycle hook (any of which would defeat the runtime-bundle size
 * budget and leak control-plane behaviour into runtime call paths) and
 * a consumer pulling `./control` does not drag in `EncryptedString`,
 * the SDK interface, the codec runtime, or the bulk-encrypt middleware.
 *
 * This test is the canonical isolation guard. It asserts:
 *
 *   1. **Entry-body forbidden-substring check** (per entry): the
 *      entry `.js` body — both the inline source and its `import` /
 *      `export` statements — does not contain forbidden symbol names.
 *      Mirrors the predecessor `wip/verify-cipherstash-isolation.js`
 *      shallow check, which catches both inlined runtime behavior in
 *      a control entry and cross-chunk leaks via named-import lines
 *      (`import { ForbiddenName } from "./<chunk>.js"`). Forbidden
 *      identifiers occurring inside a chunk's JSDoc or as a PSL type
 *      identifier string literal are out of scope — they ship no
 *      executable behavior — and are caught structurally by the
 *      disjointness check below if the chunk crosses planes.
 *   2. **Chunk-graph disjointness**: control's transitively reachable
 *      chunk-file set and runtime's (resp. middleware's) chunk-file
 *      set are disjoint, modulo the shared `constants-*.js` chunk
 *      (pure literal constants — no SDK / codec / migration code).
 *
 * The dist outputs are produced by `tsup` from `src/exports/*.ts`.
 * The package's `turbo.json` declares `test` depends on its own
 * `build`, so the assertions below always read fresh dist output for
 * the current source.
 */

import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'pathe'
import { describe, expect, it } from 'vitest'

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const DIST = join(PACKAGE_ROOT, 'dist')

const ENTRY_FILES = ['control.js', 'runtime.js', 'middleware.js'] as const

/**
 * Forbidden in `control.js` and its transitive chunk graph.
 * These are runtime-plane symbols (envelope / SDK interface / codec
 * runtime / middleware factory) that must never reach a control-plane
 * consumer.
 */
const CONTROL_FORBIDDEN = [
  'EncryptedString',
  'EncryptedDouble',
  'EncryptedBigInt',
  'EncryptedDate',
  'EncryptedBoolean',
  'EncryptedJson',
  'setHandleCiphertext',
  'CipherstashSdk',
  'bulkEncryptMiddleware',
  'createCipherstashStringCodec',
  'createCipherstashDoubleCodec',
  'createCipherstashBigIntCodec',
  'createCipherstashDateCodec',
  'createCipherstashBooleanCodec',
  'createCipherstashJsonCodec',
  'createCipherstashRuntimeDescriptor',
  'cipherstashAsc',
  'cipherstashDesc',
  'cipherstashJsonbGet',
  'cipherstashJsonbPathQueryFirst',
] as const

/**
 * Forbidden in `runtime.js` / `middleware.js` and their transitive
 * chunk graph. These are contract-space artefacts (EQL bundle SQL,
 * cipherstash contract IR, baseline migration, head-ref, the
 * codec-control lifecycle hook, EQL bundle migration-op terms) that
 * must never reach a runtime consumer.
 */
const RUNTIME_FORBIDDEN = [
  'EQL_BUNDLE_SQL',
  'cipherstashContract',
  'cipherstashBaselineMigration',
  'cipherstashHeadRef',
  'cipherstashStringCodecHooks',
  'cipherstashDoubleCodecHooks',
  'cipherstashBigIntCodecHooks',
  'cipherstashDateCodecHooks',
  'cipherstashBooleanCodecHooks',
  'cipherstashJsonCodecHooks',
  'add_search_config',
  'remove_search_config',
] as const

/**
 * Chunks whose name matches this pattern are allowed to appear in
 * both the control graph and the runtime graph. Our tsup build emits
 * code-split chunks as `chunk-<hash>.js` (vs upstream's `tsdown`,
 * which uses content-named `constants-<hash>.mjs`). The cross-plane
 * shared chunk in our output carries pure literal constants (codec
 * id, native types, invariant ids) — sharing them is safe and
 * desirable. `ALLOWED_SHARED_CHUNK_MARKER_SETS` below guards that
 * the matched chunk's body does not also smuggle runtime-plane logic
 * across the boundary.
 */
const SHARED_CHUNK_PATTERN = /^chunk-[A-Za-z0-9_-]+\.js$/

/**
 * Identifiers that uniquely fingerprint an allowed shared chunk: every
 * shared chunk we accept must export every marker of at least one set.
 * If a `chunk-*.js` is shared between planes but does NOT match a set,
 * it is not one of the known-safe metadata chunks and the test rightly
 * fails.
 *
 * Three safe-to-share chunks exist today:
 *
 *   - the v2 constants chunk (pure codec-id / native-type / invariant
 *     literals);
 *   - the v3 constants chunk (`src/extension-metadata/constants-v3.ts`
 *     — the pinned v3 codec-id tuple, invariant ids, baseline
 *     migration name, space id, and the pure `v3TraitsForCapabilities`
 *     mapper over trait literals). The control plane reaches it through
 *     the v3 baseline migration wiring in `control.ts`, the runtime
 *     plane through the v3 codec descriptors;
 *   - the v3 catalog chunk (`src/v3/catalog.ts` — per-domain metadata
 *     derived from the stack's `DOMAIN_REGISTRY`: codec ids, castAs,
 *     capabilities, index names). The control plane reaches it through
 *     the v3 authoring constructors, the runtime plane through the v3
 *     codec descriptors / operators; it carries no SDK, codec, wire, or
 *     migration behaviour.
 */
const ALLOWED_SHARED_CHUNK_MARKER_SETS: ReadonlyArray<readonly string[]> = [
  // v2 constants chunk
  [
    'CIPHERSTASH_STRING_CODEC_ID',
    'CIPHERSTASH_DOUBLE_CODEC_ID',
    'CIPHERSTASH_BIGINT_CODEC_ID',
    'CIPHERSTASH_DATE_CODEC_ID',
    'CIPHERSTASH_BOOLEAN_CODEC_ID',
    'CIPHERSTASH_JSON_CODEC_ID',
  ],
  // v3 constants chunk
  [
    'CIPHERSTASH_V3_CODEC_IDS',
    'CIPHERSTASH_V3_BASELINE_MIGRATION_NAME',
    'v3TraitsForCapabilities',
  ],
  // v3 catalog chunk
  ['V3_DOMAIN_META_BY_CODEC_ID', 'V3_FACTORY_BY_NATIVE_TYPE', 'toV3CodecId'],
] as const

interface ChunkFile {
  readonly file: string
  readonly body: string
  readonly size: number
}

function readChunk(file: string): ChunkFile {
  const path = join(DIST, file)
  const body = readFileSync(path, 'utf8')
  return { file, body, size: Buffer.byteLength(body, 'utf8') }
}

// Captures relative `.js` edges in three forms:
//   `from "./x.js"`            — `import ... from`, `export ... from`
//   `import "./x.js"`          — side-effect imports
//   `import("./x.js")`         — dynamic imports
// Without each of these the disjointness check can silently pass for a
// chunk graph that re-exports cross-plane state through side-effect
// imports or `export ... from` edges.
const RELATIVE_IMPORT_RE = /(?:from|import)\s*\(?\s*["'](\.\/[^"']+\.js)["']/g

function collectGraph(entry: string): Map<string, ChunkFile> {
  const graph = new Map<string, ChunkFile>()
  const queue: string[] = [entry]
  while (queue.length > 0) {
    const next = queue.shift()
    if (next === undefined || graph.has(next)) {
      continue
    }
    const chunk = readChunk(next)
    graph.set(next, chunk)
    for (const match of chunk.body.matchAll(RELATIVE_IMPORT_RE)) {
      const importPath = match[1]
      if (importPath === undefined) {
        continue
      }
      const importFile = importPath.replace(/^\.\//, '')
      if (!graph.has(importFile)) {
        queue.push(importFile)
      }
    }
  }
  return graph
}

function findLeaksInEntry(
  entry: ChunkFile,
  forbidden: readonly string[],
): string[] {
  return forbidden.filter((needle) => entry.body.includes(needle))
}

function isAllowedSharedChunk(chunk: string): boolean {
  if (!SHARED_CHUNK_PATTERN.test(chunk)) {
    return false
  }
  const body = readChunk(chunk).body
  return ALLOWED_SHARED_CHUNK_MARKER_SETS.some((markers) =>
    markers.every((marker) => body.includes(marker)),
  )
}

describe('bundling isolation', () => {
  it('dist entry files exist (run `pnpm --filter @cipherstash/prisma-next build` first)', () => {
    for (const entry of ENTRY_FILES) {
      expect(existsSync(join(DIST, entry)), `dist/${entry} is missing`).toBe(
        true,
      )
    }
  })

  it('control.js does not pull runtime-plane symbols', () => {
    const entry = readChunk('control.js')
    const leaks = findLeaksInEntry(entry, CONTROL_FORBIDDEN)
    expect(leaks, `control entry leaks: ${leaks.join(', ')}`).toEqual([])
  })

  it('runtime.js does not pull contract-space artefacts', () => {
    const entry = readChunk('runtime.js')
    const leaks = findLeaksInEntry(entry, RUNTIME_FORBIDDEN)
    expect(leaks, `runtime entry leaks: ${leaks.join(', ')}`).toEqual([])
  })

  it('middleware.js does not pull contract-space artefacts', () => {
    const entry = readChunk('middleware.js')
    const leaks = findLeaksInEntry(entry, RUNTIME_FORBIDDEN)
    expect(leaks, `middleware entry leaks: ${leaks.join(', ')}`).toEqual([])
  })

  it('control vs runtime chunk graphs are disjoint (modulo shared constants chunk)', () => {
    const controlChunks = new Set(collectGraph('control.js').keys())
    const runtimeChunks = new Set(collectGraph('runtime.js').keys())
    controlChunks.delete('control.js')
    runtimeChunks.delete('runtime.js')
    const intersection = [...controlChunks].filter((f) => runtimeChunks.has(f))
    const unexpectedShared = intersection.filter(
      (f) => !isAllowedSharedChunk(f),
    )
    expect(
      unexpectedShared,
      `control & runtime share unexpected chunks: ${unexpectedShared.join(', ')}`,
    ).toEqual([])
  })

  it('control vs middleware chunk graphs are disjoint (modulo shared constants chunk)', () => {
    const controlChunks = new Set(collectGraph('control.js').keys())
    const middlewareChunks = new Set(collectGraph('middleware.js').keys())
    controlChunks.delete('control.js')
    middlewareChunks.delete('middleware.js')
    const intersection = [...controlChunks].filter((f) =>
      middlewareChunks.has(f),
    )
    const unexpectedShared = intersection.filter(
      (f) => !isAllowedSharedChunk(f),
    )
    expect(
      unexpectedShared,
      `control & middleware share unexpected chunks: ${unexpectedShared.join(', ')}`,
    ).toEqual([])
  })
})

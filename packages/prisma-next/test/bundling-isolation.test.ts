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

import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'pathe'
import { describe, expect, it } from 'vitest'

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const DIST = join(PACKAGE_ROOT, 'dist')

const ENTRY_FILES = [
  'control.js',
  'runtime.js',
  'middleware.js',
  'v3.js',
] as const

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

/**
 * Fingerprints of the v2 WIRE plane — the composite-literal codec
 * (`encodeEqlV2EncryptedWire` produces the `("...")` wire) and the v2
 * cell-codec factory built on it. A v3 consumer must never load either:
 * the v3 wire is plain JSONB (`v3ToDriver`), and mixing the two wire
 * planes in one module graph is exactly the confusion decision 1b
 * (a client is v2 or v3, never both) exists to prevent.
 *
 * Marker choice note: `bulkEncryptMiddleware` is NOT usable as a v2 marker —
 * it is a substring of its v3 sibling `bulkEncryptMiddlewareV3`, so a substring
 * scan would false-positive on every v3 chunk. (The setup functions carry the
 * reverse hazard post-rename: the v3 `cipherstashFromStack` is a substring of
 * the v2 `cipherstashFromStackV2`, so the v3 name can't serve as a v3 marker —
 * neither setup symbol is used as a marker here.)
 */
const V2_WIRE_MARKERS = [
  'encodeEqlV2EncryptedWire',
  'makeCipherstashCellCodec',
] as const

/**
 * Fingerprints of the v3 WIRE plane — the plain-JSONB cell codec, the
 * per-domain descriptor factory, and the v3 bulk-encrypt middleware.
 * A v2-only consumer (the `./middleware` entry) must never load these.
 */
const V3_WIRE_MARKERS = [
  'CipherstashV3CellCodec',
  'createV3CodecDescriptors',
  'bulkEncryptMiddlewareV3',
] as const

/**
 * The six v2 codec-RUNTIME factories (all built on the composite wire's
 * `makeCipherstashCellCodec`). Distinct from {@link V2_WIRE_MARKERS} so
 * the v3-graph scans can name exactly which factory leaked, and safe as
 * substrings: no v3 identifier contains any of them.
 */
const V2_CODEC_FACTORY_MARKERS = [
  'createCipherstashStringCodec',
  'createCipherstashDoubleCodec',
  'createCipherstashBigIntCodec',
  'createCipherstashDateCodec',
  'createCipherstashBooleanCodec',
  'createCipherstashJsonCodec',
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

/**
 * Scan an entry's COMPLETE import graph (entry body + every transitive
 * chunk) for forbidden markers, returning `"<chunk> → <marker>"`
 * diagnostics so a failure names the offending chunk, not just the
 * entry. `exempt` skips known-safe chunks (with the invariant that the
 * exemption itself is pinned elsewhere — see the call sites).
 */
function findLeaksInGraph(
  entry: string,
  forbidden: readonly string[],
  exempt: (chunk: ChunkFile) => boolean = () => false,
): string[] {
  const leaks: string[] = []
  for (const [file, chunk] of collectGraph(entry)) {
    if (exempt(chunk)) continue
    for (const marker of forbidden) {
      if (chunk.body.includes(marker)) {
        leaks.push(`${file} → ${marker}`)
      }
    }
  }
  return leaks
}

/**
 * The version-neutral execution chunk — envelope base/classes, routing,
 * abort, `stampRoutingKeysFromAst` — is legitimately reachable from
 * EVERY entry (the v3 middleware imports the shared routing walk), and
 * it currently also DEFINES the v2 wire encoder. Identified by CONTENT
 * (it is the one chunk that defines the envelope base class), never by
 * tsup's hash-named file. It is exempted ONLY from the v2-wire-marker
 * scan of the v3 graph; the per-chunk "no chunk mixes the two wires"
 * test below still pins that this chunk never gains a v3 wire marker,
 * so the exemption cannot hide a fused chunk.
 */
function definesVersionNeutralExecutionChunk(chunk: ChunkFile): boolean {
  return /var EncryptedEnvelopeBase\s*=/.test(chunk.body)
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

  it('v3.js does not pull contract-space artefacts', () => {
    const entry = readChunk('v3.js')
    const leaks = findLeaksInEntry(entry, RUNTIME_FORBIDDEN)
    expect(leaks, `v3 entry leaks: ${leaks.join(', ')}`).toEqual([])
  })

  it('no chunk in the v3 graph references the v2 composite-literal wire (version-neutral execution chunk exempted)', () => {
    // COMPLETE-graph scan, not just the entry body: a cross-plane leak
    // usually arrives through a transitive chunk import, which an
    // entry-body substring check never sees. `v3.js` legitimately
    // shares the version-neutral execution chunk (envelope
    // base/classes, routing, abort, `stampRoutingKeysFromAst`) with the
    // v2 entries — that chunk currently also DEFINES the v2 wire
    // encoder, so it is exempted here by content and pinned against v3
    // contamination by the per-chunk disjointness test below.
    const leaks = findLeaksInGraph(
      'v3.js',
      V2_WIRE_MARKERS,
      definesVersionNeutralExecutionChunk,
    )
    expect(leaks, `v3 graph leaks v2 wire: ${leaks.join(', ')}`).toEqual([])
  })

  it('no chunk in the v3 graph references any v2 codec-runtime factory', () => {
    // All six `createCipherstash*Codec` factories (built on the
    // composite wire), against every chunk in the v3 graph — including
    // the version-neutral execution chunk, which must never grow one.
    const leaks = findLeaksInGraph('v3.js', V2_CODEC_FACTORY_MARKERS)
    expect(
      leaks,
      `v3 graph reaches v2 codec-runtime factories: ${leaks.join(', ')}`,
    ).toEqual([])
  })

  it('no chunk in the middleware.js graph (v2 bulk-encrypt entry) references the v3 wire plane', () => {
    const leaks = findLeaksInGraph('middleware.js', V3_WIRE_MARKERS)
    expect(
      leaks,
      `middleware graph leaks v3 wire: ${leaks.join(', ')}`,
    ).toEqual([])
  })

  it('no code-split chunk mixes the v2 composite wire with the v3 JSONB wire', () => {
    // Chunk-level two-wires-never-co-located pin. A chunk "references a
    // wire plane" when any of that plane's marker identifiers appears in
    // its body — which covers both defining the symbol and importing it
    // by name from another chunk (`import { encodeEqlV2EncryptedWire }
    // from "./chunk-*.js"`). Entry files are exempt: `runtime.js` and
    // `stack.js` deliberately aggregate the v2 AND v3 public API (each
    // client picks one at construction time); the invariant is that no
    // shared IMPLEMENTATION chunk fuses the two wire codecs, which is
    // what would let one wire's encode path silently reach the other's
    // consumers.
    const chunkFiles = readdirSync(DIST).filter((f) =>
      SHARED_CHUNK_PATTERN.test(f),
    )
    expect(chunkFiles.length).toBeGreaterThan(0)
    const mixed = chunkFiles.filter((file) => {
      const body = readChunk(file).body
      const referencesV2Wire = V2_WIRE_MARKERS.some((m) => body.includes(m))
      const referencesV3Wire = V3_WIRE_MARKERS.some((m) => body.includes(m))
      return referencesV2Wire && referencesV3Wire
    })
    expect(
      mixed,
      `chunk(s) mix v2 and v3 wire planes: ${mixed.join(', ')}`,
    ).toEqual([])
  })

  it('v3-wire chunks reachable from runtime.js never reference the v2 composite encoder', () => {
    // The plan's original Task-10 assertion, made chunk-name-agnostic:
    // identify v3 chunks by CONTENT (they carry a v3 wire marker), not
    // by tsup's hash-named files.
    const runtimeChunks = collectGraph('runtime.js')
    for (const [file, chunk] of runtimeChunks) {
      if (file === 'runtime.js') continue
      const isV3WireChunk = V3_WIRE_MARKERS.some((m) => chunk.body.includes(m))
      if (!isV3WireChunk) continue
      const leaks = V2_WIRE_MARKERS.filter((m) => chunk.body.includes(m))
      expect(
        leaks,
        `v3 chunk ${file} references v2 wire: ${leaks.join(', ')}`,
      ).toEqual([])
    }
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

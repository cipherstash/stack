/**
 * Control vs runtime byte-level subpath isolation (EQL v3).
 *
 * The cipherstash extension publishes control- and runtime-plane subpath
 * entries: `./control` (contract-space authoring + the v3 codec
 * lifecycle hook), `./runtime` (envelopes + SDK + v3 codec runtime +
 * bulk-encrypt middleware), and `./v3` (the aggregated v3 surface). Each
 * entry must compose tree-shakably so a consumer pulling `./runtime`
 * (or `./v3`) does not drag in the EQL install SQL, the cipherstash
 * baseline migration, or the codec lifecycle hook (any of which would
 * defeat the runtime-bundle size budget and leak control-plane behaviour
 * into runtime call paths), and a consumer pulling `./control` does not
 * drag in the envelope classes, the SDK interface, the codec runtime, or
 * the bulk-encrypt middleware.
 *
 * This test is the canonical isolation guard. It asserts:
 *
 *   1. **Entry-body forbidden-substring check** (per entry): the entry
 *      `.js` body — both the inline source and its `import` / `export`
 *      statements — does not contain forbidden symbol names.
 *   2. **Chunk-graph disjointness**: control's transitively reachable
 *      chunk-file set and runtime's set are disjoint, modulo shared
 *      `chunk-*.js` files that carry ONLY pure constants / catalog
 *      metadata (no control- or runtime-plane behaviour).
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

const ENTRY_FILES = ['control.js', 'runtime.js', 'v3.js'] as const

/**
 * Forbidden in `control.js` and its transitive chunk graph. These are
 * runtime-plane symbols (envelope classes / codec runtime / bulk-encrypt
 * middleware / read-side walker) that must never reach a control-plane
 * consumer.
 */
const CONTROL_FORBIDDEN = [
  'EncryptedString',
  'EncryptedBigInt',
  'EncryptedDate',
  'EncryptedBoolean',
  'EncryptedJson',
  'EncryptedNumber',
  'setHandleCiphertext',
  'bulkEncryptMiddlewareV3',
  'createV3CodecDescriptors',
  'CipherstashV3CellCodec',
  'decryptAll',
] as const

/**
 * Forbidden in `runtime.js` / `v3.js` and their transitive chunk graph.
 * These are contract-space artefacts (the EQL v3 install SQL injector,
 * the contract-space builder, the codec-control lifecycle hook, and the
 * search-config migration-op terms) that must never reach a runtime
 * consumer.
 */
const RUNTIME_FORBIDDEN = [
  'contractSpaceFromJson',
  'withRuntimeEqlSqlPackage',
  'RUNTIME_EQL_SQL_SENTINEL',
  'cipherstashV3CodecControlHooks',
  'add_search_config',
  'remove_search_config',
] as const

/**
 * A code-split chunk is emitted as `chunk-<hash>.js`. Such a chunk may
 * legitimately be shared across the control and runtime graphs ONLY when
 * it is one of the pure-metadata chunks below — codec ids / native types
 * / invariant ids / trait literals, or the per-domain catalog data and
 * the pure `envelopeTypeNameForCastAs` / `v3TraitsForCapabilities`
 * mappers (which carry envelope type-NAME strings, never the envelope
 * classes or any SDK / codec / migration behaviour).
 *
 * Each allowed shared chunk must export every marker of at least one set;
 * a `chunk-*.js` shared between planes that matches no set is not a
 * known-safe metadata chunk and the disjointness test rightly fails.
 */
const SHARED_CHUNK_PATTERN = /^chunk-[A-Za-z0-9_-]+\.js$/

const ALLOWED_SHARED_CHUNK_MARKER_SETS: ReadonlyArray<readonly string[]> = [
  // constants chunk (constants.ts + constants-v3.ts — pure literals)
  [
    'CIPHERSTASH_SPACE_ID',
    'CIPHERSTASH_V3_CODEC_IDS',
    'v3TraitsForCapabilities',
  ],
  // v3 catalog chunk (per-domain metadata + name/trait mappers)
  ['V3_DOMAIN_META_BY_CODEC_ID', 'toV3CodecId', 'EXPOSED_DOMAIN_ENTRIES'],
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

/**
 * A shared `chunk-*.js` is allowed across planes iff it matches one of
 * the known-safe pure-metadata marker sets AND smuggles no control- or
 * runtime-plane BEHAVIOUR marker (the envelope base class, the codec
 * runtime, the middleware, the contract-space builder). The first clause
 * pins WHICH chunks may be shared; the second guards that a matched
 * metadata chunk has not also fused in behaviour.
 */
function isAllowedSharedChunk(chunk: string): boolean {
  if (!SHARED_CHUNK_PATTERN.test(chunk)) {
    return false
  }
  const body = readChunk(chunk).body
  const isKnownMetadataChunk = ALLOWED_SHARED_CHUNK_MARKER_SETS.some(
    (markers) => markers.every((marker) => body.includes(marker)),
  )
  if (!isKnownMetadataChunk) {
    return false
  }
  // A metadata chunk must never define/import plane behaviour. Envelope
  // type-NAME strings (e.g. "EncryptedString" from `envelopeTypeNameForCastAs`)
  // are fine; the envelope CLASS is not, so we fingerprint the class /
  // codec-runtime / middleware / contract-space builders directly.
  const behaviourMarkers = [
    'EncryptedEnvelopeBase',
    'setHandleCiphertext',
    'bulkEncryptMiddlewareV3',
    'createV3CodecDescriptors',
    'CipherstashV3CellCodec',
    'decryptAll',
    ...RUNTIME_FORBIDDEN,
  ]
  return !behaviourMarkers.some((marker) => body.includes(marker))
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

  it('v3.js does not pull contract-space artefacts', () => {
    const entry = readChunk('v3.js')
    const leaks = findLeaksInEntry(entry, RUNTIME_FORBIDDEN)
    expect(leaks, `v3 entry leaks: ${leaks.join(', ')}`).toEqual([])
  })

  it('control vs runtime chunk graphs are disjoint (modulo pure metadata chunks)', () => {
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
})

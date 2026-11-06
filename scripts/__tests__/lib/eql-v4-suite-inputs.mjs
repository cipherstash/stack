import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { compiledCrateFiles } from './rust-compiled-files.mjs'

/**
 * The `paths:` filter entries under `packages/eql/crates/` that the protect-ffi
 * migration suites (`integration-tests/tests/migrate-v*-to-v4.test.ts`) need,
 * derived from the two builds those suites run rather than listed.
 *
 * - `mise run eql:v4:codec` builds `packages/eql/tests/encryption/examples/v4_codec.rs`,
 *   which compiles `eql-bindings` with the features that crate's manifest asks
 *   for. Those turn on the `v4`, `encryption` and `encoding` modules the native
 *   binding never compiles.
 * - `mise run eql:v4:install` runs `tasks/build.sh`, which renders the v4 SQL
 *   bundle through `eql-codegen` (and `eql-domains`). Its `#MISE sources` line
 *   is the list of what that render reads.
 *
 * `integration-protect-ffi.yml` must trigger on every entry returned here, or a
 * change to the v4 codec or the SQL it is checked against starts no suite that
 * runs it. `wasm-build-inputs-paths-filter.test.mjs` forbids every other
 * workflow from naming these paths, and allows exactly these for that one.
 *
 * Each compiled file becomes the smallest entry a reader would write: a file
 * at the crate root or directly under `src/` is named itself, anything deeper
 * becomes its top module directory with `/**` (`src/v4/**`, `sql/**`).
 */
const EQL_ROOT = 'packages/eql'
const EQL_CRATES = `${EQL_ROOT}/crates`
const CODEC_MANIFEST = `${EQL_ROOT}/tests/encryption/Cargo.toml`
const BINDINGS = `${EQL_CRATES}/eql-bindings`
const BUILD_SCRIPT = `${EQL_ROOT}/tasks/build.sh`

/** The `features = [...]` the codec crate requests of `eql-bindings`. */
function requestedBindingsFeatures(repoRoot) {
  const text = readFileSync(resolve(repoRoot, CODEC_MANIFEST), 'utf8')
  const line = text.split('\n').find((l) => /^\s*eql-bindings\s*=\s*\{/.test(l))
  if (!line)
    throw new Error(`${CODEC_MANIFEST} no longer depends on eql-bindings`)
  const list = /features\s*=\s*\[([^\]]*)\]/.exec(line)
  if (!list) return []
  return [...list[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
}

/** `eql-bindings`' `[features]` table: name -> the entries it enables. */
function bindingsFeatureTable(repoRoot) {
  const text = readFileSync(resolve(repoRoot, `${BINDINGS}/Cargo.toml`), 'utf8')
  const start = text.indexOf('\n[features]')
  if (start === -1) return new Map()
  const rest = text.slice(start + '\n[features]'.length)
  const end = rest.search(/\n\[[^\]]+\]/)
  const body = (end === -1 ? rest : rest.slice(0, end)).replace(/#.*$/gm, '')
  const table = new Map()
  for (const m of body.matchAll(/^\s*([\w-]+)\s*=\s*\[([^\]]*)\]/gm)) {
    table.set(
      m[1],
      [...m[2].matchAll(/"([^"]+)"/g)].map((e) => e[1]),
    )
  }
  return table
}

/** The requested features plus every crate-local feature they turn on. */
function enabledFeatures(requested, table) {
  const enabled = new Set()
  const queue = [...requested]
  while (queue.length > 0) {
    const name = queue.shift()
    if (enabled.has(name)) continue
    enabled.add(name)
    for (const entry of table.get(name) ?? []) {
      if (!entry.includes('/') && !entry.startsWith('dep:')) queue.push(entry)
    }
  }
  return enabled
}

/** The smallest filter entry covering one compiled file of a crate. */
function entryForCompiledFile(crateDir, file) {
  const rel = file.slice(crateDir.length + 1).split('/')
  if (rel.length === 1) return file
  if (rel[0] === 'src') {
    return rel.length === 2 ? file : `${crateDir}/src/${rel[1]}/**`
  }
  return `${crateDir}/${rel[0]}/**`
}

/** `tasks/build.sh`'s `#MISE sources` that live under `crates/`. */
function codegenSources(repoRoot) {
  const text = readFileSync(resolve(repoRoot, BUILD_SCRIPT), 'utf8')
  const line = /^#MISE sources=(\[.*\])\s*$/m.exec(text)
  if (!line) throw new Error(`${BUILD_SCRIPT} no longer declares #MISE sources`)
  return JSON.parse(line[1])
    .filter((source) => source.startsWith('crates/'))
    .map((source) => `${EQL_ROOT}/${source}`)
}

/** A glob reduced to its directory with `/**`, or a literal path as is. */
function entryForSource(source) {
  const segments = source.split('/')
  const at = segments.findIndex((segment) => /[*?[]/.test(segment))
  return at === -1 ? source : `${segments.slice(0, at).join('/')}/**`
}

export function eqlV4SuiteFilterEntries(repoRoot) {
  const features = enabledFeatures(
    requestedBindingsFeatures(repoRoot),
    bindingsFeatureTable(repoRoot),
  )
  const walk = compiledCrateFiles(repoRoot, BINDINGS, features)
  if (walk.unresolved.length > 0) {
    throw new Error(
      `Could not resolve every eql-bindings file the v4 codec compiles:\n${walk.unresolved.join('\n')}`,
    )
  }
  const entries = new Set([
    ...walk.files.map((file) => entryForCompiledFile(BINDINGS, file)),
    ...codegenSources(repoRoot).map(entryForSource),
  ])
  return { features, entries: [...entries].sort() }
}

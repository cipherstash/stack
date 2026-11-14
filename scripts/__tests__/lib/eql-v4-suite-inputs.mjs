import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
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
const CODEC_CRATE = `${EQL_ROOT}/tests/encryption`
const CODEC_MANIFEST = `${CODEC_CRATE}/Cargo.toml`
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

/** `tasks/build.sh`'s `#MISE sources`, relative to the subtree root. */
function buildScriptSources(repoRoot) {
  const text = readFileSync(resolve(repoRoot, BUILD_SCRIPT), 'utf8')
  const line = /^#MISE sources=(\[.*\])\s*$/m.exec(text)
  if (!line) throw new Error(`${BUILD_SCRIPT} no longer declares #MISE sources`)
  return JSON.parse(line[1])
}

/** `tasks/build.sh`'s `#MISE sources` that live under `crates/`. */
function codegenSources(repoRoot) {
  return buildScriptSources(repoRoot)
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

/**
 * The `paths:` filter entries for what `mise run eql:v4:install` reads outside
 * `crates/`: every other `#MISE sources` entry of `tasks/build.sh`, plus the
 * script itself, which is what that task runs and does not list itself.
 *
 * Kept apart from `eqlV4SuiteFilterEntries` because that function's entries are
 * the allowlist `wasm-build-inputs-paths-filter.test.mjs` applies under
 * `packages/eql/crates/`, and nothing here is under it.
 */
export function eqlV4SqlBuildEntries(repoRoot) {
  const sources = buildScriptSources(repoRoot)
    .filter((source) => !source.startsWith('crates/'))
    .map((source) => entryForSource(`${EQL_ROOT}/${source}`))
  return [...new Set([BUILD_SCRIPT, ...sources])].sort()
}

/**
 * Dependency tables of a manifest. `kind` is `workspace` for
 * `[workspace.dependencies]`. `name` is set for the `[dependencies.foo]`
 * spelling, where the table is the spec. Target-specific tables count as their
 * unconditional twins: the build host decides which apply, and a filter has to
 * cover all of them. The `^(?=\[)` split is the one
 * `lint-no-eql-registry-pins.mjs` uses and does not export: no TOML parser is
 * installed, and adding one is an audit decision.
 */
function dependencyTables(source) {
  const shape =
    /^(?:(workspace)\.dependencies|(?:target\..+\.)?(dev|build)?[-_]?dependencies)(?:\.(.+))?$/
  const tables = []
  for (const block of source.replace(/#.*$/gm, '').split(/^(?=\[)/m)) {
    const header = /^\[([^\]\n]+)\]/.exec(block)
    const match = header && shape.exec(header[1].trim())
    if (!match) continue
    tables.push({
      kind: match[1] ?? match[2] ?? 'normal',
      name: match[3]?.replace(/^["']|["']$/g, ''),
      body: block.slice(header[0].length),
    })
  }
  return tables
}

/** Whether a value has opened more brackets than it has closed. */
function isUnterminated(value) {
  const bare = value.replace(/"[^"]*"|'[^']*'/g, '')
  return bare.split(/[{[]/).length > bare.split(/[}\]]/).length
}

/**
 * Each dependency a table declares, as `{ name, spec }`. An inline table may
 * carry a `features` array across lines, and a key may be dotted
 * (`foo.path = "…"`), so neither is a one-line regex. A line that is not a
 * key/value pair throws, since skipping it would drop a dependency unseen.
 */
function tableDependencies({ name, body }, manifest) {
  if (name) return [{ name, spec: body }]
  const lines = body.split('\n')
  const specs = new Map()
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === '') continue
    const match =
      /^\s*("[^"]+"|'[^']+'|[\w-]+)((?:\.[\w-]+)*)\s*=\s*(.*)$/.exec(lines[i])
    if (!match) {
      throw new Error(`${manifest}: cannot read "${lines[i].trim()}"`)
    }
    let value = match[3]
    while (isUnterminated(value) && i + 1 < lines.length) {
      value += ` ${lines[++i]}`
    }
    const key = match[1].replace(/^["']|["']$/g, '')
    const piece = match[2] ? `${match[2].slice(1)} = ${value}` : value
    specs.set(key, [...(specs.get(key) ?? []), piece])
  }
  return [...specs].map(([key, pieces]) => ({
    name: key,
    spec: pieces.join(', '),
  }))
}

/**
 * Where a spec points: `{ path }`, `{ workspace: true }`, `{ external: true }`
 * for a registry or git source, or undefined for a spec this cannot read.
 * `path` is tested first because a published in-tree crate carries both `path`
 * and `version`, and cargo builds the path.
 */
function specSource(spec) {
  if (/(?:^|[\s,{])path\s*=/.test(spec)) {
    const path = /(?:^|[\s,{])path\s*=\s*(?:"([^"]*)"|'([^']*)')/.exec(spec)
    return path ? { path: path[1] ?? path[2] } : undefined
  }
  if (/(?:^|[\s,{])workspace\s*=\s*true\b/.test(spec)) {
    return { workspace: true }
  }
  if (/^\s*["']|(?:^|[\s,{])(?:version|git|registry)\s*=/.test(spec)) {
    return { external: true }
  }
  return undefined
}

/** The nearest directory at or above `crateAbs` declaring `[workspace]`. */
function owningWorkspace(rootAbs, crateAbs) {
  for (let dir = crateAbs; ; dir = dirname(dir)) {
    const manifest = join(dir, 'Cargo.toml')
    if (
      existsSync(manifest) &&
      /^\[workspace\]/m.test(readFileSync(manifest, 'utf8'))
    ) {
      return dir
    }
    if (dir === rootAbs) return undefined
  }
}

/**
 * The in-tree crates cargo compiles for `startManifest`'s crate, as repo-relative
 * crate directories, and the workspace manifests whose
 * `[workspace.dependencies]` their `workspace = true` specs resolved through.
 * Editing one of those changes what the crates build with while touching no
 * file in any of them. Read from the manifests alone so the guard needs no Rust
 * toolchain. `path` dependencies are followed through `[dependencies]` and
 * `[build-dependencies]`; `[dev-dependencies]` count only for the starting
 * crate, whose examples and tests are what use them. `foo = { workspace = true }`
 * resolves through the workspace that owns the declaring crate, which is not the
 * workspace being built when a path dependency crosses into another one.
 *
 * Optional dependencies are followed without working out whether a feature
 * enables them. That over-approximates, at the cost of a spurious trigger, where
 * the opposite error is the silent skip this guard exists to catch. Anything
 * that cannot be resolved to a manifest throws, so a walk that stopped early
 * cannot read as a small graph.
 */
export function cargoPathDependencyWalk(repoRoot, startManifest) {
  const rootAbs = resolve(repoRoot)
  const rel = (abs) => relative(rootAbs, abs).split(sep).join('/')
  const startAbs = dirname(resolve(rootAbs, startManifest))
  const seen = new Set()
  const workspaceManifests = new Set()

  const crateAt = (dirAbs, declaredBy, name) => {
    if (dirAbs !== rootAbs && !dirAbs.startsWith(`${rootAbs}${sep}`)) {
      throw new Error(`${declaredBy}: ${name} resolves outside the repository`)
    }
    if (!existsSync(join(dirAbs, 'Cargo.toml'))) {
      throw new Error(
        `${declaredBy}: ${name} resolves to ${rel(dirAbs)}, which has no Cargo.toml`,
      )
    }
    return dirAbs
  }

  const throughWorkspace = (crateAbs, manifest, name) => {
    const workspaceAbs = owningWorkspace(rootAbs, crateAbs)
    if (!workspaceAbs) {
      throw new Error(
        `${manifest}: ${name} says workspace = true, but no workspace owns the crate`,
      )
    }
    const workspaceManifest = `${rel(workspaceAbs)}/Cargo.toml`.replace(
      /^\//,
      '',
    )
    workspaceManifests.add(workspaceManifest)
    const source = readFileSync(join(workspaceAbs, 'Cargo.toml'), 'utf8')
    const entry = dependencyTables(source)
      .filter((table) => table.kind === 'workspace')
      .flatMap((table) => tableDependencies(table, workspaceManifest))
      .find((dependency) => dependency.name === name)
    if (!entry) {
      throw new Error(
        `${manifest}: ${name} says workspace = true, but ${workspaceManifest} has no [workspace.dependencies] entry for it`,
      )
    }
    const target = specSource(entry.spec)
    if (target?.path !== undefined) {
      return crateAt(
        resolve(workspaceAbs, target.path),
        workspaceManifest,
        name,
      )
    }
    if (target?.external) return undefined
    throw new Error(
      `${workspaceManifest}: cannot resolve ${name}: ${entry.spec}`,
    )
  }

  crateAt(startAbs, startManifest, 'the starting crate')
  const queue = [startAbs]
  while (queue.length > 0) {
    const crateAbs = queue.shift()
    if (seen.has(crateAbs)) continue
    seen.add(crateAbs)
    const manifest = `${rel(crateAbs)}/Cargo.toml`.replace(/^\//, '')
    const source = readFileSync(join(crateAbs, 'Cargo.toml'), 'utf8')
    const tables = dependencyTables(source).filter(
      (table) =>
        table.kind === 'normal' ||
        table.kind === 'build' ||
        (table.kind === 'dev' && crateAbs === startAbs),
    )
    for (const table of tables) {
      for (const { name, spec } of tableDependencies(table, manifest)) {
        const target = specSource(spec)
        if (target === undefined) {
          throw new Error(`${manifest}: cannot resolve ${name}: ${spec.trim()}`)
        }
        if (target.path !== undefined) {
          queue.push(crateAt(resolve(crateAbs, target.path), manifest, name))
        } else if (target.workspace) {
          const found = throughWorkspace(crateAbs, manifest, name)
          if (found) queue.push(found)
        }
      }
    }
  }
  return {
    crates: [...seen].map(rel).sort(),
    workspaceManifests: [...workspaceManifests].sort(),
  }
}

/** The crate directories of `cargoPathDependencyWalk`. */
export function cargoPathDependencyClosure(repoRoot, startManifest) {
  return cargoPathDependencyWalk(repoRoot, startManifest).crates
}

/**
 * What the codec's in-tree dependencies contribute to the workflow's `paths:`
 * filter. Two crates take something other than the default whole-source entries:
 * `eql-bindings`, of which the codec compiles only the feature-gated part that
 * `eqlV4SuiteFilterEntries` names file by file, and the codec crate itself, which
 * has no `src/` and whose only build target here is the example.
 *
 * Kept apart from `eqlV4SuiteFilterEntries` because that function's entries are
 * the allowlist `wasm-build-inputs-paths-filter.test.mjs` applies under
 * `packages/eql/crates/`, where `eql-domains`' entries from this walk have no
 * place.
 */
const CODEC_CRATE_ENTRIES = new Map([
  [BINDINGS, []],
  [
    CODEC_CRATE,
    [`${CODEC_CRATE}/Cargo.toml`, `${CODEC_CRATE}/examples/v4_codec.rs`],
  ],
])

export function eqlV4CodecCrateEntries(repoRoot) {
  const { crates, workspaceManifests } = cargoPathDependencyWalk(
    repoRoot,
    CODEC_MANIFEST,
  )
  const entries = crates.flatMap((crate) => {
    const special = CODEC_CRATE_ENTRIES.get(crate)
    if (special) return special
    const buildScript = existsSync(resolve(repoRoot, crate, 'build.rs'))
      ? [`${crate}/build.rs`]
      : []
    return [`${crate}/Cargo.toml`, `${crate}/src/**`, ...buildScript]
  })
  return { crates, workspaceManifests, entries: [...new Set(entries)].sort() }
}

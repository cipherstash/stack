/**
 * Fail if any manifest in the tree resolves EQL from a registry instead of from
 * this repo.
 *
 * ## What this is protecting
 *
 * EQL ships as two halves that have to agree: `eql-bindings` (the Rust wire
 * types that EMIT a payload) and `@cipherstash/eql` (the npm package carrying
 * the SQL bundle that STORES and queries one). They are released at a single
 * lockstep version for exactly that reason.
 *
 * Before the subtree import, `packages/protect-ffi` pinned `eql-bindings
 * = "=3.0.2"` from crates.io while the EQL tree carried 3.0.4. That skew was
 * benign only by luck — the Rust was byte-identical across those releases, and
 * what 3.0.3/3.0.4 changed was SQL. Phase 3 of the absorption plan replaced the
 * pin with a path dep so the two halves are the same commit and the skew is
 * unrepresentable.
 *
 * Nothing else notices if that is undone. Restoring a registry version compiles
 * clean, passes every unit test, and produces payloads the installed SQL may
 * not read — a failure that surfaces in a database, not in CI. Hence a linter:
 * the property is invisible at every layer that would otherwise catch it.
 *
 * ## What counts as in-tree
 *
 * Cargo: the dependency carries a `path`. `workspace = true` is also accepted
 * and defers the judgement to the workspace root's `[workspace.dependencies]`
 * entry — which this scan reads as a declaration in its own right, so the
 * deferral cannot launder a registry pin.
 *
 * npm: the specifier starts with `workspace:`. Nothing else — `link:` and
 * `file:` would resolve in-tree too, but they bypass the version range that
 * `workspace:^` exists to express, and no manifest here uses them.
 *
 * ## Exemptions
 *
 * `EXEMPT_DECLARATIONS`, keyed `<manifest> :: <dependency>` with a mandatory
 * written reason, in the shape of `BINDING_EXEMPT_JOBS` in
 * `scripts/__tests__/ffi-binding-step-order.test.mjs`. One entry today.
 *
 * The alternative — narrowing the scan so it never reaches the directory — was
 * rejected for the reason this whole absorption keeps rediscovering: a scan
 * that does not reach a file reads exactly like a scan that found it clean. An
 * exemption that has to be written down and justified stays visible, and goes
 * stale loudly (see the exit-2 contract below).
 *
 * ## Exit codes
 *
 * - `0` — every declaration is in-tree or explicitly exempt.
 * - `1` — it ran and found a registry pin. Fix the manifest.
 * - `2` — it could not do its job: the scan matched less than it must, or an
 *   exemption is excusing nothing. Both mean the linter's own configuration is
 *   wrong, which is a different thing to go and fix, and must never be mistaken
 *   for a pass.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve, sep } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(import.meta.dirname, '..')

/** The Cargo crate and the npm package, and the manifest each lives in. */
const CARGO_DEPENDENCY = 'eql-bindings'
const NPM_DEPENDENCY = '@cipherstash/eql'

/**
 * Directories the walk does not descend into.
 *
 * `target` and `node_modules` are the load-bearing two: both are full of
 * manifests belonging to OTHER packages — vendored registry sources under
 * `target/package`, and every transitive dependency under `node_modules` —
 * which name their own dependencies by registry version, correctly. Scanning
 * them turns this linter into a permanent false alarm.
 */
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'target',
  'dist',
  '.turbo',
  '.next',
])

/**
 * Manifests known to declare one of the two dependencies, as the guard on the
 * scan itself.
 *
 * A discovery linter that matches nothing exits 0 and proves nothing, and the
 * ways this one could stop matching are all silent: a rename of either package,
 * a `SKIP_DIRS` entry that swallows `packages/`, a TOML shape the block reader
 * does not know. Held as a MINIMUM — a new consumer must not fail this — and
 * checked with exit 2, because a scan that lost its subject has not passed.
 *
 * The failure prints what the scan DID find, so a rename is a copy from the
 * message rather than a re-derivation from the tree.
 */
export const EXPECTED_DECLARERS = [
  `packages/cli/package.json :: ${NPM_DEPENDENCY}`,
  `packages/eql/tests/sqlx/Cargo.toml :: ${CARGO_DEPENDENCY}`,
  `packages/protect-ffi/crates/protect-ffi/Cargo.toml :: ${CARGO_DEPENDENCY}`,
  `packages/protect-ffi/integration-tests/package.json :: ${NPM_DEPENDENCY}`,
  `packages/stack-prisma/package.json :: ${NPM_DEPENDENCY}`,
  `packages/stack/package.json :: ${NPM_DEPENDENCY}`,
]

/**
 * Declarations allowed to name a registry version, each with the reason.
 *
 * Keep this at one entry if at all possible. Every entry is a place the two
 * halves of EQL can drift apart again, and the reason is what a later reader
 * needs in order to decide whether it is still true.
 */
export const EXEMPT_DECLARATIONS = new Map([
  [
    `packages/protect-ffi/integration-tests/package.json :: ${NPM_DEPENDENCY}`,
    'Not a pnpm workspace member: `pnpm-workspace.yaml` globs one level under ' +
      '`packages/`, so this directory is invisible to pnpm, installs with `npm ' +
      'ci`, and cannot resolve a `workspace:` specifier. Absorbing it into the ' +
      'workspace is open decision 3 in ' +
      'docs/plans/2026-08-13-eql-monorepo-absorption.md — it moves ' +
      '`@cipherstash/auth`, `vitest` and this pin at once, and only a run with ' +
      'Docker plus CS_* credentials can show that is neutral.',
  ],
])

/** Every `Cargo.toml` and `package.json` under `root`, repo-relative. */
export function manifestFiles(root) {
  const found = []
  const walk = (abs) => {
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue
        walk(join(abs, entry.name))
      } else if (entry.name === 'Cargo.toml' || entry.name === 'package.json') {
        found.push(join(abs, entry.name))
      }
    }
  }
  walk(root)
  // Repo-relative and POSIX-spelled, so the ids in EXPECTED_DECLARERS and
  // EXEMPT_DECLARATIONS are the same strings on every platform.
  return found.map((abs) => relative(root, abs).split(sep).join('/')).sort()
}

/**
 * A TOML table header, split from its body.
 *
 * No TOML parser: adding a dependency is an audit decision in this repo, and
 * the shape needed here is small. `^(?=\[)` splits on table headers, which are
 * the only thing cargo writes at column 0 with a leading bracket — array values
 * wrap with their continuation lines indented. The same trick, for the same
 * reason, as `taskGraph()` in `scripts/__tests__/eql-suite-ci.test.mjs`.
 */
function tomlTables(source) {
  return source
    .split(/^(?=\[)/m)
    .map((block) => {
      const header = /^\[([^\]\n]+)\]/.exec(block)
      return header ? { path: header[1].trim(), body: block } : null
    })
    .filter(Boolean)
}

/**
 * Whether a TOML table path is a dependency table — `[dependencies]`,
 * `[dev-dependencies]`, `[workspace.dependencies]`, and the
 * `[target.'cfg(unix)'.dependencies]` family.
 *
 * Matched on the LAST segment so the target-specific spelling is covered
 * without enumerating it, and the cfg predicate (which is quoted and may
 * contain dots) never has to be parsed.
 */
const DEPENDENCY_TABLE =
  /(^|\.)(dependencies|dev-dependencies|build-dependencies)$/

/**
 * Classify a dependency spec: `path` and `workspace` are in-tree, everything
 * else is a registry pin.
 *
 * `spec` is either an inline table's text (`{ version = "=3.0.2" }`), a bare
 * version string, or the body of a `[dependencies.<name>]` table. All three
 * answer the same question — is there a `path` key — so all three take the
 * same reader.
 */
function classifySpec(spec) {
  if (/(^|[\s,{])path\s*=/.test(spec)) return { inTree: true, form: 'path' }
  if (/(^|[\s,{])workspace\s*=\s*true/.test(spec)) {
    return { inTree: true, form: 'workspace' }
  }
  if (/(^|[\s,{])git\s*=/.test(spec)) return { inTree: false, form: 'git' }
  return { inTree: false, form: 'version' }
}

/** Strip a trailing `#` comment. Cargo manifests quote no `#` in a dep spec. */
function uncommented(line) {
  return line.replace(/#.*$/, '')
}

/**
 * Every declaration of `CARGO_DEPENDENCY` in one `Cargo.toml`.
 *
 * Two spellings, and the second is the one a line-oriented scan misses:
 *
 *     [dependencies]
 *     eql-bindings = { version = "=3.0.2" }
 *
 *     [dependencies.eql-bindings]
 *     version = "=3.0.2"
 */
export function cargoDeclarations(file, source) {
  const found = []
  for (const { path, body } of tomlTables(source)) {
    if (DEPENDENCY_TABLE.test(path)) {
      for (const line of body.split('\n')) {
        const bare = uncommented(line)
        const match = new RegExp(
          `^\\s*(?:["']?)${CARGO_DEPENDENCY}(?:["']?)\\s*=\\s*(.+)$`,
        ).exec(bare)
        if (!match) continue
        found.push({
          file,
          dependency: CARGO_DEPENDENCY,
          spec: match[1].trim(),
          ...classifySpec(match[1]),
        })
      }
      continue
    }
    // `[<something>.dependencies.eql-bindings]` — the table IS the spec.
    const dotted = new RegExp(
      `(^|\\.)(?:dependencies|dev-dependencies|build-dependencies)\\.(?:["']?)${CARGO_DEPENDENCY}(?:["']?)$`,
    )
    if (!dotted.test(path)) continue
    const spec = body.split('\n').slice(1).map(uncommented).join('\n')
    found.push({
      file,
      dependency: CARGO_DEPENDENCY,
      spec: spec.trim().replace(/\s+/g, ' '),
      ...classifySpec(spec),
    })
  }
  return found
}

/**
 * Every declaration of `NPM_DEPENDENCY` in one `package.json`.
 *
 * `resolutions` and the two `overrides` spellings are read alongside the four
 * dependency tables. An override is the quietest way to reintroduce the skew:
 * it moves what actually gets installed while every `workspace:^` in the tree
 * still reads correct.
 *
 * A manifest that does not parse contributes nothing rather than throwing —
 * `package.json` syntax is checked by every other tool in the repo, and a
 * linter that dies on someone else's broken file reports its own crash instead
 * of the thing it was asked about.
 */
export function npmDeclarations(file, source) {
  let manifest
  try {
    manifest = JSON.parse(source)
  } catch {
    return []
  }
  const tables = [
    ['dependencies', manifest.dependencies],
    ['devDependencies', manifest.devDependencies],
    ['peerDependencies', manifest.peerDependencies],
    ['optionalDependencies', manifest.optionalDependencies],
    ['resolutions', manifest.resolutions],
    ['overrides', manifest.overrides],
    ['pnpm.overrides', manifest.pnpm?.overrides],
  ]
  const found = []
  for (const [table, entries] of tables) {
    const spec = entries?.[NPM_DEPENDENCY]
    if (typeof spec !== 'string') continue
    found.push({
      file,
      dependency: NPM_DEPENDENCY,
      table,
      spec,
      inTree: spec.startsWith('workspace:'),
      form: spec.startsWith('workspace:') ? 'workspace' : 'version',
    })
  }
  return found
}

/** Every declaration of either dependency under `root`. */
export function scanTree(root) {
  const found = []
  for (const rel of manifestFiles(root)) {
    const source = readFileSync(join(root, rel), 'utf8')
    found.push(
      ...(rel.endsWith('Cargo.toml')
        ? cargoDeclarations(rel, source)
        : npmDeclarations(rel, source)),
    )
  }
  return found
}

/** The id a declaration is named by, in both hand-maintained lists. */
export const declarationId = (declaration) =>
  `${declaration.file} :: ${declaration.dependency}`

/**
 * The whole check, as data. Separated from the reporting below so the tests can
 * drive every branch — including the two exit-2 ones — by passing a different
 * `exemptions` or `expected`, rather than by mutating this file's source.
 */
export function lint({
  root = REPO_ROOT,
  exemptions = EXEMPT_DECLARATIONS,
  expected = EXPECTED_DECLARERS,
} = {}) {
  const declarations = scanTree(root)
  const ids = declarations.map(declarationId)
  const registryPinned = declarations
    .filter((d) => !d.inTree)
    .map(declarationId)
  return {
    declarations,
    ids,
    offenders: declarations.filter(
      (d) => !d.inTree && !exemptions.has(declarationId(d)),
    ),
    exempted: declarations.filter(
      (d) => !d.inTree && exemptions.has(declarationId(d)),
    ),
    // An exemption that is not excusing anything, and an exemption whose reason
    // was emptied out. Both are the configuration going stale, and both must
    // fail — the first because it is a standing permission nothing needs, the
    // second because an exemption without a reason is indistinguishable from an
    // oversight.
    //
    // Measured against the declarations that are ACTUALLY registry-pinned, not
    // against every declaration found. The difference is the case that will
    // really happen: `packages/protect-ffi/integration-tests` is exempt because
    // it installs with `npm ci` and cannot take a `workspace:` specifier, and
    // absorbing it into the workspace is a scheduled follow-up. On the day that
    // lands, the manifest still declares `@cipherstash/eql` — so an
    // existence-based check would keep passing and leave the exemption behind,
    // permanently permitting a pin nothing has needed since. This spelling
    // fails that PR until the entry is deleted.
    staleExemptions: [...exemptions.keys()].filter(
      (id) => !registryPinned.includes(id),
    ),
    unreasonedExemptions: [...exemptions]
      .filter(([, reason]) => !String(reason ?? '').trim())
      .map(([id]) => id),
    missingExpected: expected.filter((id) => !ids.includes(id)),
  }
}

/**
 * A `lint()` result, turned into an exit code and the text that explains it.
 *
 * Separate from `main()` and exported, because the interesting half of this
 * linter is the two exit-2 branches — and those fire only when its own
 * configuration has gone stale, which by construction is not the state of the
 * tree the tests run against. Driving `report()` with a synthetic result
 * exercises the SAME mapping the CLI uses, without a harness that rewrites this
 * file's source in order to make a branch reachable.
 *
 * Ordering is deliberate: both exit-2 branches are checked before offenders.
 * A scan that lost its subject cannot be trusted to have found every offender
 * either, and reporting "3 registry pins" from a broken scan sends the reader
 * to fix the wrong thing.
 */
export function report(result) {
  const sawIds = result.ids.length
    ? result.ids.map((id) => `  ${id}`).join('\n')
    : '  (nothing — the scan matched no manifest)'

  if (result.missingExpected.length > 0) {
    return {
      code: 2,
      err:
        'This linter no longer sees manifests it is supposed to be checking:\n\n' +
        result.missingExpected.map((id) => `  ${id}`).join('\n') +
        `\n\nThe scan currently sees:\n${sawIds}\n\n` +
        'Either a package was renamed — copy the new id from the list above\n' +
        'into EXPECTED_DECLARERS — or the scan itself stopped working, which\n' +
        'is the failure this list exists to catch. A dependency linter that\n' +
        'matches nothing exits 0 and proves nothing.\n',
    }
  }

  if (
    result.staleExemptions.length > 0 ||
    result.unreasonedExemptions.length > 0
  ) {
    return {
      code: 2,
      err:
        'EXEMPT_DECLARATIONS no longer describes this tree:\n\n' +
        [
          ...result.staleExemptions.map(
            (id) => `  ${id} — exempted, but nothing there needs an exemption`,
          ),
          ...result.unreasonedExemptions.map(
            (id) => `  ${id} — exempted with no reason written`,
          ),
        ].join('\n') +
        `\n\nThe scan currently sees:\n${sawIds}\n\n` +
        'Either the manifest is gone, or it now resolves in-tree and the\n' +
        'exemption is dead weight. Delete the entry, or write the reason. An\n' +
        'exemption that outlives the thing it excused is a standing permission\n' +
        'nobody decided to grant — and the next manifest to land at that path\n' +
        'inherits it silently.\n',
    }
  }

  if (result.offenders.length === 0) {
    const suffix = result.exempted.length
      ? ` (${result.exempted.length} exempt: ${result.exempted
          .map(declarationId)
          .join(', ')})`
      : ''
    return { code: 0, out: `Every EQL dependency resolves in-tree${suffix}.` }
  }

  return {
    code: 1,
    err:
      '\nAn EQL dependency is pinned to a registry version:\n\n' +
      result.offenders
        .map(
          (o) =>
            `  ${o.file}${o.table ? ` [${o.table}]` : ''}\n      ${o.dependency} = ${o.spec}`,
        )
        .join('\n') +
      `\n\n\`${CARGO_DEPENDENCY}\` (the Rust that EMITS EQL payloads) and\n` +
      `\`${NPM_DEPENDENCY}\` (the SQL bundle that STORES and queries them) are\n` +
      'released at one lockstep version, and both now live in this repo. A\n' +
      'registry pin lets the installed SQL and the emitting Rust drift apart\n' +
      'silently — it compiles, it passes CI, and it fails in a database.\n\n' +
      'Resolve it in-tree instead:\n\n' +
      `    ${CARGO_DEPENDENCY} = { path = "../../../eql/crates/eql-bindings" }\n` +
      `    "${NPM_DEPENDENCY}": "workspace:^"\n\n` +
      'If the manifest genuinely cannot take an in-tree specifier, add it to\n' +
      'EXEMPT_DECLARATIONS in this script WITH the reason. There is one such\n' +
      'case today and it is written up there.\n',
  }
}

function main() {
  const root = process.argv[2] ? resolve(process.argv[2]) : REPO_ROOT
  try {
    statSync(root)
  } catch {
    console.error(`Root \`${root}\` does not exist.`)
    process.exit(2)
  }

  // An argv override is a fixture run: the two hand-maintained lists describe
  // THIS repo, so applying them to another tree would fail on every invocation
  // for a reason that has nothing to do with the tree being scanned.
  const scanningRepo = root === REPO_ROOT
  const { code, out, err } = report(
    lint({
      root,
      expected: scanningRepo ? EXPECTED_DECLARERS : [],
      exemptions: scanningRepo ? EXEMPT_DECLARATIONS : new Map(),
    }),
  )
  if (out) console.log(out)
  if (err) console.error(err)
  process.exit(code)
}

// Importable without running: the self-tests exercise the functions above, and
// the tree walk must not fire on import.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()

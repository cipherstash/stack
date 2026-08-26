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
 * the workspace protocol exists to express, and no manifest here uses them.
 * `catalog:`
 * is NOT given Cargo's `workspace = true` treatment: a catalog entry holds a
 * version range, so the deferral has no in-tree answer to defer to. Both ends
 * are flagged — the manifest that says `catalog:` and the catalog entry itself.
 *
 * ## What gets read
 *
 * Every `Cargo.toml` and `package.json`, and `pnpm-workspace.yaml`. The last
 * one is not a package manifest and no manifest scan would reach it, which is
 * exactly why it matters: pnpm 10 reads `overrides` and `catalogs` from there,
 * so an entry in that file moves what actually installs while every
 * `workspace:` specifier in the tree still reads correct. The file says so
 * itself, in a comment above its own `overrides:` block.
 *
 * Three shapes get read that a name-keyed scan walks straight past, and all
 * three install `@cipherstash/eql` from the registry:
 *
 *   - a NESTED npm override — `{"overrides": {"pkg": {"@cipherstash/eql": …}}}`
 *   - a SELECTOR key — `@cipherstash/eql@<3.0.5`, `pkg>@cipherstash/eql`, or
 *     a yarn `resolutions` key carrying a glob prefix
 *   - an ALIAS, where the package name is on the right-hand side —
 *     `{"eql-legacy": "npm:@cipherstash/eql@3.0.4"}`
 *
 * ## Exemptions
 *
 * `EXEMPT_DECLARATIONS`, keyed `<manifest> :: <dependency>` with a mandatory
 * written reason, in the shape of `BINDING_EXEMPT_JOBS` in
 * `scripts/__tests__/ffi-binding-step-order.test.mjs`. NONE today — the one
 * entry there had ever been was retired when its directory joined the pnpm
 * workspace.
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
 * - `2` — it could not do its job: a source it depends on would not read, the
 *   scan matched less than it must, or an exemption is excusing nothing. All
 *   three mean the linter's own configuration is wrong, which is a different
 *   thing to go and fix, and must never be mistaken for a pass.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { basename, dirname, join, relative, resolve, sep } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'

const REPO_ROOT = resolve(import.meta.dirname, '..')

/** The Cargo crate and the npm package, and the manifest each lives in. */
const CARGO_DEPENDENCY = 'eql-bindings'
const NPM_DEPENDENCY = '@cipherstash/eql'

/**
 * The one file pnpm resolves dependencies from that is not a package manifest.
 *
 * Only the repo root's copy is read by pnpm, but the walk collects every one it
 * finds: a nested copy is inert to pnpm and therefore the perfect place to
 * stage a pin, and reading it costs nothing.
 */
const WORKSPACE_FILE = 'pnpm-workspace.yaml'

/**
 * Directories the walk does not descend into.
 *
 * `target` and `node_modules` are the load-bearing two: both are full of
 * manifests belonging to OTHER packages — vendored registry sources under
 * `target/package`, and every transitive dependency under `node_modules` —
 * which name their own dependencies by registry version, correctly. Scanning
 * them turns this linter into a permanent false alarm.
 *
 * `.claude` is the same argument one tool along. Claude Code puts agent
 * worktrees under `.claude/worktrees/`, and a worktree is a FULL checkout of
 * some other commit — including ones predating the in-tree flip, which still
 * pin `@cipherstash/eql` by registry version and were correct when they were
 * written. Descending into them reported 31 offenders and exited 1 on a clean
 * tree. It is excluded through `.git/info/exclude`, which is local and travels
 * to no other checkout, so `git check-ignore` is not a substitute for naming
 * it here.
 */
const SKIP_DIRS = new Set([
  '.git',
  '.claude',
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
 * Non-manifest sources the scan must have read AND understood, as the floor on
 * those sources — the same idea as `EXPECTED_DECLARERS`, for a file that
 * declares nothing today.
 *
 * `EXPECTED_DECLARERS` cannot cover `pnpm-workspace.yaml`, because a clean tree
 * has no EQL entry in it: "found no declarations there" is the correct answer
 * and is also what a renamed file, a `SKIP_DIRS` entry that swallowed it, or a
 * YAML parse failure produce. Those are indistinguishable by their result, so
 * this list checks the antecedent instead: the file was opened and it parsed.
 *
 * Held as a minimum, checked with exit 2, for the reason in the header: a scan
 * that lost a source has not passed.
 */
export const EXPECTED_SOURCES = [WORKSPACE_FILE]

/**
 * Declarations allowed to name a registry version, each with the reason.
 *
 * EMPTY, and that is the goal state rather than an oversight. Every entry is a
 * place the two halves of EQL can drift apart again, and the reason is what a
 * later reader needs in order to decide whether it is still true.
 *
 * There was one, for `packages/protect-ffi/integration-tests`: it was not a
 * pnpm workspace member, installed with `npm ci`, and so could not resolve a
 * `workspace:` specifier at all. Absorbing it into the workspace (CIP-3744) was
 * what retired the exemption — and the `staleExemptions` spelling below is what
 * forced the entry to be deleted in the same change, since the manifest still
 * DECLARES `@cipherstash/eql` and an existence-based check would have gone on
 * passing over a standing permission nothing needed.
 *
 * Adding one back means writing the reason down here. Prefer not to.
 */
export const EXEMPT_DECLARATIONS = new Map([])

/** Files this scan reads, by name. */
const SCANNED_FILES = new Set(['Cargo.toml', 'package.json', WORKSPACE_FILE])

/**
 * Cargo's own config, which is not a manifest and carries `[patch]` anyway.
 *
 * The npm-side twin of this is `pnpm-workspace.yaml`, and it is here for the
 * same reason: a `[patch.crates-io]` block written in a config redirects the
 * whole tree while every `Cargo.toml` in it still reads correct. `config` with
 * no extension is cargo's older spelling and is still honoured.
 *
 * Matched on the DIRECTORY as well as the name — `config.toml` is a common
 * filename, and reading every one of them would turn this into a scanner of
 * arbitrary TOML. Deliberately NOT in `EXPECTED_SOURCES`: no such file exists
 * in this repo, and a floor on a file that does not exist fails on every run.
 *
 * What this does not read is a SOURCE replacement (`[source.crates-io]
 * replace-with = …`). That redirects every crate rather than naming one, so
 * there is no `eql-bindings` declaration to classify — it is a whole-registry
 * decision, and one this repo would notice in other ways.
 */
const CARGO_CONFIG_DIR = '.cargo'
const CARGO_CONFIG_FILES = new Set(['config.toml', 'config'])

/** Whether a repo-relative path is a file the Cargo readers understand. */
const isCargoSource = (rel) =>
  basename(rel) === 'Cargo.toml' ||
  (CARGO_CONFIG_FILES.has(basename(rel)) &&
    basename(dirname(rel)) === CARGO_CONFIG_DIR)

/**
 * Every `Cargo.toml`, `package.json` and `pnpm-workspace.yaml` under `root`,
 * repo-relative.
 *
 * The workspace file is here because pnpm reads dependency resolution from it —
 * see the header. It is not a package manifest, and a scan built around package
 * manifests is exactly what would leave it out.
 */
export function manifestFiles(root) {
  const found = []
  const walk = (abs) => {
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue
        walk(join(abs, entry.name))
      } else if (
        SCANNED_FILES.has(entry.name) ||
        (CARGO_CONFIG_FILES.has(entry.name) &&
          basename(abs) === CARGO_CONFIG_DIR)
      ) {
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
 * The tables that redirect where a dependency RESOLVES FROM without declaring
 * one: `[patch.<source>]` and the deprecated-but-honoured `[replace]`.
 *
 * These are the Cargo-side twin of npm's `overrides`, and they are read for the
 * reason that side has always been read — a redirect moves what actually gets
 * built while every specifier in the tree still reads correct. A manifest can
 * keep `eql-bindings = { path = … }` word for word and build against crates.io
 * by adding four lines further down the same file.
 *
 * `<source>` is a registry name (`crates-io`) or a quoted git URL, so the
 * segment after `patch` is not enumerated. `^` anchors both so a table like
 * `[workspace.metadata.replace]` is not mistaken for one.
 *
 * Classification is unchanged: a patch carrying `path` redirects in-tree, which
 * is where the dependency already points, and is fine. `git` or a version is
 * the skew.
 */
const REDIRECT_TABLE = /^(patch(\.|$)|replace$)/

/** Whether a TOML table holds entries keyed by crate name. */
const isEntryTable = (path) =>
  DEPENDENCY_TABLE.test(path) || REDIRECT_TABLE.test(path)

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
    // `[<entry table>.eql-bindings]` — the table IS the spec. Checked FIRST,
    // because `[patch.crates-io.eql-bindings]` is also matched by
    // `REDIRECT_TABLE`, and the line scan below would find no `eql-bindings =`
    // line in it and report the whole table clean.
    const dotted = new RegExp(
      `^(.+)\\.(?:["']?)${CARGO_DEPENDENCY}(?:["']?)$`,
    ).exec(path)
    if (dotted && isEntryTable(dotted[1])) {
      const spec = body.split('\n').slice(1).map(uncommented).join('\n')
      found.push({
        file,
        dependency: CARGO_DEPENDENCY,
        spec: spec.trim().replace(/\s+/g, ' '),
        ...classifySpec(spec),
      })
      continue
    }
    if (!isEntryTable(path)) continue
    for (const line of body.split('\n')) {
      const bare = uncommented(line)
      // The optional `:<version>` suffix is `[replace]`'s key spelling —
      // `"eql-bindings:3.0.4" = { … }`. It appears only inside quotes, since a
      // TOML bare key cannot contain a colon.
      const match = new RegExp(
        `^\\s*(?:["']?)${CARGO_DEPENDENCY}(?::[^"'\\s=]*)?(?:["']?)\\s*=\\s*(.+)$`,
      ).exec(bare)
      if (!match) continue
      found.push({
        file,
        dependency: CARGO_DEPENDENCY,
        spec: match[1].trim(),
        ...classifySpec(match[1]),
      })
    }
  }
  return found
}

const escapeForRegExp = (literal) =>
  literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/**
 * Whether an entry KEY names the npm package.
 *
 * Not an equality test, because none of the four ways to write the key is a
 * bare package name:
 *
 *     @cipherstash/eql@<3.0.5     a version selector (npm and pnpm)
 *     some-pkg>@cipherstash/eql   pnpm's scoped override
 *     a/b/@cipherstash/eql        a resolutions path — and, with yarn's `**`
 *                                 glob in front of it, a resolutions glob
 *
 * So: the name, at the end of the key, preceded by nothing or by a `/` or `>`
 * boundary, optionally followed by an `@<range>`. The boundary is what keeps
 * `@cipherstash/eql-extras` from matching — a prefix match here would make the
 * linter cry wolf, and the fix for a linter that cries wolf is always to
 * weaken it.
 *
 * The range is `.*` and not `[^@]*`. pnpm's own keys never need a second `@` —
 * its ranges are semver and its `parent>child` selector puts the second name
 * after a `>` — but a yarn `resolutions` descriptor may alias in the KEY
 * (`"<name>@npm:<other-name>@<range>"`), and both names may be scoped. The
 * widening cannot cry wolf, because the boundary that separates
 * `@cipherstash/eql` from `@cipherstash/eql-extras` is the `@` that has to
 * follow the name, not what comes after it.
 */
const NPM_KEY = new RegExp(`(^|[>/])${escapeForRegExp(NPM_DEPENDENCY)}(@.*)?$`)

/**
 * Whether an entry VALUE aliases the npm package — `"eql-legacy":
 * "npm:@cipherstash/eql@3.0.4"`.
 *
 * The package name is on the RIGHT-hand side here, so a scan that looks only at
 * keys never sees it: the manifest declares no dependency called
 * `@cipherstash/eql` and installs one anyway.
 */
const NPM_ALIAS = new RegExp(
  `^(?:npm|workspace|jsr):${escapeForRegExp(NPM_DEPENDENCY)}(?:@|$)`,
)

/**
 * Classify an npm specifier. Only `workspace:` is in-tree — see the header.
 *
 * `catalog:` is called out separately from a plain version because the fix is
 * different: the pin it defers to lives in `pnpm-workspace.yaml`, not in the
 * manifest the reader is looking at.
 */
function classifyNpmSpec(spec) {
  if (spec.startsWith('workspace:')) return { inTree: true, form: 'workspace' }
  if (spec.startsWith('npm:')) return { inTree: false, form: 'alias' }
  if (spec.startsWith('catalog:')) return { inTree: false, form: 'catalog' }
  return { inTree: false, form: 'version' }
}

/**
 * Walk one dependency/override/catalog table, recursively, collecting every
 * entry that names the npm package by either side.
 *
 * Recursion is for npm's nested overrides, which are a TREE and not a flat map:
 *
 *     { "overrides": { "some-pkg": { "@cipherstash/eql": "3.0.4" } } }
 *
 * Reading only the top level of `overrides` finds nothing there and reports the
 * tree clean, while the install resolves 3.0.4 from the registry.
 *
 * YAML scalars are coerced: `'@cipherstash/eql': 3.0` parses as the NUMBER 3
 * under YAML 1.1, and dropping non-strings would drop exactly that pin.
 */
function collectNpmEntries(file, table, entries, found) {
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) return
  for (const [key, value] of Object.entries(entries)) {
    const named = NPM_KEY.test(key)
    const scalar =
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
        ? String(value)
        : null

    if (scalar !== null) {
      if (named || NPM_ALIAS.test(scalar)) {
        found.push({
          file,
          // Always the package, never the key it was found under: both
          // hand-maintained lists are keyed `<file> :: <dependency>`, so an
          // alias filed under its alias name could never be exempted.
          dependency: NPM_DEPENDENCY,
          table,
          key,
          spec: scalar,
          ...classifyNpmSpec(scalar),
        })
      }
      continue
    }
    if (!value || typeof value !== 'object') continue
    // npm's nested form: `.` pins the package the key names, and the sibling
    // keys are overrides scoped beneath it.
    if (named && typeof value['.'] === 'string') {
      found.push({
        file,
        dependency: NPM_DEPENDENCY,
        table,
        key,
        spec: value['.'],
        ...classifyNpmSpec(value['.']),
      })
    }
    collectNpmEntries(file, `${table}.${key}`, value, found)
  }
}

/**
 * Every declaration of `NPM_DEPENDENCY` in one `package.json`.
 *
 * `resolutions` and the two `overrides` spellings are read alongside the four
 * dependency tables. An override is the quietest way to reintroduce the skew:
 * it moves what actually gets installed while every `workspace:` specifier
 * still reads correct.
 *
 * A manifest that does not parse contributes nothing rather than throwing —
 * `package.json` syntax is checked by every other tool in the repo, and a
 * linter that dies on someone else's broken file reports its own crash instead
 * of the thing it was asked about. The manifests that matter are floored by
 * `EXPECTED_DECLARERS`, so one of them going unreadable is exit 2 anyway.
 */
export function npmDeclarations(file, source) {
  let manifest
  try {
    manifest = JSON.parse(source)
  } catch {
    return []
  }
  if (!manifest || typeof manifest !== 'object') return []
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
    collectNpmEntries(file, table, entries, found)
  }
  return found
}

/**
 * `pnpm-workspace.yaml` as an object, or `null` if it would not read.
 *
 * `null` is a first-class answer here rather than an empty result, because
 * "parsed, and declares nothing" is the normal state of this file and must not
 * be spelled the same way as "did not parse". `EXPECTED_SOURCES` turns the
 * difference into exit 2.
 *
 * A YAML library is used, unlike `scripts/release-gate.mjs`, which hand-parses
 * the same file with node builtins and says why in its header: that script runs
 * in the publishing gate on every push to main, where an import obliges a cold
 * full-workspace install. This one runs as an ordinary lint job that has
 * already installed, and it has to read `overrides` keys and nested `catalogs`
 * maps rather than one flat sequence of scalars.
 */
export function parseWorkspace(source) {
  let config
  try {
    config = yaml.load(source)
  } catch {
    return null
  }
  return config && typeof config === 'object' && !Array.isArray(config)
    ? config
    : null
}

/**
 * Every declaration of `NPM_DEPENDENCY` in a parsed `pnpm-workspace.yaml`.
 *
 * `overrides` is the one that matters — pnpm 10 reads it from here, and the
 * file's own comment says a top-level npm-format `overrides` block in
 * `package.json` is silently ignored, which makes this the ONLY place a
 * workspace-wide pin can be written and take effect.
 *
 * `catalog` / `catalogs` are read for the same reason one level along: every
 * manifest keeps saying `catalog:repo` while the version behind it moves.
 */
function workspaceConfigDeclarations(file, config) {
  const found = []
  collectNpmEntries(file, 'overrides', config.overrides, found)
  collectNpmEntries(file, 'catalog', config.catalog, found)
  const catalogs = config.catalogs
  if (catalogs && typeof catalogs === 'object' && !Array.isArray(catalogs)) {
    for (const [name, entries] of Object.entries(catalogs)) {
      collectNpmEntries(file, `catalogs.${name}`, entries, found)
    }
  }
  return found
}

/** `workspaceConfigDeclarations`, from source text. Empty if it would not parse. */
export function workspaceDeclarations(file, source) {
  const config = parseWorkspace(source)
  return config ? workspaceConfigDeclarations(file, config) : []
}

/**
 * Every declaration of either dependency under `root`, plus the files the scan
 * successfully read AND understood.
 *
 * The second half is what `EXPECTED_SOURCES` is measured against. A
 * `pnpm-workspace.yaml` that does not parse is deliberately left out of it: it
 * contributes no declarations, which is indistinguishable from a file with no
 * EQL entry in it, and one of those two is a linter that stopped working.
 */
export function scanTree(root) {
  const declarations = []
  const sources = []
  for (const rel of manifestFiles(root)) {
    const source = readFileSync(join(root, rel), 'utf8')
    if (isCargoSource(rel)) {
      declarations.push(...cargoDeclarations(rel, source))
    } else if (basename(rel) === WORKSPACE_FILE) {
      const config = parseWorkspace(source)
      if (!config) continue
      declarations.push(...workspaceConfigDeclarations(rel, config))
    } else {
      declarations.push(...npmDeclarations(rel, source))
    }
    sources.push(rel)
  }
  return { declarations, sources }
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
  sources = EXPECTED_SOURCES,
} = {}) {
  const { declarations, sources: read } = scanTree(root)
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
    // against every declaration found. The difference is the case that already
    // happened: `packages/protect-ffi/integration-tests` was exempt because it
    // installed with `npm ci` and could not take a `workspace:` specifier, and
    // absorbing it into the workspace was a scheduled follow-up. When that
    // landed the manifest still declared `@cipherstash/eql` — so an
    // existence-based check would have kept passing and left the exemption
    // behind, permanently permitting a pin nothing needed any more. This
    // spelling failed that PR until the entry was deleted.
    staleExemptions: [...exemptions.keys()].filter(
      (id) => !registryPinned.includes(id),
    ),
    unreasonedExemptions: [...exemptions]
      .filter(([, reason]) => !String(reason ?? '').trim())
      .map(([id]) => id),
    missingExpected: expected.filter((id) => !ids.includes(id)),
    // The same idea one level down: not "an expected declaration is missing"
    // but "a file this scan depends on was never successfully read". A source
    // that declares nothing today cannot be floored any other way.
    missingSources: sources.filter((rel) => !read.includes(rel)),
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
 * Ordering is deliberate: every exit-2 branch is checked before offenders.
 * A scan that lost its subject cannot be trusted to have found every offender
 * either, and reporting "3 registry pins" from a broken scan sends the reader
 * to fix the wrong thing.
 */
export function report(result) {
  const sawIds = result.ids.length
    ? result.ids.map((id) => `  ${id}`).join('\n')
    : '  (nothing — the scan matched no manifest)'

  if (result.missingSources.length > 0) {
    return {
      code: 2,
      err:
        'This linter could not read a file it resolves dependencies from:\n\n' +
        result.missingSources.map((rel) => `  ${rel}`).join('\n') +
        '\n\nEither the file is gone, or it did not parse. Both leave the scan\n' +
        'with nothing to say about it — and "no EQL entry in there" is also\n' +
        'what a clean tree looks like, so this cannot be reported as a pass.\n' +
        `pnpm reads \`overrides\` and \`catalogs\` from ${WORKSPACE_FILE}, which\n` +
        'is the one place a workspace-wide pin can be written while every\n' +
        '`workspace:` specifier in the tree still reads correct.\n',
    }
  }

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
            // The KEY, not the dependency name: for an alias or a selector they
            // differ, and the key is the string the reader has to go and find.
            `  ${o.file}${o.table ? ` [${o.table}]` : ''}\n      ${o.key ?? o.dependency} = ${o.spec}`,
        )
        .join('\n') +
      `\n\n\`${CARGO_DEPENDENCY}\` (the Rust that EMITS EQL payloads) and\n` +
      `\`${NPM_DEPENDENCY}\` (the SQL bundle that STORES and queries them) are\n` +
      'released at one lockstep version, and both now live in this repo. A\n' +
      'registry pin lets the installed SQL and the emitting Rust drift apart\n' +
      'silently — it compiles, it passes CI, and it fails in a database.\n\n' +
      'Resolve it in-tree instead:\n\n' +
      `    ${CARGO_DEPENDENCY} = { path = "../../../eql/crates/eql-bindings" }\n` +
      `    "${NPM_DEPENDENCY}": "workspace:*"\n\n` +
      '`workspace:*` and not `workspace:^`: both resolve in-tree and both\n' +
      'satisfy this linter, but pnpm packs them differently into a published\n' +
      "tarball — `*` becomes the dependency's EXACT version, `^` becomes a\n" +
      'caret RANGE. For a RUNTIME dependency on a package this repo does not\n' +
      'yet publish, that range is the skew back again: a customer resolves\n' +
      'whatever later version the other repository publishes, while the Rust\n' +
      'that emits payloads stays pinned here. `workspace:^` is fine for a\n' +
      'devDependency, which no consumer installs.\n\n' +
      `If the offender is in ${WORKSPACE_FILE} or in an \`overrides\` block, the\n` +
      'fix is to delete it: an override exists to move what installs, and there\n' +
      'is nothing in-tree for it to move to that the workspace protocol does\n' +
      'not already say.\n\n' +
      'If the manifest genuinely cannot take an in-tree specifier, add it to\n' +
      'EXEMPT_DECLARATIONS in this script WITH the reason. That list is empty\n' +
      'today — the last entry was retired when its directory joined the pnpm\n' +
      'workspace — so an addition is a new standing permission, not a\n' +
      'precedent being followed.\n',
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

  // An argv override is a fixture run: the three hand-maintained lists describe
  // THIS repo, so applying them to another tree would fail on every invocation
  // for a reason that has nothing to do with the tree being scanned.
  const scanningRepo = root === REPO_ROOT
  const { code, out, err } = report(
    lint({
      root,
      expected: scanningRepo ? EXPECTED_DECLARERS : [],
      exemptions: scanningRepo ? EXEMPT_DECLARATIONS : new Map(),
      sources: scanningRepo ? EXPECTED_SOURCES : [],
    }),
  )
  if (out) console.log(out)
  if (err) console.error(err)
  process.exit(code)
}

// Importable without running: the self-tests exercise the functions above, and
// the tree walk must not fire on import.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()

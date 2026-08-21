/**
 * Guards the two supply-chain-shaped properties of the protect-ffi build
 * action and the Rust workflow that shares its toolchain step.
 *
 * 1. A GitHub Actions cache restore is an untrusted write into the checkout.
 *    `packages/protect-ffi/dist/wasm` holds BOTH wasm-pack output and three
 *    declaration files that are tracked in git (see the package `.gitignore`
 *    for why they are tracked). Caching that directory whole, on a key hashed
 *    from the Rust inputs only, means a restore replaces the checked-out
 *    declarations with whatever a previous run happened to archive — silently,
 *    and with no diff to show for it. Either the key has to move when those
 *    files move, or they must not be in the archive at all.
 *
 * 2. `jdx/mise-action` is a third-party action this repo did not depend on
 *    before the absorption, and it runs in jobs that hold live CipherStash
 *    credentials. A mutable major tag means the code that runs there can change
 *    without a commit here. SHA-pin it, per the convention the deposited
 *    upstream workflows already use.
 *
 * 3. The converse of (1), and the one that bites in the other direction: a
 *    cache key has to hash every INPUT of the build it skips, including inputs
 *    that are neither tracked nor under the cached path. `build:wasm` is
 *    wasm-pack plus `tsc -p tsconfig.wasm-errors.json`, and that tsc half
 *    compiles `src/errors.ts` into `dist/wasm/errors.js` — which
 *    `scripts/inline-wasm.mjs` re-exports from the generated `./wasm` and
 *    `./wasm-inline` entries, so it is live runtime code. The key hashed the
 *    emitted `dist/wasm/*.d.ts` but not the `src/` file they are emitted from,
 *    and a body-only edit to `isProtectErrorCode` leaves the declaration
 *    byte-identical while changing the JavaScript. Verified: the key still hit,
 *    the build step was skipped, and `errors.js` — gitignored, so nothing
 *    tracked forced a miss either — was restored stale. The WASM integration
 *    suites would then test an implementation the release build does not ship.
 *
 * The scan-found-something assertions are not padding. All three properties are
 * expressed as "nothing in this set violates X", and an empty set satisfies
 * that for free — the same failure mode `lintWiring.test.ts` and
 * `scripts/lint-no-hardcoded-runners.mjs` exist to rule out.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { readJsonc } from './lib/read-jsonc.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

const ACTION = '.github/actions/build-ffi-binding/action.yml'
const RUST_WORKFLOW = '.github/workflows/tests-rust.yml'
const FFI_PKG = 'packages/protect-ffi'

const read = (rel) => readFileSync(resolve(REPO_ROOT, rel), 'utf8')

/**
 * Files git tracks under a workspace-relative path or pathspec.
 *
 * Derived at test time rather than hardcoded: a fourth tracked declaration
 * file added to `dist/wasm` must fail this suite, not slip past a stale list.
 */
function trackedUnder(pathspec) {
  const stdout = execFileSync('git', ['ls-files', '-z', '--', pathspec], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
  return stdout.split('\0').filter(Boolean)
}

/**
 * Approximates the `@actions/glob` semantics that both `actions/cache`'s
 * `path:` and `hashFiles()` are built on: `*` stops at a path separator, `**`
 * does not, and a pattern that names a directory implicitly covers everything
 * beneath it (`implicitDescendants`, on by default in both).
 */
function globToRegExp(pattern) {
  let source = '^'
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i]
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        source += '.*'
        i += 1
        if (pattern[i + 1] === '/') i += 1
      } else {
        source += '[^/]*'
      }
    } else if (ch === '?') {
      source += '[^/]'
    } else {
      source += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    }
  }
  // The implicit-descendants tail. Harmless on a pattern that names a file.
  return new RegExp(`${source}(?:/.*)?$`)
}

const globMatches = (pattern, path) => globToRegExp(pattern).test(path)

/** Splits a cache `path:` block into include and exclude (`!`) patterns. */
function splitCachePaths(value) {
  const lines = String(value ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
  return {
    includes: lines.filter((line) => !line.startsWith('!')),
    excludes: lines
      .filter((line) => line.startsWith('!'))
      .map((line) => line.slice(1).trim()),
  }
}

const isGlob = (pattern) => /[*?[]/.test(pattern)

/**
 * Every git-tracked file that would end up inside the step's cache archive.
 *
 * The `!` handling here is deliberately narrow, because `actions/cache`'s is.
 * It resolves `path:` through `@actions/glob` with `implicitDescendants: false`
 * and feeds the result to `tar --files-from`, which recurses on its own. So an
 * include naming a DIRECTORY yields exactly that one path, tar walks the whole
 * subtree, and a `!` pattern aimed at files underneath never fires — those
 * files were never glob results to subtract from. Excludes only bite when the
 * include enumerates files.
 */
function trackedFilesInArchive(step) {
  const { includes, excludes } = splitCachePaths(step?.with?.path)
  const archived = new Set()
  for (const include of includes) {
    const dir = include.replace(/\/$/, '')
    for (const file of trackedUnder(include)) {
      if (!isGlob(include) && file.startsWith(`${dir}/`)) {
        archived.add(file) // swept up by tar's recursion; excludes cannot help
      } else if (!excludes.some((pattern) => globMatches(pattern, file))) {
        archived.add(file)
      }
    }
  }
  return [...archived]
}

/** The glob arguments of every `hashFiles(...)` call in a cache key. */
function hashFilesPatterns(key) {
  const patterns = []
  for (const call of String(key ?? '').matchAll(/hashFiles\(([^)]*)\)/g)) {
    for (const arg of call[1].matchAll(/'([^']*)'/g)) patterns.push(arg[1])
  }
  return patterns
}

/**
 * The tsconfig the `build:wasm` script compiles, parsed out of the script
 * rather than named here — point `build:wasm` at a different project and this
 * guard follows it instead of checking a file CI no longer builds.
 */
function wasmTsconfigRel() {
  const scripts = JSON.parse(read(`${FFI_PKG}/package.json`))?.scripts ?? {}
  const match = /tsc\s+-p\s+(\S+)/.exec(scripts['build:wasm'] ?? '')
  return match ? `${FFI_PKG}/${match[1]}` : null
}

const TS_SOURCE = /\.(m|c)?tsx?$/

/**
 * The source files a tsconfig names directly, through `files` and `include`
 * minus `exclude`. Paths come back repo-relative, as the key's globs are.
 */
function tsconfigNamedInputs(configRel) {
  const dir = dirname(configRel)
  const config = readJsonc(resolve(REPO_ROOT, configRel))
  const named = new Set((config.files ?? []).map((entry) => `${dir}/${entry}`))

  const excludes = (config.exclude ?? []).map((pattern) => `${dir}/${pattern}`)
  for (const pattern of config.include ?? []) {
    for (const file of trackedUnder(dir)) {
      if (!TS_SOURCE.test(file)) continue
      if (!globMatches(`${dir}/${pattern}`, file)) continue
      if (excludes.some((exclude) => globMatches(exclude, file))) continue
      named.add(file)
    }
  }
  return [...named]
}

/**
 * Relative module specifiers a source pulls in, in every form that makes
 * another file part of the compilation.
 *
 * Deliberately over-matching — it reads comments too. A false positive fails
 * loudly and is answered by widening the key; a false negative is a build input
 * silently outside it, which is the whole defect this guards.
 */
function relativeSpecifiers(source) {
  const forms = [
    /(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]/g,
    /import\s*['"]([^'"]+)['"]/g,
    /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /<reference\s+path\s*=\s*['"]([^'"]+)['"]/g,
  ]
  const specifiers = new Set()
  for (const form of forms) {
    for (const match of source.matchAll(form)) {
      if (match[1].startsWith('.')) specifiers.add(match[1])
    }
  }
  return [...specifiers]
}

const RESOLVE_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.d.ts', '.json']

/** Resolve a relative specifier to a repo-relative file, or null. */
function resolveSpecifier(fromRel, specifier) {
  const base = join(dirname(fromRel), specifier)
  const candidates = [
    base,
    // The `node16` form: `./x.js` names `x.ts` on disk.
    base.replace(/\.js$/, '.ts').replace(/\.mjs$/, '.mts'),
    ...RESOLVE_EXTENSIONS.map((ext) => `${base}${ext}`),
    ...RESOLVE_EXTENSIONS.map((ext) => `${base}/index${ext}`),
  ]
  return (
    candidates.find((candidate) => {
      const full = resolve(REPO_ROOT, candidate)
      return existsSync(full) && statSync(full).isFile()
    }) ?? null
  )
}

/** Every repo file `tsc -p <config>` reads: its named inputs, transitively. */
function tsconfigSourceGraph(configRel) {
  const files = new Set()
  const unresolved = []
  const queue = tsconfigNamedInputs(configRel)
  while (queue.length > 0) {
    const file = queue.shift()
    if (files.has(file)) continue
    files.add(file)
    const full = resolve(REPO_ROOT, file)
    if (!existsSync(full)) continue
    for (const specifier of relativeSpecifiers(readFileSync(full, 'utf8'))) {
      const target = resolveSpecifier(file, specifier)
      if (target) queue.push(target)
      else unresolved.push(`${file} -> ${specifier}`)
    }
  }
  return { files: [...files], unresolved }
}

const CACHE_ACTION = /^actions\/cache(\/(restore|save))?@/

const actionDoc = yaml.load(read(ACTION))
const actionSteps = actionDoc?.runs?.steps ?? []
const cacheSteps = actionSteps.filter(
  (step) => typeof step?.uses === 'string' && CACHE_ACTION.test(step.uses),
)
const label = (step, idx) => step?.name ?? step?.uses ?? `step #${idx + 1}`

describe('build-ffi-binding — cache restores cannot clobber tracked files', () => {
  it('found the cache steps it means to check', () => {
    // Two today: index.node and dist/wasm. If this drops to zero the property
    // below becomes a tautology over an empty list.
    expect(cacheSteps.length).toBeGreaterThanOrEqual(2)
    for (const [idx, step] of cacheSteps.entries()) {
      expect(step?.with?.path, `${label(step, idx)} has no path`).toBeTruthy()
      expect(step?.with?.key, `${label(step, idx)} has no key`).toBeTruthy()
    }
  })

  it('found the tracked declaration files this guard exists for', () => {
    // If `git ls-files` returns nothing here — wrong cwd, renamed directory,
    // the .gitignore negations lost — every assertion below passes vacuously.
    const tracked = trackedUnder('packages/protect-ffi/dist/wasm')
    expect(tracked.length).toBeGreaterThanOrEqual(3)
    expect(tracked.every((file) => file.endsWith('.d.ts'))).toBe(true)
  })

  for (const [idx, step] of cacheSteps.entries()) {
    const name = label(step, idx)
    it(`"${name}" archives no tracked file its key does not cover`, () => {
      const uncovered = trackedFilesInArchive(step).filter(
        (file) =>
          !hashFilesPatterns(step?.with?.key).some((pattern) =>
            globMatches(pattern, file),
          ),
      )
      // Either shape is sound: exclude the tracked files from the archive so a
      // restore cannot reach them, or hash them into the key so any restore
      // that lands necessarily carries identical content. Both are fine; a
      // tracked file that is in the archive AND absent from the key is not.
      expect(uncovered).toEqual([])
    })
  }
})

/**
 * The complement of the suite above: that one asks whether a restore can
 * overwrite a tracked file, this one whether a restore should have happened at
 * all. A key that omits a build input hits when it should miss, and the step it
 * guards is skipped over stale output.
 *
 * Only the WASM step is checked, because only it has a second, non-Rust
 * compiler in its build. `build:native` is `tsc && cargo build --release`, but
 * its cached path is `index.node` and that comes from `neon dist < cargo.log`;
 * the `tsc` half writes `lib/`, which is not in the archive and which the
 * action rebuilds unconditionally a step later. No crate has a `build.rs` or an
 * `include_str!`, so nothing under `src/` reaches the binary — the Rust inputs
 * plus `package.json` (the neon config) and `mise.toml` (the toolchain) are the
 * whole input set, and the native key already names all three.
 */
const WASM_STEP = cacheSteps.find((step) =>
  String(step?.with?.path ?? '').includes(`${FFI_PKG}/dist/wasm`),
)
const WASM_TSCONFIG = wasmTsconfigRel()
const WASM_GRAPH = WASM_TSCONFIG
  ? tsconfigSourceGraph(WASM_TSCONFIG)
  : { files: [], unresolved: [] }

describe('build-ffi-binding — the WASM key covers the build it skips', () => {
  it('found the tsc half of build:wasm, and the sources it compiles', () => {
    expect(
      WASM_STEP,
      `no cache step archives ${FFI_PKG}/dist/wasm`,
    ).toBeTruthy()
    expect(
      WASM_TSCONFIG,
      `\`build:wasm\` in ${FFI_PKG}/package.json no longer runs \`tsc -p <config>\`. If the tsc half moved, point this guard at wherever it went; if it is gone, the check below has nothing to verify and would pass whatever the key said.`,
    ).toBeTruthy()

    // Resolution failures are reported, not ignored: an import this resolver
    // cannot follow is a build input the coverage check never sees.
    expect(WASM_GRAPH.unresolved).toEqual([])
    for (const file of WASM_GRAPH.files) {
      expect(existsSync(resolve(REPO_ROOT, file)), `${file} is missing`).toBe(
        true,
      )
    }
    expect(
      WASM_GRAPH.files.length,
      `${WASM_TSCONFIG} resolved to no source files at all, so the coverage check below is a loop over nothing. Its \`files\`/\`include\` was probably renamed.`,
    ).toBeGreaterThan(0)
  })

  it(`"${label(WASM_STEP, 0)}" hashes every source its tsc step compiles`, () => {
    const patterns = hashFilesPatterns(WASM_STEP?.with?.key)
    const uncovered = WASM_GRAPH.files.filter(
      (file) => !patterns.some((pattern) => globMatches(pattern, file)),
    )
    // Hashing the EMITTED declarations is not a substitute for hashing the
    // source: a body-only edit changes `dist/wasm/errors.js` while leaving
    // `errors.d.ts` byte-identical, so the key hits and restores the old JS.
    expect(
      uncovered,
      `These are compiled into the cached directory but absent from the cache key, so an edit to one leaves the key unchanged, the restore hits, and the build step is skipped over stale output. Add each to the \`hashFiles(...)\` list on the "${label(WASM_STEP, 0)}" step.`,
    ).toEqual([])
  })
})

/**
 * The third question a cache key has to answer, and the one the two suites
 * above cannot see: does it cover every crate the build COMPILES?
 *
 * Both of those reason about files inside `packages/protect-ffi`. Cargo does
 * not. `crates/protect-ffi/Cargo.toml` carries
 *
 *     eql-bindings = { path = "../../../eql/crates/eql-bindings" }
 *
 * — an in-tree path dependency in a DIFFERENT package, and a genuine compile
 * input to both `index.node` and the wasm32 build. A path dep carries no
 * registry checksum, so a src-only edit under that crate touches nothing else:
 * not `packages/protect-ffi/crates/**`, not either `Cargo.toml`, and not
 * `Cargo.lock` (which records the path dep by name and version, and only moves
 * when the version does). Every glob in both keys therefore hashes identically,
 * the restore hits, `Build index.node (cargo)` is SKIPPED, and every
 * credentialed job in CI proceeds on a binding compiled from the old crate.
 *
 * That is not hypothetical: across the three commits that shipped this
 * dependency the crate's version moved 3.0.4 -> 4.0.0 -> 3.0.5 and neither
 * cache key changed by a byte.
 *
 * DISCOVERED, not listed. The dependency set is read out of the manifest and
 * followed transitively, so the second path dep — or one that moves — is held
 * to the same bar the day it lands. A hand-written list would have been right
 * on the commit that added it and silently wrong afterwards, which is the same
 * failure shape one level down.
 *
 * `[dev-dependencies]` are deliberately NOT followed. `build:native` is
 * `cargo build --release` and `build:wasm` is wasm-pack; neither compiles a
 * dependency's dev-deps, so requiring them in the key would bust the cache on
 * edits that cannot reach the artifact. (`eql-bindings` has one — `eql-domains`,
 * its parity oracle — so this is a live distinction, not a hypothetical.)
 */

const CARGO_ROOT_CRATE = `${FFI_PKG}/crates/protect-ffi/Cargo.toml`

/**
 * The path dependencies declared by one Cargo manifest, as `{ name, path }`
 * with `path` exactly as written.
 *
 * Deliberately a narrow reader over the text rather than a TOML parse: there is
 * no TOML parser in this repo's dependency tree, and `cargo metadata` would put
 * a Rust toolchain on `pnpm test:scripts` — which `packages/protect-ffi`'s
 * `lintWiring.test.ts` exists to keep off the JS entry points.
 *
 * It reads both spellings cargo accepts: the inline table
 * (`foo = { path = "..." }`) and the section form (`[dependencies.foo]` with a
 * `path =` line beneath it). Sections are matched by their TAIL, so
 * `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` is read the same
 * as `[dependencies]` — the wasm and native halves of this crate declare
 * different dependency sets and both compile.
 *
 * Exported shape is a pure function of the text so `the manifest reader is
 * sound` below can exercise it on a literal, rather than on whatever the real
 * manifest happens to say today.
 */
function parsePathDependencies(text) {
  const found = []
  let section = null
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim()
    if (line === '') continue

    const header = /^\[([^\]]+)\]$/.exec(line)
    if (header) {
      section = header[1]
      continue
    }
    if (section === null) continue

    // `[dependencies]`, `[build-dependencies]`, `[target.'…'.dependencies]`.
    // `dev-dependencies` is excluded — see the note above the describe.
    const isDepTable = /(^|\.)(build-)?dependencies$/.test(section)
    // `[dependencies.foo]` / `[target.'…'.dependencies.foo]`
    const namedDep = /(^|\.)(build-)?dependencies\.([A-Za-z0-9_-]+)$/.exec(
      section,
    )

    if (isDepTable) {
      const inline = /^([A-Za-z0-9_-]+)\s*=\s*\{(.*)\}$/.exec(line)
      if (!inline) continue
      const path = /\bpath\s*=\s*"([^"]+)"/.exec(inline[2])
      if (path) found.push({ name: inline[1], path: path[1] })
    } else if (namedDep) {
      const path = /^path\s*=\s*"([^"]+)"$/.exec(line)
      if (path) found.push({ name: namedDep[3], path: path[1] })
    }
  }
  return found
}

/**
 * Every crate `cargo build` compiles into the artifact, as repo-relative
 * directories, starting from the cdylib crate and following path deps
 * transitively. The starting crate itself is excluded: it lives under
 * `packages/protect-ffi/crates/**`, which both keys already hash.
 */
function compiledPathDependencies(rootManifestRel) {
  const crates = new Map()
  const unresolved = []
  const queue = [rootManifestRel]
  const seen = new Set([rootManifestRel])

  while (queue.length > 0) {
    const manifestRel = queue.shift()
    const full = resolve(REPO_ROOT, manifestRel)
    if (!existsSync(full)) {
      unresolved.push(manifestRel)
      continue
    }
    for (const dep of parsePathDependencies(readFileSync(full, 'utf8'))) {
      const dirRel = relative(
        REPO_ROOT,
        resolve(dirname(full), dep.path),
      ).replaceAll('\\', '/')
      const depManifest = `${dirRel}/Cargo.toml`
      if (!crates.has(dirRel)) crates.set(dirRel, dep.name)
      if (seen.has(depManifest)) continue
      seen.add(depManifest)
      queue.push(depManifest)
    }
  }
  return {
    crates: [...crates.entries()].map(([dir, name]) => ({ dir, name })),
    unresolved,
  }
}

/**
 * The nearest ancestor manifest declaring `[workspace]` — the file cargo reads
 * for the crate's workspace context, and the one a `foo.workspace = true` key
 * inherits from. `eql-bindings` inherits nothing today, and three of its four
 * siblings inherit `[lints]`, so the file is one `workspace = true` away from
 * being a compile input for this crate too.
 */
function workspaceRootOf(dirRel) {
  let current = dirRel
  while (current !== '' && current !== '.') {
    const candidate = `${current}/Cargo.toml`
    const full = resolve(REPO_ROOT, candidate)
    if (
      existsSync(full) &&
      /^\s*\[workspace\]/m.test(readFileSync(full, 'utf8'))
    ) {
      return candidate
    }
    current = dirname(current)
  }
  return null
}

const COMPILED = compiledPathDependencies(CARGO_ROOT_CRATE)

/** Which of this action's cache steps must cover a Rust compile input. */
const RUST_CACHE_STEPS = cacheSteps.map((step, idx) => ({
  step,
  name: label(step, idx),
}))

describe('build-ffi-binding — the keys cover every crate the build compiles', () => {
  it('the manifest reader is sound', () => {
    // The discovery below is only as good as this. An over-accepting reader
    // that returned nothing would make every check that follows vacuous, and a
    // reader that missed the `[target.'cfg(…)'.dependencies]` form would miss
    // exactly the half of this crate that only the wasm build compiles.
    const deps = parsePathDependencies(`
      [package]
      name = "example"
      path = "not-a-dependency"

      [dependencies]
      registry-only = "1.0"
      inline = { path = "../inline", version = "1" }

      [dev-dependencies]
      oracle = { path = "../oracle" }

      [build-dependencies]
      codegen = { path = "../codegen" }

      [target.'cfg(not(target_arch = "wasm32"))'.dependencies]
      native = { path = "../native" }

      [dependencies.sectioned]
      path = "../sectioned"
    `)
    expect(deps).toEqual([
      { name: 'inline', path: '../inline' },
      { name: 'codegen', path: '../codegen' },
      { name: 'native', path: '../native' },
      { name: 'sectioned', path: '../sectioned' },
    ])
  })

  it('found the path dependencies it means to check', () => {
    expect(
      COMPILED.unresolved,
      `These manifests are named by a \`path = \` dependency and do not exist. A path dep cargo cannot resolve does not build at all, so this is a broken manifest rather than a broken guard.`,
    ).toEqual([])

    expect(
      COMPILED.crates.map((crate) => crate.dir),
      `\`${CARGO_ROOT_CRATE}\` declares no path dependencies, so every assertion below iterates nothing and passes having checked nothing. If the in-tree crate moved to a registry pin, this guard is obsolete — but read \`scripts/lint-no-eql-registry-pins.mjs\` first, which exists to stop exactly that.`,
    ).not.toEqual([])

    for (const crate of COMPILED.crates) {
      expect(
        trackedUnder(crate.dir).length,
        `${crate.dir} (\`${crate.name}\`) has no git-tracked files, so the coverage check below has nothing to compare against.`,
      ).toBeGreaterThan(0)
    }
  })

  for (const { step, name } of RUST_CACHE_STEPS) {
    it(`"${name}" hashes every crate the build compiles`, () => {
      const patterns = hashFilesPatterns(step?.with?.key)
      const uncovered = COMPILED.crates.flatMap((crate) =>
        trackedUnder(crate.dir).filter(
          (file) => !patterns.some((pattern) => globMatches(pattern, file)),
        ),
      )
      expect(
        uncovered,
        `These files are compiled into the artifact this step caches and are absent from its key, so an edit to one leaves the key unchanged, the restore hits, and the build step is skipped over a stale binary. A path dependency carries no registry checksum and does not move \`Cargo.lock\` on a source-only edit, so nothing else in the key covers it either.\nAdd a glob for each crate to the \`hashFiles(...)\` list on the "${name}" step.`,
      ).toEqual([])
    })

    it(`"${name}" hashes the workspace root of every out-of-tree crate`, () => {
      const patterns = hashFilesPatterns(step?.with?.key)
      const roots = [
        ...new Set(
          COMPILED.crates
            .map((crate) => workspaceRootOf(crate.dir))
            .filter(Boolean),
        ),
      ]
      expect(
        roots,
        'No path dependency resolved to a crate inside a Cargo workspace, so this check compares nothing.',
      ).not.toEqual([])

      const uncovered = roots.filter(
        (root) => !patterns.some((pattern) => globMatches(pattern, root)),
      )
      expect(
        uncovered,
        `Cargo reads these workspace manifests to resolve the path dependencies above — a \`<key>.workspace = true\` in a dependency crate inherits from here, and \`[patch]\` is read from here too. They are build inputs on the same footing as the crate sources, and neither is covered by \`${FFI_PKG}\`'s own manifests.\nAdd each to the \`hashFiles(...)\` list on the "${name}" step.`,
      ).toEqual([])
    })
  }
})

describe('jdx/mise-action is pinned to an immutable commit', () => {
  const files = [ACTION, RUST_WORKFLOW]

  for (const file of files) {
    const refs = [...read(file).matchAll(/jdx\/mise-action@(\S+)/g)].map(
      (m) => m[1],
    )

    it(`${file} references mise-action at all`, () => {
      // The pin assertion is "every ref is a SHA"; zero refs satisfies it.
      expect(refs.length).toBeGreaterThanOrEqual(1)
    })

    it(`${file} pins mise-action by SHA, not by tag`, () => {
      for (const ref of refs) expect(ref).toMatch(/^[0-9a-f]{40}$/)
    })

    it(`${file} annotates each mise-action pin with its tag`, () => {
      // `@<sha> # <tag>` is the convention the deposited upstream workflows
      // use. The comment is what keeps the pin readable and lets Dependabot
      // rewrite both halves together.
      const lines = read(file)
        .split('\n')
        .filter((line) => line.includes('jdx/mise-action@'))
      expect(lines.length).toBe(refs.length)
      for (const line of lines) expect(line).toMatch(/#\s*v\d/)
    })
  }
})

describe('build-ffi-binding — composite action shape', () => {
  it('parses and declares steps', () => {
    expect(actionDoc?.runs?.using).toBe('composite')
    expect(actionSteps.length).toBeGreaterThan(0)
  })

  it('gives every `run:` step a `shell:`', () => {
    // A composite action has no default shell; omitting it fails the whole
    // workflow at load time with "Required property is missing: shell".
    const missing = actionSteps
      .map((step, idx) => (step?.run && !step?.shell ? label(step, idx) : null))
      .filter(Boolean)
    expect(missing).toEqual([])
  })
})

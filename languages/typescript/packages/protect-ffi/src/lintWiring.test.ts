/**
 * Guards the *call graph* of the checks, not the checks themselves.
 *
 * `cargo fmt --check` sat in package.json as `test:format:rust` for months with
 * no caller, and clippy never ran against `wasm32-unknown-unknown` because
 * `--all-targets` means target *kinds*, not platform targets. Neither failed —
 * they simply never ran, which reads exactly like passing (#145).
 *
 * So the property under test is reachability: a check that nothing invokes is
 * the failure, and it is invisible by construction. Every exemption below has
 * to name why.
 *
 * One test here is not static: `keeps cargo OUTPUT off the default test path
 * too` re-runs this suite in a child process with the compiled binding made
 * unresolvable. It sits with the wiring checks because it guards the same rule
 * as `keeps cargo off the default test path` — the entry-point split — and
 * because the half it covers cannot be read off the manifest: a test that
 * requires `index.node` makes cargo a prerequisite of root `pnpm test` without
 * a `cargo` token appearing anywhere in package.json.
 */
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'

// Vitest resolves cwd to the directory holding vitest.config.ts — this
// package, NOT the repository root, which is why every reference to a root
// workflow below climbs two levels out of it. `import.meta` is unavailable
// here: tsconfig emits CommonJS, and tsc rejects it (TS1470).
const packageRoot = process.cwd()
const read = (relative: string) =>
  readFileSync(join(packageRoot, relative), 'utf8')

const manifest = JSON.parse(read('package.json'))
const scripts: Record<string, string> = manifest.scripts
const miseToml = read('mise.toml')

/**
 * A workflow with its comment lines removed.
 *
 * Every workflow assertion below is a substring search, and a comment is prose.
 * tests-rust.yml's header explains that the Rust checks moved behind
 * `mise run lint:rust` — so the assertion that CI *runs* the aggregate was
 * satisfied by the sentence saying it should, and stayed green with the job
 * running `lint:rust:host` alone. `nativeLoading.test.ts` strips comments from
 * the emitted entry for the same reason: a comment describing a thing is
 * indistinguishable from the thing.
 */
const withoutComments = (yaml: string) => yaml.replace(/^[ \t]*#.*$/gm, '')
// The ROOT workflow that actually runs the Rust checks. GitHub only reads
// workflows from the repository root, so this must never point back inside this
// package — that was true of the deposited upstream copy this used to read,
// which made the CI assertion below vacuous from the day of the absorption.
const testWorkflow = withoutComments(
  read('../../.github/workflows/tests-rust.yml'),
)
// Every root workflow an exempted script may hang off, discovered by reading
// the DIRECTORY rather than by listing filenames. Same rule as above: root
// only — a script "run by CI" according to a file under
// packages/protect-ffi/.github/ is a script nothing runs.
//
// The scan is the point. A hardcoded list has to be maintained in step with a
// set of files nothing forces it to track: move a job to a new workflow and
// this reads as "the script runs nowhere", and the tempting repair is to widen
// the list until it includes the dead package-local path. A directory cannot
// drift out of date with itself.
const ROOT_WORKFLOW_DIR = '../../.github/workflows'
const rootWorkflowNames = readdirSync(
  join(packageRoot, ROOT_WORKFLOW_DIR),
).filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
const rootWorkflows = rootWorkflowNames
  .map((name) => withoutComments(read(`${ROOT_WORKFLOW_DIR}/${name}`)))
  .join('\n')

// The upstream repo's CI was deposited here by the subtree merge and was inert
// from that moment: GitHub reads workflows from the repository root alone. It
// was kept while the release pipeline was ported from it, and deleted once
// `_build-ffi-artifacts.yml` and `ffi-preflight.yml` had consumed the last of
// it.
const DEAD_GITHUB_DIR = '.github'

/**
 * Script names reachable from `root`, following `pnpm run` / `npm run`
 * references and the lifecycle hooks pnpm runs on its own.
 *
 * Both spellings are matched. The scripts moved to `pnpm run` when the package
 * was absorbed into the monorepo, and a stray `npm run` left behind would
 * otherwise drop a whole subtree from this analysis and read as "no orphans".
 *
 * `pre<name>` / `post<name>` are followed because pnpm invokes them around
 * every script it runs, and NOTHING names them — so a walk that only follows
 * `run` references cannot see them. Verified on the pinned pnpm 10.33.2, which
 * runs them with no `enable-pre-post-scripts` opt-in, and this manifest already
 * leans on the behaviour (`postcargo-build`, `postbuild:wasm`, `prepack`). A
 * `pretest: "cargo test"` is therefore an edit in keeping with the file, and it
 * would put cargo on every contributor's default `pnpm test` — the one thing
 * the entry-point split exists to prevent.
 */
function reachableFrom(root: string): Set<string> {
  const seen = new Set<string>()
  const queue = [root]
  while (queue.length > 0) {
    const name = queue.pop()
    if (name === undefined || seen.has(name)) continue
    seen.add(name)
    const body = scripts[name]
    if (body === undefined) continue
    queue.push(`pre${name}`, `post${name}`)
    for (const match of body.matchAll(/(?:pnpm|npm) run ([\w:-]+)/g)) {
      queue.push(match[1])
    }
  }
  return seen
}

/**
 * A mise task's `[tasks."<name>"]` block, isolated from the next one.
 *
 * Comments are stripped first. A block scan runs to the following `[tasks.`
 * header, so it swallows the prose sitting between two tasks — and the prose
 * above `[tasks."lint:rust"]` cites `cargo fmt --check` by name, which would
 * report cargo in `build:debug`, the block before it. Same trap
 * `nativeLoading.test.ts` documents for the emitted entry: a comment warning
 * about a thing is indistinguishable from the thing.
 */
function miseTask(name: string): string | undefined {
  const header = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(
    `^\\[tasks\\."${header}"\\]$(?:\\n(?!\\[tasks\\.)[^\\n]*)*`,
    'm',
  ).exec(miseToml.replace(/^[ \t]*#.*$/gm, ''))?.[0]
}

/**
 * Whether `mise run <task>` ends in cargo — through the task's own `run`, its
 * `depends` fan-out, or a hop back into package.json (`build:debug` is
 * `pnpm run debug`).
 *
 * `mise run` is the other way out of this manifest, and the check below cannot
 * see it by grepping script bodies for `cargo`: mise.toml's `lint:rust` arms
 * are all cargo, so a `test` ending `&& mise run lint:rust` is cargo on every
 * contributor's default `pnpm test` with no `cargo` token in package.json at
 * all.
 */
function taskReachesCargo(task: string, seen = new Set<string>()): boolean {
  if (seen.has(task)) return false
  seen.add(task)
  const block = miseTask(task)
  if (block === undefined) return false
  if (block.includes('cargo')) return true
  const depends = /^depends = \[(.*?)\]$/m.exec(block)?.[1] ?? ''
  return (
    [...depends.matchAll(/"([^"]+)"/g)].some(([, dep]) =>
      taskReachesCargo(dep, seen),
    ) ||
    [...block.matchAll(/(?:pnpm|npm) run ([\w:-]+)/g)].some(([, script]) =>
      [...reachableFrom(script)].some((name) =>
        scripts[name]?.includes('cargo'),
      ),
    )
  )
}

/**
 * The two entry points every check must hang off, and the split is the point.
 *
 * `test` is the default task Turborepo reaches through the root `pnpm test`,
 * so it must stay JavaScript-only: a cargo process on that path puts the Rust
 * toolchain on every contributor's machine and every PR job in a repo where
 * almost nothing else needs it.
 *
 * `test:cargo` is the Rust half, run by the path-filtered Rust job. Reachable
 * from neither is still an orphan — that is the property #145 was about, and
 * splitting the roots must not become a way to lose it.
 */
const ENTRY_POINTS = ['test', 'test:cargo']

function reachableFromAnyEntryPoint(): Set<string> {
  return new Set(ENTRY_POINTS.flatMap((root) => [...reachableFrom(root)]))
}

/**
 * Checks no entry point is expected to run, each with its reason. Anything
 * added here is a deliberate carve-out, which is the point of making it a list.
 *
 * A carve-out still has to run SOMEWHERE, and the test below enforces that by
 * requiring the script's name to appear in a root workflow. Without it this
 * list is a way to launder an orphan into an intention: `test:typecheck:wasm`
 * sat here from the absorption onward reading "run by the wasm job", and the
 * only jobs that ran it were the upstream copies under
 * packages/protect-ffi/.github/ — which GitHub, reading workflows from the
 * repository root alone, never executed.
 */
const ENTRY_POINT_EXEMPT: Record<string, string> = {
  // Runs against the generated wasm .d.ts, so it needs `pnpm run build:wasm`
  // first. The default test must still pass in a clone with no dist/, so this
  // one belongs to the wasm job in the root tests.yml.
  'test:typecheck:wasm': 'needs dist/wasm, run by the root wasm-e2e job',
}

/**
 * Set on the nested `vitest run` the artifact guard below spawns, so the guard
 * does not spawn itself forever.
 *
 * It is the ONE place in this file a test is allowed to disappear, and it is a
 * bounded one: the only process that ever carries this variable is one the
 * guard itself started, and the guard then asserts on that process's exit
 * status. The skip is reported by the assertion that caused it.
 */
const ARTIFACT_FREE_RUN = 'PROTECT_FFI_ARTIFACT_FREE_RUN'

/**
 * A `--require` preload that removes every cargo-built binding from the child's
 * world: unresolvable through `require`, and absent from `fs`.
 *
 * BOTH halves are needed and they are not redundant. `Module._load` is what
 * `@neon-rs/load`'s proxy goes through — for the six platform packages and for
 * the `../index.node` debug fallback alike — so patching it simulates the
 * missing binary. But `nativeLoading.test.ts` decides which case it is in by
 * looking at the DISK, and it has to: an env var the test consults would be a
 * back door that silently disables the check for anyone who exports it. So the
 * filesystem has to agree with the loader, or the child fails the wrong way —
 * loudly, but for the wrong reason, on precisely the machines this guard exists
 * to serve.
 *
 * `syncBuiltinESMExports` is what makes the fs patch visible to
 * `import { existsSync } from 'node:fs'`. Without it the named ESM export stays
 * bound to the original function and only `require('node:fs').existsSync` sees
 * the patch — a half-applied hook, which reads as a working one.
 *
 * The pid log is the proof that the preload reached the test WORKERS and not
 * just the vitest process that spawns them. `--require` is per-process: forks
 * inherit it through the environment, worker_threads would not. Vitest's
 * default pool is forks today, and if that ever changes this guard would run
 * against unhooked workers and pass by proving nothing — so the parent counts
 * the pids rather than trusting the pool.
 */
function preloadSource(marker: string): string {
  return `
const fs = require('node:fs')
const Module = require('node:module')

// The package root's \`index.node\`, a \`platforms/<target>/index.node\`, and the
// bare specifier of a platform package — every shape \`src/load.cts\` reaches for.
const BINDING =
  /(?:^|[\\\\/])index\\.node$|@cipherstash[\\\\/]protect-ffi-(?:darwin|linux|win32)-/

fs.appendFileSync(${JSON.stringify(marker)}, process.pid + '\\n')

const load = Module._load
Module._load = function (request, parent, isMain) {
  if (BINDING.test(request)) {
    // Shaped like the real thing: \`code\` is what packages/cli keys on.
    const error = new Error("Cannot find module '" + request + "'")
    error.code = 'MODULE_NOT_FOUND'
    throw error
  }
  return load.call(this, request, parent, isMain)
}

const existsSync = fs.existsSync
fs.existsSync = (path) => (BINDING.test(String(path)) ? false : existsSync(path))

const statSync = fs.statSync
fs.statSync = (path, ...rest) => {
  if (!BINDING.test(String(path))) return statSync(path, ...rest)
  const error = new Error('ENOENT: no such file or directory, stat ' + path)
  error.code = 'ENOENT'
  throw error
}

Module.syncBuiltinESMExports()
`
}

describe('lint and format wiring', () => {
  it('reads the files it means to read', () => {
    // Everything below asserts on file contents resolved from cwd. A wrong cwd
    // would make those assertions vacuous rather than failing, so pin it.
    expect(manifest.name).toBe('@cipherstash/protect-ffi')

    // The two workflow-directory checks below both pass by finding nothing to
    // contradict, so an empty or mis-resolved scan turns them green. Pin that
    // it resolved to the root workflow directory, naming files that have to be
    // there for those checks to mean anything.
    expect(rootWorkflowNames).toContain('tests.yml')
    expect(rootWorkflowNames).toContain('release.yml')
  })

  it('has no test:* script that nothing invokes', () => {
    const reachable = reachableFromAnyEntryPoint()
    const orphans = Object.keys(scripts)
      .filter((name) => name.startsWith('test:'))
      .filter((name) => !reachable.has(name))
      .filter((name) => !(name in ENTRY_POINT_EXEMPT))

    expect(orphans).toEqual([])
  })

  it('runs every entry-point-exempt script from a root workflow', () => {
    // The other half of the exemption list. Being unreachable from `test` and
    // `test:cargo` is allowed; being unreachable from everything is the bug
    // the whole file exists to catch, and an exemption is exactly where it
    // hides — the reason string is prose, and prose does not fail.
    //
    // "Some other job runs it" is only a legitimate exemption while that claim
    // is mechanically checkable, so it is checked against every workflow in the
    // root directory rather than against a job named in the reason string.
    const notInCi = Object.keys(ENTRY_POINT_EXEMPT).filter(
      (name) => !rootWorkflows.includes(`run ${name}`),
    )

    expect(notInCi).toEqual([])
  })

  it('has no script dispatching a workflow this repo cannot run', () => {
    // `release` and `dryrun` were `gh workflow run release.yml -f dryrun=…
    // -f version=…`, written for the standalone repo's workflow_dispatch
    // release. This repo has a root release.yml too — Changesets-driven, `on:
    // push` to main, no inputs — so a check for the file's existence alone is
    // green while both scripts exit non-zero: the name survived the absorption
    // and nothing else about the workflow did. Hence the trigger and the
    // inputs, not just the path.
    //
    // Nothing else catches this. These scripts are invoked by hand, so the
    // failure waits for whoever reaches for them under release pressure — and
    // a package-level `release` script is also a `turbo run release` target,
    // where a stale one dispatches a real workflow from an unrelated command.

    // Matches the block form (`on:` → indented `workflow_dispatch:`) and the
    // inline and flow-sequence spellings on the `on:` line itself.
    const dispatchable = /^\s+workflow_dispatch:|^on:.*\bworkflow_dispatch\b/m

    const problems = Object.entries(scripts).flatMap(([script, body]) =>
      [...body.matchAll(/gh workflow run ([\w.-]+)((?: -f [\w-]+=\S+)*)/g)]
        .flatMap(([, workflow, flags]) => {
          if (!rootWorkflowNames.includes(workflow)) {
            return [`no ${ROOT_WORKFLOW_DIR}/${workflow}`]
          }
          const definition = read(`${ROOT_WORKFLOW_DIR}/${workflow}`)
          if (!dispatchable.test(definition)) {
            return [`${workflow} has no workflow_dispatch trigger`]
          }
          // Crude by intent — an input's declaration is `<name>:` somewhere in
          // the file, and matching that beats a hand-rolled YAML walk. It
          // under-reports (a coincidental `version:` elsewhere satisfies it)
          // and never over-reports, so it cannot fail a working script.
          return [...flags.matchAll(/ -f ([\w-]+)=/g)]
            .filter(([, input]) => !definition.includes(`${input}:`))
            .map(([, input]) => `${workflow} declares no ${input} input`)
        })
        .map((problem) => `${script}: ${problem}`),
    )

    expect(problems).toEqual([])
  })

  it('keeps no .github directory inside this package', () => {
    // `packages/protect-ffi/.github/` is gone: the release pipeline ported the
    // last of what it held (`build.yml`'s per-platform CARGO_BUILD_TARGET
    // matrix, and `actions/setup`'s `neon list-platforms` step) into
    // `.github/workflows/_build-ffi-artifacts.yml`.
    //
    // It must not come back. A workflow file under a package reads as live CI
    // and is not — that is how `test:typecheck:wasm` sat exempt "run by the
    // wasm job" from the absorption onward with no job running it, and how
    // mise.toml told contributors CI installs the wasm32 target "in the `Add
    // wasm32 target` step of test.yml" while the step that runs is in the root
    // tests-rust.yml. A re-deposit is not far-fetched: the next subtree import
    // brings its own `.github/`, and it will arrive looking exactly as
    // authoritative as this one did.
    //
    // The whole directory, not the `.ya?ml` files in it. The deposit also
    // carried `.env` and `actions/setup/action.yml`, which read as live CI just
    // as readily as a workflow does.
    expect(existsSync(join(packageRoot, DEAD_GITHUB_DIR))).toBe(false)
  })

  it('runs the Rust format check from the cargo entry point', () => {
    // The specific one that was orphaned (#145). Asserted by name so a rename
    // that drops it from the chain is caught even if the generic check above
    // is relaxed later. It moved off `test` when this package was absorbed
    // into the monorepo, so the assertion moved with it rather than being
    // deleted — which is how a check goes quiet.
    expect(reachableFrom('test:cargo')).toContain('test:format:rust')
    expect(scripts['test:format:rust']).toContain('cargo fmt --check')
  })

  it('keeps cargo off the default test path', () => {
    // The load-bearing half of the split. Root `pnpm test` runs
    // `turbo test --filter './packages/*'`, which reaches this package's
    // `test` — so anything cargo on that path is cargo on every PR, in a repo
    // where one package out of eighteen is Rust.
    //
    // Two hops out of a script body, because grepping the bodies for `cargo`
    // only sees one of them. `mise run <task>` leaves package.json entirely,
    // and `mise run lint:rust` is three cargo invocations — so it is spelled
    // out here rather than left to the reader of a green test.
    const reachable = [...reachableFrom('test')]
    const cargoScripts = reachable.filter((name) =>
      scripts[name]?.includes('cargo'),
    )
    const viaMise = reachable.flatMap((name) =>
      [...(scripts[name]?.matchAll(/mise run ([\w:.-]+)/g) ?? [])]
        .filter(([, task]) => taskReachesCargo(task))
        .map(([, task]) => `${name} → mise run ${task}`),
    )
    expect([...cargoScripts, ...viaMise]).toEqual([])
  })

  it.skipIf(process.env[ARTIFACT_FREE_RUN] === '1')(
    'keeps cargo OUTPUT off the default test path too',
    () => {
      // The other half of the rule the test above states, and the half nothing
      // was checking. Keeping cargo out of the SCRIPTS is worth nothing if a
      // test then requires what cargo produces: `src/nativeLoading.test.ts`
      // asserted `assertNativeBindingAvailable()` does not throw, which needs
      // an `index.node` that only `build:native` writes. Root `pnpm test`
      // reaches this package through `turbo test --filter './packages/*'`, so
      // that made a Rust build a prerequisite of the whole repo's default test
      // — the exact thing the entry-point split exists to prevent, arriving
      // through the tests instead of through the scripts.
      //
      // Static analysis cannot see this. A test does not name `index.node`; it
      // calls an export that happens to reach the addon, four hops down. So
      // the suite is RE-RUN with every binding artifact made unresolvable, and
      // the property is the child's exit status.
      //
      // Which is also why it is not enough that this checkout currently has no
      // binary. The failure is invisible exactly where it is introduced: an
      // author who ran `build:native` sees green, and so does CI, which builds
      // the binding before running this suite. Only the artifact-free
      // contributor sees it — and by then it is on main. In CI this nested run
      // is the ONLY execution of the artifact-free path.
      const workspace = mkdtempSync(join(tmpdir(), 'protect-ffi-no-artifact-'))
      const marker = join(workspace, 'preloaded-pids')
      const preload = join(workspace, 'hide-binding.cjs')
      writeFileSync(marker, '')
      writeFileSync(preload, preloadSource(marker))

      // Resolved through the manifest rather than assumed: `vitest/vitest.mjs`
      // is the `bin` entry, and pnpm's store path is not guessable.
      const resolve = createRequire(join(packageRoot, 'package.json'))
      const manifestPath = resolve.resolve('vitest/package.json')
      const vitestBin = join(
        dirname(manifestPath),
        JSON.parse(readFileSync(manifestPath, 'utf8')).bin.vitest,
      )

      const env: Record<string, string | undefined> = {
        ...process.env,
        [ARTIFACT_FREE_RUN]: '1',
        // The summary line is asserted on below, and vitest wraps every field
        // of it in colour escapes when it thinks it has a TTY-ish consumer.
        NO_COLOR: '1',
        // Quoted because Node splits NODE_OPTIONS on whitespace unless a value
        // is wrapped in double quotes, and `preload` sits under `tmpdir()` —
        // not a path this file chose. No tmpdir on Linux or macOS contains a
        // space, so this is not reachable here; it is one character against a
        // failure that would read as "vitest could not start".
        NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require "${preload}"`]
          .filter(Boolean)
          .join(' '),
      }
      // This process IS a vitest worker, and its VITEST_* variables describe
      // that worker. Inherited, they make the child think it is one too.
      for (const key of Object.keys(env)) {
        if (key.startsWith('VITEST')) delete env[key]
      }

      const child = spawnSync(process.execPath, [vitestBin, 'run'], {
        cwd: packageRoot,
        env,
        encoding: 'utf8',
        timeout: 300_000,
      })
      const output = `${child.stdout ?? ''}\n${child.stderr ?? ''}`

      expect(
        child.error,
        `Could not start the nested vitest run at ${vitestBin}.`,
      ).toBeUndefined()

      expect(
        child.status,
        `The default test suite does not survive a checkout with no cargo build.\n\`packages/protect-ffi\`'s \`test\` is what root \`pnpm test\` runs through turbo, and it must pass with no \`index.node\` anywhere — the six \`platforms/*\` packages are empty until someone compiles one, and \`build\` is \`tsc\`, not cargo.\nGate the assertion on the artifact being present (see \`builtArtifacts\` in nativeLoading.test.ts) and give the artifact-free case its own contract, rather than making a Rust toolchain a prerequisite of the repo's default test.\nThe nested run said:\n${output}`,
      ).toBe(0)

      // Non-vacuity, in two parts. A child that ran nothing exits 0 on some
      // configurations, and a preload that never reached the workers leaves
      // the artifact visible to them — either one turns this green while
      // testing nothing.
      // Recursive, matching `vitest.config.ts`'s `src/**/*.test.ts`. A flat
      // readdir agrees with it only for as long as nobody nests a test file,
      // and then this fails on a correct suite.
      const files = readdirSync(join(packageRoot, 'src'), {
        recursive: true,
      }).filter((name) => String(name).endsWith('.test.ts'))
      expect(
        output,
        `The nested run did not report ${files.length} passing test files, so it did not run this suite.\n${output}`,
      ).toContain(`Test Files  ${files.length} passed (${files.length})`)

      const pids = new Set(
        readFileSync(marker, 'utf8').split('\n').filter(Boolean),
      )
      expect(
        pids.size,
        `The preload logged ${pids.size} process(es). It has to reach the vitest process AND the workers that run the test files — \`--require\` travels through the environment to forked children, but not into worker_threads. If vitest's pool is no longer fork-based, this guard ran against workers that could still see the binding.\nPids: ${[...pids].join(', ')}`,
      ).toBeGreaterThan(1)
    },
    300_000,
  )

  it('reaches every cargo check from the cargo entry point', () => {
    // The mirror of the check above: cargo scripts are allowed to exist, but
    // not to exist unreachable. Without this, moving a check off `test` and
    // forgetting to add it to `test:cargo` passes both other assertions.
    const reachable = reachableFrom('test:cargo')
    const unreachable = Object.keys(scripts)
      .filter((name) => name.startsWith('test:'))
      .filter((name) => scripts[name]?.includes('cargo'))
      .filter((name) => !reachable.has(name))

    expect(unreachable).toEqual([])
  })

  it('passes `--locked` from the cargo entry point', () => {
    // Nothing in this repo passed `--locked` at all, and the cost of that was
    // paid in silence. `scripts/sync-lockstep-versions.mjs` rewrites
    // `eql-bindings`'s version on every lockstep bump; this package depends on
    // that crate BY PATH, so its `Cargo.lock` records the version and nothing
    // was updating it. After the 3.0.5 bump the lock said 3.0.4 and `cargo
    // metadata --locked` exited 101 — while every cargo command in CI happily
    // regenerated the lock in memory, built against the regenerated one, and
    // threw it away with the runner. The committed file drifted further on each
    // bump and nothing went red.
    //
    // `scripts/__tests__/cargo-lock-freshness.test.mjs` covers the part of that
    // reachable without a Rust toolchain — a repo-owned crate recorded at the
    // wrong version — and its header says so, along with what it cannot see: a
    // lock stale because a crate gained a NEW dependency. It names this script
    // as where the remainder belongs, and this is that.
    //
    // Scoped to `test:cargo`, the Rust CHECK entry point, and deliberately not
    // to the build scripts. `cargo-build` is also `debug`, and `build:native`
    // is a documented local command (README.md, packages/cli/AGENTS.md) — a
    // contributor who has just edited `Cargo.toml` regenerates the lock on
    // their next build, legitimately, and `--locked` would turn that into a
    // failure at the end of a compile. The check runs on the same commit and
    // answers the same question without standing in the way of a build.
    const LOCKED_EXEMPT: Record<string, string> = {
      'test:format:rust':
        '`cargo fmt` is an external subcommand: it resolves no dependency ' +
        'graph, and cargo forwards the flag through to rustfmt, which rejects ' +
        'it as unknown.',
    }

    const cargoChecks = [...reachableFrom('test:cargo')].filter((name) =>
      scripts[name]?.includes('cargo'),
    )
    // Non-vacuity. An empty or one-element set satisfies the assertion below
    // having checked nothing, which is the state this whole file exists for.
    expect(
      cargoChecks.length,
      'No cargo script is reachable from `test:cargo`, so the `--locked` check below reads nothing.',
    ).toBeGreaterThan(1)

    const unlocked = cargoChecks.filter(
      (name) =>
        !scripts[name]?.includes('--locked') && !(name in LOCKED_EXEMPT),
    )
    expect(
      unlocked,
      `These cargo checks resolve a dependency graph without \`--locked\`, so a stale \`Cargo.lock\` is regenerated in memory and the run passes against dependencies the committed lock does not describe: ${unlocked.join(', ')}`,
    ).toEqual([])

    // The exemption list, both directions — the same rule every other list in
    // this repo is held to. An entry for a script that has gone, or that now
    // carries the flag, is a standing permission nobody decided to grant.
    const stale = Object.keys(LOCKED_EXEMPT).filter(
      (name) =>
        scripts[name] === undefined ||
        !scripts[name].includes('cargo') ||
        scripts[name].includes('--locked'),
    )
    expect(stale).toEqual([])
  })

  it('forwards script arguments without the npm `--` separator', () => {
    // npm strips the `--` in `npm run x -- --release`; pnpm forwards it
    // verbatim. Since the cargo scripts end in `> cargo.log`, the appended
    // args land after the redirect, so pnpm produced
    //
    //     cargo build --message-format=… > cargo.log -- --release
    //
    // and cargo rejected `--release` as a positional argument. The failure is
    // at the end of a build, not the start, and the error names `--release`
    // rather than the separator that caused it.
    //
    // The release matrix passes `--target "${CARGO_BUILD_TARGET}.2.28"` this
    // way to pin glibc, so the phase-3 workflow port must use the same
    // separator-free spelling.
    const withSeparator = Object.entries(scripts)
      .filter(([, body]) => /(?:pnpm|npm) run [\w:-]+ --(?:\s|$)/.test(body))
      .map(([name]) => name)

    expect(withSeparator).toEqual([])
  })

  it('has no lint:rust:* mise task the lint:rust entry point skips', () => {
    const defined = [
      ...miseToml.matchAll(/^\[tasks\."(lint:rust:[\w:-]+)"\]$/gm),
    ].map((match) => match[1])
    expect(defined.length).toBeGreaterThan(0)

    // Isolate this task before looking for `depends`: a search over the whole
    // remainder of the file could silently borrow a later task's list.
    const lintRustBlock =
      /^\[tasks\."lint:rust"\]$(?:\n(?!\[tasks\.)[^\n]*)*/m.exec(miseToml)?.[0]
    const dependsOn = /^depends = \[(.*?)\]$/m.exec(lintRustBlock ?? '')
    expect(
      dependsOn,
      'lint:rust should be an aggregate with a depends list',
    ).not.toBeNull()

    const skipped = defined.filter(
      (task) => !dependsOn?.[1].includes(`"${task}"`),
    )
    expect(skipped).toEqual([])
  })

  it('lints both the host and the wasm32 target', () => {
    expect(miseToml).toContain('--target wasm32-unknown-unknown')
  })

  it('runs the lint entry point in CI, with the wasm32 target installed', () => {
    // Live again: this reads the root workflow GitHub actually executes, so a
    // failure here means the Rust checks have stopped running — the exact
    // condition that held silently between the absorption and this port.
    //
    // `lint:rust` is the aggregate entry point — an arm reachable only by name
    // is an arm nobody runs (#145) — and wasm32 must be installed before
    // clippy can lint it.
    //
    // Terminated, not a prefix. `toContain('mise run lint:rust')` is satisfied
    // by `mise run lint:rust:host`, so the assertion that CI runs the aggregate
    // was green for a workflow running one arm and skipping the other two —
    // which is the #145 failure itself, dressed as the check against it.
    expect(testWorkflow).toMatch(/mise run lint:rust(?![\w:-])/)
    expect(testWorkflow).toContain('rustup target add wasm32-unknown-unknown')
  })
})

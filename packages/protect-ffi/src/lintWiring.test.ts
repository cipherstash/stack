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
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// Vitest resolves cwd to the directory holding vitest.config.ts. `import.meta`
// is unavailable here: tsconfig emits CommonJS, and tsc rejects it (TS1470).
const repoRoot = process.cwd()
const read = (relative: string) =>
  readFileSync(join(repoRoot, relative), 'utf8')

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
const rootWorkflowNames = readdirSync(join(repoRoot, ROOT_WORKFLOW_DIR)).filter(
  (name) => name.endsWith('.yml') || name.endsWith('.yaml'),
)
const rootWorkflows = rootWorkflowNames
  .map((name) => withoutComments(read(`${ROOT_WORKFLOW_DIR}/${name}`)))
  .join('\n')

// The upstream repo's CI, deposited here by the subtree merge and inert since:
// GitHub reads workflows from the repository root alone. It is kept on purpose
// — the phase-4 publishing cutover ports `build.yml`'s per-platform
// `CARGO_BUILD_TARGET` matrix — so this reads the directory rather than
// assuming it is gone, and the check below goes quiet on its own once the
// cutover deletes it.
const DEAD_WORKFLOW_DIR = '.github/workflows'
const deadWorkflowNames = existsSync(join(repoRoot, DEAD_WORKFLOW_DIR))
  ? readdirSync(join(repoRoot, DEAD_WORKFLOW_DIR)).filter((name) =>
      /\.ya?ml$/.test(name),
    )
  : []

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

  it('justifies nothing by pointing into the dead upstream workflow directory', () => {
    // `packages/protect-ffi/.github/workflows/{build,test,release}.yml` are
    // still present and still inert, kept until the phase-4 cutover has ported
    // what it needs from them. Keeping them is the hazard: a comment or an
    // exemption reason that names `test.yml` reads as a check that runs
    // somewhere, and the only file with that name is one GitHub never
    // executes. That is exactly how `test:typecheck:wasm` sat exempt "run by
    // the wasm job" from the absorption onward with no job running it.
    //
    // mise.toml did it too — it told contributors CI installs the wasm32
    // target "in the `Add wasm32 target` step of test.yml", while the step that
    // runs is in the root tests-rust.yml.
    //
    // Only names unique to that directory are checked: `release.yml` exists at
    // the root as well, so a citation of it is ambiguous and this under-reports
    // rather than guessing — the same trade the workflow-dispatch check makes.
    const deadOnly = deadWorkflowNames.filter(
      (name) => !rootWorkflowNames.includes(name),
    )
    const liveConfig = [
      miseToml,
      JSON.stringify(scripts),
      ...Object.values(ENTRY_POINT_EXEMPT),
    ].join('\n')

    expect(deadOnly.filter((name) => liveConfig.includes(name))).toEqual([])
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

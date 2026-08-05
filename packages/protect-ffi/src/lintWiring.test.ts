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
import { readFileSync } from 'node:fs'
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
// The ROOT workflow that actually runs the Rust checks. GitHub only reads
// workflows from the repository root, so this must never point back inside this
// package — that was true of the deposited upstream copy this used to read,
// which made the CI assertion below vacuous from the day of the absorption.
const testWorkflow = read('../../.github/workflows/tests-rust.yml')
// Every other root workflow an exempted script may hang off. Same rule as
// above: root only. A script "run by CI" according to a file under
// packages/protect-ffi/.github/ is a script nothing runs.
const rootWorkflows = testWorkflow + read('../../.github/workflows/tests.yml')

/**
 * Script names reachable from `root`, following `pnpm run` / `npm run`
 * references.
 *
 * Both spellings are matched. The scripts moved to `pnpm run` when the package
 * was absorbed into the monorepo, and a stray `npm run` left behind would
 * otherwise drop a whole subtree from this analysis and read as "no orphans".
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
    for (const match of body.matchAll(/(?:pnpm|npm) run ([\w:-]+)/g)) {
      queue.push(match[1])
    }
  }
  return seen
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
    const notInCi = Object.keys(ENTRY_POINT_EXEMPT).filter(
      (name) => !rootWorkflows.includes(`run ${name}`),
    )

    expect(notInCi).toEqual([])
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
    const cargoScripts = [...reachableFrom('test')].filter((name) =>
      scripts[name]?.includes('cargo'),
    )
    expect(cargoScripts).toEqual([])
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
    expect(testWorkflow).toContain('mise run lint:rust')
    expect(testWorkflow).toContain('rustup target add wasm32-unknown-unknown')
  })
})

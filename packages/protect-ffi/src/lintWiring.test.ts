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
const testWorkflow = read('.github/workflows/test.yml')

/** Script names reachable from `npm test`, following `npm run` references. */
function reachableFromNpmTest(): Set<string> {
  const seen = new Set<string>()
  const queue = ['test']
  while (queue.length > 0) {
    const name = queue.pop()
    if (name === undefined || seen.has(name)) continue
    seen.add(name)
    const body = scripts[name]
    if (body === undefined) continue
    for (const match of body.matchAll(/npm run ([\w:-]+)/g)) {
      queue.push(match[1])
    }
  }
  return seen
}

/**
 * Checks `npm test` is not expected to run, each with its reason. Anything
 * added here is a deliberate carve-out, which is the point of making it a list.
 */
const NPM_TEST_EXEMPT: Record<string, string> = {
  // Runs against the generated wasm .d.ts, so it needs `npm run build:wasm`
  // first. `npm test` must still pass in a clone with no dist/, so this one
  // belongs to the wasm job in build.yml.
  'test:typecheck:wasm': 'needs dist/wasm, run by the wasm job in build.yml',
}

describe('lint and format wiring', () => {
  it('reads the files it means to read', () => {
    // Everything below asserts on file contents resolved from cwd. A wrong cwd
    // would make those assertions vacuous rather than failing, so pin it.
    expect(manifest.name).toBe('@cipherstash/protect-ffi')
  })

  it('has no test:* script that nothing invokes', () => {
    const reachable = reachableFromNpmTest()
    const orphans = Object.keys(scripts)
      .filter((name) => name.startsWith('test:'))
      .filter((name) => !reachable.has(name))
      .filter((name) => !(name in NPM_TEST_EXEMPT))

    expect(orphans).toEqual([])
  })

  it('runs the Rust format check from npm test', () => {
    // The specific one that was orphaned. Asserted by name so a rename that
    // drops it from the chain is caught even if the generic check above is
    // relaxed later.
    expect(reachableFromNpmTest()).toContain('test:format:rust')
    expect(scripts['test:format:rust']).toContain('cargo fmt --check')
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
    expect(testWorkflow).toContain('mise run lint:rust')
    expect(testWorkflow).toContain('rustup target add wasm32-unknown-unknown')
  })
})

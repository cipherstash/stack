import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * `mise run setup` runs `eql:v4:install` before `eql:v4:codec`. The install
 * task's `tasks/build.sh` runs `cargo run -p eql-codegen` with no `--locked`,
 * and that rewrites a stale `packages/eql/Cargo.lock` on the runner. The
 * codec's `cargo build --locked` then passes against the rewritten file, so
 * the flag proves nothing: the failure "Working on protect-ffi" in AGENTS.md
 * records for the 3.0.5 bump.
 *
 * `build.sh` stays as it is (the EQL subtree's cargo tasks carry no
 * `--locked`), so the install task has to check the lockfile before it runs
 * anything that could rewrite it. No TOML parser is installed, so the task
 * body is read by hand.
 */
const TASKS =
  'languages/typescript/packages/protect-ffi/integration-tests/tasks.toml'

/** The shell lines of a task's `run` body, comments dropped. */
function taskRunLines(name) {
  const source = readFileSync(resolve(REPO_ROOT, TASKS), 'utf8')
  const header = `["${name}"]`
  const start = source.indexOf(header)
  if (start === -1) throw new Error(`${TASKS} has no task ${header}`)
  const rest = source.slice(start + header.length)
  const body =
    /^run\s*=\s*(?:"""([\s\S]*?)"""|"([^"\n]*)"|\[([\s\S]*?)^\])/m.exec(rest)
  if (!body) throw new Error(`${header} has no run body`)
  // The `run = [ "…", "…" ]` form: one shell command per string.
  if (body[3] !== undefined) {
    return [...body[3].matchAll(/^\s*"([^"\n]*)"/gm)].map((m) => m[1])
  }
  return (body[1] ?? body[2])
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'))
}

const invokesCargo = (line) => /(^|[\s;&|])cargo\s/.test(line)

describe('eql:v4:install checks the EQL lockfile before building', () => {
  const lines = taskRunLines('eql:v4:install')
  const build = lines.indexOf('bash tasks/build.sh')
  const gate = lines.findIndex(
    (line) => invokesCargo(line) && /\s--locked(\s|$)/.test(line),
  )

  it('still runs tasks/build.sh', () => {
    expect(build, 'the task no longer runs tasks/build.sh').toBeGreaterThan(-1)
  })

  it('runs a --locked cargo command before tasks/build.sh', () => {
    expect(
      gate,
      `no \`cargo … --locked\` line in eql:v4:install: ${JSON.stringify(lines)}`,
    ).toBeGreaterThan(-1)
    expect(gate, '--locked has to run before the build').toBeLessThan(build)
  })

  it('fails the task when the gate fails', () => {
    expect(gate, 'there is no gate to fail').toBeGreaterThan(-1)
    expect(lines[gate], 'the gate has been made non-fatal').not.toMatch(
      /\|\||;/,
    )
    const setE = lines.indexOf('set -e')
    expect(setE, 'the gate needs set -e above it').toBeGreaterThan(-1)
    expect(setE, 'set -e has to precede the gate').toBeLessThan(gate)
  })
})

/**
 * The migration suites shell out to a codec binary built outside vitest and
 * query SQL installed outside vitest. A local `mise run test:integration` that
 * skipped either would pass against whatever an earlier `mise run setup` left.
 */
describe.each(['test:integration', 'test:integration:all'])(
  '%s rebuilds EQL v4 before vitest',
  (task) => {
    const lines = taskRunLines(task)
    const vitest = lines.findIndex((line) => /\bvitest\b/.test(line))

    it('still runs vitest', () => {
      expect(vitest, `${task} no longer runs vitest`).toBeGreaterThan(-1)
    })

    it.each(['mise run eql:v4:install', 'mise run eql:v4:codec'])(
      'runs %s first',
      (step) => {
        const at = lines.indexOf(step)
        expect(
          at,
          `${task} does not run ${step}: ${JSON.stringify(lines)}`,
        ).toBeGreaterThan(-1)
        expect(at, `${step} has to run before vitest`).toBeLessThan(vitest)
      },
    )

    it('installs the bundle before building the codec, after the binding', () => {
      expect(lines.indexOf('mise run build:debug')).toBeGreaterThan(-1)
      expect(
        lines.indexOf('mise run eql:v4:install'),
        'the lock gate in eql:v4:install has to run first',
      ).toBeLessThan(lines.indexOf('mise run eql:v4:codec'))
      expect(lines.indexOf('mise run build:debug')).toBeLessThan(
        lines.indexOf('mise run eql:v4:install'),
      )
    })
  },
)

/**
 * May this repository publish the EQL release line?
 *
 * The pipeline was built here while `@cipherstash/eql` was still published from
 * `cipherstash/encrypt-query-language`, so it had to reach no registry until
 * the Phase-5 cutover. That is a state, and it needs a switch.
 *
 * The switch is DERIVED, not flipped. `FROZEN_PUBLISHERS` in
 * `scripts/release-gate.mjs` is the single record of "this package lives here
 * and is published elsewhere", and the cutover has to delete its entry because
 * the release gate blocks every release until it does. Deleting it arms this
 * pipeline. A hand-flipped flag would have nothing forcing it: the cutover
 * would repoint the registries, forget the flag, and the pipeline would stay
 * inert — publishing an npm package with no SQL release, docs or crate.
 *
 * Why not reuse the release gate: it answers a REGISTRY question about npm, and
 * `release-plz.yml` publishes a CRATE on its own trigger. Keying that on the npm
 * answer would also race `release.yml` on the very push that releases a version.
 * This asks a question with no registry and no clock in it.
 *
 * ## A second line: the stack-* crates
 *
 * `release-plz.yml` also publishes `stack-auth` and `stack-profile` from the
 * root Cargo workspace. They are imported from cipherstash-suite with
 * `@cipherstash/auth`, and all three lines move here together in the arming PR
 * of that import (PR E), which repoints crates.io and npm trusted publishing in
 * one step. No crate is in `FROZEN_PUBLISHERS` — it is an npm map — so the
 * crates line keys on `@cipherstash/auth`, whose entries that PR deletes.
 * `node scripts/eql-pipeline-armed.mjs crates` answers for it. The file keeps
 * its EQL name because the EQL workflows and tests name it.
 */
import { appendFileSync } from 'node:fs'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { FROZEN_PUBLISHERS } from './release-gate.mjs'

/** The package whose publisher decides whether the whole line is armed. */
export const EQL_PACKAGE = '@cipherstash/eql'

/**
 * Each release line, and the frozen package whose entry arms it. The first
 * command-line argument names the line; with none, it is `eql`.
 */
export const LINES = new Map([
  ['eql', { pkg: EQL_PACKAGE, pipeline: 'the EQL release pipeline' }],
  [
    'crates',
    {
      pkg: '@cipherstash/auth',
      pipeline: 'the stack-auth / stack-profile crates.io pipeline',
    },
  ],
])

function lineOf(name) {
  const line = LINES.get(name)
  if (!line) {
    throw new Error(
      `unknown release line \`${name}\`; expected one of ${[...LINES.keys()].join(', ')}`,
    )
  }
  return line
}

/** `true` when this repository may publish the named release line. */
export function pipelineArmed(name, frozen = FROZEN_PUBLISHERS) {
  return !frozen.has(lineOf(name).pkg)
}

/** Why the named line is not armed, or `null`. */
export function lineFrozenReason(name, frozen = FROZEN_PUBLISHERS) {
  return frozen.get(lineOf(name).pkg) ?? null
}

/**
 * `true` when this repository may publish the EQL release line.
 *
 * The map is a parameter so the tests can drive both states — the armed one
 * included, rather than exercising it for the first time at the cutover.
 */
export function eqlPipelineArmed(frozen = FROZEN_PUBLISHERS) {
  return pipelineArmed('eql', frozen)
}

/** Why it is not armed, or `null`. Taken from the map, so it cannot drift. */
export function frozenReason(frozen = FROZEN_PUBLISHERS) {
  return lineFrozenReason('eql', frozen)
}

function main() {
  const name = process.argv[2] ?? 'eql'
  const { pkg, pipeline } = lineOf(name)
  const armed = pipelineArmed(name)

  console.log(
    armed
      ? `${pkg} is published from this repository — ${pipeline} is ARMED.`
      : `${pkg} is a frozen publisher — ${pipeline} is INERT.\n  ${lineFrozenReason(name)}`,
  )

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `armed=${armed}\n`)
  }
}

// Importable without running, so the tests read the exports without writing to
// GITHUB_OUTPUT.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()

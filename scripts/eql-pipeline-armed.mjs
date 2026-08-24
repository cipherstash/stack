/**
 * May this repository publish the EQL release line?
 *
 * The pipeline was built here while `@cipherstash/eql` is still published from
 * `cipherstash/encrypt-query-language`, so it must reach no registry until the
 * Phase-5 cutover. That is a state, and it needs a switch.
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
 */
import { appendFileSync } from 'node:fs'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { FROZEN_PUBLISHERS } from './release-gate.mjs'

/** The package whose publisher decides whether the whole line is armed. */
export const EQL_PACKAGE = '@cipherstash/eql'

/**
 * `true` when this repository may publish the EQL release line.
 *
 * The map is a parameter so the tests can drive both states — the armed one
 * included, rather than exercising it for the first time at the cutover.
 */
export function eqlPipelineArmed(frozen = FROZEN_PUBLISHERS) {
  return !frozen.has(EQL_PACKAGE)
}

/** Why it is not armed, or `null`. Taken from the map, so it cannot drift. */
export function frozenReason(frozen = FROZEN_PUBLISHERS) {
  return frozen.get(EQL_PACKAGE) ?? null
}

function main() {
  const armed = eqlPipelineArmed()

  console.log(
    armed
      ? `${EQL_PACKAGE} is published from this repository — the EQL release pipeline is ARMED.`
      : `${EQL_PACKAGE} is a frozen publisher — the EQL release pipeline is INERT.\n  ${frozenReason()}`,
  )

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `armed=${armed}\n`)
  }
}

// Importable without running, so the tests read the exports without writing to
// GITHUB_OUTPUT.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()

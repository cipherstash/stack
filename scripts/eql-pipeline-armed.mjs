/**
 * Is the EQL release pipeline allowed to publish anything from THIS repository?
 *
 * ## Why this is a script and not a workflow input
 *
 * The whole EQL release pipeline — `release.yml`'s EQL jobs, `release-plz.yml`,
 * `_build-eql-sql.yml`, `_build-eql-docs.yml`,
 * `release-postgres-eql-image.yml` — was built here while `@cipherstash/eql` is
 * still published from `cipherstash/encrypt-query-language`. It exists so it
 * can be reviewed, dry-run and corrected, and it must reach no registry until
 * the Phase-5 cutover repoints trusted publishing. That is a state, and a state
 * needs a switch.
 *
 * The obvious switch is a boolean somebody flips. It is the wrong one, for the
 * reason `scripts/release-gate.mjs` records about its own map: an entry left
 * behind does not fail on the day it goes wrong, it fails on the next release.
 * A hand-flipped flag has the same shape in reverse — the cutover PR repoints
 * npm and crates.io, and NOTHING fails if it forgets the flag. The pipeline
 * simply stays inert, and the first EQL release after the cutover quietly
 * publishes an npm package with no SQL release, no docs and no crate.
 *
 * So the switch is DERIVED from the fact it depends on. `FROZEN_PUBLISHERS` in
 * `scripts/release-gate.mjs` is the single written record of "this package
 * lives here and is published elsewhere", and the cutover deletes its entry
 * because the release gate blocks every release until it does. Deleting it is
 * what arms this pipeline. There is no second edit to forget.
 *
 * ## Why not just use the release gate
 *
 * `release-gate.mjs` answers a REGISTRY question — which committed versions are
 * missing from npm — and it already blocks a frozen package's release by
 * exiting non-zero. That covers `release.yml`, whose EQL jobs all sit behind
 * `needs: [gate]`.
 *
 * It does not cover `release-plz.yml`. That workflow publishes a CRATE, on its
 * own `push: main` trigger, and crates.io is not a registry the gate models at
 * all. Keying it on the npm answer would also be a race: on the push that
 * releases version V, `release.yml` and `release-plz.yml` start together, and
 * whichever npm publish finishes first would flip the other's answer from
 * "missing" to "published" mid-run — so the crate would be skipped on exactly
 * the push that was supposed to release it.
 *
 * This asks a question with no registry in it and no clock in it: is
 * `@cipherstash/eql` still recorded as published from somewhere else? Same
 * answer for every job in every workflow on every run.
 */
import { appendFileSync } from 'node:fs'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { FROZEN_PUBLISHERS } from './release-gate.mjs'

/** The npm package whose publisher decides whether the whole line is armed. */
export const EQL_PACKAGE = '@cipherstash/eql'

/**
 * `true` when this repository may publish the EQL release line.
 *
 * The map is a parameter so the tests can drive both states without mutating
 * the real one — and so the "armed" case is exercised now rather than first
 * being exercised by the cutover.
 */
export function eqlPipelineArmed(frozen = FROZEN_PUBLISHERS) {
  return !frozen.has(EQL_PACKAGE)
}

/**
 * Why it is not armed, or `null` when it is.
 *
 * The reason is the `FROZEN_PUBLISHERS` entry itself rather than a sentence
 * written here, so the job log says which repository still owns the publish and
 * cannot drift from the map that decided it.
 */
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

// Importable without running, so the tests can read the two exports above
// without writing to GITHUB_OUTPUT.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()

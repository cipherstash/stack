import { describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * Every release-plz step pins the release-plz CLI, and all of them pin the
 * same version.
 *
 * Without a `version:` input `release-plz/action` installs its own default
 * CLI, so a later action bump (or an edit that drops the input) silently moves
 * the crates.io publish onto a CLI nobody has reviewed. The two publish lines —
 * `eql-bindings` and the root stack-* crates — must also agree, or one of them
 * publishes on a different CLI from the other.
 */

const WORKFLOW = '.github/workflows/release-plz.yml'
const jobs = readWorkflow(WORKFLOW).jobs
const releasePlzSteps = Object.entries(jobs).flatMap(([job, { steps = [] }]) =>
  steps
    .filter((step) => String(step.uses ?? '').startsWith('release-plz/action@'))
    .map((step) => ({ job, name: step.name, version: step.with?.version })),
)

describe('release-plz CLI pin', () => {
  it('finds the release-plz steps it guards', () => {
    expect(releasePlzSteps.length).toBeGreaterThanOrEqual(2)
  })

  it.each(releasePlzSteps)(
    '$job › $name pins an exact CLI version',
    ({ version }) => {
      expect(String(version ?? '')).toMatch(/^\d+\.\d+\.\d+$/)
    },
  )

  it('pins the same CLI version in every release-plz step', () => {
    expect(new Set(releasePlzSteps.map((step) => step.version)).size).toBe(1)
  })
})

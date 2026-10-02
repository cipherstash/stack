import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * Guards the `STEPS` pipeline in `init/index.ts` against the failure mode
 * that produced #923.
 *
 * `installSkills()` was never broken. What broke was its REACHABILITY: the
 * init/plan/impl restructure left the handoff steps as its only callers, and
 * `stash init` reaches no handoff — so `stash@1.1.0` shipped a CLI that
 * installed zero skills for anyone, in any mode, for an entire release.
 * Nothing caught it because every unit test of the module still passed. A
 * step that nothing invokes reads exactly like a step that works.
 *
 * Scanning the source rather than importing it is deliberate, and matches
 * `lintWiring.test.ts` / `integrationSuiteCi.test.ts` elsewhere in the repo:
 * `init/index.ts` transitively imports the plan command and the whole
 * provider graph, so an import-based assertion would trade a precise check
 * for a fragile one.
 */
const INIT_INDEX = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'index.ts',
)

function stepsArray(): string {
  const source = readFileSync(INIT_INDEX, 'utf-8')
  const match = source.match(/const STEPS = \[([\s\S]*?)\n\]/)
  if (!match) throw new Error('Could not find the STEPS array in init/index.ts')
  return match[1]
}

/** Step identifiers in pipeline order, comments stripped. */
function stepOrder(): string[] {
  return stepsArray()
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.endsWith('Step,'))
    .map((line) => line.slice(0, -1))
}

describe('init STEPS wiring', () => {
  it('runs installSkillsStep', () => {
    expect(stepOrder()).toContain('installSkillsStep')
  })

  /**
   * Ordering is load-bearing, not cosmetic. Installing skills needs no
   * network, no credentials and no database; authenticate, resolve-database
   * and install-eql each need one and each can exit non-zero. Running first
   * is what makes the guidance survive those failures — and `stash-cli`,
   * which covers recovering from them, is in every skill set.
   */
  it('runs it first, ahead of every fallible step', () => {
    expect(stepOrder()[0]).toBe('installSkillsStep')
  })

  it('still imports the step it names', () => {
    const source = readFileSync(INIT_INDEX, 'utf-8')
    expect(source).toContain("from './steps/install-skills.js'")
  })
})

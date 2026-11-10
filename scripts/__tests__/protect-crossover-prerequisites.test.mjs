import { describe, expect, it } from 'vitest'
import { runsWhen } from './lib/expressions.mjs'
import { readWorkflow } from './lib/workflows.mjs'

const steps = readWorkflow('.github/workflows/tests.yml').jobs['e2e-tests']
  .steps
const database = steps.find((step) => step.id === 'db')
const crossover = steps.find((step) =>
  step.run?.includes('run test:protect-crossover'),
)
const bindings = steps.filter((step) =>
  [
    './.github/actions/build-ffi-binding',
    './.github/actions/build-auth-binding',
  ].includes(step.uses),
)

// Model each named step's outcome. Explicit !cancelled() conditions bypass
// GitHub's implicit success() guard, so they must inspect prerequisite outcomes.
function contextWithFailure(failed) {
  return {
    steps: Object.fromEntries(
      steps
        .filter((step) => step.id)
        .map((step) => [
          step.id,
          { outcome: step === failed ? 'failure' : 'success' },
        ]),
    ),
  }
}

describe('cross-store suite prerequisites', () => {
  it('finds both bindings and the database and suite steps', () => {
    expect(bindings).toHaveLength(2)
    expect(database).toBeDefined()
    expect(crossover).toBeDefined()
  })

  for (const binding of bindings) {
    it(`does not start postgres or crossover after ${binding.name} fails`, () => {
      const context = contextWithFailure(binding)
      const startsDatabase = runsWhen(database.if, context)
      expect(
        startsDatabase,
        'A failed binding must prevent database startup',
      ).toBe(false)
      context.steps.db.outcome = startsDatabase ? 'success' : 'skipped'
      expect(runsWhen(crossover.if, context)).toBe(false)
    })
  }

  it('still runs crossover after the independent compatibility suite fails', () => {
    const compat = steps.find((step) =>
      step.run?.includes('run test:protect-compat'),
    )
    expect(compat).toBeDefined()
    const context = contextWithFailure(compat)
    expect(runsWhen(database.if, context)).toBe(true)
    expect(runsWhen(crossover.if, context)).toBe(true)
  })

  it('does not run crossover when postgres fails', () => {
    expect(runsWhen(crossover.if, contextWithFailure(database))).toBe(false)
  })
})

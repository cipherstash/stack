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

// The integration image is PostgreSQL 17. The upgrade example's dependency
// preflight reads pg_constraint, whose contents changed in 18 (NOT NULL rows),
// so the suite must keep running against 18 as well.
describe('upgrade example on PostgreSQL 18', () => {
  const db18 = steps.find((step) => step.id === 'db18')
  const run18 = steps.find((step) => step.if?.includes('steps.db18.outcome'))

  it('starts a digest-pinned PostgreSQL 18 after both bindings build', () => {
    expect(db18?.run).toMatch(/postgres:18@sha256:[0-9a-f]{64}/)
    for (const binding of bindings) {
      expect(runsWhen(db18.if, contextWithFailure(binding))).toBe(false)
    }
  })

  it('runs the upgrade suite against that database', () => {
    expect(run18?.run).toContain('run test:protect-crossover')
    expect(run18?.run).toContain('tests/protect-postgres-upgrade.e2e.test.ts')
    expect(run18?.env?.DATABASE_URL).toBe(
      '${{ steps.db18.outputs.database-url }}',
    )
    expect(runsWhen(run18.if, contextWithFailure(db18))).toBe(false)
  })
})

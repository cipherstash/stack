import { describe, expect, it } from 'vitest'
import { runsWhen } from './lib/expressions.mjs'
import {
  readSelectorJob,
  SELECTOR_JOB,
  selectedJobs,
  selectorOutputsRead,
} from './lib/selector.mjs'

/**
 * What the selector jobs of the credentialed integration and E2E workflows
 * decide for a pull request. Each filter keeps the list it replaced, which
 * integration-workflow-paths, wasm-build-inputs-paths-filter and
 * auth-binding-step-order check entry by entry. These pin the decisions and
 * that the fork guard still holds.
 */

const WORKFLOWS = {
  '.github/workflows/integration-drizzle.yml': 'integration',
  '.github/workflows/integration-prisma-next.yml': 'integration',
  '.github/workflows/integration-protect-ffi.yml': 'integration',
  '.github/workflows/integration-supabase.yml': 'integration',
  '.github/workflows/prisma-example-readme-e2e.yml': 'walkthrough',
  '.github/workflows/prisma-next-e2e.yml': 'e2e',
}

const REPO = 'cipherstash/stack'

for (const [relPath, job] of Object.entries(WORKFLOWS)) {
  describe(relPath, () => {
    const runs = (files) => selectedJobs(relPath, files).includes(job)

    it('has a selector job that decides the suite', () => {
      const selector = readSelectorJob(relPath)
      expect(selector).not.toBeNull()
      expect(selectorOutputsRead(selector.workflow.jobs[job])).toHaveLength(1)
    })

    it('runs the suite for a change to the binding it encrypts through', () => {
      expect(
        runs(['languages/typescript/packages/protect-ffi/crates/a/src/lib.rs']),
      ).toBe(true)
      expect(runs(['packages/eql/Cargo.toml'])).toBe(true)
      expect(runs([relPath])).toBe(true)
    })

    it('skips the suite for an unrelated change', () => {
      expect(runs(['languages/golang/encrypt/encrypt.go'])).toBe(false)
      expect(runs(['docs/sdk-design-principles.md'])).toBe(false)
    })

    it('still skips a fork pull request, whatever the selector says', () => {
      // The suite holds live credentials, which a fork run does not get.
      const output = selectorOutputsRead(
        readSelectorJob(relPath).workflow.jobs[job],
      )[0]
      const verdict = runsWhen(readSelectorJob(relPath).workflow.jobs[job].if, {
        github: {
          event_name: 'pull_request',
          repository: REPO,
          event: {
            pull_request: { head: { repo: { full_name: 'fork/stack' } } },
          },
        },
        needs: { [SELECTOR_JOB]: { outputs: { [output]: 'true' } } },
        vars: {},
      })
      expect(verdict).toBe(false)
    })
  })
}

describe('suite-specific trigger paths', () => {
  it('runs the protect-ffi suite for its own tests, and not the others', () => {
    const file =
      'languages/typescript/packages/protect-ffi/integration-tests/a.ts'
    expect(
      selectedJobs('.github/workflows/integration-protect-ffi.yml', [file]),
    ).toContain('integration')
    expect(
      selectedJobs('.github/workflows/integration-drizzle.yml', [file]),
    ).not.toContain('integration')
  })

  it('runs the Drizzle suite for stack-drizzle, and not the Prisma suites', () => {
    const file = 'languages/typescript/packages/stack-drizzle/src/index.ts'
    expect(
      selectedJobs('.github/workflows/integration-drizzle.yml', [file]),
    ).toContain('integration')
    expect(
      selectedJobs('.github/workflows/prisma-next-e2e.yml', [file]),
    ).not.toContain('e2e')
  })
})

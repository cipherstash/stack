import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  EQL_PACKAGE,
  eqlPipelineArmed,
  frozenReason,
} from '../eql-pipeline-armed.mjs'
import { FROZEN_PUBLISHERS } from '../release-gate.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The arming switch, and the wiring that makes it mean anything.
 *
 * Deriving the switch from `FROZEN_PUBLISHERS` buys nothing if a job stops
 * reading it, and a dropped `if:` is invisible: the pipeline is inert for other
 * reasons too, so an unguarded job behaves exactly like a guarded one right up
 * to the cutover, when it publishes. Hence the equality on the wiring below.
 */

const SCRIPT = join(REPO_ROOT, 'scripts/eql-pipeline-armed.mjs')

/**
 * Every job that must be gated on the switch.
 *
 * `promote-latest` is absent on purpose: it `needs:` two gated jobs, so it
 * cannot run without them, and its own `if:` carries the floating-tag policy.
 */
const GATED_JOBS = [
  '.github/workflows/release-plz.yml / release',
  '.github/workflows/release-postgres-eql-image.yml / build-images',
  '.github/workflows/release-postgres-eql-image.yml / build-sql',
  '.github/workflows/release.yml / eql-docs',
  '.github/workflows/release.yml / eql-docs-rebuild',
  '.github/workflows/release.yml / eql-image',
  '.github/workflows/release.yml / eql-sql',
  '.github/workflows/release.yml / prerelease-eql-crate',
  '.github/workflows/release.yml / prerelease-eql-docs',
  '.github/workflows/release.yml / prerelease-eql-npm',
  '.github/workflows/release.yml / prerelease-eql-sql',
]

/** The workflows that run the script, each exposing it as an `armed` output. */
const SWITCH_WORKFLOWS = [
  '.github/workflows/release.yml',
  '.github/workflows/release-plz.yml',
  '.github/workflows/release-postgres-eql-image.yml',
]

/** The condition text of every job in a workflow, keyed `<file> / <job>`. */
function jobConditions(relPath) {
  const wf = readWorkflow(relPath)
  return Object.entries(wf?.jobs ?? {}).map(([name, job]) => [
    `${relPath} / ${name}`,
    String(job?.if ?? '').replace(/\s+/g, ' '),
  ])
}

function run(env = {}) {
  return execFileSync('node', [SCRIPT], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  })
}

describe('the switch answers from FROZEN_PUBLISHERS', () => {
  it('is inert while the package is frozen', () => {
    expect(eqlPipelineArmed(new Map([[EQL_PACKAGE, 'a reason']]))).toBe(false)
  })

  it('is armed once the entry is gone — the cutover, exercised now', () => {
    // Without this the armed branch first executes at the cutover, which is the
    // worst moment to discover the switch was inverted.
    expect(eqlPipelineArmed(new Map())).toBe(true)
    expect(eqlPipelineArmed(new Map([['@cipherstash/other', 'x']]))).toBe(true)
  })

  it('reports the reason from the map, not from a sentence of its own', () => {
    expect(frozenReason(new Map([[EQL_PACKAGE, 'because']]))).toBe('because')
    expect(frozenReason(new Map())).toBeNull()
  })

  it('matches the live map, whichever state that is in', () => {
    // Not "is currently false" — pinning the verdict would make the cutover
    // fail here for no reason.
    expect(eqlPipelineArmed()).toBe(!FROZEN_PUBLISHERS.has(EQL_PACKAGE))
  })
})

describe('the switch is readable by a workflow', () => {
  it('writes `armed=` to GITHUB_OUTPUT', () => {
    const dir = mkdtempSync(join(tmpdir(), 'eql-armed-'))
    const outputFile = join(dir, 'output')
    try {
      execFileSync('sh', ['-c', `: > "${outputFile}"`])
      run({ GITHUB_OUTPUT: outputFile })
      expect(readFileSync(outputFile, 'utf8')).toBe(
        `armed=${eqlPipelineArmed()}\n`,
      )
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('says which state it is in, and why, on stdout', () => {
    const stdout = run()
    expect(stdout).toContain(EQL_PACKAGE)
    expect(stdout).toContain(eqlPipelineArmed() ? 'ARMED' : 'INERT')
    if (!eqlPipelineArmed()) expect(stdout).toContain(frozenReason())
  })

  it('does not write GITHUB_OUTPUT when there is none', () => {
    // A local run is how someone checks the answer before a cutover.
    const stdout = run({ GITHUB_OUTPUT: '' })
    expect(stdout).toContain(EQL_PACKAGE)
  })
})

describe('every EQL publish job reads it', () => {
  it('exposes the switch as a job output in each release workflow', () => {
    const missing = SWITCH_WORKFLOWS.filter((relPath) => {
      const job = readWorkflow(relPath)?.jobs?.['eql-armed']
      const runsIt = (job?.steps ?? []).some((step) =>
        String(step?.run ?? '').includes('scripts/eql-pipeline-armed.mjs'),
      )
      return !(runsIt && job?.outputs?.armed)
    })
    expect(
      missing,
      'These workflows publish an EQL artefact and no longer compute the arming switch, so nothing downstream can be gated on it.',
    ).toEqual([])
  })

  it('gates exactly the jobs that publish an EQL artefact', () => {
    const gated = SWITCH_WORKFLOWS.flatMap(jobConditions)
      .filter(([, condition]) =>
        condition.includes("needs.eql-armed.outputs.armed == 'true'"),
      )
      .map(([id]) => id)

    expect(
      gated.sort(),
      "The set of jobs gated on the EQL arming switch has changed. A job that LOST its guard will publish on the day the FROZEN_PUBLISHERS entry is deleted, whether or not anyone meant it to — and until then it is indistinguishable from a job that still has one. Spell the guard exactly `needs.eql-armed.outputs.armed == 'true'`.",
    ).toEqual(GATED_JOBS)
  })
})

import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import {
  isRunsOnJob,
  MATRIX_RUNNERS,
  RUNS_ON_LABELS,
  runsOnLabel,
} from './lib/runs-on.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * Every self-hosted job runs on a RunsOn machine of the size its Blacksmith
 * job had. ADR 0004 records the decision and the two labels.
 *
 * - No job names a Blacksmith label.
 * - Every RunsOn label is one of the labels ADR 0004 names. A job that ran out
 *   of memory may use the same label with `family=m8a`. Any other label, such
 *   as `cpu=8`, gives the job a machine of the wrong size.
 * - A job whose runner comes from an expression is listed in
 *   `MATRIX_RUNNERS`, with whether its matrix gives it RunsOn machines. The
 *   other guards read that list, because they cannot see which runner a matrix
 *   picks.
 */

const jobs = workflowFiles().flatMap((file) =>
  Object.entries(readWorkflow(file)?.jobs ?? {}).map(([id, job]) => ({
    ref: `${file}#${id}`,
    job,
  })),
)

const refsWhere = (predicate) => jobs.filter(predicate).map(({ ref }) => ref)

/** A runner chosen when the job starts, so a guard cannot read it. */
function isExpressionRunner(job) {
  const label = job?.['runs-on']
  if (label === undefined) return false
  if (typeof label !== 'string') return true
  return label.includes('${{') && !label.startsWith('runs-on=')
}

const expressionRunnerRefs = () =>
  refsWhere(({ job }) => isExpressionRunner(job))

// A new RunsOn machine can still be running apt from boot. apt-get fails at
// once on the held lock unless told to wait for it.
const APT_COMMAND =
  /\bapt(?:-get)?\s.*\b(?:update|install|upgrade|dist-upgrade|remove|purge|autoremove)\b/

export function aptFinding(run) {
  for (const line of String(run).split('\n')) {
    if (/^\s*#/.test(line)) continue
    if (APT_COMMAND.test(line) && !line.includes('DPkg::Lock::Timeout='))
      return `runs apt without waiting for the lock: "${line.trim()}". Add -o DPkg::Lock::Timeout=300.`
  }
  return null
}

/** A step, or the steps of the local composite action it uses. */
function stepsOf(step, seen = new Set()) {
  const uses = typeof step?.uses === 'string' ? step.uses.trim() : ''
  if (!uses.startsWith('./')) return [step]
  const dir = uses.replace(/^\.\//, '').replace(/\/$/, '')
  if (seen.has(dir)) return []
  seen.add(dir)
  for (const file of ['action.yml', 'action.yaml']) {
    const rel = `${dir}/${file}`
    if (existsSync(join(REPO_ROOT, rel)))
      return (readWorkflow(rel)?.runs?.steps ?? []).flatMap((inner) =>
        stepsOf(inner, seen),
      )
  }
  return []
}

export function aptFindingsInRunsOnJobs() {
  return jobs
    .filter(({ job, ref }) => isRunsOnJob(job, ref))
    .flatMap(({ ref, job }) =>
      (job.steps ?? []).flatMap((step, i) =>
        stepsOf(step)
          .map((inner) => aptFinding(inner?.run ?? ''))
          .filter(Boolean)
          .map((finding) => `${ref} step ${i + 1}: ${finding}`),
      ),
    )
}

describe('RunsOn runner labels', () => {
  it('builds the labels ADR 0004 names', () => {
    expect(runsOnLabel(16)).toBe(
      // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, the literal `runs-on` value under test.
      'runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=16/image=ubuntu22-full-x64/volume=80gb/extras=s3-cache',
    )
    expect(runsOnLabel(4)).toBe(
      // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, the literal `runs-on` value under test.
      'runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache',
    )
    expect(runsOnLabel(4, { family: 'm8a' })).toBe(
      // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, the literal `runs-on` value under test.
      'runs-on=${{ github.run_id }}/family=m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache',
    )
    expect(() => runsOnLabel(8)).toThrow()
  })

  it('finds the jobs it checks', () => {
    // A scan that finds nothing passes every check below.
    expect(
      jobs.filter(({ job, ref }) => isRunsOnJob(job, ref)).length,
    ).toBeGreaterThan(50)
  })

  it('names no Blacksmith label', () => {
    // JSON.stringify also covers a runs-on that is a list or an object.
    expect(
      refsWhere(({ job }) =>
        /blacksmith-/.test(JSON.stringify(job?.['runs-on'] ?? '')),
      ),
    ).toEqual([])
  })

  it('uses only the labels ADR 0004 names', () => {
    expect(
      refsWhere(({ job }) => {
        const label = job?.['runs-on']
        return (
          typeof label === 'string' &&
          label.startsWith('runs-on=') &&
          !RUNS_ON_LABELS.has(label)
        )
      }),
    ).toEqual([])
  })

  it('lists every job whose runner comes from an expression', () => {
    // Both directions: a new matrix job must be listed, and an entry whose
    // job is gone must be removed.
    expect(expressionRunnerRefs().sort()).toEqual(
      Object.keys(MATRIX_RUNNERS).sort(),
    )
    expect(
      Object.values(MATRIX_RUNNERS).every(({ reason }) => reason.trim()),
    ).toBe(true)
  })
})

describe('apt on a new RunsOn machine', () => {
  it('recognises an apt command that does not wait for the lock', () => {
    expect(aptFinding('sudo apt-get update')).toMatch(/DPkg::Lock::Timeout/)
    expect(aptFinding('sudo apt install -y jq')).toMatch(/DPkg::Lock::Timeout/)
    expect(
      aptFinding('sudo apt-get -o DPkg::Lock::Timeout=300 install -y doxygen'),
    ).toBeNull()
    expect(aptFinding('# sudo apt-get update')).toBeNull()
    expect(aptFinding('apt-cache policy doxygen')).toBeNull()
  })

  it('waits for the apt lock in every RunsOn job', () => {
    expect(aptFindingsInRunsOnJobs()).toEqual([])
  })
})

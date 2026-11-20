/**
 * The RunsOn labels ADR 0004 names, and which jobs run on RunsOn. Shared by
 * the guards that hold RunsOn jobs to their rules.
 */

// biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, written into the label verbatim.
const RUN_ID_EXPRESSION = '${{ github.run_id }}'

// Each Blacksmith size keeps its Ubuntu version on RunsOn.
const IMAGE_FOR_CPU = { 16: 'ubuntu22-full-x64', 4: 'ubuntu24-full-x64' }

/** `family: 'm8a'` is for a job that ran out of memory on c8a's 2 GB per vCPU. */
export function runsOnLabel(
  cpu,
  { family = 'c8a+m8a', runId = RUN_ID_EXPRESSION } = {},
) {
  const image = IMAGE_FOR_CPU[cpu]
  if (!image)
    throw new Error(`ADR 0004 names no RunsOn label with ${cpu} vCPUs`)
  return `runs-on=${runId}/family=${family}/cpu=${cpu}/image=${image}/volume=80gb/extras=s3-cache`
}

export const RUNS_ON_LABELS = new Set([
  runsOnLabel(16),
  runsOnLabel(4),
  runsOnLabel(16, { family: 'm8a' }),
  runsOnLabel(4, { family: 'm8a' }),
])

// A guard cannot read which runner a matrix picks, so each such job is
// classified here. workflow-runs-on.test.mjs keeps this list complete.
export const MATRIX_RUNNERS = {
  '.github/workflows/_build-ffi-artifacts.yml#binaries': {
    runsOn: true,
    reason:
      'scripts/ffi-release-matrix.mjs gives every Linux platform a RunsOn label.',
  },
  '.github/workflows/_build-auth-artifacts.yml#binaries': {
    runsOn: false,
    reason: 'Its matrix names GitHub-hosted runners only.',
  },
  '.github/workflows/tests-golang.yml#go-binding-cross': {
    runsOn: false,
    reason: 'Its matrix is macos-latest and windows-latest.',
  },
}

export function isRunsOnJob(job, ref) {
  const label = job?.['runs-on']
  if (typeof label === 'string' && label.startsWith('runs-on=')) return true
  return MATRIX_RUNNERS[ref]?.runsOn === true
}

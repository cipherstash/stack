import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * No `run:` block may pipe a command into `grep -q`.
 *
 * `grep -q` exits at the first match. Whatever is writing upstream then takes
 * SIGPIPE, and `pipefail` — which GitHub turns on for every `shell: bash` step,
 * before any `set -euo pipefail` the block writes itself — makes the pipeline's
 * status that of the killed writer, 141. So the pipeline reports FAILURE on a
 * successful match. The more the writer has left to say, the likelier it is.
 *
 * Two things make this worth a guard rather than a fix in place.
 *
 * It is platform-split, so it does not look like a shell bug. GNU tar writes an
 * entry at a time and hits it; bsdtar buffers a short listing into one write
 * and does not. `_build-ffi-artifacts.yml`'s "does the tarball contain
 * index.node" check therefore passed on both Darwin legs of the FFI matrix and
 * failed on Linux and Windows — presenting as a cross-compilation problem, on
 * the packaging step, in a pipeline that had just been rewritten.
 *
 * And the direction it fails in is not fixed. `cmd | grep -q x || die` fails
 * CLOSED — noisy, and someone investigates. `if cmd | grep -q x ; then die ; fi`
 * fails OPEN: the poisoned status makes the condition false and the check
 * silently passes. `ffi-preflight.yml` had one of each, and the open one was
 * the check that stops a glibc binary shipping inside the musl platform
 * package — a failure that lands on an Alpine user at `dlopen`, not in CI.
 *
 * The fix is to capture first and match against the variable:
 *
 *   listing=$(tar tzf "$tgz")
 *   grep -qx package/index.node <<< "$listing" || die
 *
 * `grep -q` reading a FILE or a here-string is fine and stays allowed — there
 * is no writer to signal. Only pipelines are rejected.
 */

/** Composite actions are part of the same call tree, and run the same shells. */
function actionManifests() {
  const dir = '.github/actions'
  return readdirSync(join(REPO_ROOT, dir), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => `${dir}/${entry.name}/action.yml`)
    .sort()
}

/** Every `run:` script in a workflow or composite action, with its location. */
function runBlocks(doc, file) {
  const fromJobs = Object.entries(doc.jobs ?? {}).flatMap(([jobId, job]) =>
    (job.steps ?? [])
      .filter((step) => typeof step.run === 'string')
      .map((step) => ({
        file,
        where: `${jobId} › ${step.name ?? '(unnamed)'}`,
        run: step.run,
      })),
  )
  const fromAction = (doc.runs?.steps ?? [])
    .filter((step) => typeof step.run === 'string')
    .map((step) => ({ file, where: step.name ?? '(unnamed)', run: step.run }))
  return [...fromJobs, ...fromAction]
}

/**
 * A pipe into grep carrying `-q` in any spelling: `-q`, `-qx`, `--quiet`, and
 * the same after other flags. Deliberately not trying to parse shell — a
 * pattern that over-matches here costs a comment on a line that should be
 * rewritten anyway.
 */
const PIPED_QUIET_GREP = /\|\s*grep\s+(?:-[a-zA-Z]*q[a-zA-Z]*|--quiet)\b/

describe('no run: block pipes into grep -q', () => {
  const files = [...workflowFiles(), ...actionManifests()]

  it('finds workflows and composite actions to check', () => {
    expect(files.length).toBeGreaterThan(0)
  })

  const offenders = files.flatMap((file) =>
    runBlocks(readWorkflow(file), file)
      .flatMap(({ where, run }) =>
        run
          .split('\n')
          .map((line, i) => ({ where, line: line.trim(), number: i + 1 }))
          .filter(({ line }) => PIPED_QUIET_GREP.test(line)),
      )
      .map((hit) => `${file} › ${hit.where} › line ${hit.number}: ${hit.line}`),
  )

  it('has none', () => {
    expect(offenders).toEqual([])
  })
})

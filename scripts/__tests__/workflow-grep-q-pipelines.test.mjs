import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync } from 'node:fs'
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
 *
 * The second `describe` below extends the same rule to tracked shell scripts,
 * because the hazard is a property of the shell and not of GitHub Actions.
 * `packages/eql/tasks/test/docs_v3_grep.sh` had it in the fail-OPEN direction:
 *
 *   elif tasks/docs/doxygen-filter.sh src/v3/json/functions.sql | grep -q 'ste_vec_contains'
 *
 * On the failure path — the deprecated aliases DO leak through the Doxygen
 * filter — grep matched, exited 0, and closed the pipe; awk took SIGPIPE, the
 * pipeline reported 141 under `set -o pipefail`, the `elif` was false, and the
 * FAIL branch never ran. Only the clean case was reported correctly, so the
 * guard could only ever say "OK". Measured at 141 against the real 16 KB filter
 * output on macOS, whose pipe buffer starts at 16 KB; Linux's 64 KB buffer hid
 * it, which is exactly the platform split the tar case above describes.
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

/**
 * Whole-line `#` comments are not code, and the rule has to survive being
 * WRITTEN DOWN: the fix comment on `docs_v3_grep.sh` quotes the very pipeline
 * it replaced, and without this the guard reported the explanation as the
 * defect. Only leading-`#` lines are skipped — stripping `#` to end-of-line
 * would eat it out of grep patterns and quoted strings.
 */
const isComment = (line) => /^\s*#/.test(line)

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
          .filter(
            ({ line }) => !isComment(line) && PIPED_QUIET_GREP.test(line),
          ),
      )
      .map((hit) => `${file} › ${hit.where} › line ${hit.number}: ${hit.line}`),
  )

  it('has none', () => {
    expect(offenders).toEqual([])
  })
})

/**
 * `echo` and `printf` writing a bounded diagnostic string — an error message, a
 * captured comment block — are exempt: the whole write lands in the pipe buffer
 * before grep can exit, so there is no blocked writer left to signal. The
 * exemption is about SIZE, not about them being builtins (a builtin in a
 * pipeline still runs in a subshell and still takes SIGPIPE), so `echo "$x"`
 * where `$x` could grow past a pipe buffer would reintroduce the hazard. Every
 * exempted call site in this tree pipes a short, known-bounded string.
 */
const BOUNDED_WRITERS = new Set(['echo', 'printf'])

/** The first word of the command immediately upstream of the `| grep -q`. */
function upstreamWriter(line) {
  const match = line.match(PIPED_QUIET_GREP)
  if (!match) return null
  const feeding = line.slice(0, match.index).split('|').pop() ?? ''
  let head = feeding.trim()
  let previous
  do {
    previous = head
    head = head
      .replace(/^(?:!|if|elif|while|until|then|do|&&|\|\||;)\s*/, '')
      .trim()
  } while (head !== previous)
  return head.split(/\s+/)[0] ?? ''
}

/** Tracked shell scripts, via git so it honours .gitignore. */
function shellScripts() {
  return execFileSync('git', ['ls-files', '-z', '--', '*.sh'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
    .split('\0')
    .filter(Boolean)
}

describe('no shell script pipes an unbounded writer into grep -q', () => {
  const scripts = shellScripts()

  it('finds shell scripts to check', () => {
    expect(scripts.length).toBeGreaterThan(0)
    expect(scripts).toContain('packages/eql/tasks/test/docs_v3_grep.sh')
  })

  it('parses the upstream writer out of a pipeline', () => {
    // The classifier is what decides whether a line is reported, so a bug in it
    // silently empties the check below.
    expect(upstreamWriter('if ! echo "$b" | grep -q "@brief"; then')).toBe(
      'echo',
    )
    expect(upstreamWriter("printf '%s' \"$err\" | grep -qi 'HTTP 404'")).toBe(
      'printf',
    )
    expect(
      upstreamWriter("elif tasks/docs/doxygen-filter.sh x.sql | grep -q 'y'"),
    ).toBe('tasks/docs/doxygen-filter.sh')
    expect(upstreamWriter('cat f | tr a b | grep -q x')).toBe('tr')
    expect(upstreamWriter('grep -q x file')).toBeNull()
    expect(isComment('  # never `foo.sh | grep -q bar`')).toBe(true)
    expect(isComment('grep -q \'#tag\' <<< "$x"')).toBe(false)
  })

  const offenders = scripts.flatMap((file) =>
    readFileSync(join(REPO_ROOT, file), 'utf8')
      .split('\n')
      .map((line, i) => ({ line: line.trim(), number: i + 1 }))
      .filter(({ line }) => {
        if (isComment(line)) return false
        const writer = upstreamWriter(line)
        return writer !== null && !BOUNDED_WRITERS.has(writer)
      })
      .map((hit) => `${file}:${hit.number}: ${hit.line}`),
  )

  it('has none', () => {
    expect(
      offenders,
      'Capture the output first and match against the variable:\n' +
        '  out=$(producer)\n' +
        '  grep -q pattern <<< "$out"',
    ).toEqual([])
  })
})

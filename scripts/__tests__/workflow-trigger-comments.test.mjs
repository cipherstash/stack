import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A CI comment that describes WHEN a step runs is load-bearing documentation,
 * and it is the one kind of documentation nothing in this repo checks. The YAML
 * around it is validated six ways — `integration-workflow-paths.test.mjs`
 * compares the two copies of every `paths:` filter,
 * `ffi-binding-step-order.test.mjs` checks step order and coverage,
 * `workflow-dispatch-job-conditions.test.mjs` checks the fork gate — while the
 * prose explaining the filter to the next reader is free to say the opposite of
 * what the filter does.
 *
 * It did. Both prisma workflows carried "the step itself is only ever exercised
 * by the push-to-main run", written when the protect-ffi inputs were about to be
 * added to the `push` filter, and left in place after they were added to the
 * `pull_request` filter as well. A PR touching `packages/protect-ffi/src/**` has
 * run both workflows since the day those entries landed. The comment told you it
 * could not — which is worse than no comment, because the next person reasoning
 * about protect-ffi coverage on PRs reads it and concludes there is none, and
 * either adds a redundant job or drops a filter entry to "make it consistent".
 *
 * So: the invariant here is agreement between the filter and the prose, DERIVED
 * from the parsed `on:` block rather than asserted against a fixed sentence. A
 * workflow that a protect-ffi change can trigger on `pull_request` may not
 * contain a comment that names `push to main` as the trigger and stops there. If
 * the filter loses its protect-ffi entries tomorrow, the workflow drops out of
 * scope and the push-only sentence becomes legal again — which is the property
 * you want, and the one a "these files must contain this string" check cannot
 * express.
 *
 * WHAT THIS DOES NOT COVER, deliberately:
 *
 * - The fork-PR caveat. Both jobs are gated on
 *   `github.event.pull_request.head.repo.full_name == github.repository`, so a
 *   fork PR triggers the workflow and then skips the job for want of CS_*
 *   credentials. The comments say so in prose; requiring the word "fork" in
 *   every comment that mentions a PR trigger would fail comments that had no
 *   business discussing forks.
 * - "Path-filtered away from the absorption PR", the other false half of the
 *   same two comments — false because each workflow lists its own path, the
 *   build action, and the protect-ffi package in its own filter, and the
 *   absorption branch edits all three. Checking it mechanically would mean
 *   knowing what a particular PR touches, which a test in the tree cannot.
 * - Trailing inline comments (`key: value # note`). Only full-line comment
 *   blocks are scanned, because a `#` inside a quoted YAML scalar is not a
 *   comment and telling the two apart needs a real parser. Every long-form
 *   explanation in the workflow directory is a full-line block today; if one of
 *   these claims ever shows up inline, this will not see it.
 */

const BUILD_FFI_ACTION = '.github/actions/build-ffi-binding'

/**
 * The files that, when edited, change what the binding build produces —
 * read out of the action's own cache keys rather than listed here.
 *
 * `build-ffi-binding` caches `index.node` and `dist/wasm` on `hashFiles(...)`
 * of its inputs, so those globs ARE the definition of "a change to the
 * binding": anything in them must miss the cache and recompile. Reusing them
 * means this scope follows the action. Add a build input to the key and the set
 * of workflows held to the invariant below grows with it; the alternative — a
 * hardcoded `packages/protect-ffi/**` — would keep passing while quietly
 * describing a different package than the one CI builds.
 *
 * The action's own directory is in the set for the same reason it is in both
 * workflows' `paths:` filters: editing the action changes the build.
 */
function bindingBuildInputs() {
  const action = yaml.load(
    readFileSync(join(REPO_ROOT, `${BUILD_FFI_ACTION}/action.yml`), 'utf8'),
  )
  const inputs = new Set([`${BUILD_FFI_ACTION}/**`])
  for (const step of action?.runs?.steps ?? []) {
    for (const call of String(step?.with?.key ?? '').matchAll(
      /hashFiles\(([^)]*)\)/g,
    )) {
      for (const arg of call[1].matchAll(/'([^']*)'/g)) inputs.add(arg[1])
    }
  }
  return [...inputs]
}

const BINDING_INPUTS = bindingBuildInputs()

/**
 * Do a `paths:` entry and a build input describe overlapping trees?
 *
 * Overlap in EITHER direction, because both sides are globs and either can be
 * the broader one: the filter may say `packages/protect-ffi/src/**` against an
 * input file, or `packages/protect-ffi/crates/protect-ffi/**` against the
 * input glob `packages/protect-ffi/crates/**`. Both mean a change to the
 * binding can trigger the workflow, which is the only question being asked.
 */
function overlaps(entry, input) {
  const literal = entry.replace(/\*\*$/, '').replace(/\/$/, '')
  const target = input.replace(/\*\*$/, '').replace(/\/$/, '')
  return (
    literal === target ||
    target.startsWith(`${literal}/`) ||
    literal.startsWith(`${target}/`)
  )
}

/**
 * How a protect-ffi change reaches this workflow through `pull_request`:
 * `'unfiltered'` (no `paths:`, so every PR runs it), `'filtered'` (a `paths:`
 * entry overlaps a binding input), or `false` (it cannot).
 *
 * `on:` parses as the boolean `true` under YAML 1.1 — the "Norway problem" —
 * hence `wf.on ?? wf[true]`. And `Object.hasOwn` rather than a truthiness test:
 * a bare `pull_request:` with no body parses to `null` and triggers on
 * everything, which is the opposite of what `!pr` would conclude.
 *
 * `wf` itself is optional-chained because `readWorkflow` hands back whatever
 * `yaml.load` returned, and that is `null` for a comment-only file and
 * `undefined` for an empty one — see the fixtures below.
 */
function pullRequestReach(wf) {
  const on = wf?.on ?? wf?.[true]
  if (!on || !Object.hasOwn(on, 'pull_request')) return false
  const paths = on.pull_request?.paths
  if (!Array.isArray(paths) || paths.length === 0) return 'unfiltered'
  const reached = paths.some((entry) =>
    BINDING_INPUTS.some((input) => overlaps(entry, input)),
  )
  return reached ? 'filtered' : false
}

/**
 * Full-line comment blocks, as `{ startLine, text }`. Consecutive `#` lines are
 * one block — a bare `#` separator line included, so a paragraph stays whole and
 * a sentence split across two lines is matched as one string rather than two
 * halves that each match nothing.
 */
function commentBlocks(relPath) {
  const lines = readFileSync(join(REPO_ROOT, relPath), 'utf8').split('\n')
  const blocks = []
  let current = null
  for (const [index, line] of lines.entries()) {
    if (line.trim().startsWith('#')) {
      if (!current) {
        current = { startLine: index + 1, parts: [] }
        blocks.push(current)
      }
      current.parts.push(line.trim().replace(/^#+\s?/, ''))
    } else {
      current = null
    }
  }
  return blocks.map(({ startLine, parts }) => ({
    startLine,
    text: parts.join(' ').replace(/\s+/g, ' ').trim(),
  }))
}

/** Names the push-to-main trigger: "push to main", "push-to-main run". */
const NAMES_PUSH_TRIGGER = /push[\s-]+to[\s-]+main/i

/**
 * Names the pull_request trigger too. Several forms, because the point is to
 * recognise the acknowledgement rather than to mandate a phrasing — and one
 * form it must NOT accept is a bare mention of some PR as a noun. "the
 * absorption PR that introduced the need" is not a statement about when the
 * step runs, and the comment that contained it was exactly the one claiming
 * push-to-main exclusivity in the same breath.
 */
const NAMES_PR_TRIGGER = [
  /\bpull_request\b/,
  /\bon (?:any|every|each|all|a) [^.]{0,60}?\bPRs?\b/i,
  /\bon (?:any|every|each|all) [^.]{0,60}?pull requests?\b/i,
  /\bPRs?\b[^.]{0,40}?(?:touching|touches|matching|match(?:es)? the|whose diff)/i,
]

const IN_SCOPE = workflowFiles().filter(
  (relPath) => pullRequestReach(readWorkflow(relPath)) !== false,
)

/** Per in-scope workflow, the comment blocks that name the push trigger. */
const CLAIMS = new Map(
  IN_SCOPE.map((relPath) => [
    relPath,
    commentBlocks(relPath).filter((block) =>
      NAMES_PUSH_TRIGGER.test(block.text),
    ),
  ]),
)

/**
 * The guard on the scan, in the shape the rest of this directory uses (see
 * `EXPECTED_PAIRED_JOBS` in `ffi-binding-step-order.test.mjs`, and the
 * scan-found-something assertions in `ffi-binding-action.test.mjs`). Every
 * check below is "no comment in this set violates X", and an empty set
 * satisfies that for free.
 *
 * Held as a minimum: a new workflow that a protect-ffi change can trigger on a
 * PR must not fail this. If one genuinely stops being reachable that way,
 * update the list deliberately — the entry disappearing is the same event as
 * the coverage disappearing.
 */
const EXPECTED_IN_SCOPE = [
  '.github/workflows/integration-drizzle.yml',
  '.github/workflows/integration-prisma-next.yml',
  '.github/workflows/integration-protect-ffi.yml',
  '.github/workflows/integration-supabase.yml',
  '.github/workflows/prisma-example-readme-e2e.yml',
  '.github/workflows/prisma-next-e2e.yml',
  '.github/workflows/tests-rust.yml',
  '.github/workflows/tests.yml',
]

/**
 * The workflows that today explain their trigger in prose naming push-to-main.
 * The second half of the guard, and the one that catches a broken scan rather
 * than a broken scope: `commentBlocks` returning nothing, or
 * `NAMES_PUSH_TRIGGER` stopping matching, empties `CLAIMS` for every file and
 * the per-file checks below stop being generated — silently, since a `describe`
 * that produces no `it` reports success.
 *
 * If a comment here is deleted or reworded off the push trigger, that is fine
 * and this needs a deliberate edit. It is not fine for all of them to vanish at
 * once, which is what a regex or parser regression looks like.
 */
const EXPECTED_CLAIM_FILES = [
  '.github/workflows/prisma-example-readme-e2e.yml',
  '.github/workflows/prisma-next-e2e.yml',
]

describe('workflow trigger comments match the trigger', () => {
  it('derives the binding build inputs from the action manifest', () => {
    expect(
      BINDING_INPUTS,
      `No \`hashFiles(...)\` globs were parsed out of ${BUILD_FFI_ACTION}/action.yml, so "a change to the protect-ffi binding" resolves to nothing and every workflow falls out of scope. Either the cache steps moved (follow them), or the key syntax changed (update bindingBuildInputs).`,
    ).toContain('packages/protect-ffi/crates/**')
    expect(BINDING_INPUTS).toContain(`${BUILD_FFI_ACTION}/**`)
  })

  it('finds the workflows a protect-ffi change can trigger on a PR', () => {
    const missing = EXPECTED_IN_SCOPE.filter((file) => !IN_SCOPE.includes(file))
    expect(
      missing,
      `A protect-ffi change used to reach these workflows through \`on.pull_request\`, and the scan no longer sees it. Either a \`paths:\` filter dropped its protect-ffi entries — in which case the coverage went with them — or \`pullRequestReach\` needs teaching about a new filter shape. Found:\n${IN_SCOPE.map((file) => `  ${file}`).join('\n')}`,
    ).toEqual([])
  })

  it('finds the trigger-claim comments it means to inspect', () => {
    const missing = EXPECTED_CLAIM_FILES.filter(
      (file) => (CLAIMS.get(file) ?? []).length === 0,
    )
    expect(
      missing,
      `These workflows explained their trigger in a comment naming push-to-main, and the scan no longer finds one. If the comments were deliberately reworded, update EXPECTED_CLAIM_FILES; if not, \`commentBlocks\` or NAMES_PUSH_TRIGGER has stopped working and the per-file checks below are no longer being generated at all.`,
    ).toEqual([])
  })

  /**
   * `IN_SCOPE` is built at module load, over EVERY file in the workflow
   * directory, before a single `it` has been registered — so a workflow
   * `pullRequestReach` cannot read does not fail one test, it aborts collection
   * and takes this whole file with it. What the reader sees is a TypeError
   * against a line of test infrastructure, with no mention of the workflow that
   * caused it and no result at all from the checks that would have run.
   *
   * And "cannot read" is not exotic: `yaml.load` returns `null` for a file that
   * is only comments and `undefined` for an empty one, which is what a workflow
   * looks like for the length of the commit that adds its header before its
   * jobs. The sibling `ffi-binding-step-order.test.mjs` has always spelt its
   * equivalent `wf?.jobs ?? {}`; this one read `wf.on` bare.
   *
   * A file that parses to nothing declares no triggers, so `false` — out of
   * scope — is also the honest answer, not merely the safe one. Fixtures rather
   * than the real directory, because the failure has to be reproducible without
   * committing a broken workflow to a directory GitHub reads.
   */
  describe('a workflow file that parses to nothing', () => {
    const UNPARSED = [
      'scripts/__tests__/fixtures/workflow-trigger-comments/comment-only.yml',
      'scripts/__tests__/fixtures/workflow-trigger-comments/empty.yml',
    ]

    for (const relPath of UNPARSED) {
      it(`reports no reach for ${relPath.split('/').pop()}`, () => {
        const wf = readWorkflow(relPath)
        // Both spellings of "nothing" reach this function — `null` from the
        // comment-only file, `undefined` from the empty one — and optional
        // chaining is what makes them the same case.
        expect(wf ?? null).toBeNull()
        expect(pullRequestReach(wf)).toBe(false)
      })
    }

    // The module-level line itself (`IN_SCOPE`), run over the fixtures. The
    // assertion is `[]`, but the property under test is that the expression
    // above it evaluates at all.
    it('drops out of the scan rather than aborting it', () => {
      const inScope = UNPARSED.filter(
        (relPath) => pullRequestReach(readWorkflow(relPath)) !== false,
      )
      expect(inScope).toEqual([])
    })
  })

  for (const relPath of IN_SCOPE) {
    const blocks = CLAIMS.get(relPath) ?? []
    if (blocks.length === 0) continue

    it(`${relPath} does not describe the trigger as push-to-main only`, () => {
      const reach = pullRequestReach(readWorkflow(relPath))
      const offenders = blocks
        .filter(
          (block) => !NAMES_PR_TRIGGER.some((form) => form.test(block.text)),
        )
        .map((block) => `  line ${block.startLine}: ${block.text}`)

      expect(
        offenders,
        `These comments in ${relPath} name \`push\` to main as the trigger and never mention \`pull_request\`, but a change to the protect-ffi binding reaches this workflow on a pull request too — ${
          reach === 'unfiltered'
            ? 'it has no `paths:` filter on `pull_request`, so every PR runs it'
            : 'its `pull_request` `paths:` filter carries the binding inputs'
        }. Reword them to name both events; a comment that under-states when a step runs sends the next reader looking for coverage that is already there.\n${offenders.join('\n')}`,
      ).toEqual([])
    })
  }
})

import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * GitHub Actions has no YAML anchors, so a workflow that wants the same
 * `paths:` filter on `push` and `pull_request` has to write the list twice.
 * Nothing makes the copies agree, and a one-sided edit is silent in the worst
 * direction: drop an entry from the `pull_request` copy and the workflow keeps
 * running on `main`, keeps reporting green, and stops running on the pull
 * request — which is the only run that could have caught the change before it
 * landed. The reverse edit is loud by comparison; you notice a job that never
 * runs on main.
 *
 * This invariant is NOT integration-specific, and for a long time the check was.
 * It lived in `integration-workflow-paths.test.mjs`, whose discovery selects
 * workflows by their `CS_IT_SUITE` globs — two files today. The other seven
 * workflows that write the list twice were covered by nothing, including the
 * two prisma e2e workflows whose own comments (until this file existed) claimed
 * otherwise. Generalising it costs nothing: all nine were already identical, so
 * the widened check went green on the first run and the coverage roughly
 * quadrupled.
 *
 * The comparison is on the PARSED lists, not the text. Comments between entries,
 * ordering of unrelated keys and quoting style are all free to differ; only the
 * sequence of path globs has to match, because only that is what GitHub reads.
 *
 * THE ASYMMETRY CASE is the interesting half. A workflow declaring `paths:` on
 * one event and not the other has no second copy to compare, so it drops out of
 * the parity check entirely — and "drops out of the check" is exactly what a
 * one-sided DELETION looks like. `tests-rust.yml` is a legitimate instance and
 * therefore the reason the expected-asymmetry map below is not just an
 * exemption but a fixed list: a tenth workflow arriving in that state has to be
 * justified in writing rather than quietly stop being checked.
 */

/** The two events whose filters are written out separately. */
const FILTERED_EVENTS = ['push', 'pull_request']

/**
 * A workflow's `paths:` filters, per event, `null` where the event declares
 * none.
 *
 * `on:` parses as the boolean `true` under YAML 1.1 — the "Norway problem" —
 * hence `wf.on ?? wf[true]`. An event key present with no `paths:` (a bare
 * `pull_request:`, or `push: { branches: [main] }`) is `null` here and means
 * "unfiltered", which is a different thing from an empty list and a very
 * different thing from a filter that lost an entry.
 */
function pathsFilters(relPath) {
  const wf = readWorkflow(relPath)
  const on = wf?.on ?? wf?.[true]
  return Object.fromEntries(
    FILTERED_EVENTS.map((event) => [
      event,
      Array.isArray(on?.[event]?.paths) ? on[event].paths : null,
    ]),
  )
}

const CLASSIFIED = workflowFiles().map((relPath) => {
  const filters = pathsFilters(relPath)
  const declared = FILTERED_EVENTS.filter((event) => filters[event] !== null)
  return { relPath, filters, declared }
})

/** Workflows writing the list twice — the ones the parity check applies to. */
const PARITY = CLASSIFIED.filter((entry) => entry.declared.length === 2)

/** Workflows filtering one event and not the other. */
const ASYMMETRIC = CLASSIFIED.filter((entry) => entry.declared.length === 1)

/**
 * The guard on the scan, in the shape the rest of this directory uses. Every
 * assertion below is "these two lists agree", and a scan that finds no
 * workflows satisfies that for free.
 *
 * Held as a minimum: a new workflow that filters both events must not fail
 * this. A workflow LEAVING the list is the event worth interrupting for —
 * either it stopped filtering both events (see the asymmetry check, which will
 * also fire) or the discovery broke.
 */
const EXPECTED_PARITY_WORKFLOWS = [
  '.github/workflows/fta-v3.yml',
  '.github/workflows/integration-drizzle.yml',
  '.github/workflows/integration-prisma-next.yml',
  '.github/workflows/integration-protect-ffi.yml',
  '.github/workflows/integration-supabase.yml',
  '.github/workflows/prisma-example-readme-e2e.yml',
  '.github/workflows/prisma-next-e2e.yml',
  '.github/workflows/tests-bench.yml',
  '.github/workflows/tests-supply-chain.yml',
]

/**
 * Workflows that deliberately filter one event and not the other, each with the
 * reason. An entry here is a workflow the parity check cannot see, so the
 * reason has to explain why the drift it guards against is not possible.
 */
const EXPECTED_ASYMMETRIES = new Map([
  [
    '.github/workflows/tests-rust.yml',
    // `push:` is `branches: [main]` with no `paths:`, so every push to main runs
    // the Rust checks and only pull requests are filtered. There is no second
    // list to drift from, and the direction that would hurt — a `push` filter
    // narrower than the `pull_request` one, letting a change land on main
    // unchecked — is unreachable when `push` is unfiltered.
    'push is deliberately unfiltered (branches: [main]), so main runs a superset of what PRs run',
  ],
  [
    '.github/workflows/lint-release.yml',
    // There is no `push:` trigger at all — this gate exists to catch a broken
    // release workflow BEFORE it merges, and a copy running after the merge
    // would report the same finding at the moment it is no longer useful. With
    // one event there is no second list to drift from, and the direction that
    // would hurt (a narrower `pull_request` filter, so the PR that breaks the
    // release machinery never runs the check) is what the single list IS.
    'pull_request is the only trigger; a post-merge copy would report a release-blocking finding too late to act on',
  ],
  [
    '.github/workflows/test-eql.yml',
    // `pull_request` is deliberately UNFILTERED and `push: branches: [main]`
    // carries the list, which is the same shape as tests-rust.yml with the two
    // events swapped. Unfiltered on the PR side because this workflow's
    // `ci-required` is the check branch protection is meant to reference, and a
    // workflow skipped by a path filter leaves a required check stuck Pending;
    // relevance is applied per-job via `if:` instead. Filtered on the push side
    // because nothing waits on a push run, so skipping one costs nothing.
    //
    // The direction that would hurt — a `pull_request` filter narrower than the
    // `push` one, so the PR introducing a change never runs the suite — is
    // unreachable when `pull_request` has no filter at all. The push list is
    // not unchecked: `eql-workflow-filters.test.mjs` compares it against the
    // `relevant:` filter in the `changes` job, which is the second copy of the
    // same list and the one this file cannot see.
    'pull_request is deliberately unfiltered (per-job relevance instead), so PRs run a superset of what push runs; the push list is compared against the `changes` job filter by eql-workflow-filters.test.mjs',
  ],
  [
    '.github/workflows/bench-eql.yml',
    // The mirror image of lint-release.yml: `push: branches: [main]` with a
    // `paths:` list, and no `pull_request:` trigger at all. Deliberate upstream
    // and unchanged by the port — the bench suite is budgeted at 60 minutes and
    // runs the slow `bench`-gated SQLx tests, so it stays off the PR path and
    // catches regressions after merge and nightly. With one event there is no
    // second list to drift from, and the direction that would hurt (a narrower
    // PR filter) does not exist because PRs never run it.
    'push to main and a nightly schedule are the only triggers; a 60-minute bench deliberately stays off the PR path',
  ],
])

describe('paths filters are written twice, identically', () => {
  it('finds the workflows that filter both events', () => {
    const found = PARITY.map((entry) => entry.relPath)
    const missing = EXPECTED_PARITY_WORKFLOWS.filter(
      (relPath) => !found.includes(relPath),
    )
    expect(
      missing,
      `These workflows declared \`paths:\` under both \`push\` and \`pull_request\`, and the scan no longer sees it. A workflow that stops filtering both events stops being parity-checked — which is indistinguishable from a one-sided deletion, the exact edit this file exists to catch. Either justify the change in EXPECTED_ASYMMETRIES, or restore the filter. Found:\n${found.map((relPath) => `  ${relPath}`).join('\n')}`,
    ).toEqual([])
  })

  it('accounts for every workflow that filters only one event', () => {
    const unexplained = ASYMMETRIC.filter(
      (entry) => !EXPECTED_ASYMMETRIES.has(entry.relPath),
    ).map(
      (entry) =>
        `  ${entry.relPath} filters \`${entry.declared[0]}\` only (${entry.filters[entry.declared[0]].length} entries)`,
    )
    expect(
      unexplained,
      `These workflows filter one event and not the other, so nothing compares their filters — and a workflow arrives in that state either deliberately or because someone deleted one copy.\nIf it is deliberate, add it to EXPECTED_ASYMMETRIES with the reason the drift this file guards against cannot happen there.\n${unexplained.join('\n')}`,
    ).toEqual([])
  })

  it('keeps no stale asymmetry exemptions', () => {
    // The mirror of the check above, and the one that matters when a workflow
    // is FIXED: an entry that no longer describes an asymmetry sits there
    // reading as deliberate while exempting nothing, and hides the next one.
    const asymmetric = ASYMMETRIC.map((entry) => entry.relPath)
    const stale = [...EXPECTED_ASYMMETRIES.keys()].filter(
      (relPath) => !asymmetric.includes(relPath),
    )
    expect(
      stale,
      'These EXPECTED_ASYMMETRIES entries no longer match a workflow that filters exactly one event. If the workflow gained the second filter, delete the entry — it now belongs to the parity check above. If it was renamed or removed, fix the key.',
    ).toEqual([])
  })

  for (const { relPath } of PARITY) {
    it(`${relPath} filters push and pull_request identically`, () => {
      const filters = pathsFilters(relPath)
      expect(
        filters.pull_request,
        `The \`push\` and \`pull_request\` \`paths:\` filters in ${relPath} have diverged. GitHub Actions has no YAML anchors, so the list is written twice and nothing but this check keeps the copies together.\nA \`pull_request\` filter narrower than the \`push\` one is the silent direction: the workflow still runs on main and still reports green, while the PR that introduces the change no longer runs it at all.`,
      ).toEqual(filters.push)
    })
  }
})

import { execFileSync } from 'node:child_process'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The two EQL workflows decide what to run from a list of path globs, and both
 * lists are written by hand more than once.
 *
 * `test-eql.yml` writes its list TWICE and in two different mechanisms: an
 * `on: push: paths:` filter (which decides whether the workflow starts at all
 * after a merge) and a `dorny/paths-filter` `relevant:` filter (which decides
 * whether the heavy jobs run inside a pull-request run). GitHub gives no way to
 * share them. `bench-eql.yml` writes a third copy, for the same tree, on its own
 * `push` trigger.
 *
 * Three properties, and each of them was violated by the imported files:
 *
 * 1. THE COPIES AGREE. Same argument as `workflow-paths-filter-parity.test.mjs`
 *    makes for the `push`/`pull_request` pair, one mechanism over: a filter that
 *    loses an entry keeps reporting green, and the run it stops starting is the
 *    one that would have caught the change.
 *
 * 2. NO GLOB IS DEAD. `packages/eql/sql/**` sat in the relevance filter from the
 *    port onward and there is no such directory — the SQL lives in
 *    `packages/eql/src/`. A glob that matches nothing narrows the filter by
 *    exactly nothing while reading, to anyone auditing coverage, as though that
 *    tree were covered. Compared against the real index, so a directory that is
 *    RENAMED fails here rather than quietly stopping being an input.
 *
 * 3. THE COMPOSITE ACTIONS ARE COVERED. Both workflows invoke
 *    `./.github/actions/require-cs-secrets`, whose job is to fail a credentialed
 *    run in seconds. Neither filter listed it, so an edit that broke the
 *    pre-flight ran in neither workflow. Discovered from each workflow's own
 *    `uses:` edges rather than named here, so a second local action is covered
 *    the day it is wired in.
 *
 * NOT COVERED, deliberately: whether the lists are COMPLETE. Nothing here can
 * tell that `mise run postgres:up` reads `tests/docker-compose.yml`; that is
 * read out of the task bodies by hand, and three such omissions are recorded in
 * the comment above `bench-eql.yml`'s filter. What this file can guarantee is
 * that the three lists stay one list, so the next such omission has to be made
 * three times rather than once.
 */

const TEST_EQL = '.github/workflows/test-eql.yml'
const BENCH_EQL = '.github/workflows/bench-eql.yml'

/** `on:` parses as the boolean `true` under YAML 1.1 — the "Norway problem". */
function triggers(wf) {
  const on = wf?.on ?? wf?.[true]
  return on && typeof on === 'object' ? on : {}
}

/** A workflow's `on.push.paths` list, or `[]`. */
function pushPaths(relPath) {
  const paths = triggers(readWorkflow(relPath))?.push?.paths
  return Array.isArray(paths) ? paths : []
}

/**
 * Every path listed by a `dorny/paths-filter` step, across every filter it
 * declares. `filters:` is a YAML document embedded in a YAML string, so it is
 * parsed rather than pattern-matched — a regex over the raw block would also
 * match the commentary around it.
 */
function dornyFilterPaths(relPath) {
  const wf = readWorkflow(relPath)
  return Object.values(wf?.jobs ?? {})
    .flatMap((job) => job?.steps ?? [])
    .filter((step) =>
      String(step?.uses ?? '').startsWith('dorny/paths-filter@'),
    )
    .flatMap((step) =>
      Object.values(yaml.load(step?.with?.filters ?? '') ?? {}),
    )
    .flat()
}

/** The local composite actions a workflow reaches through `uses: ./…`. */
function localActions(relPath) {
  const wf = readWorkflow(relPath)
  return [
    ...new Set(
      Object.values(wf?.jobs ?? {})
        .flatMap((job) => job?.steps ?? [])
        .map((step) => String(step?.uses ?? '').trim())
        .filter((uses) => uses.startsWith('./.github/actions/'))
        .map((uses) => uses.slice('./'.length)),
    ),
  ].sort()
}

/** Files git tracks under a pathspec. */
function trackedUnder(pathspec) {
  return execFileSync('git', ['ls-files', '-z', '--', pathspec], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
    .split('\0')
    .filter(Boolean)
}

/**
 * Approximates picomatch, which is what `dorny/paths-filter` and GitHub's own
 * `paths:` matcher are built on: `*` stops at a separator, `**` does not.
 *
 * No implicit-descendants tail here, unlike the `@actions/glob` approximation
 * in `ffi-binding-action.test.mjs` — a bare directory name is NOT a prefix
 * match in a `paths:` filter, which is the difference that makes a
 * `.../require-cs-secrets` entry without its `/**` cover nothing.
 */
function globToRegExp(pattern) {
  let source = '^'
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i]
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        source += '.*'
        i += 1
        if (pattern[i + 1] === '/') i += 1
      } else {
        source += '[^/]*'
      }
    } else if (ch === '?') {
      source += '[^/]'
    } else {
      source += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    }
  }
  return new RegExp(`${source}$`)
}

const matches = (pattern, path) => globToRegExp(pattern).test(path)

/** Everything in the index a filter entry could plausibly select. */
const TRACKED = trackedUnder('.')

/** The list each mechanism carries, keyed for the messages below. */
const LISTS = [
  { id: `${TEST_EQL} (on.push.paths)`, entries: pushPaths(TEST_EQL) },
  { id: `${TEST_EQL} (dorny relevant:)`, entries: dornyFilterPaths(TEST_EQL) },
  { id: `${BENCH_EQL} (on.push.paths)`, entries: pushPaths(BENCH_EQL) },
]

/**
 * The workflow file each list is allowed to name, and the only entry that may
 * differ between them: a filter naming its own workflow is not a copy of the
 * same claim, it is each file saying "and me".
 */
const SELF_REFERENCES = new Set([TEST_EQL, BENCH_EQL])

const shared = (entries) =>
  entries.filter((entry) => !SELF_REFERENCES.has(entry)).sort()

describe('the EQL path filters are three copies of one list', () => {
  it('finds all three lists', () => {
    // Each check below is "these lists agree" or "no entry violates X", and an
    // empty list satisfies both for free. The `dorny` one is the fragile
    // member — its `filters:` is YAML inside a YAML string, so a reformat can
    // empty it without failing anything else.
    for (const { id, entries } of LISTS) {
      expect(
        entries,
        `${id} parsed to an empty list, so every comparison below is vacuous for it. Either the filter moved, or the shape this file reads it out of changed.`,
      ).not.toEqual([])
    }
  })

  it('names the same paths in every copy', () => {
    const [reference, ...rest] = LISTS
    for (const list of rest) {
      expect(
        shared(list.entries),
        `The EQL path filters have diverged. ${list.id} and ${reference.id} answer the same question — "can this diff affect EQL?" — through mechanisms GitHub gives no way to share, so the list is written three times and nothing but this check keeps the copies together.\nThe silent direction is a DELETION from one copy: the workflows that still carry the entry keep running and keep reporting green, so the only signal is the run that stopped happening.\nIf a divergence is genuinely intended, it needs a different guard, not a wider one — the bench being a subset of the test suite's inputs is exactly the reasoning that produced the three drifted entries this list replaced.`,
      ).toEqual(shared(reference.entries))
    }
  })

  for (const { id, entries } of LISTS) {
    it(`${id} lists no glob that matches nothing`, () => {
      const dead = entries.filter(
        (entry) => !TRACKED.some((file) => matches(entry, file)),
      )
      expect(
        dead,
        `These entries in ${id} match no file git tracks. A dead glob narrows the filter by nothing while reading as coverage of the tree it names — \`packages/eql/sql/**\` sat in this filter from the subtree import onward, and there is no such directory.\nEither fix the path, or delete the entry.`,
      ).toEqual([])
    })
  }
})

describe('every composite action a workflow runs can trigger it', () => {
  for (const relPath of [TEST_EQL, BENCH_EQL]) {
    const actions = localActions(relPath)

    it(`${relPath} runs at least one local composite action`, () => {
      // The scan guard. Both workflows use `require-cs-secrets` today; if the
      // discovery stops seeing it, the coverage check below iterates nothing
      // and passes.
      expect(
        actions,
        `No step in ${relPath} runs a \`./.github/actions/…\` composite action, so the coverage check below compares nothing. Either the action was inlined, or the \`uses:\` shape changed.`,
      ).not.toEqual([])
    })

    it(`${relPath} triggers on a change to each of them`, () => {
      // Every list this workflow gates on has to cover them: for test-eql that
      // is the `push` filter AND the relevance filter, and an action edit that
      // reached only one of the two would start the workflow and then skip
      // every job inside it.
      const lists = LISTS.filter((list) => list.id.startsWith(relPath))
      expect(lists.length).toBeGreaterThan(0)

      const uncovered = lists.flatMap(({ id, entries }) =>
        actions
          .filter(
            (action) =>
              !trackedUnder(action).every((file) =>
                entries.some((entry) => matches(entry, file)),
              ),
          )
          .map((action) => `${id} does not cover ${action}`),
      )
      expect(
        uncovered,
        `${relPath} runs these composite actions and does not trigger on a change to them. \`require-cs-secrets\` is the pre-flight that turns a rotated credential into a failure in seconds rather than one four minutes into a compile — an edit that breaks it must run the workflows that depend on it.\nAdd \`<action path>/**\` to every filter listed.`,
      ).toEqual([])
    })
  }
})

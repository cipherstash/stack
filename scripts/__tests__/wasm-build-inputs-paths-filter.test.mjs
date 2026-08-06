import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A cache key and a `paths:` filter are two answers to the same question — "did
 * this diff change the WASM build?" — and nothing makes them agree.
 *
 * `.github/actions/build-ffi-binding` answers it for the CACHE: every file it
 * hashes into the WASM key is a file that, when edited, must miss the cache and
 * rebuild `dist/wasm/**` — including `protect_ffi_inline.js`, the bundle
 * `@cipherstash/stack/wasm-inline` imports. Its sibling
 * `ffi-binding-action.test.mjs` guards that half (the key must cover the build
 * it skips).
 *
 * A path-filtered workflow answers it for the TRIGGER. Get the two out of step
 * in this direction — a file the key hashes that the filter does not list — and
 * the failure is silent in the worst way: the PR regenerates the WASM bundle and
 * starts no job that loads it. Nothing is red, because nothing ran.
 *
 * That was live. `packages/protect-ffi/scripts/inline-wasm.mjs` and
 * `tsconfig.wasm-errors.json` are both in the WASM key (they are `build:wasm`'s
 * non-cargo half: `tsc -p tsconfig.wasm-errors.json`, then a `postbuild:wasm`
 * hook running the inliner), and neither was listed in
 * `integration-drizzle.yml` — the workflow whose `CS_IT_SUITE` selects
 * `integration/wasm/**`, i.e. the suites that load the very file the inliner
 * emits. Reported in review on #863.
 *
 * The input list is PARSED OUT of the action's key rather than copied here. A
 * copy would go stale the moment someone adds an input — which is precisely the
 * edit that needs guarding, since adding an input to the key is how you declare
 * "this file changes the WASM build".
 */

const ACTION = '.github/actions/build-ffi-binding/action.yml'
const ACTION_USES = './.github/actions/build-ffi-binding'
const CACHE_ACTION = /^actions\/cache(\/(restore|save))?@/

/** Both trigger events that carry a `paths:` filter, in GitHub's own order. */
const FILTERED_EVENTS = ['push', 'pull_request']

const actionDoc = yaml.load(readFileSync(resolve(REPO_ROOT, ACTION), 'utf8'))
const actionSteps = actionDoc?.runs?.steps ?? []

/**
 * The cache step gated on the action's `wasm` input — found by that gate, not
 * by name, so renaming the step does not quietly empty this guard.
 */
const WASM_CACHE_STEP = actionSteps.find(
  (step) =>
    typeof step?.uses === 'string' &&
    CACHE_ACTION.test(step.uses) &&
    /inputs\.wasm/.test(String(step?.if ?? '')),
)

/** The glob arguments of every `hashFiles(...)` call in a cache key. */
function hashFilesPatterns(key) {
  const patterns = []
  for (const call of String(key ?? '').matchAll(/hashFiles\(([^)]*)\)/g)) {
    for (const arg of call[1].matchAll(/'([^']*)'/g)) patterns.push(arg[1])
  }
  return patterns
}

/** The include patterns of a cache step's `path:` block. */
function cachedPaths(step) {
  return String(step?.with?.path ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('!'))
    .map((line) => line.replace(/\/$/, ''))
}

/**
 * Everything before a glob's first wildcard SEGMENT — the deepest path both a
 * cache pattern and a `paths:` entry can be compared on.
 *
 * `packages/protect-ffi/crates/**` -> `packages/protect-ffi/crates`
 * `packages/protect-ffi/src/errors.ts` -> itself (no wildcard)
 */
function literalPrefix(pattern) {
  const segments = pattern.split('/')
  const wildcardAt = segments.findIndex((segment) => /[*?[]/.test(segment))
  return (wildcardAt === -1 ? segments : segments.slice(0, wildcardAt)).join(
    '/',
  )
}

const CACHED_PATHS = cachedPaths(WASM_CACHE_STEP)
const HASHED_PATTERNS = hashFilesPatterns(WASM_CACHE_STEP?.with?.key)

/**
 * The hashed patterns that are BUILD INPUTS, which is not all of them.
 *
 * The key hashes files for two different reasons, and only one of them implies
 * a trigger. `packages/protect-ffi/dist/wasm/*.d.ts` is in there because those
 * declarations are tracked in git AND inside the cached directory, so a restore
 * would overwrite them — hashing them makes any restore that lands necessarily
 * byte-identical (see the action's comment, and the first suite in
 * `ffi-binding-action.test.mjs`). They are OUTPUT of the build this filter
 * question is about, so requiring a workflow to trigger on them would be
 * requiring it to trigger on its own artifact.
 *
 * The rule is mechanical rather than a name check: a hashed pattern that lives
 * under the step's own `path:` is output, everything else is input.
 */
const BUILD_INPUTS = HASHED_PATTERNS.filter((pattern) => {
  const prefix = literalPrefix(pattern)
  return !CACHED_PATHS.some(
    (cached) => prefix === cached || prefix.startsWith(`${cached}/`),
  )
})

/**
 * Does one `paths:` entry cover everything a build-input pattern can match?
 *
 * Deliberately conservative: only a literal entry or a `**`-tailed one counts.
 * An entry with a wildcard in any earlier segment (a mid-path `*`, or a tail
 * like `*.ts`) is treated as covering nothing, so it fails loudly and gets a
 * matcher that understands it — the opposite
 * bias would be a false green, which here means a WASM input nothing triggers
 * on, which is the entire defect this file exists for.
 */
function entryCovers(entry, inputPattern) {
  const prefix = literalPrefix(entry)
  const tail = entry.slice(prefix.length).replace(/^\//, '')
  if (tail !== '' && tail !== '**') return false
  const target = literalPrefix(inputPattern)
  return target === prefix || target.startsWith(`${prefix}/`)
}

/** Every workflow that runs the action with `wasm: 'true'`. */
function buildsWasm(relPath) {
  const wf = readWorkflow(relPath)
  return Object.values(wf?.jobs ?? {}).some((job) =>
    (Array.isArray(job?.steps) ? job.steps : []).some(
      (step) =>
        typeof step?.uses === 'string' &&
        step.uses.trim() === ACTION_USES &&
        String(step?.with?.wasm) === 'true',
    ),
  )
}

/**
 * The `paths:` filters a workflow declares, one entry per filtered event.
 *
 * `on:` parses as the boolean `true` under YAML 1.1 (the "Norway problem"),
 * hence `wf.on ?? wf[true]`. An event with no `paths:` is UNFILTERED and is
 * skipped rather than failed — it already runs on every diff, so it cannot miss
 * one. `tests.yml` is that case, and it is why this check finding two workflows
 * rather than three is correct.
 */
function filteredEvents(relPath) {
  const wf = readWorkflow(relPath)
  const on = wf?.on ?? wf?.[true]
  return FILTERED_EVENTS.filter((event) =>
    Array.isArray(on?.[event]?.paths),
  ).map((event) => ({ relPath, event, paths: on[event].paths }))
}

const WASM_WORKFLOWS = workflowFiles().filter(buildsWasm)
const FILTERED = WASM_WORKFLOWS.flatMap(filteredEvents)

/**
 * The workflows that build the WASM output today — the guard on the scan, not
 * the list it iterates. A discovery test that matches nothing passes while
 * checking nothing, and this directory has been bitten by that before (see the
 * scan guards in `ffi-binding-step-order.test.mjs`).
 *
 * Held as a minimum: a new workflow that builds WASM must not fail this. One
 * LEAVING the list is what deserves the interruption — either it stopped
 * building WASM, or the discovery broke.
 */
const EXPECTED_WASM_WORKFLOWS = [
  '.github/workflows/integration-drizzle.yml',
  '.github/workflows/integration-protect-ffi.yml',
  '.github/workflows/tests.yml',
]

/**
 * KNOWN GAPS — not justifications.
 *
 * Every entry here would be a WASM build input a workflow really should trigger
 * on and does not — written down rather than fixed only when the fix belongs to
 * a file outside the change that found it. Empty today, and that is the
 * intended steady state: this guard found one gap when it was written
 * (`integration-protect-ffi.yml` never triggered on `tsconfig.wasm-errors.json`,
 * despite its `wasm-round-trip` suite loading what that tsconfig feeds) and it
 * was closed in the same commit rather than recorded here.
 *
 * The stale check below deletes an entry the moment its gap closes, so one
 * cannot outlive the thing it documents. Verified against the real fix, not
 * asserted: with the entry present and the filter corrected, that check went
 * red naming this map.
 *
 * Keyed `<workflow> / <input pattern>`, event-independent: the `push` and
 * `pull_request` copies of a filter are identical (enforced by
 * `workflow-paths-filter-parity.test.mjs`), so a gap is never one-sided.
 */
const KNOWN_UNCOVERED = new Map([
  // ['<workflow> / <input pattern>', 'why it is still uncovered, and the fix'],
])

const gapKey = (relPath, pattern) => `${relPath} / ${pattern}`

describe('the WASM cache key and the filters that trigger it agree', () => {
  it('finds the WASM cache step and the inputs it hashes', () => {
    // Without this the two checks below iterate an empty list and pass having
    // compared nothing — the failure mode every scan in this directory guards.
    expect(
      WASM_CACHE_STEP,
      `No \`actions/cache\` step in ${ACTION} is gated on \`inputs.wasm\`. If the WASM cache moved or its gate was renamed, point this guard at it; as it stands there is no key to derive build inputs from and every check below is vacuous.`,
    ).toBeTruthy()

    expect(
      HASHED_PATTERNS.length,
      `The WASM cache key hashes nothing. \`hashFiles(...)\` was probably reformatted into a shape this parser does not read — fix the parser rather than the key.`,
    ).toBeGreaterThanOrEqual(5)

    expect(
      BUILD_INPUTS.length,
      `Every hashed pattern resolved to output under the step's own \`path:\`, leaving no build inputs to check.`,
    ).toBeGreaterThan(0)

    // A pattern naming nothing on disk is an input that silently stopped being
    // one — the key still hashes it, and hashFiles over a missing path is not
    // an error, so both this guard and the cache go quietly wrong together.
    const missing = BUILD_INPUTS.filter(
      (pattern) => !existsSync(resolve(REPO_ROOT, literalPrefix(pattern))),
    )
    expect(
      missing,
      `These patterns are hashed into the WASM cache key but name nothing in the repo. \`hashFiles\` treats a miss as the empty string, so a renamed input stops contributing to the key without failing anything.`,
    ).toEqual([])
  })

  it('finds the workflows that build the WASM output', () => {
    const missing = EXPECTED_WASM_WORKFLOWS.filter(
      (relPath) => !WASM_WORKFLOWS.includes(relPath),
    )
    expect(
      missing,
      `These workflows ran \`${ACTION_USES}\` with \`wasm: 'true'\` and the scan no longer sees them. Either the action path or the input spelling changed (update the constants here), or a job stopped building the WASM — update EXPECTED_WASM_WORKFLOWS deliberately.\nThe scan currently sees:\n${
        WASM_WORKFLOWS.length === 0
          ? '  (nothing — the scan matched no workflows)'
          : WASM_WORKFLOWS.map((relPath) => `  ${relPath}`).join('\n')
      }`,
    ).toEqual([])
  })

  it('finds the path-filtered ones, which are the ones that can miss a diff', () => {
    // `tests.yml` builds the WASM on every diff and declares no `paths:` at
    // all, so it is correctly absent here. If THIS list empties, every
    // per-event check below stops existing rather than failing.
    expect(
      FILTERED.length,
      `No workflow that builds the WASM declares a \`paths:\` filter, so there is nothing to compare the cache key against. Either every such workflow became unfiltered (then this guard is obsolete), or \`filteredEvents\` stopped reading the trigger block.`,
    ).toBeGreaterThan(0)
  })

  for (const { relPath, event, paths } of FILTERED) {
    it(`${relPath} (${event}) triggers on every WASM build input`, () => {
      const uncovered = BUILD_INPUTS.filter(
        (pattern) =>
          !paths.some((entry) => entryCovers(entry, pattern)) &&
          !KNOWN_UNCOVERED.has(gapKey(relPath, pattern)),
      )
      expect(
        uncovered,
        `These files are hashed into the WASM cache key of \`${ACTION}\`, so an edit to one MISSES the cache and rebuilds \`packages/protect-ffi/dist/wasm/**\` — including \`protect_ffi_inline.js\`, the bundle \`@cipherstash/stack/wasm-inline\` imports. ${relPath} runs that action with \`wasm: 'true'\`, but its \`${event}\` \`paths:\` filter does not list them, so a PR touching only one of them regenerates the bundle and starts no suite that loads it. Nothing goes red; nothing ran.\nAdd each to BOTH copies of the filter — GitHub Actions has no YAML anchors, and \`workflow-paths-filter-parity.test.mjs\` fails a one-sided edit.`,
      ).toEqual([])
    })
  }

  it('keeps no stale known-gap entries', () => {
    // The mirror of the checks above, and the one that matters when a gap is
    // FIXED: an entry that no longer describes an uncovered input sits there
    // reading as deliberate while suppressing nothing, and hides the next one.
    const live = new Set(
      FILTERED.flatMap(({ relPath, paths }) =>
        BUILD_INPUTS.filter(
          (pattern) => !paths.some((entry) => entryCovers(entry, pattern)),
        ).map((pattern) => gapKey(relPath, pattern)),
      ),
    )
    const stale = [...KNOWN_UNCOVERED.keys()].filter((key) => !live.has(key))
    expect(
      stale,
      'These KNOWN_UNCOVERED entries no longer name an uncovered WASM build input. If the filter gained the entry — thank you — delete the line here; the gap it documented is closed. If the workflow or the input was renamed, fix the key.',
    ).toEqual([])
  })
})

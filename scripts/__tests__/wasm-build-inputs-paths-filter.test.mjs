import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A cache key and a `paths:` filter are two answers to the same question — "did
 * this diff change the binding?" — and nothing makes them agree.
 *
 * `.github/actions/build-ffi-binding` answers it for the CACHE. It carries two
 * keys: one over `index.node` (the Node-API binding every credentialed suite
 * encrypts through) and one over `dist/wasm/**` (including
 * `protect_ffi_inline.js`, the bundle `@cipherstash/stack/wasm-inline`
 * imports). Every file a key hashes is a file that, when edited, must miss that
 * cache and rebuild. Its sibling `ffi-binding-action.test.mjs` guards that half
 * (each key must cover the build it skips).
 *
 * A path-filtered workflow answers it for the TRIGGER. Get the two out of step
 * in this direction — a file a key hashes that the filter does not list — and
 * the failure is silent in the worst way: the PR rebuilds the artifact and
 * starts no job that loads it. Nothing is red, because nothing ran.
 *
 * That was live, twice.
 *
 *  - `packages/protect-ffi/scripts/inline-wasm.mjs` and
 *    `tsconfig.wasm-errors.json` are both in the WASM key (they are
 *    `build:wasm`'s non-cargo half) and neither was listed in
 *    `integration-drizzle.yml` — the workflow whose `CS_IT_SUITE` selects
 *    `integration/wasm/**`, i.e. the suites that load the very file the inliner
 *    emits. Reported in review on #863; this file was written for it.
 *  - `packages/eql/crates/**` and `packages/eql/Cargo.toml` are in BOTH keys —
 *    `crates/protect-ffi/Cargo.toml` carries
 *    `eql-bindings = { path = "../../../eql/crates/eql-bindings" }`, so that
 *    tree compiles into `index.node` — and five path-filtered workflows that
 *    build or compile the binding did not list them. Four of them run the
 *    action NATIVELY (`wasm:` left at its default), so the first version of
 *    this file, which only ever inspected the WASM key and only over workflows
 *    passing `wasm: 'true'`, could not see any of them. Hence the generalised
 *    shape below: every key in the action, against every workflow that reaches
 *    the build it caches.
 *
 * THE FILENAME is historical and deliberately unchanged: `integration-drizzle.yml`
 * and `integration-protect-ffi.yml` cite this path in the comments above the
 * entries it pins, and a rename would leave those citations dangling. The WASM
 * key is still the reason it exists; it is no longer all it covers.
 *
 * The input lists are PARSED OUT of the action's keys rather than copied here.
 * A copy would go stale the moment someone adds an input — which is precisely
 * the edit that needs guarding, since adding an input to a key is how you
 * declare "this file changes what the build produces".
 */

const ACTION = '.github/actions/build-ffi-binding/action.yml'
const ACTION_USES = './.github/actions/build-ffi-binding'
const CACHE_ACTION = /^actions\/cache(\/(restore|save))?@/

/** Both trigger events that carry a `paths:` filter, in GitHub's own order. */
const FILTERED_EVENTS = ['push', 'pull_request']

/** The package whose Rust both cache keys are about. */
const FFI_PACKAGE = 'packages/protect-ffi'
const FFI_PACKAGE_NAME = '@cipherstash/protect-ffi'

/** What a command has to reach before it is compiling anything. */
const COMPILES_RUST = /\b(cargo|wasm-pack|cross)\b/

const actionDoc = yaml.load(readFileSync(resolve(REPO_ROOT, ACTION), 'utf8'))
const actionSteps = actionDoc?.runs?.steps ?? []

/** Every `actions/cache` step in the action, in file order. */
const CACHE_STEPS = actionSteps.filter(
  (step) => typeof step?.uses === 'string' && CACHE_ACTION.test(step.uses),
)

/**
 * The two keys, told apart by the `wasm` gate rather than by name, so renaming
 * a step does not quietly empty this guard. The WASM archive is the one built
 * only when the caller asks for it; the native one is unconditional.
 */
const WASM_CACHE_STEP = CACHE_STEPS.find((step) =>
  /inputs\.wasm/.test(String(step?.if ?? '')),
)
const NATIVE_CACHE_STEP = CACHE_STEPS.find(
  (step) => !/inputs\.wasm/.test(String(step?.if ?? '')),
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

/**
 * The patterns a key hashes that are BUILD INPUTS, which is not all of them.
 *
 * A key hashes files for two different reasons, and only one of them implies a
 * trigger. `packages/protect-ffi/dist/wasm/*.d.ts` is in the WASM key because
 * those declarations are tracked in git AND inside the cached directory, so a
 * restore would overwrite them — hashing them makes any restore that lands
 * necessarily byte-identical (see the action's comment, and the first suite in
 * `ffi-binding-action.test.mjs`). They are OUTPUT of the build this filter
 * question is about, so requiring a workflow to trigger on them would be
 * requiring it to trigger on its own artifact.
 *
 * The rule is mechanical rather than a name check: a hashed pattern that lives
 * under the step's own `path:` is output, everything else is input.
 */
function buildInputs(step) {
  const cached = cachedPaths(step)
  return hashFilesPatterns(step?.with?.key).filter((pattern) => {
    const prefix = literalPrefix(pattern)
    return !cached.some(
      (path) => prefix === path || prefix.startsWith(`${path}/`),
    )
  })
}

/**
 * Does one `paths:` entry cover everything a build-input pattern can match?
 *
 * Deliberately conservative: only a literal entry or a `**`-tailed one counts.
 * An entry with a wildcard in any earlier segment (a mid-path `*`, or a tail
 * like `*.ts`) is treated as covering nothing, so it fails loudly and gets a
 * matcher that understands it — the opposite
 * bias would be a false green, which here means a build input nothing triggers
 * on, which is the entire defect this file exists for.
 */
function entryCovers(entry, inputPattern) {
  const prefix = literalPrefix(entry)
  const tail = entry.slice(prefix.length).replace(/^\//, '')
  if (tail !== '' && tail !== '**') return false
  const target = literalPrefix(inputPattern)
  return target === prefix || target.startsWith(`${prefix}/`)
}

// ---------------------------------------------------------------------------
// Which workflows reach each build
// ---------------------------------------------------------------------------

/**
 * The names of the things that compile this package's Rust, derived from the
 * package rather than listed here.
 *
 * The WASM key has one consumer shape — a workflow that runs the action with
 * `wasm: 'true'` — but the native one has two: the action, and a workflow that
 * runs cargo against the same crate graph itself. `tests-rust.yml` is the
 * second kind (`pnpm --filter @cipherstash/protect-ffi run test:cargo`, then
 * `mise run lint:rust`), and it compiles `eql-bindings` through the same path
 * dependency, so the native key's input list is exactly its trigger list too.
 *
 * Both name sets are computed to a fixpoint: a script or task that only invokes
 * another one still counts, which is how `test:cargo` (`test:rust` +
 * `test:format:rust`) and `lint:rust` (three `depends` arms) are found without
 * being named.
 */
const escapeRe = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** Does `body` invoke any of `names`, as whole words? */
const mentionsAny = (body, names) =>
  [...names].some((name) => new RegExp(`\\b${escapeRe(name)}\\b`).test(body))

/** Grow `bodies` (name -> command text) to a fixpoint over cross-references. */
function reachesRust(bodies) {
  const reaching = new Set(
    [...bodies].filter(([, body]) => COMPILES_RUST.test(body)).map(([n]) => n),
  )
  for (;;) {
    const before = reaching.size
    for (const [name, body] of bodies) {
      if (!reaching.has(name) && mentionsAny(body, reaching)) reaching.add(name)
    }
    if (reaching.size === before) return reaching
  }
}

const ffiManifest = JSON.parse(
  readFileSync(resolve(REPO_ROOT, FFI_PACKAGE, 'package.json'), 'utf8'),
)
const CARGO_SCRIPTS = reachesRust(
  Object.entries(ffiManifest.scripts ?? {}).map(([name, cmd]) => [
    name,
    String(cmd),
  ]),
)

/**
 * mise tasks, from `mise.toml` and everything its `[task_config].includes`
 * pulls in — read rather than hard-coded, because a fourth config landing is
 * exactly the edit that would otherwise leave a whole file of tasks unscanned.
 *
 * Parsed by section rather than with a TOML library: the two files spell task
 * headers three ways (`[tasks."lint:rust"]`, `["test:integration"]`,
 * `[setup]`), and `run` is variously a string, a triple-quoted block and an
 * array. Only the raw body text matters here, since the reachability rule is
 * "mentions a name that reaches Rust".
 */
function parseTaskBodies(text) {
  const bodies = []
  const parts = text.split(/^\[(?:tasks\.)?"?([\w:@./-]+)"?\][^\n]*$/m)
  for (let i = 1; i < parts.length; i += 2) {
    bodies.push([parts[i], parts[i + 1]])
  }
  return bodies
}

function miseTaskBodies() {
  const rootText = readFileSync(
    resolve(REPO_ROOT, FFI_PACKAGE, 'mise.toml'),
    'utf8',
  )
  const includes =
    /^includes\s*=\s*\[([^\]]*)\]/m
      .exec(
        /^\[task_config\][^\n]*\n([\s\S]*?)(?=^\[|$)/m.exec(rootText)?.[1] ??
          '',
      )?.[1]
      ?.match(/"([^"]+)"|'([^']+)'/g)
      ?.map((quoted) => quoted.slice(1, -1)) ?? []
  return [
    rootText,
    ...includes.map((rel) =>
      readFileSync(resolve(REPO_ROOT, FFI_PACKAGE, rel), 'utf8'),
    ),
  ].flatMap(parseTaskBodies)
}

const TASK_BODIES = miseTaskBodies()
const CARGO_TASKS = reachesRust(
  TASK_BODIES.map(([name, body]) => [
    name,
    // A task that shells out to a cargo-reaching npm script reaches Rust too;
    // splicing the script names in lets the same fixpoint find both.
    mentionsAny(body, CARGO_SCRIPTS) ? `${body}\ncargo` : body,
  ]),
)

/** A step's effective working directory, including the two `defaults:` levels. */
function stepDir(wf, job, step) {
  return (
    step?.['working-directory'] ??
    job?.defaults?.run?.['working-directory'] ??
    wf?.defaults?.run?.['working-directory'] ??
    '.'
  )
}

/** Every job step of a workflow, paired with the job that owns it. */
function steps(wf) {
  return Object.values(wf?.jobs ?? {}).flatMap((job) =>
    (Array.isArray(job?.steps) ? job.steps : []).map((step) => ({ job, step })),
  )
}

/** Runs `./.github/actions/build-ffi-binding`, optionally with `wasm: 'true'`. */
function usesAction(relPath, { wasmOnly = false } = {}) {
  return steps(readWorkflow(relPath)).some(
    ({ step }) =>
      typeof step?.uses === 'string' &&
      step.uses.trim() === ACTION_USES &&
      (!wasmOnly || String(step?.with?.wasm) === 'true'),
  )
}

/**
 * Compiles this package's Rust — through the action, or directly.
 *
 * The direct forms are scoped: either the command targets the package by name
 * (`pnpm --filter @cipherstash/protect-ffi …`, `pnpm --dir packages/protect-ffi
 * …`) or the step runs INSIDE it, so a `cargo` elsewhere in the monorepo — the
 * EQL workspace has its own, with its own workflows — is not mistaken for this
 * one.
 */
function compilesFfiRust(relPath) {
  if (usesAction(relPath)) return true
  const wf = readWorkflow(relPath)
  return steps(wf).some(({ job, step }) => {
    const run = String(step?.run ?? '')
    if (!run) return false
    const targetsPackage =
      run.includes(FFI_PACKAGE_NAME) || run.includes(FFI_PACKAGE)
    const inPackage = stepDir(wf, job, step) === FFI_PACKAGE
    if (!targetsPackage && !inPackage) return false
    if (inPackage && COMPILES_RUST.test(run)) return true
    return (
      mentionsAny(run, CARGO_SCRIPTS) ||
      (inPackage && mentionsAny(run, CARGO_TASKS))
    )
  })
}

/**
 * The `paths:` filters a workflow declares, one entry per filtered event.
 *
 * `on:` parses as the boolean `true` under YAML 1.1 (the "Norway problem"),
 * hence `wf.on ?? wf[true]`. An event with no `paths:` is UNFILTERED and is
 * skipped rather than failed — it already runs on every diff, so it cannot miss
 * one. `tests.yml` is that case, and it is why this check finding two workflows
 * rather than three is correct. `tests-rust.yml` is the half-case: `push` is
 * `branches: [main]` with no filter, so only its `pull_request` list is here.
 */
function filteredEvents(relPath) {
  const wf = readWorkflow(relPath)
  const on = wf?.on ?? wf?.[true]
  return FILTERED_EVENTS.filter((event) =>
    Array.isArray(on?.[event]?.paths),
  ).map((event) => ({ relPath, event, paths: on[event].paths }))
}

const ALL_WORKFLOWS = workflowFiles()

/**
 * KNOWN GAPS — not justifications.
 *
 * Every entry here would be a build input a workflow really should trigger on
 * and does not — written down rather than fixed only when the fix belongs to a
 * file outside the change that found it. Empty today, and that is the intended
 * steady state: both gaps this guard has found so far were closed in the commit
 * that found them rather than recorded here.
 *
 * The stale check below deletes an entry the moment its gap closes, so one
 * cannot outlive the thing it documents. Verified against the real fix, not
 * asserted: with the entry present and the filter corrected, that check went
 * red naming this map.
 *
 * Keyed `<workflow> / <input pattern>`, event-independent (the `push` and
 * `pull_request` copies of a filter are identical, enforced by
 * `workflow-paths-filter-parity.test.mjs`, so a gap is never one-sided) and
 * key-independent (the two keys share inputs; a gap is a workflow that does not
 * trigger on a file, whichever key names it).
 */
const KNOWN_UNCOVERED = new Map([
  // ['<workflow> / <input pattern>', 'why it is still uncovered, and the fix'],
])

const gapKey = (relPath, pattern) => `${relPath} / ${pattern}`

/**
 * The two keys, each with the workflows that reach the build it caches.
 *
 * `expected` is the guard on the scan, not the list it iterates. A discovery
 * test that matches nothing passes while checking nothing, and this directory
 * has been bitten by that before (see the scan guards in
 * `ffi-binding-step-order.test.mjs`). Held as a MINIMUM: a new workflow that
 * builds the binding must not fail it. One LEAVING the list is what deserves
 * the interruption — either it stopped building, or the discovery broke.
 */
const KEYS = [
  {
    id: 'native',
    step: NATIVE_CACHE_STEP,
    what: '`index.node`, the binding every credentialed suite encrypts through',
    reaches: 'compiles the crate graph behind `index.node`',
    workflows: ALL_WORKFLOWS.filter(compilesFfiRust),
    expected: [
      '.github/workflows/_build-ffi-artifacts.yml',
      '.github/workflows/integration-drizzle.yml',
      '.github/workflows/integration-prisma-next.yml',
      '.github/workflows/integration-protect-ffi.yml',
      '.github/workflows/integration-supabase.yml',
      '.github/workflows/prisma-example-readme-e2e.yml',
      '.github/workflows/prisma-next-e2e.yml',
      '.github/workflows/tests-rust.yml',
      '.github/workflows/tests.yml',
    ],
  },
  {
    id: 'wasm',
    step: WASM_CACHE_STEP,
    what: '`packages/protect-ffi/dist/wasm/**` — including `protect_ffi_inline.js`, the bundle `@cipherstash/stack/wasm-inline` imports',
    reaches: "runs the action with `wasm: 'true'`",
    workflows: ALL_WORKFLOWS.filter((relPath) =>
      usesAction(relPath, { wasmOnly: true }),
    ),
    expected: [
      '.github/workflows/integration-drizzle.yml',
      '.github/workflows/integration-protect-ffi.yml',
      '.github/workflows/tests.yml',
    ],
  },
]

describe('the FFI cache keys and the filters that trigger them agree', () => {
  it('finds both cache steps in the action', () => {
    // Without these the checks below iterate empty lists and pass having
    // compared nothing — the failure mode every scan in this directory guards.
    expect(
      CACHE_STEPS.length,
      `${ACTION} no longer declares exactly two \`actions/cache\` steps. A third key is a third build whose inputs need a trigger — add it to KEYS with the workflows that reach it, rather than leaving it unguarded.`,
    ).toBe(2)

    expect(
      WASM_CACHE_STEP,
      `No \`actions/cache\` step in ${ACTION} is gated on \`inputs.wasm\`. If the WASM cache moved or its gate was renamed, point this guard at it; as it stands there is no key to derive WASM build inputs from.`,
    ).toBeTruthy()

    expect(
      NATIVE_CACHE_STEP,
      `Every \`actions/cache\` step in ${ACTION} is gated on \`inputs.wasm\`, so nothing here is the native \`index.node\` key. Point this guard at it; as it stands the native half of the check is vacuous.`,
    ).toBeTruthy()
  })

  it('derives the commands that compile this package Rust', () => {
    // The native key's consumers are not only the action's callers, so the
    // discovery reads `packages/protect-ffi`'s own scripts and mise tasks. If
    // either set empties, `compilesFfiRust` degrades to "uses the action" and
    // a workflow like tests-rust.yml silently stops being checked.
    expect(
      [...CARGO_SCRIPTS],
      `No script in ${FFI_PACKAGE}/package.json resolved to a cargo/wasm-pack command. The scripts were probably restructured — fix the walk, not the manifest.`,
    ).toContain('test:cargo')

    expect(
      [...CARGO_TASKS],
      `No mise task in ${FFI_PACKAGE}/mise.toml resolved to a cargo command. \`lint:rust\` reaches cargo through three \`depends\` arms; if the parse or the fixpoint broke, every workflow that runs Rust checks by task name stops being discovered.`,
    ).toContain('lint:rust')
  })

  for (const key of KEYS) {
    const inputs = buildInputs(key.step)
    const filtered = key.workflows.flatMap(filteredEvents)

    describe(`the ${key.id} key`, () => {
      it('hashes build inputs that name real files', () => {
        expect(
          hashFilesPatterns(key.step?.with?.key).length,
          `The ${key.id} cache key hashes nothing. \`hashFiles(...)\` was probably reformatted into a shape this parser does not read — fix the parser rather than the key.`,
        ).toBeGreaterThanOrEqual(5)

        expect(
          inputs.length,
          `Every pattern hashed into the ${key.id} key resolved to output under the step's own \`path:\`, leaving no build inputs to check.`,
        ).toBeGreaterThan(0)

        // A pattern naming nothing on disk is an input that silently stopped
        // being one — the key still hashes it, and hashFiles over a missing
        // path is not an error, so both this guard and the cache go quietly
        // wrong together.
        const missing = inputs.filter(
          (pattern) => !existsSync(resolve(REPO_ROOT, literalPrefix(pattern))),
        )
        expect(
          missing,
          `These patterns are hashed into the ${key.id} cache key but name nothing in the repo. \`hashFiles\` treats a miss as the empty string, so a renamed input stops contributing to the key without failing anything.`,
        ).toEqual([])
      })

      it('finds the workflows that reach the build it caches', () => {
        const missing = key.expected.filter(
          (relPath) => !key.workflows.includes(relPath),
        )
        expect(
          missing,
          `These workflows ${key.reaches} and the scan no longer sees them. Either the action path, an input spelling or a build command changed (update the discovery here), or a job stopped building — update the expected list deliberately.\nThe scan currently sees:\n${
            key.workflows.length === 0
              ? '  (nothing — the scan matched no workflows)'
              : key.workflows.map((relPath) => `  ${relPath}`).join('\n')
          }`,
        ).toEqual([])
      })

      it('finds the path-filtered ones, which are the ones that can miss a diff', () => {
        // `tests.yml` reaches both builds on every diff and declares no
        // `paths:` at all, so it is correctly absent here. If THIS list
        // empties, every per-event check below stops existing rather than
        // failing.
        expect(
          filtered.length,
          `No workflow that reaches the ${key.id} build declares a \`paths:\` filter, so there is nothing to compare the cache key against. Either every such workflow became unfiltered (then this half of the guard is obsolete), or \`filteredEvents\` stopped reading the trigger block.`,
        ).toBeGreaterThan(0)
      })

      for (const { relPath, event, paths } of filtered) {
        it(`${relPath} (${event}) triggers on every ${key.id} build input`, () => {
          const uncovered = inputs.filter(
            (pattern) =>
              !paths.some((entry) => entryCovers(entry, pattern)) &&
              !KNOWN_UNCOVERED.has(gapKey(relPath, pattern)),
          )
          expect(
            uncovered,
            `These files are hashed into the ${key.id} cache key of \`${ACTION}\`, so an edit to one MISSES the cache and rebuilds ${key.what}. ${relPath} ${key.reaches}, but its \`${event}\` \`paths:\` filter does not list them, so a PR touching only one of them rebuilds the artifact and starts no suite that exercises it. Nothing goes red; nothing ran.\nAdd each to BOTH copies of the filter — GitHub Actions has no YAML anchors, and \`workflow-paths-filter-parity.test.mjs\` fails a one-sided edit.`,
          ).toEqual([])
        })
      }
    })
  }

  it('keeps no stale known-gap entries', () => {
    // The mirror of the checks above, and the one that matters when a gap is
    // FIXED: an entry that no longer describes an uncovered input sits there
    // reading as deliberate while suppressing nothing, and hides the next one.
    const live = new Set(
      KEYS.flatMap((key) => {
        const inputs = buildInputs(key.step)
        return key.workflows
          .flatMap(filteredEvents)
          .flatMap(({ relPath, paths }) =>
            inputs
              .filter(
                (pattern) =>
                  !paths.some((entry) => entryCovers(entry, pattern)),
              )
              .map((pattern) => gapKey(relPath, pattern)),
          )
      }),
    )
    const stale = [...KNOWN_UNCOVERED.keys()].filter((key) => !live.has(key))
    expect(
      stale,
      'These KNOWN_UNCOVERED entries no longer name an uncovered build input. If the filter gained the entry — thank you — delete the line here; the gap it documented is closed. If the workflow or the input was renamed, fix the key.',
    ).toEqual([])
  })
})

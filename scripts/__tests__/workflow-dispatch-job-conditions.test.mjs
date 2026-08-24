import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A workflow that declares `workflow_dispatch:` must actually run when someone
 * presses "Run workflow". A job-level `if:` can quietly take that away.
 *
 * WHAT HAPPENED. `.github/workflows/integration-protect-ffi.yml` declared
 * `workflow_dispatch: {}` and gated its only job with
 *
 *     if: ${{ github.event_name == 'push' ||
 *             github.event.pull_request.head.repo.full_name == github.repository }}
 *
 * On a manual dispatch `github.event_name` is `workflow_dispatch`, and the
 * dispatch payload carries no `pull_request` object at all — so the second
 * operand dereferences to null, GitHub coerces null to 0 and the repository
 * string to NaN, and both disjuncts are false. The button is present, the run
 * is created, the single job is skipped, and the run reports success having
 * executed nothing. For the one credentialed suite in this repo that has no
 * other way to be re-run on demand (its `paths:` filter means an unrelated
 * commit will not start it either), that is the difference between a manual
 * trigger and a decorative one.
 *
 * The defect is an ALLOWLIST OF EVENTS: it enumerates the cases known at
 * writing time and fails shut on the one nobody enumerated. Same shape as the
 * `CACHE_ACTION` enumeration fixed in 233f3ee5, and the corrected form is the
 * same inversion — say which single case must NOT run (a fork pull request,
 * which has no secrets) and let every other trigger through.
 *
 * WHY AN EVALUATOR RATHER THAN A PATTERN. Matching the known-bad string only
 * catches the bug already fixed; the next one will be spelled differently.
 * This evaluates each job condition against a synthetic context for each event
 * instead, which is the property itself rather than a proxy for it. The
 * grammar it understands is small on purpose and it THROWS on anything outside
 * it — a condition this file cannot reason about fails loudly rather than
 * being waved through, because "the evaluator did not understand it" and "the
 * job runs" must not produce the same green.
 */

/**
 * Synthetic, and only ever compared against itself: what matters is that the
 * fork context disagrees with `github.repository` and the same-repo one agrees.
 */
const REPOSITORY = 'cipherstash/stack'

/**
 * The workflows that declare `workflow_dispatch` today. This is NOT the list
 * the checks iterate — those scan the directory — it is the guard on the scan.
 * A discovery test that matches nothing passes and proves nothing, and this
 * repo has been bitten by exactly that (`integration-workflow-paths.test.mjs`'s
 * `required.size` floor, added in e93a0a3d after the derived requirement set
 * turned out to be empty).
 *
 * A minimum, not an equality: adding `workflow_dispatch` to another workflow
 * must not fail this — it must subject that workflow to the check below.
 */
const EXPECTED_DISPATCHABLE = [
  // The manual dry run for an FFI release. Dispatch is not a convenience here:
  // it is the ONLY way to run it, and it exists to be pointed at a Version
  // Packages branch before the irreversible publish.
  '.github/workflows/ffi-preflight.yml',
  '.github/workflows/integration-protect-ffi.yml',
  // Path-filtered to the release machinery, so dispatch is how it gets run
  // against a branch that changed something the filter does not name.
  '.github/workflows/lint-release.yml',
  '.github/workflows/osv-scanner.yml',
  '.github/workflows/tests-rust.yml',
  // The EQL release line. `release.yml` gained a dispatch with the port,
  // because the EQL PRERELEASE path is cut by dispatching a batching branch
  // whose HEAD is a `chore(release):` marker; the other two are how an image or
  // a crate publish is re-run by hand after a partial failure.
  '.github/workflows/release.yml',
  '.github/workflows/release-plz.yml',
  '.github/workflows/release-postgres-eql-image.yml',
]

/**
 * Jobs that legitimately do NOT run on a plain manual dispatch, with the reason.
 *
 * WHY THIS EXISTS AT ALL. The check below reads "a declared `workflow_dispatch`
 * must actually dispatch", and it enforced that by requiring EVERY job-level
 * `if:` in such a workflow to be true under one synthetic dispatch context.
 * That is exact for a workflow with one path through it, which every
 * dispatchable workflow here had. `release.yml` has two, and they are mutually
 * exclusive by construction: `classify` reports `production` for `main` and
 * `prerelease` for a marker commit on any other branch, and each half of the
 * file is keyed on one of them. Under any single context one half is false. No
 * spelling of the conditions avoids that, because the exclusivity is the
 * design.
 *
 * WHAT IS NOT WEAKENED. The alternative was to relax the rule to "at least one
 * job runs", which would still have caught the original defect (a
 * single-job workflow whose only job skipped) and would have said nothing about
 * a ten-job workflow where nine skip. This keeps the per-job requirement and
 * makes the exceptions an equality instead — so an unlisted job that stops
 * running on dispatch fails, AND an entry that stops being needed fails.
 *
 * The synthetic context dispatches against `refs/heads/main`, so "production"
 * is the path being modelled. That is the right default: it is what a dispatch
 * of `release.yml` does unless someone deliberately points it at a release
 * branch.
 */
const DISPATCH_SKIPPED_JOBS = [
  // The four prerelease jobs. A dispatch against `main` classifies as
  // `production`, so these are correctly skipped; they run when the dispatch
  // names a branch whose HEAD commit subject is `chore(release):`.
  '.github/workflows/release.yml / prerelease-eql-crate',
  '.github/workflows/release.yml / prerelease-eql-docs',
  '.github/workflows/release.yml / prerelease-eql-npm',
  '.github/workflows/release.yml / prerelease-eql-sql',
]

/**
 * The jobs carrying the fork-PR guard. Every one of these holds live
 * CipherStash credentials, so the guard's MEANING is what must not drift:
 * a fork PR cannot supply secrets and must skip cleanly, everything else runs.
 *
 * Jobs, not files, and held as an equality below rather than a floor —
 * see `ffi-binding-step-order.test.mjs` for why slack in a scan guard is where
 * the un-run check hides.
 */
const EXPECTED_FORK_GUARDED_JOBS = [
  '.github/workflows/integration-drizzle.yml / integration',
  '.github/workflows/integration-prisma-next.yml / integration',
  '.github/workflows/integration-protect-ffi.yml / integration',
  '.github/workflows/integration-supabase.yml / integration',
  '.github/workflows/prisma-example-readme-e2e.yml / walkthrough',
  '.github/workflows/prisma-next-e2e.yml / e2e',
  '.github/workflows/test-eql.yml / build-archive',
  '.github/workflows/test-eql.yml / e2e',
]

/** The context path every fork guard turns on. */
const FORK_PATH = 'github.event.pull_request.head.repo.full_name'

/**
 * The guard clause itself, as every copy must spell it.
 *
 * Six of the eight conditions ARE this string and nothing else. The two EQL
 * jobs `&&` it with a relevance gate, because a docs-only PR should not pay a
 * four-minute compile — so "identical spelling" had to become a claim about the
 * CLAUSE rather than the whole condition. The clause is still compared
 * verbatim: what the check below permits is another conjunct beside it, not a
 * different way of writing it.
 *
 * Keeping it whole matters more here than the parenthesisation does. A guard
 * rewritten as `github.event_name == 'pull_request' && <same-repo>` reads the
 * same and is not: it skips push, merge_group and dispatch runs entirely. That
 * class of edit is what the single-spelling rule catches, and it survives the
 * generalisation.
 */
const CANONICAL_FORK_CLAUSE = `github.event_name != 'pull_request' || ${FORK_PATH} == github.repository`

/**
 * The clause as it appears inside a condition, ignoring the line breaks and
 * indentation YAML block scalars introduce. Returns null when the condition
 * contains `FORK_PATH` but not the canonical clause — which is the finding, not
 * a parse failure.
 */
function extractForkClause(condition) {
  const flat = unwrap(condition).replace(/\s+/g, ' ')
  return flat.includes(CANONICAL_FORK_CLAUSE) ? CANONICAL_FORK_CLAUSE : null
}

// ---------------------------------------------------------------------------
// A small evaluator for the GitHub Actions expression subset used by job `if:`
// ---------------------------------------------------------------------------

class UnsupportedExpression extends Error {}

/**
 * GitHub's loose equality: "if the types do not match, GitHub coerces the type
 * to a number", with null -> 0, booleans -> 0/1, non-numeric strings and
 * objects -> NaN. That coercion is why the original condition failed silently
 * rather than erroring — `null == 'cipherstash/stack'` is `0 == NaN`, false.
 */
function toNumber(value) {
  if (value === null || value === undefined) return 0
  if (typeof value === 'boolean') return value ? 1 : 0
  if (typeof value === 'number') return value
  if (typeof value === 'string') {
    if (value.trim() === '') return 0
    return Number(value)
  }
  return Number.NaN
}

function looseEquals(a, b) {
  // GitHub compares strings case-insensitively.
  if (typeof a === 'string' && typeof b === 'string') {
    return a.toLowerCase() === b.toLowerCase()
  }
  if (typeof a === 'boolean' && typeof b === 'boolean') return a === b
  const [x, y] = [toNumber(a), toNumber(b)]
  return Number.isNaN(x) || Number.isNaN(y) ? false : x === y
}

/** GitHub truthiness: null, false, 0 and the empty string are false. */
function truthy(value) {
  if (value === null || value === undefined) return false
  if (typeof value === 'string') return value !== ''
  if (typeof value === 'number') return value !== 0
  if (typeof value === 'boolean') return value
  return true
}

function tokenize(expression) {
  const tokens = []
  let i = 0
  while (i < expression.length) {
    const ch = expression[i]
    if (/\s/.test(ch)) {
      i++
      continue
    }
    if (ch === "'") {
      // `''` is GitHub's escape for a literal quote inside a string.
      let value = ''
      i++
      while (i < expression.length) {
        if (expression[i] === "'") {
          if (expression[i + 1] === "'") {
            value += "'"
            i += 2
            continue
          }
          i++
          break
        }
        value += expression[i]
        i++
      }
      tokens.push({ type: 'string', value })
      continue
    }
    const two = expression.slice(i, i + 2)
    if (two === '==' || two === '!=' || two === '&&' || two === '||') {
      tokens.push({ type: 'operator', value: two })
      i += 2
      continue
    }
    if (ch === '(' || ch === ')' || ch === '!') {
      tokens.push({ type: 'operator', value: ch })
      i++
      continue
    }
    const path = /^[A-Za-z_][A-Za-z0-9_.-]*/.exec(expression.slice(i))
    if (path) {
      tokens.push({ type: 'path', value: path[0] })
      i += path[0].length
      continue
    }
    const number = /^\d+(\.\d+)?/.exec(expression.slice(i))
    if (number) {
      tokens.push({ type: 'number', value: Number(number[0]) })
      i += number[0].length
      continue
    }
    throw new UnsupportedExpression(
      `unexpected character ${JSON.stringify(ch)} at offset ${i}`,
    )
  }
  return tokens
}

/** Walk a dotted path; a missing property yields null, as GitHub does. */
function lookup(path, context) {
  let current = context
  for (const segment of path.split('.')) {
    if (current === null || typeof current !== 'object') return null
    current = segment in current ? current[segment] : null
  }
  return current === undefined ? null : current
}

/**
 * The only status function this evaluator will accept, and only in its
 * zero-argument form.
 *
 * `always()` is total: it is true on every event, for every job, whatever its
 * `needs:` reported. So it can be modelled exactly rather than guessed at,
 * which is the bar the rest of this file sets. An aggregator job — EQL's
 * `ci-required`, the single required status check its merge queue references —
 * cannot be written without it, and refusing the whole grammar would have meant
 * either no such job in a dispatchable workflow, or this guard skipping the
 * workflow that contains one.
 *
 * Everything else still throws. `success()`, `failure()` and `cancelled()`
 * depend on run state this file does not model, and `contains()` / `startsWith`
 * take arguments the parser below deliberately cannot evaluate.
 */
const SUPPORTED_FUNCTIONS = new Map([['always', () => true]])

/**
 * Recursive descent over `|| && ! == != ()`, string / number / boolean
 * literals, context paths, and the zero-argument functions in
 * `SUPPORTED_FUNCTIONS`. Any other call throws: guessing at a function's
 * verdict is worse than refusing it, because "the evaluator did not understand
 * it" and "the job runs" must not produce the same green.
 */
function evaluate(expression, context) {
  const tokens = tokenize(expression)
  let position = 0

  const peek = () => tokens[position]
  const eat = (value) => {
    if (peek()?.value === value) {
      position++
      return true
    }
    return false
  }

  const parsePrimary = () => {
    const token = peek()
    if (!token) throw new UnsupportedExpression('unexpected end of expression')
    if (eat('(')) {
      const value = parseOr()
      if (!eat(')')) throw new UnsupportedExpression('unbalanced parentheses')
      return value
    }
    position++
    if (token.type === 'string' || token.type === 'number') return token.value
    if (token.type === 'path') {
      if (peek()?.value === '(') {
        const fn = SUPPORTED_FUNCTIONS.get(token.value)
        // Zero-argument only: `(` must be followed directly by `)`. A call with
        // arguments falls through to the throw, even for a supported name.
        if (fn && tokens[position + 1]?.value === ')') {
          position += 2
          return fn()
        }
        throw new UnsupportedExpression(
          `function call ${token.value}() is not understood`,
        )
      }
      if (token.value === 'true') return true
      if (token.value === 'false') return false
      if (token.value === 'null') return null
      return lookup(token.value, context)
    }
    throw new UnsupportedExpression(`unexpected token ${token.value}`)
  }

  const parseUnary = () => {
    if (eat('!')) return !truthy(parseUnary())
    return parsePrimary()
  }

  const parseEquality = () => {
    let left = parseUnary()
    for (;;) {
      if (eat('==')) left = looseEquals(left, parseUnary())
      else if (eat('!=')) left = !looseEquals(left, parseUnary())
      else return left
    }
  }

  const parseAnd = () => {
    let left = parseEquality()
    while (eat('&&')) {
      const right = parseEquality()
      left = truthy(left) ? right : left
    }
    return left
  }

  function parseOr() {
    let left = parseAnd()
    while (eat('||')) {
      const right = parseAnd()
      left = truthy(left) ? left : right
    }
    return left
  }

  const value = parseOr()
  if (position !== tokens.length) {
    throw new UnsupportedExpression(
      `trailing input from token ${position}: ${tokens
        .slice(position)
        .map((token) => token.value)
        .join(' ')}`,
    )
  }
  return truthy(value)
}

/** Strip the optional `${{ … }}` wrapper GitHub allows around a condition. */
function unwrap(condition) {
  const trimmed = String(condition).trim()
  const match = /^\$\{\{([\s\S]*)\}\}$/.exec(trimmed)
  return (match ? match[1] : trimmed).trim()
}

function runsWhen(condition, context) {
  return evaluate(unwrap(condition), context)
}

// ---------------------------------------------------------------------------
// The four contexts a condition has to land correctly in
// ---------------------------------------------------------------------------

/**
 * Every upstream job output a condition in this repo reads, set to the value
 * that lets the run PROCEED.
 *
 * The fork guard is the property under test, so every other gate has to be
 * held open — otherwise a job that skips for an unrelated reason reads as a
 * job the fork guard skipped, and the assertion below would be satisfied by
 * the wrong mechanism. `test-eql.yml`'s two credentialed jobs are `&&`-ed with
 * `needs.changes.outputs.relevant == 'true'`, which is that unrelated reason:
 * with `needs` absent the path resolves to null, `null == 'true'` is false,
 * and both jobs read as skipped on EVERY event including the ones that must
 * run.
 */
const PERMISSIVE_NEEDS = {
  changes: { outputs: { relevant: 'true' } },
  // release.yml, release-plz.yml and release-postgres-eql-image.yml. Every one
  // of these is a gate that has nothing to do with how the run was triggered,
  // so it is held open — otherwise "this job skips because there is nothing to
  // publish" would be indistinguishable from "this job skips on a dispatch",
  // and the check below would pass for the wrong reason on the FFI jobs it has
  // been covering since before the EQL port.
  classify: { outputs: { mode: 'production', version: '3.0.6' } },
  'eql-armed': { outputs: { armed: 'true' } },
  gate: { result: 'success', outputs: { ffi: 'true' } },
  'publish-ffi': { result: 'success' },
  release: {
    result: 'success',
    outputs: {
      eql_published: 'true',
      eql_version: '3.0.6',
      // A FINAL, not a prerelease: `eql-image` runs only for a final, and this
      // is the value that lets it through. The prerelease half of the file is
      // in DISPATCH_SKIPPED_JOBS rather than being served by a second context.
      eql_prerelease: 'false',
    },
  },
  // release-postgres-eql-image.yml's `promote-latest` reads this from its own
  // `build-sql` job, which copies the dispatch input through.
  'build-sql': { outputs: { update_floating_tags: 'true' } },
}

/**
 * `github.event` carries the webhook payload of the triggering event, so on a
 * manual dispatch there is no `pull_request` key to reach through — that
 * absence is the whole bug.
 *
 * Keyed by CONTEXT, not by event: the two pull_request entries differ only in
 * which repository the head branch lives in, and that difference is the whole
 * point. `EVENT_OF` below maps each back to the `on:` key that produces it.
 */
const CONTEXTS = {
  push: {
    needs: PERMISSIVE_NEEDS,
    github: {
      event_name: 'push',
      repository: REPOSITORY,
      ref: 'refs/heads/main',
      event: { ref: 'refs/heads/main', repository: { full_name: REPOSITORY } },
    },
  },
  merge_group: {
    needs: PERMISSIVE_NEEDS,
    github: {
      event_name: 'merge_group',
      repository: REPOSITORY,
      ref: 'refs/heads/gh-readonly-queue/main/pr-1-abc',
      event: { merge_group: { head_ref: 'refs/heads/main' } },
    },
  },
  workflow_dispatch: {
    needs: PERMISSIVE_NEEDS,
    github: {
      event_name: 'workflow_dispatch',
      repository: REPOSITORY,
      ref: 'refs/heads/main',
      event: { inputs: {}, ref: 'refs/heads/main' },
    },
  },
  same_repo_pull_request: {
    needs: PERMISSIVE_NEEDS,
    github: {
      event_name: 'pull_request',
      repository: REPOSITORY,
      ref: 'refs/pull/1/merge',
      event: {
        pull_request: { head: { repo: { full_name: REPOSITORY } } },
      },
    },
  },
  fork_pull_request: {
    needs: PERMISSIVE_NEEDS,
    github: {
      event_name: 'pull_request',
      repository: REPOSITORY,
      ref: 'refs/pull/2/merge',
      event: {
        pull_request: { head: { repo: { full_name: 'contributor/stack' } } },
      },
    },
  },
}

/** The `on:` key each context stands in for. */
const EVENT_OF = {
  push: 'push',
  merge_group: 'merge_group',
  workflow_dispatch: 'workflow_dispatch',
  same_repo_pull_request: 'pull_request',
  fork_pull_request: 'pull_request',
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/**
 * `on:` parses as the boolean `true` under YAML 1.1 (the "Norway problem"),
 * hence the two keys. `workflow_dispatch:` with no value parses as null, so
 * membership — not truthiness — is what says the trigger is declared.
 */
function triggers(wf) {
  const on = wf?.on ?? wf?.[true]
  return on && typeof on === 'object' ? on : {}
}

function declaresDispatch(wf) {
  return 'workflow_dispatch' in triggers(wf)
}

/** Job-level conditions only: a step `if:` cannot skip the job. */
function jobConditions(relPath) {
  const wf = readWorkflow(relPath)
  return Object.entries(wf?.jobs ?? {})
    .filter(([, job]) => job?.if !== undefined)
    .map(([jobName, job]) => ({
      id: `${relPath} / ${jobName}`,
      relPath,
      jobName,
      condition: String(job.if),
    }))
}

const ALL_CONDITIONS = workflowFiles().flatMap(jobConditions)

const DISPATCHABLE = workflowFiles().filter((relPath) =>
  declaresDispatch(readWorkflow(relPath)),
)

const DISPATCHABLE_CONDITIONS = ALL_CONDITIONS.filter((entry) =>
  DISPATCHABLE.includes(entry.relPath),
)

const FORK_GUARDS = ALL_CONDITIONS.filter((entry) =>
  entry.condition.includes(FORK_PATH),
)

describe('a declared workflow_dispatch actually dispatches', () => {
  it('finds the workflows that declare workflow_dispatch', () => {
    const missing = EXPECTED_DISPATCHABLE.filter(
      (relPath) => !DISPATCHABLE.includes(relPath),
    )
    expect(
      missing,
      `These workflows declared \`workflow_dispatch\` and the scan no longer sees them. Either the trigger was removed deliberately (update EXPECTED_DISPATCHABLE) or the \`on:\` block no longer parses the way this file expects.`,
    ).toEqual([])
  })

  it('examines at least one job-level condition in a dispatchable workflow', () => {
    // Without this the suite passes by vacuum the moment the last job-level
    // `if:` leaves a dispatchable workflow — the same failure mode as a
    // discovery test that matches nothing. If a guard was legitimately
    // deleted rather than fixed, delete this floor deliberately.
    expect(
      DISPATCHABLE_CONDITIONS.map((entry) => entry.id),
      'No job in any workflow declaring `workflow_dispatch` carries a job-level `if:`, so the check below has nothing to evaluate.',
    ).not.toEqual([])
  })

  it('skips exactly the jobs declared unreachable by a plain dispatch', () => {
    // An equality, both directions. A job that quietly stops running on
    // dispatch fails; an entry left behind after its job starts running (or
    // after the job is deleted) fails too, so the list cannot become a place
    // findings go to be forgotten.
    const skipped = DISPATCHABLE_CONDITIONS.filter(
      ({ condition }) => !runsWhen(condition, CONTEXTS.workflow_dispatch),
    ).map((entry) => entry.id)

    expect(
      skipped.sort(),
      'The set of jobs that do not run on a manual dispatch has changed. If a job JOINED it, its `workflow_dispatch:` just became decorative for that job — gate on the case that genuinely cannot run rather than enumerating the events that can. If a job LEFT it, delete its DISPATCH_SKIPPED_JOBS entry in the same commit.',
    ).toEqual([...DISPATCH_SKIPPED_JOBS].sort())
  })

  for (const { id, condition } of DISPATCHABLE_CONDITIONS.filter(
    (entry) => !DISPATCH_SKIPPED_JOBS.includes(entry.id),
  )) {
    it(`${id} runs on a manual dispatch`, () => {
      expect(
        runsWhen(condition, CONTEXTS.workflow_dispatch),
        `This job is skipped when the workflow is dispatched by hand, so its declared \`workflow_dispatch:\` trigger does nothing: the run is created and reports success having executed no job.\n  if: ${condition}\nGate on the case that genuinely cannot run — a fork pull request has no secrets — rather than enumerating the events that can: \`github.event_name != 'pull_request' || <same-repo check>\`.`,
      ).toBe(true)
    })
  }
})

describe('the fork-PR guard keeps its meaning', () => {
  it('finds the jobs carrying the fork-PR guard', () => {
    expect(FORK_GUARDS.map((entry) => entry.id).sort()).toEqual(
      EXPECTED_FORK_GUARDED_JOBS,
    )
  })

  it('spells the guard identically in every copy', () => {
    // GitHub Actions has no YAML anchors, so this clause is written out eight
    // times. It stays identical for the same reason the `paths:` filters are
    // compared pairwise in `integration-workflow-paths.test.mjs`: the next
    // person writes their guard by copying one of these, and a divergent copy
    // is how the copied-from version keeps being the broken one.
    //
    // The CLAUSE, not the condition — see `CANONICAL_FORK_CLAUSE`. A condition
    // that mentions FORK_PATH without containing the clause verbatim extracts
    // to `null`, which lands here as a distinct "spelling" and fails.
    const spellings = [
      ...new Set(
        FORK_GUARDS.map((entry) => extractForkClause(entry.condition)),
      ),
    ]
    expect(
      spellings,
      `Every fork guard must contain this clause verbatim, alone or as one conjunct:\n  ${CANONICAL_FORK_CLAUSE}\nFound ${spellings.length} distinct spellings (a \`null\` below means a condition names ${FORK_PATH} but not the canonical clause):\n${spellings
        .map((s) => `  ${s}`)
        .join('\n')}`,
    ).toEqual([CANONICAL_FORK_CLAUSE])
  })

  for (const { id, relPath, condition } of FORK_GUARDS) {
    it(`${id} skips fork PRs and runs everything else`, () => {
      const declared = triggers(readWorkflow(relPath))

      // Every context, then narrowed to the ones this workflow can actually be
      // in. A workflow with no `push:` trigger is never evaluated on a push, so
      // requiring `push: true` there would be asserting about a run that cannot
      // happen. (`test-eql.yml` carried no `push:` when this was written,
      // justified by a merge queue that does not exist in this repository; it
      // has one now, and this narrowing simply picks the trigger up.)
      //
      // `workflow_dispatch` is the exception and stays unconditional: this file
      // exists because a job silently skipped on a dispatch that WAS declared,
      // and "adding the trigger later would work" is worth holding even where
      // it is not declared yet. It costs nothing — no guard here gates on
      // anything a dispatch fails to provide except the fork payload, which is
      // the bug.
      const applicable = Object.keys(CONTEXTS).filter(
        (name) => name === 'workflow_dispatch' || EVENT_OF[name] in declared,
      )

      const verdicts = Object.fromEntries(
        applicable.map((name) => [name, runsWhen(condition, CONTEXTS[name])]),
      )
      const expected = Object.fromEntries(
        applicable.map((name) => [name, name !== 'fork_pull_request']),
      )

      expect(
        verdicts,
        `  if: ${condition}\nEvaluated with every OTHER gate held open (needs.changes.outputs.relevant = 'true'), so a false here is the fork guard's doing and nothing else.`,
      ).toEqual(expected)
    })
  }
})

describe('the expression evaluator this guard depends on', () => {
  // A guard built on an evaluator that answers `true` to everything is a guard
  // that cannot fail. These pin both verdicts against the two spellings that
  // motivated the file: the historical condition and its replacement.
  const BROKEN = `github.event_name == 'push' || ${FORK_PATH} == github.repository`
  const FIXED = `github.event_name != 'pull_request' || ${FORK_PATH} == github.repository`

  it('reproduces the defect in the pre-fix condition', () => {
    expect(runsWhen(BROKEN, CONTEXTS.push)).toBe(true)
    expect(runsWhen(BROKEN, CONTEXTS.same_repo_pull_request)).toBe(true)
    expect(runsWhen(BROKEN, CONTEXTS.fork_pull_request)).toBe(false)
    // The bug: a declared trigger that skips its only job.
    expect(runsWhen(BROKEN, CONTEXTS.workflow_dispatch)).toBe(false)
  })

  it('clears the fixed condition on every event', () => {
    expect(runsWhen(FIXED, CONTEXTS.push)).toBe(true)
    expect(runsWhen(FIXED, CONTEXTS.workflow_dispatch)).toBe(true)
    expect(runsWhen(FIXED, CONTEXTS.same_repo_pull_request)).toBe(true)
    expect(runsWhen(FIXED, CONTEXTS.fork_pull_request)).toBe(false)
  })

  it('rejects an expression it cannot reason about', () => {
    // Fail shut. An `if:` outside the grammar must not read as "runs".
    //
    // `success()` rather than `always()`: the latter is now modelled (see
    // SUPPORTED_FUNCTIONS), and this assertion has to name something the
    // evaluator genuinely cannot answer. `success()` is that — it depends on
    // the run state of the job's `needs:`, which nothing here models.
    expect(() => runsWhen('success()', CONTEXTS.workflow_dispatch)).toThrow(
      UnsupportedExpression,
    )
    expect(() =>
      runsWhen("contains(github.ref, 'main')", CONTEXTS.push),
    ).toThrow(UnsupportedExpression)
  })

  it('models `always()` exactly, and only in its zero-argument form', () => {
    // Total on every event, which is what makes it modellable at all. EQL's
    // `ci-required` — the single required status check its merge queue
    // references — is written this way, and a guard that threw on it would
    // have to skip the whole workflow.
    for (const context of Object.values(CONTEXTS)) {
      expect(runsWhen('always()', context)).toBe(true)
    }

    // Arguments are refused even for a supported name: `always(x)` is not a
    // thing GitHub accepts, and quietly evaluating it as `always()` would mean
    // the evaluator answering a question nobody asked.
    expect(() => runsWhen('always(true)', CONTEXTS.push)).toThrow(
      UnsupportedExpression,
    )
  })

  it('applies GitHub null coercion rather than JavaScript equality', () => {
    // `null == 'cipherstash/stack'` is `0 == NaN`. This is the coercion that
    // turned a missing `pull_request` payload into a silent `false` instead of
    // an error, so the evaluator has to model it, not JavaScript's rules.
    expect(looseEquals(null, REPOSITORY)).toBe(false)
    expect(looseEquals(null, '')).toBe(true)
    expect(looseEquals('PUSH', 'push')).toBe(true)
  })
})

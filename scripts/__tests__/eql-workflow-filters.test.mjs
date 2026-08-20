import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
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
 * 4. THE LISTS COVER WHAT THE JOBS READ — partially, and mechanically. See the
 *    second half of this file. Properties 1-3 keep the three copies equal and
 *    non-fictional; none of them can notice that the one list is MISSING a
 *    tree. `packages/eql/docker/**` and `packages/eql/docs/**` were both absent
 *    while `test:docs_v3_grep` — a step in this very workflow — read
 *    `docker/README.md` and every tracked markdown file under `docs/`, so a
 *    push to main touching only those trees started no EQL workflow at all.
 *
 * NOT COVERED, still. Property 4 derives inputs from path literals written in
 * the task bodies; it cannot see a path a task reads IMPLICITLY. `mise run
 * postgres:up` reads `tests/docker-compose.yml` by running `docker compose` in
 * that directory and naming no file, and nothing here can tell. Nor does it
 * follow paths built by shell interpolation, nor the files the Rust and SQL
 * those tasks invoke go on to open. What properties 1-4 together guarantee is
 * that a path a task NAMES is covered, and that the next omission of one it
 * merely implies has to be made three times rather than once.
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

// ---------------------------------------------------------------------------
// Property 4: the lists cover the paths the jobs' mise tasks NAME.
//
// The three checks above are all shape checks — the copies agree, the entries
// are real, the composite actions are listed. Every one of them passed on the
// day `packages/eql/docs/**` was missing from all three, because a list can be
// equal to itself, entirely non-fictional, and still leave out a tree.
//
// So this half works the other way round: start from the workflow, walk to the
// tasks it runs, and read the paths those tasks name. Concretely —
//
//   workflow `run:` bodies  ->  `mise run <task>`
//                           ->  the task's definition (a `[tasks."x"]` block in
//                               mise.toml / tasks/*.toml, or a file task under
//                               tasks/), plus everything it `depends` on and
//                               every `mise run` and `tasks/…` script inside it
//                           ->  the path literals in those bodies that git
//                               actually tracks
//
// and then every one of those paths must be selected by the workflow's
// `on: push: paths:` filter. That filter is the one this can be strict about:
// it decides whether the workflow STARTS, so it has to cover the inputs of
// every job in the file, relevance-gated or not. The `dorny` copy gates only a
// subset of the jobs, so it is not asserted here — it inherits the entries
// through the parity check above, which is the looser but correct claim (the
// bench inherits them the same way; see the comment on its own filter for why
// equal beats minimal).
//
// LIMITS, stated rather than implied. This sees paths WRITTEN DOWN. It does not
// see `docker compose` picking up `tests/docker-compose.yml` from its working
// directory, a path assembled from shell variables, or a glob pathspec —
// `tasks/test/doc-anchors.sh` enumerates `git ls-files '*.md'`, i.e. every
// tracked markdown file under the subtree, and only the literal pathspecs are
// resolved here. Those remain hand-read. The point is that the class of
// omission that has actually happened twice — a whole directory nobody
// remembered — is now mechanical.

const EQL = 'packages/eql'

const readRepoFile = (relPath) => readFileSync(join(REPO_ROOT, relPath), 'utf8')

const TRACKED_EQL = trackedUnder(EQL)
const TRACKED_EQL_FILES = new Set(TRACKED_EQL)

/** Every directory that has a tracked file under it, as a repo-relative path. */
const TRACKED_EQL_DIRS = new Set(
  TRACKED_EQL.flatMap((file) => {
    const segments = file.split('/')
    return segments
      .slice(0, -1)
      .map((_, i) => segments.slice(0, i + 1).join('/'))
  }),
)

/**
 * Drop whole-line `#` comments, and ONLY those.
 *
 * Task scripts describe paths in prose constantly ("move it under
 * docs/upgrading"), and a commented path is not a path the task reads. `#MISE`
 * lines are the exception and are kept: they are directives mise parses, so
 * `#MISE depends=[…]` names a real dependency and `#MISE sources=[…]` names
 * real inputs. Trailing comments are not stripped — `#` is too common inside
 * shell strings to remove safely — so a path mentioned after code on the same
 * line is over-counted, which errs toward demanding coverage.
 */
const stripProse = (text) =>
  text
    .split('\n')
    .filter((line) => !/^\s*#(?!MISE\b)/.test(line))
    .join('\n')

/** `mise run` flags that consume the token after them, so it is not the task. */
const MISE_VALUE_FLAGS = new Set(['--output', '-o', '--jobs', '-j'])

/** Every task name invoked by a `mise run` in this text. */
function miseRunTargets(text) {
  const targets = []
  for (const call of stripProse(text).matchAll(/\bmise\s+run\s+([^\n&|;]*)/g)) {
    const tokens = call[1].trim().split(/\s+/)
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i]
      if (token.startsWith('-')) {
        // `--output prefix` — the value is a bare word and would otherwise be
        // read as the task name. Dropping the whole invocation instead is what
        // an earlier draft did, and the scan guard below is what caught it:
        // `bench-eql.yml` runs its only real task that way.
        if (MISE_VALUE_FLAGS.has(token)) i += 1
        continue
      }
      // Positive match rather than a trim: these appear inside quoted shell
      // strings, so the raw token can carry `)`, `'` or a literal `\n`.
      const name = /[A-Za-z0-9_][A-Za-z0-9_:.-]*/.exec(token)?.[0]
      if (name) targets.push(name)
      break
    }
  }
  return targets
}

/** Every `run:` script in a workflow, across all jobs. */
function stepShellBodies(relPath) {
  return Object.values(readWorkflow(relPath)?.jobs ?? {})
    .flatMap((job) => job?.steps ?? [])
    .map((step) => step?.run)
    .filter((run) => typeof run === 'string')
}

/**
 * `mise.toml` and the files its `[task_config].includes` pulls in. Parsed by
 * hand — the repo has no TOML reader, and only the table boundaries matter:
 * each task's block is fed to the same path extractor as a shell script, so
 * `run`, `depends` and `dir` are all read without knowing TOML's types.
 */
const TASK_TOML_FILES = [
  `${EQL}/mise.toml`,
  `${EQL}/tasks/postgres.toml`,
  `${EQL}/tasks/fixtures.toml`,
]

/** Task name -> the text of its table. `[tasks."x"]` and the includes' `["x"]`. */
const TASK_BLOCKS = (() => {
  const blocks = new Map()
  for (const relPath of TASK_TOML_FILES) {
    let name = null
    let body = []
    const flush = () => {
      if (name) blocks.set(name, `${blocks.get(name) ?? ''}${body.join('\n')}`)
      name = null
      body = []
    }
    for (const line of readRepoFile(relPath).split('\n')) {
      const header = /^\[(?:tasks\.)?"([^"]+)"\]\s*$/.exec(line)
      if (header) {
        flush()
        name = header[1]
      } else if (line.startsWith('[')) {
        flush()
      } else if (name) {
        body.push(line)
      }
    }
    flush()
  }
  return blocks
})()

/** A file task: mise maps `a:b` to `tasks/a/b`, with or without an extension. */
function fileTaskPath(name) {
  const base = `${EQL}/tasks/${name.replaceAll(':', '/')}`
  return (
    ['', '.sh', '.bash', '.py']
      .map((ext) => base + ext)
      .find((candidate) => TRACKED_EQL_FILES.has(candidate)) ?? null
  )
}

/**
 * Path literals in one body that name a file git tracks under `packages/eql/`,
 * plus the literal directory pathspecs handed to `git ls-files`.
 *
 * Only TRACKED FILES are accepted for the bare-token form. Accepting tracked
 * DIRECTORIES there too was the first cut and it is unsound: `docker compose`
 * scores as the `docker/` directory and the task name `docs:validate:coverage`
 * scores as `docs/`. Both happened, and both happened to name a directory that
 * really was missing from the filter — a right answer for a reason that would
 * not survive a rename. `git ls-files -- <dir>` is the one place a directory is
 * unambiguously being READ, so that form is parsed on its own terms.
 */
function pathLiteralsIn(text) {
  const source = stripProse(text)
  const found = new Set()
  for (const token of source.matchAll(
    /[A-Za-z0-9_][A-Za-z0-9_.-]*(?:\/[A-Za-z0-9_.-]+)*/g,
  )) {
    const relPath = `${EQL}/${token[0]}`
    if (TRACKED_EQL_FILES.has(relPath)) found.add(relPath)
  }
  for (const call of source.matchAll(/git\s+ls-files\s+([^\n|)]*)/g)) {
    for (const token of call[1].trim().split(/\s+/)) {
      // Flags, pathspec magic (`:!:…`) and globs are not literal paths.
      if (token.startsWith('-') || token.startsWith(':')) continue
      if (/[*?[\]]/.test(token)) continue
      const relPath = `${EQL}/${token.replace(/^['"]|['"]$/g, '')}`
      if (TRACKED_EQL_DIRS.has(relPath)) found.add(relPath)
    }
  }
  return [...found]
}

/**
 * Walk a workflow's `mise run` calls out to every task body they reach, and
 * return the paths those bodies name, each with where it was named.
 */
function deriveTaskInputs(relPath) {
  const inputs = new Map()
  const unresolved = new Set()
  const seenTasks = new Set()
  const seenFiles = new Set()

  const record = (text, label) => {
    for (const found of pathLiteralsIn(text)) {
      if (!inputs.has(found)) inputs.set(found, new Set())
      inputs.get(found).add(label)
    }
  }

  const addScript = (scriptPath) => {
    if (seenFiles.has(scriptPath) || !TRACKED_EQL_FILES.has(scriptPath)) return
    seenFiles.add(scriptPath)
    const text = readRepoFile(scriptPath)
    record(text, scriptPath)
    walk(text)
  }

  const addTask = (name) => {
    if (!name || seenTasks.has(name)) return
    seenTasks.add(name)
    const block = TASK_BLOCKS.get(name)
    if (block !== undefined) {
      record(block, `mise task "${name}"`)
      walk(block)
      return
    }
    const scriptPath = fileTaskPath(name)
    if (scriptPath) addScript(scriptPath)
    else unresolved.add(name)
  }

  function walk(text) {
    const source = stripProse(text)
    for (const name of miseRunTargets(text)) addTask(name)
    // A task that shells out to a sibling script directly (`bash tasks/…`)
    // rather than through `mise run`.
    for (const script of source.matchAll(/tasks\/[A-Za-z0-9_./-]+/g))
      addScript(`${EQL}/${script[0]}`)
    // `depends = ["build"]` in TOML and `#MISE depends=["build"]` in a script.
    for (const list of source.matchAll(/depends\s*=\s*\[([^\]]*)\]/g))
      for (const entry of list[1].matchAll(/"([^"]+)"|'([^']+)'/g))
        addTask(entry[1] ?? entry[2])
  }

  for (const body of stepShellBodies(relPath))
    for (const name of miseRunTargets(body)) addTask(name)

  return { inputs, unresolved, tasks: seenTasks }
}

/** Files a derived input stands for: itself, or everything tracked under it. */
const filesOf = (inputPath) =>
  TRACKED_EQL_FILES.has(inputPath)
    ? [inputPath]
    : TRACKED_EQL.filter((file) => file.startsWith(`${inputPath}/`))

describe('the EQL push filters cover what the workflows actually read', () => {
  it('extracts a path literal a task names', () => {
    // The anti-vacuity pin, and the negative half of it. Once the filters are
    // correct, every assertion below passes on an EMPTY derivation too — so
    // this fixes the extractor against a body written here: a tracked file is
    // found, a commented one is not, and a bare directory name is not (that
    // last is what makes `docker compose` stop counting as `docker/`).
    const body = [
      'bash tasks/build.sh',
      'psql -f src/v3/schema.sql',
      'docker compose up',
      '# see docs/reference/json-support.md for the shape',
      'git ls-files -- docs',
    ].join('\n')

    expect(pathLiteralsIn(body).sort()).toEqual([
      `${EQL}/docs`,
      `${EQL}/src/v3/schema.sql`,
      `${EQL}/tasks/build.sh`,
    ])
  })

  for (const relPath of [TEST_EQL, BENCH_EQL]) {
    const { inputs, unresolved, tasks } = deriveTaskInputs(relPath)

    it(`${relPath} resolves every task it runs`, () => {
      // A `mise run` this file fails to resolve is a task subtree it never
      // reads — silently, and with no effect on any assertion below. That is
      // the shape of the bug this whole file exists to catch, one level up.
      expect(
        [...unresolved],
        `These task names were parsed out of \`mise run\` in ${relPath} and match no \`[tasks."…"]\` table in ${TASK_TOML_FILES.join(', ')} and no file under ${EQL}/tasks/. Either the task was renamed and the workflow not updated (a real CI break), or the invocation uses a \`mise run\` form this file cannot parse — in which case teach \`miseRunTargets\` the form rather than deleting the name.`,
      ).toEqual([])

      // Scan guard: if the walk reaches nothing, "every input is covered" is
      // true of no inputs.
      expect(tasks.size, `${relPath} runs no mise task`).toBeGreaterThan(0)
      expect(
        inputs.size,
        `${relPath} reaches ${tasks.size} mise task(s) and none of them names a tracked path, which cannot be right — the extraction shape has probably changed.`,
      ).toBeGreaterThan(0)
    })

    it(`${relPath} triggers on a push to every path those tasks name`, () => {
      const entries = pushPaths(relPath)
      const uncovered = [...inputs]
        .filter(([inputPath]) =>
          filesOf(inputPath).some(
            (file) => !entries.some((entry) => matches(entry, file)),
          ),
        )
        .map(
          ([inputPath, where]) =>
            `${inputPath}  (named by ${[...where].sort().join(', ')})`,
        )
        .sort()

      expect(
        uncovered,
        `${relPath} runs a mise task that reads these paths, and its \`on: push: paths:\` filter selects none of them — so a commit to main touching only one of them starts no run of this workflow, and the job that reads it never reports.\nThis is not the same failure as a dead glob: a dead glob narrows the filter by nothing, and a missing one narrows it to less than the workflow needs. \`packages/eql/docs/**\` and \`packages/eql/docker/**\` were both absent while \`test:docs_v3_grep\` scanned them.\nAdd a glob covering each path to the \`paths:\` list — and, because the three copies are held equal by the parity check above, to the other two lists in the same edit.`,
      ).toEqual([])
    })
  }
})

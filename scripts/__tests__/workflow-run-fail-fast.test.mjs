import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A multi-command `run:` block under a CUSTOM shell must turn on errexit
 * itself, because GitHub does not turn it on for it.
 *
 * For the built-in `shell: bash`, GitHub runs `bash --noprofile --norc -eo
 * pipefail {0}` — the `-e` is there, and a failing command anywhere in the
 * block fails the step. Write `shell: bash {0}` instead and you get exactly the
 * flags you asked for, which is none of them. The block then runs to the end
 * regardless and the step reports only the LAST command's exit code.
 *
 * Every EQL workflow imported with the subtree carries
 * `defaults.run.shell: bash {0}`, so this applied to all three files at once,
 * and it fails in the silent direction. Two live instances, both of them a
 * build followed by the check that inspects what the build produced:
 *
 *   test-eql.yml, "Clean-DB v3 install smoke"
 *     mise run clean && mise run build
 *     mise run test:clean_install_v3
 *
 *   macro-expand-eql.yml, "Regenerate and verify the matrix expansion snapshots"
 *     mise run test:matrix:expand
 *     git diff --exit-code -- … || { echo "…stale…"; exit 1; }
 *
 * In both, a failing FIRST line is discarded and the second line decides the
 * step. In the second the second line is a drift check against files the first
 * line was supposed to regenerate — so when the regeneration breaks, the
 * snapshots are unchanged, the diff is clean, and the job goes green having
 * verified that a build which did not happen produced no change.
 *
 * `test-eql.yml`'s "Verify the matrix test-name inventory" already carried
 * `set -euo pipefail` with a comment explaining exactly this. That comment is
 * the evidence the hazard was understood and the fix applied one step at a
 * time; this file is what applies it to the rest.
 *
 * ERREXIT ONLY, not pipefail. Errexit is what the defect is about, and pipefail
 * is not always safe to add retroactively: a `grep … | head -1` reports 141
 * under pipefail when the reader closes early, which is the SIGPIPE hazard
 * `workflow-grep-q-pipelines.test.mjs` documents at length. Requiring `-e` and
 * leaving `-o pipefail` to judgement keeps this guard from pushing anyone into
 * that one.
 *
 * SINGLE-COMMAND BLOCKS ARE EXEMPT, and that is not a loophole: the step's exit
 * code IS that command's, so errexit changes nothing. Only blocks with more
 * than one top-level command can lose a status.
 */

/** Composite actions run the same shells and are part of the same call tree. */
function actionManifests() {
  const dir = '.github/actions'
  return readdirSync(join(REPO_ROOT, dir), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => `${dir}/${entry.name}/action.yml`)
    .sort()
}

/**
 * Every `run:` step, with the shell that will actually execute it.
 *
 * Resolution order is GitHub's: the step's own `shell:`, then the job's
 * `defaults.run.shell`, then the workflow's. A composite action has no
 * defaults — `shell:` is required on each step there — so the same walk with
 * two empty levels is correct rather than merely convenient.
 */
function runSteps(doc, file) {
  const workflowShell = doc?.defaults?.run?.shell
  const fromJobs = Object.entries(doc?.jobs ?? {}).flatMap(([jobId, job]) =>
    (job?.steps ?? [])
      .filter((step) => typeof step?.run === 'string')
      .map((step) => ({
        file,
        where: `${jobId} › ${step.name ?? step.id ?? '(unnamed)'}`,
        run: step.run,
        shell: step.shell ?? job?.defaults?.run?.shell ?? workflowShell,
      })),
  )
  const fromAction = (doc?.runs?.steps ?? [])
    .filter((step) => typeof step?.run === 'string')
    .map((step) => ({
      file,
      where: step.name ?? step.id ?? '(unnamed)',
      run: step.run,
      shell: step.shell,
    }))
  return [...fromJobs, ...fromAction]
}

/**
 * A shell template — anything containing the `{0}` script placeholder. That
 * placeholder is precisely what turns a shell KEYWORD (for which GitHub supplies
 * its own flags) into a custom command line (for which it supplies none).
 */
const isCustomShell = (shell) => /\{0\}/.test(String(shell ?? ''))

/** Errexit, in every spelling: `-e`, `-eo`, `-euo`, `-o errexit`. */
const ERREXIT = /(?:^|\s)(?:-[a-zA-Z]*e[a-zA-Z]*|-o\s+errexit)(?:\s|$)/

/** Does the custom shell command line itself ask for errexit? */
const shellSetsErrexit = (shell) =>
  ERREXIT.test(String(shell ?? '').replace(/\{0\}/, ''))

/** Does the script turn errexit on before doing anything? */
const scriptSetsErrexit = (run) =>
  String(run)
    .split('\n')
    .some((line) => /^\s*set\s+/.test(line) && ERREXIT.test(line))

/**
 * The top-level commands in a script.
 *
 * Continuations are joined — a trailing `\`, and a line ending in `&&`, `||`,
 * `|` or `;` — because those are one command spread over several lines and
 * cannot lose a status between them. Comments and blank lines are dropped.
 *
 * Block keywords (`if`/`fi`, `for`/`done`, `case`/`esac`) are deliberately NOT
 * collapsed. A four-line `if` counts as four, and so needs `set -e` it does not
 * strictly require. That over-strictness is chosen: recognising shell blocks
 * means parsing shell, the parser is what would be wrong, and the cost of being
 * wrong in this direction is one line at the top of a script that is better for
 * having it.
 */
function topLevelCommands(script) {
  const commands = []
  let pending = ''
  let continued = false
  for (const raw of String(script).split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#')) continue
    pending = continued ? `${pending} ${line}` : line
    continued = /(?:\\|&&|\|\||\||;)$/.test(line)
    if (!continued) {
      commands.push(pending)
      pending = ''
    }
  }
  if (pending !== '') commands.push(pending)
  return commands
}

const FILES = [...workflowFiles(), ...actionManifests()]

const CUSTOM_SHELL_STEPS = FILES.flatMap((file) =>
  runSteps(readWorkflow(file), file).filter((step) =>
    isCustomShell(step.shell),
  ),
)

const MULTI_COMMAND = CUSTOM_SHELL_STEPS.filter(
  (step) => topLevelCommands(step.run).length > 1,
)

const stepId = (step) => `${step.file} › ${step.where}`

/**
 * Steps that legitimately must NOT fail fast, each with the reason. Empty
 * today and intended to stay that way — a step that wants to continue past a
 * failing command should say so at that command (`… || true`) rather than by
 * leaving errexit off for the whole block, because the second form also
 * swallows the failures nobody chose to tolerate.
 *
 * The stale check below deletes an entry the moment it stops matching a
 * multi-command custom-shell step, so an exemption cannot outlive the step it
 * was written for.
 */
const FAIL_FAST_EXEMPT = new Map([
  // ['<file> › <job> › <step>', 'why this block must run past a failing command'],
])

describe('multi-command run: blocks under a custom shell fail fast', () => {
  it('finds workflows and composite actions to check', () => {
    expect(FILES.length).toBeGreaterThan(0)
  })

  it('finds the custom-shell steps this guard exists for', () => {
    // `shell: bash {0}` is what drops GitHub's implicit `-eo pipefail`. If no
    // step uses a custom shell the property is vacuous — which would be a fine
    // state of the world, but not one to reach silently, since the three EQL
    // workflows set it at `defaults.run` level where it is easy to lose.
    expect(
      CUSTOM_SHELL_STEPS.map(stepId),
      'No `run:` step in the repository resolves to a custom shell (one containing `{0}`), so this file checks nothing. If the EQL workflows dropped `defaults.run.shell: bash {0}` in favour of the `bash` keyword, that is the better fix and this guard is obsolete — delete it deliberately.',
    ).not.toEqual([])
  })

  it('finds multi-command ones among them', () => {
    // The narrower floor, and the one that actually guards the check below:
    // single-command blocks are exempt by construction, so a scan that found
    // only those would iterate nothing while looking healthy.
    expect(
      MULTI_COMMAND.map(stepId),
      'Every custom-shell `run:` block in the repository is a single command, so the errexit check below compares nothing. Verify that is really the case before deleting this floor — `topLevelCommands` joining too eagerly looks identical from here.',
    ).not.toEqual([])
  })

  it('turns errexit on in every one', () => {
    const offenders = MULTI_COMMAND.filter(
      (step) =>
        !shellSetsErrexit(step.shell) &&
        !scriptSetsErrexit(step.run) &&
        !FAIL_FAST_EXEMPT.has(stepId(step)),
    ).map(
      (step) =>
        `  ${stepId(step)}\n    shell: ${step.shell}\n    ${topLevelCommands(step.run).length} top-level commands, first: ${topLevelCommands(step.run)[0]}`,
    )

    expect(
      offenders,
      `These \`run:\` blocks run several commands under a shell that was NOT given \`-e\`, so a failure in any but the last is discarded and the step reports the last command's status.\nThe direction it fails in is the dangerous one: a build followed by a check that inspects the build's output goes GREEN when the build breaks, because the output it checks is simply unchanged.\nAdd \`set -euo pipefail\` as the first line (or \`set -eu\` where a pipeline into an early-exiting reader makes pipefail a SIGPIPE hazard — see \`workflow-grep-q-pipelines.test.mjs\`), or put \`-eo pipefail\` on the shell line itself.\n${offenders.join('\n')}`,
    ).toEqual([])
  })

  it('keeps no stale exemptions', () => {
    const live = new Set(MULTI_COMMAND.map(stepId))
    const stale = [...FAIL_FAST_EXEMPT.keys()].filter((id) => !live.has(id))
    expect(
      stale,
      'These FAIL_FAST_EXEMPT entries no longer name a multi-command custom-shell step. If the step was fixed or collapsed to one command, delete the entry — it now exempts nothing while reading as deliberate, and hides the next one.',
    ).toEqual([])
  })
})

describe('the command counter this guard depends on', () => {
  // A counter that returns 1 for everything makes the check above unfailable,
  // and it would look exactly as green as it does now.
  it('counts a single command as one, however it is spread', () => {
    expect(topLevelCommands('mise run build')).toHaveLength(1)
    expect(topLevelCommands('# a comment\n\nmise run build\n')).toHaveLength(1)
    expect(topLevelCommands('mise run clean && mise run build')).toHaveLength(1)
    expect(topLevelCommands('cat file \\\n  | psql \\\n  -f-')).toHaveLength(1)
    expect(
      topLevelCommands('git diff --exit-code -- a b \\\n  || exit 1'),
    ).toHaveLength(1)
  })

  it('counts commands on separate lines separately', () => {
    expect(
      topLevelCommands('mise run clean && mise run build\nmise run test'),
    ).toHaveLength(2)
  })

  it('recognises errexit in the spellings CI uses', () => {
    expect(scriptSetsErrexit('set -e\nfoo')).toBe(true)
    expect(scriptSetsErrexit('set -euo pipefail\nfoo')).toBe(true)
    expect(scriptSetsErrexit('set -eu\nfoo')).toBe(true)
    expect(scriptSetsErrexit('set -o errexit\nfoo')).toBe(true)
    // The near-misses that must NOT count: pipefail alone leaves a failing
    // non-final command discarded exactly as before.
    expect(scriptSetsErrexit('set -o pipefail\nfoo')).toBe(false)
    expect(scriptSetsErrexit('set -u\nfoo')).toBe(false)
    expect(scriptSetsErrexit('foo\nbar')).toBe(false)
    // And a shell line that already carries it makes the script's own `set`
    // unnecessary — this is how the built-in `bash` keyword behaves.
    expect(shellSetsErrexit('bash --noprofile --norc -eo pipefail {0}')).toBe(
      true,
    )
    expect(shellSetsErrexit('bash {0}')).toBe(false)
  })
})

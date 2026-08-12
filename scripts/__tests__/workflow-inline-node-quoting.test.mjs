import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, WORKFLOW_DIR } from './lib/workflows.mjs'

/**
 * A backtick or a `${` inside a single-quoted `node -e` argument fails the
 * release gate — on whichever day the runner image happens to upgrade
 * shellcheck.
 *
 * WHAT HAPPENED. `_build-ffi-artifacts.yml` carries a `node -e '…'` whose JS
 * says, in a `//` comment, "Against the manifests own `neon.platforms`". Shell
 * does not know that is a comment: the whole argument is one single-quoted
 * string, and shellcheck reads a backtick in it as command substitution that
 * will not expand — SC2016. Fifteen lines further down the SAME argument spells
 * the rule out ("no backticks in this argument — shellcheck reads them as
 * command substitution and reports SC2016") and then a later edit broke it
 * anyway, because nothing was checking.
 *
 * WHY CI WAS GREEN. actionlint is pinned to v1.7.7 but shellcheck is NOT
 * pinned — it comes from whatever the `ubuntu-latest` image ships. The image's
 * shellcheck reported SC2016 only for `$`; 0.11.0 extended it to backticks. So
 * this sat as a latent failure keyed to an image bump, and would have surfaced
 * as a red `lint-release` on an unrelated pull request, which is precisely the
 * "fails at the worst possible moment" that workflow exists to prevent.
 *
 * WHY A REPO-SIDE TEST AND NOT JUST THE GATE. The gate is the same check with
 * an unpinned dependency; it cannot tell "clean" from "this shellcheck does not
 * look for that yet". This runs in `test:scripts` on every pull request, with
 * no binary to download and no version to drift.
 *
 * WHY SCOPED TO INLINE `node` ARGUMENTS rather than all single-quoted text.
 * Shell `#` comments in this repo are full of backticks — twenty of them across
 * these four workflows — and shellcheck is right to ignore every one, because a
 * comment is not a string. The dangerous construct is the inverse: a JS `//`
 * comment that LOOKS like a comment while sitting inside shell single quotes.
 * Scanning the `node -e '…'` argument is exact, and needs no shell lexer whose
 * disagreement with the real one would be the next silent hole.
 *
 * WHY IT STOPS SHORT OF APOSTROPHES, the third thing that must not appear in
 * one of these arguments — an apostrophe does not merely trip a lint, it ENDS
 * the string, and the JS after it becomes shell. That failure needs no guard
 * here because it is already loud on every shellcheck: SC1011 and SC1036 are a
 * warning and an ERROR, not the info-level SC2016, and `lint-release` is
 * path-filtered to exactly these workflows, so any edit that introduces one
 * fails the gate on the pull request that made it. The backtick was worth
 * pinning precisely because it was the quiet one.
 */

const LINT_RELEASE = `${WORKFLOW_DIR}/lint-release.yml`

/**
 * The workflows actionlint is pointed at, read out of the gate itself rather
 * than copied here. `lint-release-scope.test.mjs` already binds that list to
 * the workflow's own `paths:` filter, so deriving from it means this check
 * covers a fifth release workflow the day one is added — and covers nothing
 * silently if the list is ever emptied, which the floor below catches.
 */
const lintedWorkflows = [
  ...readFileSync(join(REPO_ROOT, LINT_RELEASE), 'utf8').matchAll(
    /^\s+(\.github\/workflows\/[\w.-]+\.ya?ml)\s*\\?$/gm,
  ),
].map((match) => match[1])

/** Every `run:` body in a workflow, as `{ job, run }`. */
const runBodies = (relPath) => {
  const doc = readWorkflow(relPath)
  return Object.entries(doc?.jobs ?? {}).flatMap(([job, spec]) =>
    (spec?.steps ?? [])
      .filter((step) => typeof step?.run === 'string')
      .map((step) => ({ job, name: step.name, run: step.run })),
  )
}

/**
 * The single-quoted arguments of inline `node` scripts in one `run:` body.
 *
 * A shell single-quoted string has NO escape sequence — there is no way to put
 * an apostrophe inside one — so the next `'` after the opening one is
 * unambiguously the terminator. That is why this can be a scan rather than a
 * parser.
 *
 * An unterminated one throws instead of being skipped: `node -e '` with no
 * closing quote is a broken workflow, and reading it as "no argument to check"
 * would report the broken file as clean.
 */
export const inlineNodeScripts = (run) => {
  const scripts = []
  const opener = /node\s+(?:-e|-p|--eval|--print)\s+'/g
  let match = opener.exec(run)
  while (match !== null) {
    const start = match.index + match[0].length
    const end = run.indexOf("'", start)
    if (end === -1) {
      throw new Error(
        `unterminated single-quoted node argument at offset ${match.index}`,
      )
    }
    scripts.push(run.slice(start, end))
    opener.lastIndex = end + 1
    match = opener.exec(run)
  }
  return scripts
}

/**
 * What shellcheck objects to in a single-quoted string: the two forms it reads
 * as an expression that will not expand.
 *
 * `$` alone is not enough — `/^\d+\.\d+\.\d+/` is a legal regex in one of these
 * arguments today and shellcheck says nothing about a bare `$`. It is `${` and
 * the backtick that trip SC2016.
 */
export const sc2016Offenders = (script) =>
  script
    .split('\n')
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(({ line }) => line.includes('`') || line.includes('${'))
    .map(({ line, number }) => `${number}: ${line.trim()}`)

describe('release workflows — inline node scripts survive shellcheck', () => {
  it('finds the workflows and the inline scripts, rather than passing on none', () => {
    // The guard on the scan: the check below is a filter over a derived list,
    // and an empty list makes it pass having read nothing. Both floors are the
    // state at writing — four linted workflows, and the inline `node` scripts
    // that verify the packed tarballs.
    expect(lintedWorkflows.length).toBeGreaterThanOrEqual(4)
    const scripts = lintedWorkflows.flatMap((file) =>
      runBodies(file).flatMap(({ run }) => inlineNodeScripts(run)),
    )
    expect(scripts.length).toBeGreaterThanOrEqual(2)
  })

  it('carries no backtick or ${ in a single-quoted node argument', () => {
    const offenders = lintedWorkflows.flatMap((file) =>
      runBodies(file).flatMap(({ job, name, run }) =>
        inlineNodeScripts(run).flatMap((script) =>
          sc2016Offenders(script).map(
            (hit) => `${file} / ${job} / ${name ?? 'unnamed step'} — ${hit}`,
          ),
        ),
      ),
    )
    expect(
      offenders,
      'Shell reads the whole argument as one string, JS comment or not: a backtick or `${` in it is SC2016, and lint-release turns that into a failed release gate.',
    ).toEqual([])
  })
})

describe('release workflows — how an inline node argument is found', () => {
  // Against synthetic input, because the sweep above only ever sees a tree
  // someone has already cleaned. A scanner that matched nothing would pass it.
  it('reads the argument up to its closing quote', () => {
    expect(inlineNodeScripts("node -e 'console.log(1)' && echo done")).toEqual([
      'console.log(1)',
    ])
  })

  it('finds every inline script in one body, not just the first', () => {
    expect(inlineNodeScripts("node -e 'a'\nnode -p 'b'")).toEqual(['a', 'b'])
  })

  it('ignores an argument that is not single-quoted', () => {
    // Double quotes are a different question — the shell expands them, so a
    // backtick there is real command substitution and shellcheck is right to
    // say nothing about SC2016. `.github/actions/build-ffi-binding` uses that
    // form deliberately.
    expect(inlineNodeScripts('node -e "require(\'./lib\')"')).toEqual([])
  })

  it('throws on an unterminated argument rather than reporting it clean', () => {
    expect(() => inlineNodeScripts("node -e 'oops")).toThrow(/unterminated/)
  })

  it('reports the offending forms and only those', () => {
    expect(sc2016Offenders('// a `backtick` comment')).toEqual([
      '1: // a `backtick` comment',
    ])
    // biome-ignore-start lint/suspicious/noTemplateCurlyInString: a literal
    // `${` in a single-quoted string is the input under test — the rule fires
    // on exactly the shape this assertion exists to pin.
    expect(sc2016Offenders('const x = "${HOME}"')).toEqual([
      '1: const x = "${HOME}"',
    ])
    // biome-ignore-end lint/suspicious/noTemplateCurlyInString: as above
    // A bare `$` is not one of them: shellcheck does not flag it, and a regex
    // anchor in one of these arguments would otherwise be a false failure.
    expect(sc2016Offenders('if (!/^\\d+\\.\\d+$/.test(v)) {}')).toEqual([])
  })
})

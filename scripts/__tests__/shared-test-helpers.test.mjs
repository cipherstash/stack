import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { WORKFLOW_DIR } from './lib/workflows.mjs'

/**
 * `scripts/__tests__/lib/` is where a helper shared by more than one guard
 * lives. This checks the guards actually use it.
 *
 * WHAT HAPPENED. Four declarations — `REPO_ROOT`, `WORKFLOW_DIR`,
 * `workflowFiles()` and `readWorkflow()` — were copied byte-for-byte between
 * test files: `REPO_ROOT` into thirteen of them, the workflow trio into three,
 * with two further copies wearing different names (`discoverWorkflows`, a bare
 * `WORKFLOWS` const) and one whole function renamed (`readYaml`). Nothing
 * failed, because copies of a working helper work.
 *
 * WHY IT MATTERS MORE HERE THAN IN NORMAL CODE. Most of these guards are
 * DISCOVERY tests: they scan the workflow directory rather than iterate a list, so
 * a workflow added tomorrow is held to the same bar without anyone registering
 * it. A discovery helper is the one kind of duplicate whose drift is silent in
 * the dangerous direction — a copy that finds fewer files does not fail, it
 * passes, having checked less. `ffi-binding-step-order.test.mjs` records a
 * mutation test where a deleted step took its suite from 9 tests to 8 with
 * nothing red; a copy that quietly stops matching `.yaml` files does the same
 * thing to every guard that holds it.
 *
 * WHAT THIS CAN AND CANNOT SEE. It reads source text, so it catches a
 * redeclaration under the SAME name as a shared export, and a hand-rolled scan
 * of the workflow directory under any name. It cannot see a one-line copy given
 * a fresh name and a fresh directory literal — no source-level check can, short
 * of comparing semantics. The two checks below are named for exactly what they
 * do rather than for the ambition.
 */

const TESTS_DIR = 'scripts/__tests__'
const LIB_DIR = `${TESTS_DIR}/lib`

/** Repo-relative paths of the shared helper modules. */
function libModules() {
  return readdirSync(join(REPO_ROOT, LIB_DIR))
    .filter((name) => name.endsWith('.mjs') && !name.endsWith('.test.mjs'))
    .map((name) => `${LIB_DIR}/${name}`)
    .sort()
}

/** Repo-relative paths of the guards themselves — `lib/` is not among them. */
function testFiles() {
  return readdirSync(join(REPO_ROOT, TESTS_DIR))
    .filter((name) => name.endsWith('.test.mjs'))
    .map((name) => `${TESTS_DIR}/${name}`)
    .sort()
}

const read = (relPath) => readFileSync(join(REPO_ROOT, relPath), 'utf8')

/**
 * Every name `lib/` exports, mapped to the module exporting it. Taken by
 * importing the modules rather than by reading their source: an export added
 * later is then protected the day it lands, which is the same discovered-not-
 * listed property the guards themselves rely on.
 */
const SHARED = new Map()
for (const relPath of libModules()) {
  const mod = await import(pathToFileURL(join(REPO_ROOT, relPath)).href)
  for (const name of Object.keys(mod)) SHARED.set(name, relPath)
}

/**
 * The guard on the scan, in the shape this directory uses everywhere else. If
 * a rename emptied `SHARED`, every check below would iterate nothing and pass —
 * the failure mode the whole directory is written to avoid.
 *
 * A minimum, not an equality: extracting a fifth helper must not fail this.
 */
const EXPECTED_SHARED = [
  'REPO_ROOT',
  'WORKFLOW_DIR',
  'readJsonc',
  'readWorkflow',
  'workflowFiles',
]

/**
 * A top-level declaration of `name`. Anchored to the start of a line, which is
 * what makes it a DECLARATION test rather than a mention test: a local inside a
 * function body is indented, and a reference in prose sits behind ` * ` or
 * `// `. Destructured forms (`const { readWorkflow } = ...`) are not matched,
 * and do not need to be — that is a re-export of the shared one, not a copy.
 */
function declaresLocally(source, name) {
  return new RegExp(
    `^(?:export\\s+)?(?:async\\s+)?(?:function\\s+${name}\\b|(?:const|let|var)\\s+${name}\\b)`,
    'm',
  ).test(source)
}

/**
 * The workflow directory written as a bare string literal — the directory
 * itself, rather than the prefix of a specific file. The closing quote is the
 * whole discrimination: `'.github/workflows/tests.yml'` in an expected-jobs
 * list is a fact being asserted, while the bare directory is the opening line
 * of a hand-rolled `readdirSync` scan. It also keeps the fixture trees under
 * `fixtures/lint-no-workflow-caching/` out of scope, since those are always
 * spelled with a trailing file segment.
 *
 * This file quotes the directory nowhere itself — it interpolates
 * `WORKFLOW_DIR` below — which is the rule being enforced, applied here first.
 * The alternative was to exempt this file from its own check, and an exemption
 * is a hole whether or not the file that opens it is the one describing the
 * rule.
 */
const BARE_WORKFLOW_DIR = /['"`]\.github\/workflows['"`]/

describe('guards import shared helpers instead of copying them', () => {
  it('lib/ still exports the helpers these checks are about', () => {
    const missing = EXPECTED_SHARED.filter((name) => !SHARED.has(name))
    expect(
      missing,
      `These helpers are no longer exported from ${LIB_DIR}/. If one was renamed, update EXPECTED_SHARED deliberately; if the directory moved, the checks below are scanning nothing and passing. Found: ${[...SHARED.keys()].sort().join(', ') || '(nothing)'}`,
    ).toEqual([])
  })

  it('no test file redefines a helper that lib/ already exports', () => {
    const offenders = []
    for (const relPath of testFiles()) {
      const source = read(relPath)
      for (const [name, module] of SHARED) {
        if (declaresLocally(source, name)) {
          offenders.push(
            `${relPath} declares \`${name}\` (exported by ${module})`,
          )
        }
      }
    }

    expect(
      offenders,
      `A helper that ${LIB_DIR}/ exports was declared locally again.\nImport it instead — \`import { <name> } from './lib/<module>.mjs'\`.\nThese guards discover what they check by scanning the repo, so a private copy that drifts does not fail: it finds less and passes.\nIf the local version genuinely needs to differ, give it a name that says how, and say why in a comment.`,
    ).toEqual([])
  })

  it('no test file scans the workflow directory itself', () => {
    const offenders = testFiles().filter((relPath) =>
      BARE_WORKFLOW_DIR.test(read(relPath)),
    )

    expect(
      offenders,
      `These files spell out \`${WORKFLOW_DIR}\` as a directory. Reading it is \`workflowFiles()\` from './lib/workflows.mjs', and the constant is \`WORKFLOW_DIR\` from the same module.\nThis check exists because the previous copies were not all called the same thing — one was \`discoverWorkflows()\`, one a bare \`WORKFLOWS\` const — so matching on the helper NAME would have missed them. Matching on the directory catches a copy whatever it is called.\nNaming a specific workflow FILE (\`${WORKFLOW_DIR}/tests.yml\`) is fine and is not matched.`,
    ).toEqual([])
  })
})

import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { runsWhen } from './expressions.mjs'
import { pathsGlobToRegExp } from './paths-filter.mjs'
import { readWorkflow } from './workflows.mjs'

/**
 * Reading and running a workflow's selector job, for the guards that pin what
 * it decides.
 *
 * The selector job is the first job of a workflow. It compares the files a
 * pull request changes with each check's trigger paths, using
 * dorny/paths-filter, and writes one output per filter. Each gated job's `if:`
 * reads the output named after its filter. ADR 0003 and `.github/CONTEXT.md`
 * describe the design.
 *
 * Everything here runs the workflow's own text: the filter rules as written,
 * the decision script as written, and each job's real `if:`. A guard that
 * reimplemented the decision would agree with a rewritten one by luck.
 */

export const SELECTOR_JOB = 'selector'

/** The events the selector decides nothing for: each one selects every job. */
export const NON_PULL_REQUEST_EVENTS = [
  'push',
  'schedule',
  'merge_group',
  'workflow_dispatch',
]

const DORNY = 'dorny/paths-filter@'

const stepOutputRef = (expression) =>
  /steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)/.exec(
    String(expression ?? ''),
  )

const selectorOutputRefs = (expression) =>
  [
    ...String(expression ?? '').matchAll(
      new RegExp(`needs\\.${SELECTOR_JOB}\\.outputs\\.([A-Za-z0-9_-]+)`, 'g'),
    ),
  ].map((match) => match[1])

/**
 * `{a,b}` expanded into its alternatives, as picomatch reads a brace pattern.
 * One level only: a nested brace throws, rather than being read wrongly.
 */
export function expandBraces(pattern) {
  const open = pattern.indexOf('{')
  if (open === -1) return [pattern]
  const close = pattern.indexOf('}', open)
  const inner = pattern.slice(open + 1, close)
  if (close === -1 || inner.includes('{')) {
    throw new Error(`Cannot expand the brace pattern ${pattern}`)
  }
  const head = pattern.slice(0, open)
  return inner
    .split(',')
    .flatMap((alternative) =>
      expandBraces(`${head}${alternative}${pattern.slice(close + 1)}`),
    )
}

/** One dorny/paths-filter rule against one file. A `!` rule negates. */
export function dornyRuleMatches(rule, file) {
  if (rule.startsWith('!')) return !dornyRuleMatches(rule.slice(1), file)
  return expandBraces(rule).some((glob) => pathsGlobToRegExp(glob).test(file))
}

/**
 * Whether a file counts for a filter. Under dorny's default quantifier, `some`,
 * one matching rule is enough; under `every`, all of them must match.
 */
export function dornyFilterMatches(rules, quantifier, file) {
  return quantifier === 'every'
    ? rules.every((rule) => dornyRuleMatches(rule, file))
    : rules.some((rule) => dornyRuleMatches(rule, file))
}

/**
 * A workflow's selector job, parsed, or `null` when it has none.
 *
 * `filters` maps each filter name to its rules. A filter that includes an
 * anchored list (`- *name`) parses to a nested list, and dorny flattens it;
 * so does this. `outputs` maps each selector output to the decision step
 * output it reads.
 */
export function readSelectorJob(relPath) {
  const workflow = readWorkflow(relPath)
  const job = workflow?.jobs?.[SELECTOR_JOB]
  if (!job) return null
  const steps = Array.isArray(job.steps) ? job.steps : []
  const filterSteps = steps.filter((step) =>
    String(step?.uses ?? '').startsWith(DORNY),
  )
  const filterStep = filterSteps.length === 1 ? filterSteps[0] : null
  const filters = Object.fromEntries(
    Object.entries(yaml.load(filterStep?.with?.filters ?? '') ?? {}).map(
      ([name, rules]) => [name, [rules].flat(Infinity).map(String)],
    ),
  )
  const outputs = Object.fromEntries(
    Object.entries(job.outputs ?? {}).map(([name, expression]) => [
      name,
      stepOutputRef(expression),
    ]),
  )
  const decideIds = [
    ...new Set(Object.values(outputs).map((ref) => ref?.[1])),
  ].filter(Boolean)
  const decideStep =
    decideIds.length === 1
      ? steps.find((step) => step?.id === decideIds[0])
      : null
  return {
    workflow,
    job,
    filterSteps,
    filterStep,
    quantifier: filterStep?.with?.['predicate-quantifier'] ?? 'some',
    filters,
    outputs: Object.fromEntries(
      Object.entries(outputs).map(([name, ref]) => [name, ref?.[2]]),
    ),
    decideStep,
  }
}

/** The selector outputs a job's `if:` reads. */
export function selectorOutputsRead(job) {
  return [...new Set(selectorOutputRefs(job?.if))]
}

/**
 * Runs the selector's decision script the way GitHub would: `answers` stands
 * in for the filter step's outputs, keyed by filter name. An env entry that
 * names no answer gets the empty string, as GitHub substitutes for an
 * expression that resolves to nothing.
 *
 * Returns the exit status, the log, and the selector job's outputs.
 */
export function runSelectorDecision(relPath, eventName, answers) {
  const selector = readSelectorJob(relPath)
  const scratch = mkdtempSync(join(tmpdir(), 'selector-'))
  try {
    const outputFile = join(scratch, 'outputs.txt')
    writeFileSync(outputFile, '')
    const env = { PATH: process.env.PATH, GITHUB_OUTPUT: outputFile }
    for (const [key, value] of Object.entries(
      selector?.decideStep?.env ?? {},
    )) {
      const text = String(value)
      if (/github\.event_name/.test(text)) env[key] = eventName
      else env[key] = answers[stepOutputRef(text)?.[2]] ?? ''
    }
    const run = spawnSync(
      'bash',
      ['-c', String(selector?.decideStep?.run ?? 'exit 99')],
      { cwd: scratch, env, encoding: 'utf8' },
    )
    const written = Object.fromEntries(
      readFileSync(outputFile, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((line) => [
          line.slice(0, line.indexOf('=')),
          line.slice(line.indexOf('=') + 1),
        ]),
    )
    return {
      status: run.status,
      log: `${run.stdout}${run.stderr}`,
      outputs: Object.fromEntries(
        Object.entries(selector?.outputs ?? {}).map(([name, stepOutput]) => [
          name,
          written[stepOutput],
        ]),
      ),
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
}

/** What each filter answers for a pull request that changes `files`. */
export function filterAnswers(relPath, files) {
  const selector = readSelectorJob(relPath)
  return Object.fromEntries(
    Object.entries(selector?.filters ?? {}).map(([name, rules]) => [
      name,
      String(
        files.some((file) =>
          dornyFilterMatches(rules, selector.quantifier, file),
        ),
      ),
    ]),
  )
}

const needsOf = (job) => [job?.needs ?? []].flat()

/**
 * The jobs that run for a same-repository pull request changing `files`,
 * sorted. The selector job's outputs come from its own script; each job's
 * `if:` is evaluated as GitHub does, including the implicit `success()` that
 * skips a job when one it needs did not succeed.
 *
 * `github` adds to the context, for a job whose `if:` reads more than the
 * event and the selector (such as `head_ref`).
 */
export function selectedJobs(relPath, files, { github = {} } = {}) {
  const selector = readSelectorJob(relPath)
  const decision = runSelectorDecision(
    relPath,
    'pull_request',
    filterAnswers(relPath, files),
  )
  if (decision.status !== 0) {
    throw new Error(`The selector failed:\n${decision.log}`)
  }
  const repository = 'cipherstash/stack'
  const context = {
    github: {
      event_name: 'pull_request',
      repository,
      head_ref: 'feature',
      event: {
        pull_request: {
          draft: false,
          head: { repo: { full_name: repository } },
          user: { type: 'User' },
        },
      },
      ...github,
    },
    needs: {},
    vars: {},
  }
  const jobs = selector.workflow.jobs
  const results = {
    [SELECTOR_JOB]: { result: 'success', outputs: decision.outputs },
  }
  const resolve = (id) => {
    if (results[id]) return results[id].result
    const job = jobs[id]
    const needs = needsOf(job)
    const needResults = needs.map(resolve)
    const condition = String(job?.if ?? '')
    const statusFunction = /\b(always|failure|cancelled|success)\(\)/.test(
      condition,
    )
    let runs
    if (!statusFunction && needResults.some((result) => result !== 'success')) {
      runs = false
    } else if (!condition) {
      runs = true
    } else {
      runs = runsWhen(condition, {
        ...context,
        needs: Object.fromEntries(needs.map((need) => [need, results[need]])),
      })
    }
    results[id] = { result: runs ? 'success' : 'skipped', outputs: {} }
    return results[id].result
  }
  return Object.keys(jobs)
    .filter((id) => resolve(id) === 'success')
    .sort()
}

// GitHub reads a `paths:` list in order, and the last matching entry decides.
export function pathsListSelects(paths, file) {
  let selected = false
  for (const entry of paths) {
    if (entry.startsWith('!')) {
      if (pathsGlobToRegExp(entry.slice(1)).test(file)) selected = false
    } else if (pathsGlobToRegExp(entry).test(file)) {
      selected = true
    }
  }
  return selected
}

/**
 * A filter as a GitHub `paths:` list: entries in order, a `!` entry excluding
 * what came before it. Lets the guards that check a workflow's `paths:`
 * coverage read a selector filter with the same code.
 *
 * Under `every`, the one positive rule's brace alternatives come first and the
 * `!` rules after, which selects exactly the files dorny selects. Under
 * `some`, a filter has no `!` rule (`workflow-selectors.test.mjs`), so it is
 * already that list.
 */
export function filterAsPathsList(rules, quantifier) {
  if (quantifier !== 'every') return rules.flatMap(expandBraces)
  const positive = rules.filter((rule) => !rule.startsWith('!'))
  const negative = rules.filter((rule) => rule.startsWith('!'))
  return [...positive.flatMap(expandBraces), ...negative]
}

/**
 * The path lists that decide whether a job runs on a change, as GitHub
 * `paths:` lists: the workflow's `on.push.paths` and `on.pull_request.paths`
 * where they exist, and each selector filter the job's `if:` reads.
 *
 * A job in a selector workflow that reads no filter runs on every pull
 * request, so only the `push` list, if any, decides it.
 */
export function jobTriggerLists(relPath, jobId) {
  const workflow = readWorkflow(relPath)
  const on = workflow?.on ?? workflow?.[true]
  const lists = ['push', 'pull_request']
    .filter((event) => Array.isArray(on?.[event]?.paths))
    .map((event) => ({
      source: `on.${event}.paths`,
      paths: on[event].paths.map(String),
    }))
  const selector = readSelectorJob(relPath)
  for (const name of selectorOutputsRead(workflow?.jobs?.[jobId])) {
    const rules = selector?.filters?.[name]
    if (!rules) continue
    lists.push({
      source: `selector filter "${name}"`,
      paths: filterAsPathsList(rules, selector.quantifier),
    })
  }
  return lists
}

/**
 * Runs the summary job's check with the given results of the jobs it needs,
 * and returns its exit status. The results stand in for
 * `join(needs.*.result, ' ')`, wherever the step reads it.
 */
export function runSummaryCheck(relPath, summaryId, results) {
  const workflow = readWorkflow(relPath)
  const steps = workflow?.jobs?.[summaryId]?.steps ?? []
  const joined = results.join(' ')
  const resultsExpression = /\$\{\{\s*join\(needs\.\*\.result,\s*' '\)\s*\}\}/g
  let status = 0
  for (const step of steps) {
    if (typeof step?.run !== 'string') continue
    const env = { PATH: process.env.PATH }
    for (const [key, value] of Object.entries(step.env ?? {})) {
      env[key] = String(value).replace(resultsExpression, joined)
    }
    const run = spawnSync(
      'bash',
      ['-c', step.run.replace(resultsExpression, joined)],
      { env, encoding: 'utf8' },
    )
    status = run.status
    if (status !== 0) break
  }
  return status
}

import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { afterAll, describe, expect, it } from 'vitest'
import { runsWhen } from './lib/expressions.mjs'
import { pathsGlobToRegExp } from './lib/paths-filter.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * Test EQL's selector job decides which checks a pull request runs, by
 * matching the changed files against each check's trigger paths.
 *
 * Only `rust-crates` compiles the stack-* crates, through eql-bindings'
 * `stack-encrypt` feature. Every other job builds `tests/sqlx` or the
 * codegen crates, which do not enable it. While the crates sat on the one list
 * that gated every job, a pull request touching only stack-encrypt ran the
 * whole Postgres suite.
 *
 * The selector is exercised the way GitHub runs it: the filter results go
 * into the real decision script, and each job's real `if:` reads its outputs.
 */

const WORKFLOW = '.github/workflows/test-eql.yml'
const SELECTOR = 'selector'
const REPO = 'cipherstash/stack'

const wf = readWorkflow(WORKFLOW)
const selector = wf?.jobs?.[SELECTOR]

const stepOutput = (expression) =>
  /steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)/.exec(
    String(expression ?? ''),
  )

const filterStep = (selector?.steps ?? []).find((step) =>
  String(step?.uses ?? '').startsWith('dorny/paths-filter@'),
)

// dorny flattens a list that includes an anchored list; so does this.
const FILTERS = Object.fromEntries(
  Object.entries(yaml.load(filterStep?.with?.filters ?? '') ?? {}).map(
    ([name, globs]) => [name, [globs].flat(Infinity)],
  ),
)

const decideStepId = stepOutput(Object.values(selector?.outputs ?? {})[0])?.[1]
const decideStep = (selector?.steps ?? []).find(
  (step) => step?.id === decideStepId,
)

const GATED = Object.entries(wf?.jobs ?? {})
  .map(([id, job]) => ({
    id,
    job,
    output: new RegExp(`needs\\.${SELECTOR}\\.outputs\\.([A-Za-z0-9_-]+)`).exec(
      String(job?.if ?? ''),
    )?.[1],
  }))
  .filter((entry) => entry.output)

const SCRATCH = mkdtempSync(join(tmpdir(), 'eql-selector-'))
afterAll(() => rmSync(SCRATCH, { recursive: true, force: true }))
let runCounter = 0

/**
 * Runs the decision script with the filter results GitHub would substitute.
 * An env entry that names no filter result gets the empty string, as GitHub
 * substitutes for an expression that resolves to nothing.
 */
function decide(eventName, filterResults) {
  runCounter += 1
  const outputFile = join(SCRATCH, `outputs-${runCounter}.txt`)
  writeFileSync(outputFile, '')
  const env = { PATH: process.env.PATH, GITHUB_OUTPUT: outputFile }
  for (const [key, value] of Object.entries(decideStep?.env ?? {})) {
    const text = String(value)
    if (/github\.event_name/.test(text)) env[key] = eventName
    else env[key] = filterResults[stepOutput(text)?.[2]] ?? ''
  }
  const run = spawnSync('bash', ['-c', String(decideStep?.run)], {
    cwd: SCRATCH,
    env,
    encoding: 'utf8',
  })
  const written = Object.fromEntries(
    readFileSync(outputFile, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => [
        line.slice(0, line.indexOf('=')),
        line.slice(line.indexOf('=') + 1),
      ]),
  )
  const outputs = Object.fromEntries(
    Object.entries(selector?.outputs ?? {}).map(([name, expression]) => [
      name,
      written[stepOutput(expression)?.[2]],
    ]),
  )
  return { status: run.status, stderr: `${run.stdout}${run.stderr}`, outputs }
}

/** The gated jobs a same-repository pull request runs, given its files. */
function jobsRunFor(changedFiles) {
  const filterResults = Object.fromEntries(
    Object.entries(FILTERS).map(([name, globs]) => [
      name,
      String(
        changedFiles.some((file) =>
          globs.some((glob) => pathsGlobToRegExp(glob).test(file)),
        ),
      ),
    ]),
  )
  const { status, stderr, outputs } = decide('pull_request', filterResults)
  expect(status, stderr).toBe(0)
  const context = {
    github: {
      event_name: 'pull_request',
      repository: REPO,
      event: { pull_request: { head: { repo: { full_name: REPO } } } },
    },
    needs: { [SELECTOR]: { result: 'success', outputs } },
    vars: {},
  }
  return GATED.filter(({ job }) => runsWhen(job.if, context))
    .map(({ id }) => id)
    .sort()
}

const ALL_GATED = GATED.map(({ id }) => id).sort()

describe('the Test EQL selector job', () => {
  it('finds the selector, its filters, and the jobs it gates', () => {
    expect(selector, `${WORKFLOW} has no \`${SELECTOR}\` job.`).toBeTruthy()
    expect(
      Object.keys(FILTERS),
      'The selector has no path filters.',
    ).not.toEqual([])
    expect(
      decideStep,
      'No step produces the selector job outputs.',
    ).toBeTruthy()
    expect(ALL_GATED).toContain('rust-crates')
    expect(ALL_GATED.length).toBeGreaterThan(1)
  })

  it('runs on a GitHub-hosted runner', () => {
    // ADR 0003: a RunsOn machine takes 40 to 50 seconds to start, and every
    // other job in the run waits for this one.
    expect(String(selector?.['runs-on'])).toMatch(/^ubuntu-/)
  })

  it('names each output after the path filter that decides it', () => {
    // eql-suite-ci.test.mjs follows a job's `if:` to its filter by this name.
    for (const { id, output } of GATED) {
      expect(
        Object.keys(FILTERS),
        `"${id}" reads \`needs.${SELECTOR}.outputs.${output}\`, and the selector has no path filter called "${output}".`,
      ).toContain(output)
    }
  })

  it('runs only rust-crates for a change to a stack crate', () => {
    expect(jobsRunFor(['packages/stack-encrypt/src/lib.rs'])).toEqual([
      'rust-crates',
    ])
    expect(jobsRunFor(['Cargo.toml'])).toEqual(['rust-crates'])
  })

  it('runs every gated job for a change to EQL', () => {
    expect(jobsRunFor(['packages/eql/src/v3/schema.sql'])).toEqual(ALL_GATED)
    expect(jobsRunFor([WORKFLOW])).toEqual(ALL_GATED)
  })

  it('runs no gated job for a change outside EQL and the crates', () => {
    expect(
      jobsRunFor(['languages/typescript/packages/stack/src/index.ts']),
    ).toEqual([])
  })

  it('opens every output on events other than pull_request', () => {
    // The filter runs only on pull_request. Every other event takes the
    // default, and a wrong default skips every gated job behind a green run.
    for (const event of [
      'push',
      'schedule',
      'merge_group',
      'workflow_dispatch',
    ]) {
      const { status, outputs } = decide(event, {})
      expect(status).toBe(0)
      for (const name of Object.keys(selector?.outputs ?? {}))
        expect(outputs[name], `${name} on ${event}`).toBe('true')
    }
  })

  it('fails when a pull request filter gives no answer', () => {
    // A missing answer would skip every gated job, and `ci-required` counts
    // skipped as passed: a green run that ran nothing.
    expect(decideStep?.run).toBeTruthy()
    for (const bad of [
      {},
      Object.fromEntries(Object.keys(FILTERS).map((name) => [name, 'maybe'])),
    ]) {
      const { status } = decide('pull_request', bad)
      expect(status).not.toBe(0)
    }
  })
})

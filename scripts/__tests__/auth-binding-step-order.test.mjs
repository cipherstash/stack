import { describe, expect, it } from 'vitest'
import { filterCovers } from './lib/paths-filter.mjs'
import { jobTriggerLists } from './lib/selector.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * Every CI job that loads `@cipherstash/stack` or runs `stash` builds the
 * `@cipherstash/auth` binding first.
 *
 * The consumers take `@cipherstash/auth` from the workspace, which ships
 * source only, and its `index.js` loads the napi module on import. Without a
 * build, `@cipherstash/stack` and `stash` die with "Failed to load native
 * binding" — on the registry, the platform package brought a prebuilt `.node`.
 * The jobs that need it are the ones that already build the protect-ffi
 * binding for the same reason, plus those listed in `AUTH_ONLY_JOBS`.
 * `@cipherstash/stack/wasm-inline` imports `@cipherstash/auth/wasm-inline`, so
 * a job that builds protect-ffi's wasm builds auth's too.
 */

const BUILD_FFI = './.github/actions/build-ffi-binding'
const BUILD_AUTH = './.github/actions/build-auth-binding'

/** Jobs that run `stash` or import the SDK without the protect-ffi binding. */
const AUTH_ONLY_JOBS = new Map([
  [
    '.github/workflows/tests-bench.yml / tests-bench',
    'the bench unit checks import @cipherstash/stack, and its globalSetup runs `stash eql install`',
  ],
])

const stepUses = (step) =>
  typeof step?.uses === 'string' ? step.uses.trim() : null
const wantsWasm = (step) => String(step?.with?.wasm ?? 'false') === 'true'

const JOBS = workflowFiles().flatMap((relPath) =>
  Object.entries(readWorkflow(relPath)?.jobs ?? {}).map(([jobName, job]) => {
    const steps = Array.isArray(job?.steps) ? job.steps : []
    const index = (uses) => steps.findIndex((step) => stepUses(step) === uses)
    return {
      id: `${relPath} / ${jobName}`,
      ffi: steps[index(BUILD_FFI)],
      auth: steps[index(BUILD_AUTH)],
      ffiIndex: index(BUILD_FFI),
      authIndex: index(BUILD_AUTH),
    }
  }),
)

const FFI_JOBS = JOBS.filter((job) => job.ffi)

describe('the @cipherstash/auth binding is built wherever the SDK runs', () => {
  it('finds the jobs that build the protect-ffi binding', () => {
    // A floor: a renamed action path would otherwise make every check below
    // pass over nothing.
    expect(FFI_JOBS.length).toBeGreaterThanOrEqual(10)
  })

  it.each(FFI_JOBS.map((job) => [job.id, job]))(
    '%s builds it after the protect-ffi binding',
    (_id, job) => {
      expect(job.auth, `${job.id} does not use ${BUILD_AUTH}`).toBeDefined()
      expect(job.authIndex).toBeGreaterThan(job.ffiIndex)
    },
  )

  it.each(FFI_JOBS.map((job) => [job.id, job]))(
    '%s builds the auth wasm exactly when it builds the protect-ffi wasm',
    (_id, job) => {
      expect(wantsWasm(job.auth)).toBe(wantsWasm(job.ffi))
    },
  )

  it.each([...AUTH_ONLY_JOBS])('%s builds it (%s)', (id) => {
    const job = JOBS.find((entry) => entry.id === id)
    expect(job, `${id} no longer exists`).toBeDefined()
    expect(job?.auth, `${id} does not use ${BUILD_AUTH}`).toBeDefined()
  })

  it('lists no job twice', () => {
    for (const id of AUTH_ONLY_JOBS.keys()) {
      expect(FFI_JOBS.map((job) => job.id)).not.toContain(id)
    }
  })
})

const same = (entry, input) => entry === input

/**
 * The path lists that decide whether the given jobs run, once each: the
 * workflow's `push` and `pull_request` `paths:` lists, and the selector filter
 * each job reads. Every job of the workflow when none are given.
 */
const filters = (relPath, jobNames) => {
  const lists = new Map()
  for (const jobName of jobNames ??
    Object.keys(readWorkflow(relPath)?.jobs ?? {})) {
    for (const { source, paths } of jobTriggerLists(relPath, jobName)) {
      lists.set(source, paths)
    }
  }
  return [...lists.values()]
}

/**
 * The integration workflows that saw an auth bump through
 * `pnpm-workspace.yaml` while auth was a catalog pin. As a workspace package,
 * a change to it edits its own sources instead.
 */
const AUTH_SOURCE_WORKFLOWS = [
  '.github/workflows/integration-drizzle.yml',
  '.github/workflows/integration-protect-ffi.yml',
  '.github/workflows/integration-supabase.yml',
]

describe('a change to the auth binding starts the jobs that load it', () => {
  /** Each workflow with a job that builds the binding, and those jobs. */
  const usersByWorkflow = new Map()
  for (const job of JOBS.filter((entry) => entry.auth)) {
    const [relPath, jobName] = job.id.split(' / ')
    usersByWorkflow.set(relPath, [
      ...(usersByWorkflow.get(relPath) ?? []),
      jobName,
    ])
  }
  const users = [...usersByWorkflow.keys()]

  it.each(users)('%s filters on the action', (relPath) => {
    for (const paths of filters(relPath, usersByWorkflow.get(relPath))) {
      expect(
        filterCovers(paths, '.github/actions/build-auth-binding/**', same),
      ).toBe(true)
    }
  })

  // What `@cipherstash/auth` ships, from the changeset check's own filter.
  const CHANGESET_WORKFLOW = '.github/workflows/require-auth-npm-changeset.yml'
  const shipped = filters(CHANGESET_WORKFLOW)
    .flat()
    .filter(
      (path) =>
        path !== CHANGESET_WORKFLOW &&
        path !== 'scripts/check-auth-npm-changeset.mjs',
    )

  it.each(AUTH_SOURCE_WORKFLOWS)(
    '%s filters on the auth sources',
    (relPath) => {
      expect(shipped.length).toBeGreaterThanOrEqual(4)
      const lists = filters(relPath, usersByWorkflow.get(relPath))
      expect(lists.length).toBe(2)
      for (const paths of lists) {
        expect(
          shipped.filter((path) => !filterCovers(paths, path, same)),
        ).toEqual([])
      }
    },
  )
})

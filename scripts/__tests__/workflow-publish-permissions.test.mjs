import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * In a workflow that can mint an npm publishing credential, a job that does not
 * publish must not be able to.
 *
 * WHAT HAPPENED. `release.yml` declared `id-token: write`, `contents: write`
 * and `pull-requests: write` at the WORKFLOW level, because the two jobs that
 * publish need them. Workflow-level permissions are a default, not a ceiling
 * applied only where asked, so the `gate` job — a checkout and one `node`
 * invocation that answers "is anything unpublished?" — inherited all three. It
 * could mint the OIDC token, push to the repository and write pull requests,
 * having no use for any of it.
 *
 * WHY THAT IS THE CREDENTIAL AND NOT JUST A SCOPE. npm trusted publishing is
 * bound to a repository AND A WORKFLOW FILENAME. Once `release.yml` is the
 * registered publisher, an `id-token: write` token minted by ANY job in that
 * file is one npm will accept for a publish — the registry cannot tell the gate
 * apart from `publish-ffi`. So the blast radius of a compromised step in the
 * cheap every-push job is the whole seven-package release, not a wasted minute.
 *
 * THE FIX IS THE DEFAULT, NOT THE OVERRIDE. Overriding the gate alone would
 * close today's hole and leave tomorrow's open: the next job added to this file
 * inherits the publish credential by omission, which is the failure mode that
 * produced this one. The workflow-level grant is `contents: read` instead, and
 * the two publishing jobs escalate explicitly. A new job now has to ASK for the
 * credential in its own diff.
 *
 * WHAT THIS FILE PINS is that property rather than the current text: any
 * workflow where some job holds `id-token: write` must grant nothing writable
 * to the jobs that do not. It scans the workflow directory, so a second
 * publishing workflow is held to the same bar the day it lands.
 */

/**
 * The jobs that may hold `id-token: write`, as `<file> / <job>`.
 *
 * AN EQUALITY, NOT A FLOOR, and that is the point of the list. A floor would
 * let an eighth job start minting publish tokens without a word in review,
 * which is the exact shape this file exists to stop. Adding a publisher means
 * editing this line — deliberately, in the same diff.
 */
const OIDC_JOBS = [
  // Uploads the seven prebuilt FFI tarballs. Publishes, so it needs OIDC.
  '.github/workflows/release.yml / publish-ffi',
  // `changeset publish` for the JS packages, plus the Version Packages PR.
  '.github/workflows/release.yml / release',
  // The EQL prerelease path publishes @cipherstash/eql directly rather than
  // through changesets, so it mints its own npm token.
  '.github/workflows/release.yml / prerelease-eql-npm',
  // release-plz publishes the eql-bindings crate to crates.io, which uses the
  // same OIDC token exchange. A DIFFERENT registry, and the reason this list
  // could not stay a two-line one: the workflow filename is bound at crates.io
  // rather than npm, but the scope is the same scope.
  '.github/workflows/release-plz.yml / release',
]

/**
 * The jobs in a publishing workflow that may hold ANY writable scope, as
 * `<file> / <job>`. A superset of `OIDC_JOBS`, asserted as such below.
 *
 * WHY THIS IS A SECOND LIST AND NOT THE SAME ONE. The third check below reads
 * "a job in a publishing workflow that does not publish must not be able to
 * write to the repository", and it enforced that by asking whether the job was
 * in `OIDC_JOBS` — which made the npm-credential list do double duty as the
 * write list. That was exactly right while the only writing jobs were the two
 * that publish. It stopped being expressible the moment `release.yml` grew the
 * EQL release line: `eql-sql` creates the `eql-<version>` GitHub release,
 * `eql-image` dispatches another workflow, `prerelease-eql-crate` moves a
 * branch ref. All three need a writable scope; none of them may mint a publish
 * token, and putting them in `OIDC_JOBS` to buy the write would have said they
 * could.
 *
 * So the two facts are separated. `OIDC_JOBS` still answers "who may publish?"
 * as an equality, which is the strong claim; this answers the weaker one, and
 * every entry names the scope and what it is for — because `contents: write` in
 * a file registered as a trusted publisher is still the scope that lets a
 * compromised step rewrite the tree the publish jobs build from.
 */
const REPO_WRITE_JOBS = [
  ...OIDC_JOBS,
  // contents: write — creates the eql-<version> tag and GitHub release, and
  // uploads the SQL bundle to it. Reached through a job-level `uses:`, whose
  // grant is the CEILING for the reusable workflow, so this is also what
  // constrains `_build-eql-sql.yml`.
  '.github/workflows/release.yml / eql-sql',
  // contents: write — attaches the docs bundle to the release above.
  '.github/workflows/release.yml / eql-docs',
  // actions: write — `gh workflow run release-postgres-eql-image.yml`.
  '.github/workflows/release.yml / eql-image',
  // contents: write — the prerelease halves of the two above.
  '.github/workflows/release.yml / prerelease-eql-sql',
  '.github/workflows/release.yml / prerelease-eql-docs',
  // actions: write to dispatch release-plz.yml, contents: write to pin the
  // release/eql-<version> branch it must be dispatched against (release-plz
  // refuses a detached HEAD).
  '.github/workflows/release.yml / prerelease-eql-crate',
]

/**
 * A `permissions:` value as a scope→level map.
 *
 * `undefined` means the key is absent — the caller decides what that inherits
 * from. Everything else normalises, including the two string forms and the
 * empty map, so a workflow written as `permissions: write-all` cannot slip past
 * a check that only understands the mapping form.
 *
 * It THROWS on a shape it does not know rather than returning an empty map: a
 * permissions block this file cannot read and a permissions block that grants
 * nothing must not produce the same green.
 */
const scopes = (permissions) => {
  if (permissions === undefined) return undefined
  // `permissions:` with an empty body parses as null and means "grant nothing".
  if (permissions === null) return {}
  if (permissions === 'read-all') return { 'read-all': 'read' }
  if (permissions === 'write-all') return { 'write-all': 'write' }
  if (typeof permissions === 'object' && !Array.isArray(permissions)) {
    return permissions
  }
  throw new Error(
    `unrecognised permissions value: ${JSON.stringify(permissions)}`,
  )
}

/** The scopes granted at `write` level, sorted, for a readable failure. */
const writable = (granted) =>
  Object.entries(granted ?? {})
    .filter(([, level]) => level === 'write')
    .map(([scope]) => scope)
    .sort()

/**
 * What a job actually gets: its own block if it has one, otherwise the
 * workflow-level default. This is the whole defect in one function — a job with
 * no `permissions:` key is not a job with no permissions.
 *
 * A `uses:` job needs no special case. The caller job's grant is the CEILING
 * for the reusable workflow it calls — a called workflow asking for more fails
 * the run rather than being given it — so a caller held to `contents: read`
 * cannot hand `id-token: write` to anything downstream, whatever that file
 * declares. Checking the caller is checking the whole subtree.
 */
const effective = (job, workflowLevel) =>
  scopes(job?.permissions) ?? workflowLevel

const workflows = workflowFiles().map((file) => {
  const doc = readWorkflow(file)
  return {
    file,
    workflowLevel: scopes(doc?.permissions),
    jobs: Object.entries(doc?.jobs ?? {}),
  }
})

/** Is this the `<file> / <job>` of a job sanctioned to publish? */
const sanctioned = (file, name) => OIDC_JOBS.includes(`${file} / ${name}`)

/** …and of a job sanctioned to hold a writable scope at all? */
const mayWrite = (file, name) => REPO_WRITE_JOBS.includes(`${file} / ${name}`)

describe('supply chain — a publishing workflow grants OIDC per job', () => {
  it('discovers the jobs that hold id-token: write', () => {
    // The guard on the scan. Every check below is "for each workflow that mints
    // OIDC…", and a scan that finds none of them passes having verified
    // nothing — the failure `integration-workflow-paths.test.mjs`'s `required`
    // floor was added for, and `workflow-dispatch-job-conditions.test.mjs`
    // repeats. Pin the set instead.
    const holders = workflows.flatMap(({ file, workflowLevel, jobs }) =>
      jobs
        .filter(
          ([, job]) => effective(job, workflowLevel)?.['id-token'] === 'write',
        )
        .map(([name]) => `${file} / ${name}`),
    )
    expect(holders.sort()).toEqual([...OIDC_JOBS].sort())
  })

  it('never grants id-token: write at the workflow level', () => {
    // Workflow level is a DEFAULT: it reaches every job that does not override
    // it, including the one added next month by someone who never read this
    // file. Escalating per job inverts that — omission becomes the safe answer.
    const offenders = workflows
      .filter(({ workflowLevel }) => workflowLevel?.['id-token'] === 'write')
      .map(({ file }) => file)
    expect(
      offenders,
      'A workflow-level `id-token: write` hands every job in the file a credential npm accepts for a publish.',
    ).toEqual([])
  })

  it('leaves the non-publishing jobs of a publishing workflow read-only', () => {
    // Not just OIDC. The gate inherited `contents: write` and
    // `pull-requests: write` too, so a compromised step there could rewrite the
    // tree the publish jobs then build from — a publish that never needed to
    // forge a token because it changed what was about to be published.
    const offenders = workflows
      // A workflow is a publishing one if it holds the credential ANYWHERE —
      // by sanction above, or by a job that granted itself `id-token: write`
      // without being listed. The second disjunct matters: an unsanctioned
      // publisher must not also switch this check off for the file it is in.
      .filter(({ file, workflowLevel, jobs }) =>
        jobs.some(
          ([name, job]) =>
            sanctioned(file, name) ||
            effective(job, workflowLevel)?.['id-token'] === 'write',
        ),
      )
      .flatMap(({ file, workflowLevel, jobs }) =>
        jobs
          .filter(([name]) => !mayWrite(file, name))
          .flatMap(([name, job]) => {
            const writes = writable(effective(job, workflowLevel))
            return writes.length
              ? [`${file} / ${name}: ${writes.join(', ')}`]
              : []
          }),
      )
    expect(
      offenders,
      'A job in a publishing workflow that does not publish must not be able to write to the repository. If it genuinely needs a writable scope and must NOT be able to publish, add it to REPO_WRITE_JOBS with the scope and the reason — not to OIDC_JOBS.',
    ).toEqual([])
  })

  it('never sanctions a write without sanctioning it as a write', () => {
    // The one way the split above could go wrong: a publisher added to
    // `OIDC_JOBS` and not carried into `REPO_WRITE_JOBS`. It is spelled as a
    // spread today, so this cannot fail — which is the point. It fails the day
    // somebody writes the two lists out separately, before the third check
    // starts reporting a publisher as an offender.
    const missing = OIDC_JOBS.filter(
      (entry) => !REPO_WRITE_JOBS.includes(entry),
    )
    expect(missing).toEqual([])
  })

  it('declares workflow-level permissions in a publishing workflow', () => {
    // Absent is not read-only: with no `permissions:` key at all, jobs fall back
    // to the REPOSITORY default, which is settings-controlled and outside this
    // tree. A publishing workflow must not have its floor set somewhere a
    // reviewer of this repo cannot see.
    const publishing = new Set(OIDC_JOBS.map((entry) => entry.split(' / ')[0]))
    const offenders = workflows
      .filter(
        ({ file, workflowLevel }) =>
          publishing.has(file) && workflowLevel === undefined,
      )
      .map(({ file }) => file)
    expect(offenders).toEqual([])
  })
})

/**
 * The reader, against synthetic input.
 *
 * The sweep above only ever sees a repo someone has already made clean, and a
 * clean repo says nothing about how strict the checker is — a `scopes()` that
 * returned `{}` for every shape it did not recognise would pass all four checks
 * above while enforcing nothing. These pin the GitHub semantics the reader
 * encodes, and inheritance is the one the defect actually lived in.
 */
describe('supply chain — how a job’s permissions are read', () => {
  it('treats an absent job block as the workflow-level grant, not as none', () => {
    // The defect, in one assertion. `gate` had no `permissions:` key and was
    // read by everyone as "this job asks for nothing".
    const workflowLevel = scopes({ 'id-token': 'write', contents: 'write' })
    expect(effective({ steps: [] }, workflowLevel)).toEqual(workflowLevel)
    expect(writable(effective({ steps: [] }, workflowLevel))).toEqual([
      'contents',
      'id-token',
    ])
  })

  it('lets a job block replace the default outright, rather than merge into it', () => {
    // GitHub does not merge the two: a job block is the complete grant. So
    // `permissions: {contents: read}` on the gate removes id-token and
    // pull-requests as well, which is why the fix needed no other line.
    const workflowLevel = scopes({ 'id-token': 'write', contents: 'write' })
    expect(
      writable(effective({ permissions: { contents: 'read' } }, workflowLevel)),
    ).toEqual([])
  })

  it('reads the string forms, which the mapping-only check would wave through', () => {
    expect(writable(scopes('write-all'))).toEqual(['write-all'])
    expect(writable(scopes('read-all'))).toEqual([])
    // `permissions:` with an empty body is the documented "grant nothing".
    expect(writable(scopes(null))).toEqual([])
  })

  it('distinguishes “absent” from “grants nothing”', () => {
    // Absent inherits — from the workflow, or from the repository default when
    // the workflow is silent too. `{}` inherits nothing. Collapsing the two is
    // how a workflow with no `permissions:` key at all reads as hardened.
    expect(scopes(undefined)).toBeUndefined()
    expect(scopes({})).toEqual({})
    expect(
      effective({ permissions: {} }, scopes({ contents: 'write' })),
    ).toEqual({})
  })

  it('throws on a shape it cannot read', () => {
    // Rather than returning an empty grant: "this file did not understand the
    // block" and "the block grants nothing" must not produce the same green.
    expect(() => scopes(['contents'])).toThrow(/unrecognised/)
    expect(() => scopes('read')).toThrow(/unrecognised/)
  })
})

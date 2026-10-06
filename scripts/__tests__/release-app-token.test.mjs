import { describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The Version Packages PR must be pushed with a GitHub App's token, not with
 * the workflow's own `GITHUB_TOKEN`. GitHub starts no workflow run for a push
 * made with `GITHUB_TOKEN`, so a Version Packages PR pushed that way carries no
 * CI at all, and #1020 merged untested with stale skill pins (#1044).
 *
 * The App's key is held in the `release` environment, which only `main` may
 * deploy to, so a workflow on any other branch cannot mint a token. The token
 * is narrowed to this repository and to the two permissions changesets needs,
 * whatever the App itself is granted.
 *
 * Each property below fails open if it is removed: the release still works,
 * and the only symptom is a later Version Packages PR with no checks, or a key
 * reachable from every branch.
 */

const RELEASE_WORKFLOW = '.github/workflows/release.yml'
const TOKEN_ACTION = 'actions/create-github-app-token'
const CHANGESETS_ACTION = 'changesets/action'

const release = readWorkflow(RELEASE_WORKFLOW)?.jobs?.release
const steps = release?.steps ?? []
const tokenIndex = steps.findIndex((step) =>
  String(step?.uses ?? '').startsWith(`${TOKEN_ACTION}@`),
)
const changesetsIndex = steps.findIndex((step) =>
  String(step?.uses ?? '').startsWith(`${CHANGESETS_ACTION}@`),
)
const tokenStep = steps[tokenIndex]
const changesetsStep = steps[changesetsIndex]

describe('release.yml pushes the Version Packages PR as a GitHub App', () => {
  it('finds the release job, the token step and the changesets step', () => {
    expect(release).toBeTruthy()
    expect(tokenIndex).toBeGreaterThanOrEqual(0)
    expect(changesetsIndex).toBeGreaterThanOrEqual(0)
  })

  it('runs the release job in the release environment', () => {
    expect(release.environment).toBe('release')
  })

  it('pins the token action to a commit', () => {
    expect(tokenStep.uses).toMatch(new RegExp(`^${TOKEN_ACTION}@[0-9a-f]{40}$`))
  })

  it('mints the token from the release environment secrets', () => {
    expect(tokenStep.with?.['client-id']).toBe(
      '${{ secrets.RELEASE_PLZ_APP_CLIENT_ID }}',
    )
    expect(tokenStep.with?.['private-key']).toBe(
      '${{ secrets.RELEASE_PLZ_APP_PRIVATE_KEY }}',
    )
  })

  it('narrows the token to this repository and two permissions', () => {
    expect(tokenStep.with?.repositories).toBe('stack')
    const permissions = Object.entries(tokenStep.with ?? {})
      .filter(([key]) => key.startsWith('permission-'))
      .sort(([a], [b]) => a.localeCompare(b))
    expect(permissions).toEqual([
      ['permission-contents', 'write'],
      ['permission-pull-requests', 'write'],
    ])
  })

  it('mints the token before changesets runs, and hands it to changesets', () => {
    expect(tokenStep.id).toBeTruthy()
    expect(tokenIndex).toBeLessThan(changesetsIndex)
    expect(changesetsStep.env?.GITHUB_TOKEN).toBe(
      `\${{ steps.${tokenStep.id}.outputs.token }}`,
    )
  })

  it('keeps the commits signed by GitHub', () => {
    expect(changesetsStep.with?.commitMode).toBe('github-api')
  })
})

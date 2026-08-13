import { describe, expect, test } from 'vitest'
import { lintWorkflowDocument } from './lint-no-workflow-caching.mjs'

describe('release workflow dependency cache guard', () => {
  test('accepts explicit pnpm cache disablement and uncached setup-node', () => {
    const errors = lintWorkflowDocument({
      jobs: {
        publish: {
          steps: [
            {
              uses: 'pnpm/action-setup@v6.0.8',
              with: { run_install: false, cache: false },
            },
            {
              uses: 'actions/setup-node@v4',
              with: { 'node-version': 22 },
            },
          ],
        },
      },
    })

    expect(errors).toEqual([])
  })

  test('rejects missing or enabled pnpm action caches', () => {
    const errors = lintWorkflowDocument({
      jobs: {
        publish: {
          steps: [
            { uses: 'pnpm/action-setup@v6.0.8', with: { run_install: false } },
            { uses: 'pnpm/action-setup@v6.0.8', with: { cache: true } },
          ],
        },
      },
    })

    expect(errors).toHaveLength(2)
    expect(errors[0]).toContain('with.cache: false')
    expect(errors[1]).toContain('with.cache: false')
  })

  test('accepts mise-action with cache disabled, rejects missing or enabled cache', () => {
    const ok = lintWorkflowDocument({
      jobs: {
        publish: {
          steps: [{ uses: 'jdx/mise-action@v3', with: { install: true, cache: false } }],
        },
      },
    })
    expect(ok).toEqual([])

    const errors = lintWorkflowDocument({
      jobs: {
        publish: {
          steps: [
            { uses: 'jdx/mise-action@v3', with: { install: true } },
            { uses: 'jdx/mise-action@v3', with: { install: true, cache: true } },
          ],
        },
      },
    })
    expect(errors).toHaveLength(2)
    expect(errors[0]).toContain('jdx/mise-action must set with.cache: false')
    expect(errors[1]).toContain('jdx/mise-action must set with.cache: false')
  })

  test('rejects setup-node package manager caches and actions/cache', () => {
    const errors = lintWorkflowDocument({
      jobs: {
        publish: {
          steps: [
            { uses: 'actions/setup-node@v4', with: { cache: 'pnpm' } },
            { uses: 'actions/setup-node@v4', with: { 'package-manager-cache': true } },
            { uses: 'actions/cache@v4', with: { path: '~/.pnpm-store' } },
          ],
        },
      },
    })

    expect(errors).toHaveLength(3)
    expect(errors[0]).toContain('setup-node dependency cache')
    expect(errors[1]).toContain('package-manager-cache')
    expect(errors[2]).toContain('actions/cache is not allowed')
  })
})

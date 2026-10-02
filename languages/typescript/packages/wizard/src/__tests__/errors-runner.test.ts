import { describe, expect, it } from 'vitest'
import { classifyError, classifyHttpError } from '../agent/errors.js'

describe('classifyError runner', () => {
  it('uses npx when runner=npx for auth failure', () => {
    expect(classifyError('authentication_failed', '', 'npx')).toContain(
      'Run: npx stash auth login',
    )
  })

  it('uses bunx when runner=bunx for auth failure', () => {
    expect(classifyError('authentication_failed', '', 'bunx')).toContain(
      'Run: bunx stash auth login',
    )
  })

  it('uses pnpm dlx when runner=pnpm dlx for auth failure', () => {
    expect(classifyError('authentication_failed', '', 'pnpm dlx')).toContain(
      'Run: pnpm dlx stash auth login',
    )
  })

  it('uses yarn dlx when runner=yarn dlx for auth failure', () => {
    expect(classifyError('authentication_failed', '', 'yarn dlx')).toContain(
      'Run: yarn dlx stash auth login',
    )
  })
})

describe('classifyHttpError runner', () => {
  it('uses npx when runner=npx for 401', () => {
    expect(classifyHttpError(401, '', 'npx')).toContain(
      'Run: npx stash auth login',
    )
  })

  it('uses bunx when runner=bunx for 401', () => {
    expect(classifyHttpError(401, '', 'bunx')).toContain(
      'Run: bunx stash auth login',
    )
  })

  it('uses pnpm dlx when runner=pnpm dlx for 401', () => {
    expect(classifyHttpError(401, '', 'pnpm dlx')).toContain(
      'Run: pnpm dlx stash auth login',
    )
  })

  it('uses yarn dlx when runner=yarn dlx for 401', () => {
    expect(classifyHttpError(401, '', 'yarn dlx')).toContain(
      'Run: yarn dlx stash auth login',
    )
  })
})

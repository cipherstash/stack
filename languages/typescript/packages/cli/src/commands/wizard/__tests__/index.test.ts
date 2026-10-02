import { describe, expect, it } from 'vitest'
import { splitRunner } from '../index.js'

describe('splitRunner', () => {
  it('splits a single-token runner like bunx', () => {
    expect(splitRunner('bunx @cipherstash/wizard')).toEqual({
      bin: 'bunx',
      preArgs: ['@cipherstash/wizard'],
    })
  })

  it('splits a multi-token runner like pnpm dlx', () => {
    expect(splitRunner('pnpm dlx @cipherstash/wizard')).toEqual({
      bin: 'pnpm',
      preArgs: ['dlx', '@cipherstash/wizard'],
    })
  })

  it('splits yarn dlx', () => {
    expect(splitRunner('yarn dlx @cipherstash/wizard')).toEqual({
      bin: 'yarn',
      preArgs: ['dlx', '@cipherstash/wizard'],
    })
  })

  it('splits npx', () => {
    expect(splitRunner('npx @cipherstash/wizard')).toEqual({
      bin: 'npx',
      preArgs: ['@cipherstash/wizard'],
    })
  })

  it('collapses consecutive whitespace', () => {
    expect(splitRunner('pnpm  dlx   @cipherstash/wizard')).toEqual({
      bin: 'pnpm',
      preArgs: ['dlx', '@cipherstash/wizard'],
    })
  })

  it('throws on an empty runner', () => {
    expect(() => splitRunner('')).toThrow(/Empty runner command/i)
  })
})

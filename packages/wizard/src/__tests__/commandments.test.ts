import { describe, expect, it } from 'vitest'
import { COMMANDMENTS, formatCommandments } from '../agent/commandments.js'

describe('COMMANDMENTS', () => {
  it('has 6 commandments', () => {
    expect(COMMANDMENTS).toHaveLength(6)
  })

  it('every commandment is a non-empty string', () => {
    for (const c of COMMANDMENTS) {
      expect(typeof c).toBe('string')
      expect(c.length).toBeGreaterThan(0)
    }
  })
})

describe('formatCommandments', () => {
  it('formats as numbered list', () => {
    const formatted = formatCommandments()
    expect(formatted).toContain('1. ')
    expect(formatted).toContain('6. ')
  })

  it('includes all commandments', () => {
    const formatted = formatCommandments()
    for (const c of COMMANDMENTS) {
      expect(formatted).toContain(c)
    }
  })
})

import { describe, expect, it } from 'vitest'
import { filterCovers } from './lib/paths-filter.mjs'

const exact = (entry, input) => entry === input
const IN = 'languages/typescript/packages/protect-ffi/crates/**'

describe('filterCovers', () => {
  it("'**' alone covers", () => {
    expect(filterCovers(['**'], IN, exact)).toBe(true)
  })
  it("'**' with an unrelated negation covers", () => {
    expect(filterCovers(['**', '!docs/plans/**'], IN, exact)).toBe(true)
  })
  it("'**' with a negation of the input does not cover", () => {
    expect(
      filterCovers(
        ['**', '!languages/typescript/packages/protect-ffi/**'],
        IN,
        exact,
      ),
    ).toBe(false)
  })
  it('a later positive entry re-includes a negated input', () => {
    expect(filterCovers(['**', '!languages/**', IN], IN, exact)).toBe(true)
  })
  it('an allowlist without the input does not cover', () => {
    expect(filterCovers(['docs/**'], IN, exact)).toBe(false)
  })
})

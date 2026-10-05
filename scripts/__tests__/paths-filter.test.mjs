import { describe, expect, it } from 'vitest'
import {
  filterCovers,
  negationRemovesAll,
  negationSubtracts,
} from './lib/paths-filter.mjs'
import { readWorkflow } from './lib/workflows.mjs'

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

describe('negationSubtracts fails closed', () => {
  it('a negation equal to the input removes it', () => {
    expect(filterCovers(['**', `!${IN}`], IN, exact)).toBe(false)
  })
  it('a negation narrower than the input removes it', () => {
    const narrower =
      '!languages/typescript/packages/protect-ffi/crates/protect-ffi/**'
    expect(filterCovers(['**', narrower], IN, exact)).toBe(false)
  })
  it('a negation that starts with a wildcard removes every input', () => {
    expect(filterCovers(['**', '!**/*.rs'], IN, exact)).toBe(false)
  })
  it('an input that starts with a wildcard is removed by any negation', () => {
    expect(negationSubtracts('docs/plans/**', '**/*.rs')).toBe(true)
  })
  it('a sibling directory with the same name prefix is not removed', () => {
    expect(
      negationSubtracts(
        'languages/typescript/packages/stack/**',
        'languages/typescript/packages/stack-auth-wasm/**',
      ),
    ).toBe(false)
  })
})

describe('negationRemovesAll subtracts only a whole-tree negation', () => {
  it('a file-type negation leaves the input selected', () => {
    expect(filterCovers(['**', '!**.md'], IN, exact, negationRemovesAll)).toBe(
      true,
    )
    expect(negationRemovesAll('**/*.md', IN)).toBe(false)
  })
  it('a negation narrower than the input leaves it selected', () => {
    expect(
      negationRemovesAll(
        'languages/typescript/packages/protect-ffi/crates/protect-ffi/**',
        IN,
      ),
    ).toBe(false)
  })
  it('an unrelated or sibling negation leaves the input selected', () => {
    expect(negationRemovesAll('docs/plans/**', IN)).toBe(false)
    expect(
      negationRemovesAll(
        'languages/typescript/packages/stack/**',
        'languages/typescript/packages/stack-auth-wasm/**',
      ),
    ).toBe(false)
  })
  it('a negation of the input or of a parent removes it', () => {
    expect(negationRemovesAll('**', IN)).toBe(true)
    expect(negationRemovesAll(IN, IN)).toBe(true)
    expect(negationRemovesAll('languages/**', IN)).toBe(true)
    expect(
      filterCovers(['**', '!languages/**'], IN, exact, negationRemovesAll),
    ).toBe(false)
  })
})

describe('tests.yml pull_request filter', () => {
  const workflow = readWorkflow('.github/workflows/tests.yml')
  // `on:` parses as the boolean `true` under YAML 1.1.
  const { paths } = (workflow.on ?? workflow[true]).pull_request

  it('skips plan-only pull requests and runs on everything else', () => {
    expect(filterCovers(paths, 'docs/plans/nested/example.md', exact)).toBe(
      false,
    )
    expect(filterCovers(paths, 'scripts/example.mjs', exact)).toBe(true)
    expect(filterCovers(paths, 'docs/example.md', exact)).toBe(true)
  })
  it('negates nothing but docs/plans/', () => {
    expect(paths.filter((entry) => entry.startsWith('!'))).toEqual([
      '!docs/plans/**',
    ])
  })
})

import { describe, expect, it } from 'vitest'
import { eqlV4SuiteFilterEntries } from './lib/eql-v4-suite-inputs.mjs'
import { filterCovers } from './lib/paths-filter.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The protect-ffi migration suites (`migrate-v*-to-v4.test.ts`) re-encrypt
 * through a Rust codec built over `eql-bindings`' v4 modules, and query SQL
 * rendered by `eql-codegen`. No other workflow runs those suites:
 * `test-eql.yml` runs the Rust and SQL suites, not this one. So
 * `integration-protect-ffi.yml` has to start when any of those files change,
 * or a change to v4 target dispatch merges with the end-to-end migration
 * coverage skipped. The entries come from `lib/eql-v4-suite-inputs.mjs`.
 */
const WORKFLOW = '.github/workflows/integration-protect-ffi.yml'

/** A literal or `/**`-tailed filter entry covering the input pattern. */
function entryCovers(entry, input) {
  const literal = (p) => {
    const segments = p.split('/')
    const at = segments.findIndex((segment) => /[*?[]/.test(segment))
    return (at === -1 ? segments : segments.slice(0, at)).join('/')
  }
  const prefix = literal(entry)
  const tail = entry.slice(prefix.length).replace(/^\//, '')
  if (tail !== '' && tail !== '**') return false
  const target = literal(input)
  return target === prefix || target.startsWith(`${prefix}/`)
}

describe('the EQL v4 migration suites trigger on their v4 inputs', () => {
  const { features, entries } = eqlV4SuiteFilterEntries(REPO_ROOT)

  it('derives the v4 modules and the codegen crates', () => {
    // An empty or shrunken derivation would pass every check below.
    expect([...features]).toContain('stack-encrypt')
    expect(entries).toEqual(
      expect.arrayContaining([
        'packages/eql/crates/eql-bindings/src/v4/**',
        'packages/eql/crates/eql-bindings/src/encryption/**',
        'packages/eql/crates/eql-codegen/src/**',
      ]),
    )
  })

  const { on } = readWorkflow(WORKFLOW)
  for (const event of ['push', 'pull_request']) {
    it(`${WORKFLOW} (${event}) triggers on every v4 codec and codegen input`, () => {
      const paths = on?.[event]?.paths ?? []
      const uncovered = entries.filter(
        (entry) => !filterCovers(paths, entry, entryCovers),
      )
      expect(
        uncovered,
        `${WORKFLOW} runs the EQL v4 migration suites, but its \`${event}\` \`paths:\` filter does not list these inputs of the v4 codec or the v4 SQL build. Add each to BOTH copies of the filter.`,
      ).toEqual([])
    })
  }
})

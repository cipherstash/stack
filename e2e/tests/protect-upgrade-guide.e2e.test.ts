/**
 * Keeps `docs/migration/protect-dynamodb-to-stack.md` aligned with the suites
 * that prove it. The guide backs each claim with a citation of the form
 * `compat › <test name>` or `crossover › <test name>`; this file fails when a
 * cited test no longer exists under that name, or when the Protect.js versions
 * the guide names are not the ones the suites install.
 *
 * Needs no credentials, so it runs in the default `test:e2e` suite. It checks
 * that the cited tests exist, not that they pass: `test:protect-compat` and
 * `test:protect-crossover` do that.
 */
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'

const read = (path: string) =>
  readFileSync(new URL(path, import.meta.url), 'utf8')

const guide = read('../../docs/migration/protect-dynamodb-to-stack.md')
const suites = {
  compat: read('./protect-dynamodb-compat.e2e.test.ts'),
  crossover: read('./protect-crossover.e2e.test.ts'),
} as const

const citations = [...guide.matchAll(/`(compat|crossover) › ([^`]+)`/g)].map(
  ([, suite, name]) => ({ suite: suite as keyof typeof suites, name }),
)

/** True when `name` is a string literal in `source`, in any quote style. */
const isLiteral = (source: string, name: string) =>
  [`'${name}'`, `"${name}"`, `\`${name}\``].some((quoted) =>
    source.includes(quoted),
  )

describe('protect-dynamodb upgrade guide', () => {
  it('cites the suites at all', () => {
    expect(citations.length).toBeGreaterThan(20)
    expect(new Set(citations.map((c) => c.suite))).toEqual(
      new Set(['compat', 'crossover']),
    )
  })

  it.each(citations.map((c) => [`${c.suite} › ${c.name}`, c] as const))(
    'cites a test that exists: %s',
    (_label, { suite, name }) => {
      expect(isLiteral(suites[suite], name)).toBe(true)
    },
  )

  it('names the Protect.js versions the suites install', () => {
    const { devDependencies } = JSON.parse(read('../package.json')) as {
      devDependencies: Record<string, string>
    }
    for (const pkg of [
      '@cipherstash/protect',
      '@cipherstash/protect-dynamodb',
    ]) {
      expect(guide, pkg).toContain(`\`${pkg}@${devDependencies[pkg]}\``)
    }
  })

  it('locks the customer transitive versions used by Protect', () => {
    const lock = parse(read('../../pnpm-lock.yaml')) as {
      snapshots: Record<string, { dependencies?: Record<string, string> }>
    }
    const legacy = lock.snapshots['@cipherstash/protect@10.2.1'].dependencies
    for (const [pkg, version] of Object.entries({
      '@cipherstash/protect-ffi': '0.18.1',
      '@cipherstash/schema': '2.0.2',
    })) {
      expect(legacy?.[pkg], pkg).toBe(version)
      expect(guide).toContain(`\`${pkg}@${version}\``)
    }
  })
})

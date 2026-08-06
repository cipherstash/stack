import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The ALTER-COLUMN rewriter exists twice: `@cipherstash/wizard`
 * runs it after its agent edits a schema, and `stash eql migration --drizzle`
 * runs it over an explicit `--out`. Both are published, neither depends on the
 * other, and `packages/utils` is not a package while `@cipherstash/test-kit` is
 * private and build-less — so there is nowhere to put shared runtime code that
 * both npm tarballs could resolve. Extracting one means either publishing a new
 * package into a fixed release group or adding `noExternal` to two CLI bundles.
 *
 * Until that happens the two files are near-clones, and drift between them is
 * the failure mode: four separate #772 review findings each needed the same fix
 * applied in both places, and a fix landing in only one still passes that
 * package's suite. Nothing else in CI compares them.
 *
 * So: everything outside the wizard's `#region wizard-only` must match the CLI
 * copy exactly, modulo comments and the tool name in the emitted header.
 */
const WIZARD = 'packages/wizard/src/lib/rewrite-migrations.ts'
const CLI = 'packages/cli/src/commands/db/rewrite-migrations.ts'

const REGION_OPEN = '// #region wizard-only'
const REGION_CLOSE = '// #endregion wizard-only'

/** Drop the wizard-only region, delimited by the markers in the source. */
function stripWizardOnly(source) {
  const open = source.indexOf(REGION_OPEN)
  if (open === -1) return source
  const close = source.indexOf(REGION_CLOSE, open)
  if (close === -1) return source
  return source.slice(0, open) + source.slice(close + REGION_CLOSE.length)
}

/**
 * Comments, imports and blank lines removed; the emitted header's tool name
 * canonicalised. Both files are Biome-formatted identically, so a pure comment
 * line is reliably one starting with `//`, `/*` or `*` — no line of code in
 * either file starts that way (the regex literals begin `/[`).
 */
function comparableCode(source) {
  return source
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .filter(
      (line) =>
        !line.startsWith('//') &&
        !line.startsWith('*') &&
        !line.startsWith('/*'),
    )
    .filter((line) => !line.startsWith('import '))
    .map((line) =>
      line.replace(/'-- Rewritten by [^:]+:/, "'-- Rewritten by <TOOL>:"),
    )
}

const read = (file) => readFileSync(resolve(REPO_ROOT, file), 'utf8')

describe('the wizard and cli rewriter copies stay in sync', () => {
  const wizardSource = read(WIZARD)
  const cliSource = read(CLI)

  it('marks the wizard-only region so the comparison knows what to exclude', () => {
    expect(wizardSource).toContain(REGION_OPEN)
    expect(wizardSource).toContain(REGION_CLOSE)
    // The CLI copy has no counterpart, so it must not carry the markers.
    expect(cliSource).not.toContain(REGION_OPEN)
  })

  it('finds real code in both (guards against a normaliser that strips everything)', () => {
    expect(
      comparableCode(stripWizardOnly(wizardSource)).length,
    ).toBeGreaterThan(200)
    expect(comparableCode(cliSource).length).toBeGreaterThan(200)
  })

  it('has identical shared logic', () => {
    const wizard = comparableCode(stripWizardOnly(wizardSource))
    const cli = comparableCode(cliSource)
    expect(
      wizard.join('\n'),
      `${WIZARD} and ${CLI} have drifted. Every fix to this rewriter must land ` +
        "in BOTH copies — a one-sided fix still passes that package's own suite, " +
        'and this rewriter now emits a staged encrypted-column addition. If the difference is intentional and ' +
        `wizard-only, move it inside the ${REGION_OPEN} region.`,
    ).toBe(cli.join('\n'))
  })

  it('keeps sweepMigrationDirs as the only wizard-only export', () => {
    // A second wizard-only export would mean shared logic had started to
    // diverge under cover of the region marker.
    const region = wizardSource.slice(
      wizardSource.indexOf(REGION_OPEN),
      wizardSource.indexOf(REGION_CLOSE),
    )
    const exported = [
      ...region.matchAll(
        /^export (?:async function|interface|const|type) (\w+)/gm,
      ),
    ]
      .map((match) => match[1])
      .sort()
    expect(exported).toEqual(['DirRewriteResult', 'sweepMigrationDirs'])
  })
})

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The JavaScript bridge's copy of the value conformance corpus is the corpus.
 *
 * `value-napi/tests/value-conformance.cjs` reads its own copy,
 * `tests/testdata/value-conformance.json`, so a package-scoped run (a
 * mutation run's copy of the workspace) finds its input. The corpus itself
 * is `conformance/vitaminc-aead/value-conformance.json`, which the Rust
 * crates read. This file holds the copy to it on every pull request, in
 * `test:scripts`, so a case added or corrected in one fails here until the
 * other matches.
 *
 * It compares parsed JSON, not text: either file may be reformatted.
 *
 * Node builtins only: no cargo on `pnpm run test:scripts` (see AGENTS.md).
 */

const COPY =
  'languages/typescript/packages/recipher-js/value-napi/tests/testdata/value-conformance.json'
const CORPUS = 'conformance/vitaminc-aead/value-conformance.json'

const read = (path) => JSON.parse(readFileSync(join(REPO_ROOT, path), 'utf8'))

describe("the JavaScript bridge's value corpus", () => {
  it('parses to the same JSON as the conformance corpus', () => {
    const copy = read(COPY)
    const corpus = read(CORPUS)
    expect(Object.keys(corpus).length).toBeGreaterThan(0)
    expect(
      copy,
      `${COPY} must parse to the same JSON as ${CORPUS}: copy the corpus over it, then run \`pnpm run code:fix\``,
    ).toEqual(corpus)
  })
})

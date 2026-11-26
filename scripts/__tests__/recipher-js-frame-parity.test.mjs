import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The JavaScript bridge's pinned frames agree with the files they are
 * compared against outside the bridge's package.
 *
 * `value-napi/tests/frames.cjs` reads nothing outside its package, so a
 * package-scoped run (a mutation run's copy of the workspace) finds its
 * inputs. It compares the bridge's frames with a copy of the conformance
 * corpus's frames, `testdata/corpus-frames.json`. This file holds that copy
 * to the corpus, and the bridge's `Date` frames to the host frames
 * stack-encrypt's `value_bytes_v1.json` pins the engine reading. It runs in
 * `test:scripts` on every pull request, so a corpus change that moves a
 * frame the bridge is compared against fails here, whatever workflow the
 * change would otherwise start.
 *
 * Node builtins only: no cargo on `pnpm run test:scripts` (see AGENTS.md).
 */

const BRIDGE_TESTDATA =
  'languages/typescript/packages/recipher-js/value-napi/tests/testdata'
const CORPUS = 'conformance/stack-encrypt/v1'
const VALUE_BYTES = 'packages/stack-encrypt/tests/fixtures/value_bytes_v1.json'

const read = (path) => JSON.parse(readFileSync(join(REPO_ROOT, path), 'utf8'))

/** Every frame the corpus froze, by `<profile>/<case id>`. */
function corpusFrames() {
  const frames = new Map()
  for (const c of read(`${CORPUS}/record-values-v1.cases.json`).cases) {
    if (c.frame) frames.set(`record-values-v1/${c.id}`, c.frame)
  }
  const scalars = read(
    `${CORPUS}/record-scalars-v1.expected.rust-native.json`,
  ).cases
  for (const [id, artifact] of Object.entries(scalars)) {
    frames.set(`record-scalars-v1/${id}`, artifact.frame)
  }
  return frames
}

describe('the JavaScript bridge frame suite', () => {
  it('compares against a copy of the corpus that is the corpus', () => {
    const corpus = corpusFrames()
    const copy = read(`${BRIDGE_TESTDATA}/corpus-frames.json`).frames
    expect(Object.keys(copy).length).toBeGreaterThan(0)
    for (const [id, frame] of Object.entries(copy)) {
      expect(corpus.has(id), `${id} is a corpus case`).toBe(true)
      expect(frame, id).toBe(corpus.get(id))
    }
  })

  it('names in its pins only the corpus cases the copy holds', () => {
    const copy = read(`${BRIDGE_TESTDATA}/corpus-frames.json`).frames
    const pinned = read(`${BRIDGE_TESTDATA}/js-frames.json`).frames
    const named = new Set(
      Object.values(pinned)
        .map((entry) => entry.corpus_case)
        .filter(Boolean),
    )
    expect([...named].sort()).toEqual(Object.keys(copy).sort())
  })

  it("pins the same Date frames the engine's host cases read", () => {
    const bridge = read(`${BRIDGE_TESTDATA}/js-frames.json`).frames
    const host = read(VALUE_BYTES).host
    expect(bridge['Date 123'].frame).toBe(host.timestamp_millis.host_frame)
    expect(bridge['Date -1'].frame).toBe(
      host.timestamp_millis_negative.host_frame,
    )
  })
})

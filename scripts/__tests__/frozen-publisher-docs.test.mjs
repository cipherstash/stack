import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { FROZEN_PUBLISHERS } from '../release-gate.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * `FROZEN_PUBLISHERS` is described in prose in two places, and the prose is
 * what an agent reads before it decides whether a red `release:gate` is news.
 *
 * Both halves of that had already drifted.
 *
 * AGENTS.md asserted a LIVE VERDICT — "It fires today on the hand-applied 3.0.5
 * bump … and it blocks the Version Packages PR as well as the publish" — which
 * stopped being true the moment `@cipherstash/eql@3.0.5` reached npm. The gate
 * now exits 0 ("nothing to publish"). A durable instruction that tells an agent
 * to expect a red gate is worse than no instruction: it turns a real blocker
 * into an expected one, and the agent stops looking.
 *
 * That is the class this guard covers. A gate verdict is computed from the
 * registry at run time, so it belongs in the gate's output, not in a checked-in
 * sentence — the docs should state the CONDITION under which it fires and point
 * at `node scripts/release-gate.mjs` for the answer.
 *
 * The second half is the deletion that is already scheduled. Phase 5 removes
 * the `@cipherstash/eql` entry from the map, and on that day both documents
 * become wrong in the other direction — still instructing agents about a freeze
 * that no longer exists. Keyed on the map rather than on a date, so the cutover
 * PR cannot land the code change without the prose.
 *
 * THE THIRD DRIFT, and the reason `SECURITY.md` is now in the list. Its "Note
 * on publishing" named the seven `@cipherstash/protect-ffi*` packages as still
 * published from `cipherstash/protectjs-ffi` — written when that was true, and
 * left behind by the cutover that repointed them at this repository. The npm
 * provenance settles it and disagrees:
 *
 *   curl -s https://registry.npmjs.org/-/npm/v1/attestations/@cipherstash%2fprotect-ffi@0.32.0
 *     → github.com/cipherstash/stack .github/workflows/release.yml
 *   curl -s https://registry.npmjs.org/-/npm/v1/attestations/@cipherstash%2feql@3.0.5
 *     → github.com/cipherstash/encrypt-query-language .github/workflows/release.yml
 *
 * That sentence had no guard of any kind: `SECURITY.md` was outside `DOCS`, so
 * the same paragraph was also on course to survive Phase 5 with its remaining
 * `@cipherstash/eql` half going wrong too. A stale freeze claim is not cosmetic
 * in a security policy — it tells a reporter which repository's release
 * pipeline produced the artefact they are reporting on.
 */

const EQL = '@cipherstash/eql'

/** Where the freeze is explained, and the instruction each file carries. */
const DOCS = [
  {
    file: 'AGENTS.md',
    // Both spellings resolve to "the `@cipherstash/eql` entry", which is the
    // thing Phase 5 deletes — matching that keeps the guard anchored to the
    // instruction rather than to a paragraph that may be rewritten.
    instruction: /`@cipherstash\/eql` entry/,
  },
  {
    file: 'docs/plans/2026-08-13-eql-monorepo-absorption.md',
    instruction: /`@cipherstash\/eql` entry/,
  },
  {
    file: 'SECURITY.md',
    // Not a regex, and deliberately: this is `foreignPublishClaims` run over
    // the file, so the SAME extractor that forbids a wrong name below is what
    // requires the right one here. A regex rewrite that blinded the extractor
    // would otherwise silently turn the prohibition into a no-op while this
    // assertion went on passing against a pattern nothing else uses.
    instruction: (body) => foreignPublishClaims(body).includes(EQL),
  },
]

/**
 * Present-tense assertions that the gate is CURRENTLY blocking. Not a style
 * rule — each of these was true when written and false by the next merge, and
 * neither has any way to notice.
 */
const LIVE_VERDICT_CLAIMS = [
  /\bfires today\b/,
  /\bblocks the Version Packages PR\b/,
  /\bcatches the hand-applied 3\.0\.5 bump\b/,
]

/**
 * A checked-in claim about what the registry holds RIGHT NOW.
 *
 * Same failure as the verdicts above, one step upstream: the gate's answer is
 * derived from the registry head, so a sentence naming that head is a verdict
 * in disguise. `npm's newest is 3.0.4` was written into the CI step that runs
 * the gate and into this suite's own preamble, and both were false eleven days
 * later — 3.0.5 published, the gate green, the comments still explaining why it
 * was red.
 */
const REGISTRY_HEAD_CLAIMS = [/\bnpm['’]s newest is\b/]

/**
 * The files that TELL SOMEONE WHAT TO DO about the gate: the gate itself, the
 * CI step that runs it, and the suite that documents it.
 *
 * `docs/plans/*` is deliberately outside this list. A plan is a dated record of
 * an investigation, and rewriting its findings every time the registry moves
 * would destroy the record rather than correct it — which is why the plan is
 * held to `LIVE_VERDICT_CLAIMS` (instructions to an agent) and not to this.
 */
const OPERATIONAL = [
  'scripts/release-gate.mjs',
  'scripts/__tests__/release-gate.test.mjs',
  '.github/workflows/tests.yml',
]

/**
 * The file as one line, with comment markers gone.
 *
 * Without this the guard is defeated by a line break. The claim it was written
 * for is wrapped across two YAML comment lines — `while npm's` / `# newest is
 * 3.0.4` — so a pattern spanning those three words matched nothing, and the
 * check reported clean over the exact sentence that motivated it. Prose in this
 * repo is hard-wrapped everywhere, so any multi-word pattern needs this.
 *
 * `>` joined the marker class with `SECURITY.md`, whose publishing note is a
 * markdown blockquote: every line of the claim being checked begins with one,
 * so without it the flattened text carries a stray `> ` at each wrap point and
 * the same line-break defeat returns in markdown clothing.
 */
const flatten = (body) =>
  body.replace(/^\s*(#|\*|\/\/|>)\s?/gm, ' ').replace(/\s+/g, ' ')

const read = (file) => flatten(readFileSync(join(REPO_ROOT, file), 'utf8'))

/**
 * The npm names a document asserts are published from SOMEWHERE ELSE.
 *
 * `FROZEN_PUBLISHERS` is the machine-readable spelling of exactly this claim,
 * so a name in one and not the other is a contradiction inside the tree — and
 * the direction that matters is the quiet one. A doc naming a package the repo
 * DOES publish is not a typo; it is a cutover that moved the pipeline and left
 * the prose behind, and nothing else in the repo can notice, because provenance
 * lives on the registry and the sentence is just words.
 *
 * A claim is a sentence carrying BOTH a `published from` and a `cipherstash/…`
 * repository that is not `cipherstash/stack`. Both halves are load-bearing:
 * `absorbed from cipherstash/protectjs-ffi` names a foreign repo and is true
 * (that is where the source came from), and `@cipherstash/protect-ffi@0.32.0
 * was published from here` names the verb and is also true. Only the pair is
 * the claim.
 *
 * Sentences are split on `.`, which a filename or a version number splits
 * early. That is deliberate and safe in one direction only: a short fragment
 * can lose a name the sentence also carried, so this can MISS a claim — it
 * cannot invent one. The alternative, a fixed-width window, has the opposite
 * bias.
 *
 * Only `@cipherstash/…` names are collected. `eql-bindings` ships from
 * crates.io under release-plz and is genuinely still published upstream; the
 * map is npm-only, so holding an unscoped crate name to it would fail on a
 * true sentence.
 */
const FOREIGN_PUBLISH = {
  verb: /publish(?:ed|es)\W{0,3}from\b/,
  // `(?<!@)` keeps `@cipherstash/eql` — a package — from reading as a repo.
  elsewhere: /(?<!@)\bcipherstash\/(?!stack\b)[a-z0-9-]+/,
  npmName: /@cipherstash\/[a-z0-9-]+/g,
}

const foreignPublishClaims = (body) =>
  body
    .split('.')
    .filter(
      (sentence) =>
        FOREIGN_PUBLISH.verb.test(sentence) &&
        FOREIGN_PUBLISH.elsewhere.test(sentence),
    )
    .flatMap((sentence) => sentence.match(FOREIGN_PUBLISH.npmName) ?? [])

/** `instruction` is a regex or a predicate over the flattened body. */
const satisfies = (instruction, body) =>
  typeof instruction === 'function' ? instruction(body) : instruction.test(body)

describe('frozen-publisher docs track the map', () => {
  it('still has a frozen entry to document', () => {
    // The map going empty is the Phase-5 end state and a legitimate one — but
    // it must arrive with the doc edits below, not ahead of them. An empty map
    // here means every `iff` assertion is vacuous, so say so out loud.
    expect(FROZEN_PUBLISHERS.size).toBeGreaterThan(0)
  })

  it.each(DOCS)(
    '$file documents the eql freeze iff the map carries it',
    ({ file, instruction }) => {
      expect(
        satisfies(instruction, read(file)),
        FROZEN_PUBLISHERS.has(EQL)
          ? `${file} no longer tells an agent about the ${EQL} freeze, but ` +
              'FROZEN_PUBLISHERS still carries it.'
          : `${EQL} has left FROZEN_PUBLISHERS (Phase-5 cutover), so ${file} ` +
              'must stop instructing agents about the freeze.',
      ).toBe(FROZEN_PUBLISHERS.has(EQL))
    },
  )

  it.each(DOCS)('$file freezes only what the map freezes', ({ file }) => {
    const claimed = [...new Set(foreignPublishClaims(read(file)))]
    expect(
      claimed.filter((name) => !FROZEN_PUBLISHERS.has(name)),
      `${file} says these packages are published from another repository, but ` +
        'FROZEN_PUBLISHERS does not carry them — so this repository publishes ' +
        'them and the sentence is a cutover that left its prose behind. The ' +
        'registry is the only thing that settles it: curl -s ' +
        'https://registry.npmjs.org/-/npm/v1/attestations/<urlencoded-name>@<version>',
    ).toEqual([])
  })

  it.each(DOCS)('$file asserts no live gate verdict', ({ file }) => {
    const body = read(file)
    expect(
      LIVE_VERDICT_CLAIMS.filter((claim) => claim.test(body)).map(String),
      `${file} states what release-gate currently does. That is decided by the ` +
        'registry at run time — describe the condition and point at ' +
        '`node scripts/release-gate.mjs` instead.',
    ).toEqual([])
  })

  it.each(OPERATIONAL)('%s asserts no live registry state', (file) => {
    const body = read(file)
    expect(
      [...LIVE_VERDICT_CLAIMS, ...REGISTRY_HEAD_CLAIMS]
        .filter((claim) => claim.test(body))
        .map(String),
      `${file} names what the registry currently holds. Write it in the past ` +
        'tense, or as the condition rather than the answer — the answer comes ' +
        'from `node scripts/release-gate.mjs`.',
    ).toEqual([])
  })
})

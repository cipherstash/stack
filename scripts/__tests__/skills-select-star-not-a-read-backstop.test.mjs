import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { packageReadmePathspecs } from './lib/package-readmes.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The declared-mode `select('*')` refusal is NOT a read backstop, and any
 * shipped document that states the refusal has to say so.
 *
 * ## The property
 *
 * `encryptedSupabase` built from declared `schemas` refuses `select('*')` and
 * bare `select()` — `expandStarOrThrow()`, `packages/stack-supabase/src/
 * query-builder.ts:159-166`. It reads like a safety net: name your columns or
 * get nothing. It is not one. A query awaited with **no `.select()` call at
 * all** takes the other branch — `query-builder.ts:703-725` sends a raw `*` —
 * and `decryptResults` returns it untouched on its `!hasSelect` passthrough
 * (`packages/stack-supabase/src/query-results.ts:127-130`). Every column comes
 * back undecrypted, declared or not. That is long-standing behaviour the
 * source deliberately leaves alone; only the docs were wrong about it.
 *
 * So an undeclared encrypted column on a declared table has a backstop on
 * WRITE (the `eql_v3_*` domain CHECK, which a NULL still passes) and none on
 * READ. A document that names the refusal without that caveat invites exactly
 * the inference this repo has already made once in print.
 *
 * ## Why nothing else catches it
 *
 * - Nothing type-checks a SKILL.md or a README, and these are shipped text.
 *   `skills/` rides inside the `stash` npm tarball and `stash init` copies it
 *   into the customer's repository, where their coding agent reads it as
 *   instruction. `packages/stack-supabase/README.md` renders on the npm
 *   package page.
 * - The runtime tests pin the two behaviours separately and correctly
 *   (`packages/stack-supabase/__tests__/supabase-declared-mode.test.ts`), but a
 *   passing test says nothing about what a document claims.
 * - The specific failure was a CORRECTION THAT LANDED IN ONE OF TWO COPIES.
 *   `578783ad` fixed the claim in `skills/stash-supabase/SKILL.md` and left the
 *   same claim standing in `skills/stash-managed-platforms/SKILL.md`, in the
 *   same PR that edited both. Two shipped copies of one fact drift the moment
 *   one of them is edited, and no reviewer diff shows the copy that was not
 *   touched.
 *
 * ## What this catches, and what it does not
 *
 * Catches: a section of a shipped markdown document whose prose states that
 * `select('*')` (or bare `select()`) is refused/rejected/throws, where no unit
 * in that same section pairs "a call omitted" with "comes back undecrypted".
 *
 * Scope is the markdown SECTION (nearest preceding ATX heading), not the
 * sentence: the caveat may be reworded, moved between bullets, or split off
 * into its own paragraph without failing, but it cannot migrate to a different
 * part of the document from the claim it corrects. Fenced code blocks are
 * blanked before scanning, so a snippet demonstrating `select('*')` is not a
 * claim about it.
 *
 * Does NOT catch:
 *
 * - The same claim in a `.ts`, `.tsx` or `.sql` file, or in a comment. Prose in
 *   shipped markdown is the surface that misled a reader here.
 * - A document that omits the refusal entirely and separately implies reads are
 *   safe. There is no phrase to key on for that.
 * - A caveat that is present but WRONG (say, one claiming the passthrough only
 *   applies to mutations). This asserts the caveat is stated, not that it is
 *   accurate — the accuracy check is reading `query-results.ts`.
 * - The second false claim fixed alongside this one, that an ambient
 *   `DATABASE_URL` is ignored "with a warning" on the edge entry. Both the
 *   ambient read and the warning are gated on `introspector`
 *   (`packages/stack-supabase/src/create.ts:304,330`), which is `null` on the
 *   `wasm-inline` build. It is left unguarded deliberately: "a warning is
 *   logged" has no stable phrasing to key on, and the correction ("gated on the
 *   introspector") is a word that appears freely in any section discussing
 *   introspection, so every detector for it either misses rewordings or passes
 *   on unrelated prose.
 */

/**
 * Files whose contents are SHIPPED — published to npm, copied into a user's
 * repo, or written there by `stash init`. Deliberately not the whole tree:
 * CHANGELOGs and `docs/**` are historical records, accurate for their dates.
 *
 * Identical to the set in `skills-supabase-edge-schema-entry.test.mjs`, and
 * derived the same way — `:(glob)` magic so `*` stops at a path separator, and
 * `packageReadmePathspecs()` for the two package roots that sit deeper than one
 * level.
 */
const SHIPPED_GLOBS = [
  ':(glob)skills/*/SKILL.md',
  ...packageReadmePathspecs(),
  'README.md',
  'AGENTS.md',
]

/** Tracked files matching the shipped globs, via git so it honours .gitignore. */
function shippedFiles() {
  const out = execFileSync('git', ['ls-files', '-z', ...SHIPPED_GLOBS], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
  return out.split('\0').filter(Boolean)
}

/**
 * Blank out fenced code blocks, preserving line numbering.
 *
 * A snippet is a demonstration, not a claim, and snippets legitimately contain
 * both `select('*')` and the word "throws". Blanking rather than deleting keeps
 * the reported line numbers pointing at the real file, and stops a `#` comment
 * inside a snippet from being read as a heading.
 */
function blankFences(body) {
  let inFence = false
  return body
    .split('\n')
    .map((line) => {
      if (/^\s*(?:`{3,}|~{3,})/.test(line)) {
        inFence = !inFence
        return ''
      }
      return inFence ? '' : line
    })
    .join('\n')
}

/** Sections split at ATX headings, as `{ heading, line, body }`. */
function sections(body) {
  const found = []
  let current = { heading: '(before the first heading)', line: 1, lines: [] }
  body.split('\n').forEach((line, index) => {
    if (/^#{1,6}\s/.test(line)) {
      found.push(current)
      current = { heading: line.trim(), line: index + 1, lines: [] }
    }
    current.lines.push(line)
  })
  found.push(current)
  return found.map(({ heading, line, lines }) => ({
    heading,
    line,
    body: lines.join('\n'),
  }))
}

/**
 * A section's prose as whitespace-normalised units — one per paragraph and one
 * per list item, so a claim and the bullet below it are not read as one
 * sentence.
 */
function units(sectionBody) {
  const collected = []
  let current = []
  const flush = () => {
    const text = current.join(' ').replace(/\s+/g, ' ').trim()
    if (text) collected.push(text)
    current = []
  }
  for (const line of sectionBody.split('\n')) {
    if (
      line.trim() === '' ||
      /^\s*(?:[-*+]|\d+[.)])\s/.test(line) ||
      /^#{1,6}\s/.test(line)
    ) {
      flush()
    }
    current.push(line)
  }
  flush()
  return collected
}

/** `select('*')`, `select("*")` or a bare `select()`, backticked or not. */
const SELECT_STAR = /select\(\s*(?:['"`]\*['"`])?\s*\)/i

/**
 * The claim that it is refused. Deliberately narrow: "unavailable" and "does
 * not work" are excluded because neighbouring bullets in
 * `skills/stash-supabase/SKILL.md` use them about PostgREST's operator surface,
 * and a unit is a bullet.
 */
const REFUSAL =
  /\brefus\w*\b|\breject\w*\b|\bthrows?\b|\bthrowing\b|does not support|not supported|\bunsupported\b/i

/** The caveat, in two halves that must appear in the same unit. */
const OMITTED_CALL =
  /(?:\bno\b|\bwithout\b|\bnever\b|\bomitt?\w*\b|\bbare\b)[\s\S]{0,40}?`?\.?select\(\s*\)/i
const UNDECRYPTED =
  /\bundecrypted\b|\bnot decrypted\b|\bnever decrypted\b|\bnothing is decrypted\b|\bwithout decrypting\b/i

function statesRefusal(unit) {
  return SELECT_STAR.test(unit) && REFUSAL.test(unit)
}

function statesCaveat(unit) {
  return OMITTED_CALL.test(unit) && UNDECRYPTED.test(unit)
}

/** Sections that claim the refusal without carrying the caveat. */
function offendingSections(file, body) {
  return sections(blankFences(body))
    .filter((section) => {
      const parts = units(section.body)
      return parts.some(statesRefusal) && !parts.some(statesCaveat)
    })
    .map((section) => `${file}:${section.line} (${section.heading})`)
}

describe("the select('*') refusal is documented as not a read backstop", () => {
  const files = shippedFiles()

  it('finds the shipped file set (guards against a silently-empty glob)', () => {
    expect(files.length).toBeGreaterThan(5)
    expect(files).toContain('skills/stash-supabase/SKILL.md')
    expect(files).toContain('skills/stash-managed-platforms/SKILL.md')
    expect(files).toContain('packages/stack-supabase/README.md')
  })

  /**
   * A detector that stops matching anything is a guard that always passes.
   * `skills/stash-supabase/SKILL.md` is the canonical adapter skill and carries
   * both halves in one bullet — if this stops finding them, the regexes have
   * decayed, not the docs.
   */
  it('still recognises both halves in the canonical adapter skill', () => {
    const parts = sections(
      blankFences(
        readFileSync(
          resolve(REPO_ROOT, 'skills/stash-supabase/SKILL.md'),
          'utf8',
        ),
      ),
    ).flatMap((section) => units(section.body))

    expect(parts.filter(statesRefusal).length).toBeGreaterThan(0)
    expect(parts.filter(statesCaveat).length).toBeGreaterThan(0)
  })

  it.each(files)('%s', (file) => {
    const offenders = offendingSections(
      file,
      readFileSync(resolve(REPO_ROOT, file), 'utf8'),
    )

    expect(
      offenders,
      `${offenders.join(', ')} states that \`select('*')\` is refused in declared mode without ` +
        'the caveat that goes with it. The refusal is real, but it is not a read backstop: a query ' +
        "awaited with no `.select()` call at all takes `query-builder.ts`'s raw-`*` branch and " +
        '`decryptResults` passes it through on `!hasSelect`, so every column comes back undecrypted, ' +
        'declared or not. Say so in the same section — writes have a backstop (the `eql_v3_*` domain ' +
        'CHECK, though a NULL still passes) and reads have none. ' +
        '`skills/stash-supabase/SKILL.md` carries the wording to match.',
    ).toEqual([])
  })
})

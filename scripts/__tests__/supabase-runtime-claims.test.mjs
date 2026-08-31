import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * Why the Supabase adapter's two entry points differ, asserted against the
 * prose that says so.
 *
 * Three claims kept being written down wrong, in the reference doc and in the
 * TSDoc that ships as `.d.ts`, and none of them is checkable by a type checker
 * or by any test that merely calls the API on Node.
 *
 * **1. Introspection is not why the native entry is Node-only.** The doc said
 * "Introspection needs a direct Postgres connection …, so this entry cannot run
 * in a Worker", and `wasm-inline.ts` said "The engine is only half of what made
 * the default entry Node-only; the other half is introspection". Both invert
 * the dependency. Passing `schemas` skips introspection entirely
 * (`create.ts`'s declared mode, tested in `supabase-declared-mode.test.ts`) and
 * the entry is *still* Node-only, because it binds the native engine and
 * because its emitted bundle carries an `import("pg")` specifier a bundler
 * resolves at build time. The reader who believes the causal version reaches
 * for `schemas` expecting an edge-capable client and gets a build failure.
 *
 * **2. Importing `@cipherstash/protect-ffi` does not load a Node-API binary.**
 * `index.ts` and `create.ts` both named it as the import-time native load. It
 * is the one package in the graph that deliberately does NOT do that:
 * `packages/protect-ffi/src/index.cts` writes `import native =
 * require('./load.cjs')` precisely so `__importStar` cannot enumerate the
 * `@neon-rs/load` proxy into resolving the platform binary, and
 * `packages/protect-ffi/src/nativeLoading.test.ts` guards it. The module-
 * evaluation-time `dlopen` in that graph belongs to `@cipherstash/auth`, whose
 * Node entry ends `module.exports = loadBinding()`.
 * `packages/stack-supabase/__tests__/wasm-entry-edge-safety.test.ts` holds the
 * mechanical half of this; here we only stop the wrong name being written back.
 *
 * **3. "a Worker" is ambiguous, and false under the reading most people take
 * first.** The native entry runs fine in Node `worker_threads`. What it cannot
 * do is run on an edge runtime — Deno, Supabase Edge Functions, Cloudflare
 * Workers — which is the list the doc's own table two screens up already
 * spells out. Every other document in this repo spells it out too.
 *
 * The detectors below are unit-tested in both directions before they are
 * pointed at the real files. A prose guard that cannot fail is worse than no
 * guard, and one that fires on correct wording gets deleted by the next person
 * who trips it — so each has a negative case pinning the shape it must NOT
 * flag.
 */

/**
 * The reference doc, plus the three sources whose TSDoc ships in `.d.ts`.
 *
 * `packages/stack-supabase/README.md` belongs on this list and is NOT on it
 * yet. It ships in the tarball and carries defect 1 verbatim — "Introspection
 * needs a direct Postgres connection (`DATABASE_URL`), so `pg` is an optional
 * peer dependency and the factory cannot run in an edge Worker or the browser"
 * — but the same lines are being rewritten on the branch behind #951, which
 * keeps the false `so` while dropping the browser half. Editing them from two
 * branches is a conflict for no gain. **Add the path here when #951 lands**;
 * the guard will name whatever survives the merge.
 */
const GUARDED = [
  'docs/reference/supabase-sdk.md',
  'packages/stack-supabase/src/index.ts',
  'packages/stack-supabase/src/create.ts',
  'packages/stack-supabase/src/wasm-inline.ts',
]

function read(file) {
  return readFileSync(join(REPO_ROOT, file), 'utf8')
}

/**
 * The prose of a file, with everything a reader does not read removed.
 *
 * Markdown: fenced blocks go — they are the only place a `.` is followed by
 * whitespace without ending a sentence. TypeScript: only `/** … *\/` blocks are
 * prose at all, so code and line comments are dropped and the leading `*`
 * gutter is stripped.
 *
 * Inline code spans are UNWRAPPED, not deleted. Deleting them is the obvious
 * move and it silently disarmed the protect-ffi guard: every mention of the
 * package in this repo's prose is inside backticks, so stripping the spans
 * removed the exact token the guard matches on and `index.ts` — which names it
 * outright — passed. Nothing needs them gone: identifiers like
 * `options.databaseUrl` carry no space after the dot, and the sentence split
 * below requires one.
 */
function prose(file, source) {
  const unwrapInlineCode = (text) => text.replace(/`([^`\n]*)`/g, '$1')
  if (file.endsWith('.md')) {
    return unwrapInlineCode(source.replace(/^```[\s\S]*?^```/gm, '\n\n'))
  }
  return unwrapInlineCode(
    [...source.matchAll(/\/\*\*([\s\S]*?)\*\//g)]
      .map(([, block]) => block.replace(/^[ \t]*\*[ \t]?/gm, ''))
      .join('\n\n'),
  )
}

function sentences(text) {
  return text
    .split(/\n\s*\n/)
    .flatMap((para) => para.replace(/\s+/g, ' ').split(/(?<=[.!?])\s+/))
    .map((s) => s.trim())
    .filter(Boolean)
}

/** Index of the first match at or after `from`, or -1. */
function indexFrom(text, pattern, from) {
  const rest = text.slice(from).search(pattern)
  return rest < 0 ? -1 : from + rest
}

/** A claim about WHERE code can run. */
const RUNTIME_CLAIM =
  /\b(?:cannot|can(?:no|')?t|could(?: no|n')t)\s+(?:run|be\s+\w+)\b|\bNode[- ]only\b|\bruns?\s+anywhere\b|\bwhere\s+(?:it|this|they|each)\s+(?:can\s+)?runs?\b/i

/** Schema discovery and the Postgres connection — the thing that is NOT the reason. */
const SCHEMA_CAUSE =
  /\b(?:introspect\w*|schemas?|Postgres connection|database connection)\b/i

/** Forward causal connectives: "X, so Y". */
const CAUSAL = /\b(?:so|therefore|hence|thus|and so|which is why)\b/i

/** Backward causal connectives: "Y because X". */
const BECAUSE = /\b(?:because|since|as it)\b/i

/**
 * Explanatory nouns — the third way to attribute a cause, with no connective at
 * all. `wasm-inline.ts` used it: "The engine is only half of what made the
 * default entry Node-only; the other half is introspection".
 */
const ATTRIBUTION = /\b(?:half|reason|cause|why|what made|what makes)\b/i

/**
 * Contrast that breaks the inference.
 *
 * "Declaring `schemas` removes the Postgres dependency, so no `databaseUrl` is
 * needed — but the entry is still Node-only" is CORRECT and contains every
 * token the forward pattern looks for; so is "the reason it is Node-only is the
 * engine, not introspection". Without this the guard would fire on the very
 * sentences the fix wants written.
 */
const CONTRAST =
  /\b(?:but|still|even so|regardless|nonetheless|however|anyway|without|not|nor|rather than)\b/i

/**
 * Sentences deriving a runtime restriction from schema discovery.
 *
 * Three shapes, because English attributes a cause three ways and the tree
 * carried one of each: forward connective ("X, so Y") in the doc, backward
 * ("Y because X"), and bare apposition ("the other half is X") in
 * `wasm-inline.ts`. A guard covering only the first would have passed two of
 * the three files it is pointed at.
 */
function falseRuntimeCause(text) {
  return sentences(text).filter((sentence) => {
    const cause = sentence.search(SCHEMA_CAUSE)
    const claim = sentence.search(RUNTIME_CLAIM)
    if (cause < 0 || claim < 0) return false

    // "X, so Y"
    const forward = indexFrom(sentence, CAUSAL, cause)
    if (forward >= 0) {
      const after = indexFrom(sentence, RUNTIME_CLAIM, forward)
      if (after >= 0 && !CONTRAST.test(sentence.slice(forward, after)))
        return true
    }

    // "Y because X" — contrast-checked like the forward shape, so that "it is
    // Node-only, and not because it introspects" stays sayable.
    const backward = indexFrom(sentence, BECAUSE, claim)
    if (
      backward >= 0 &&
      indexFrom(sentence, SCHEMA_CAUSE, backward) >= 0 &&
      !CONTRAST.test(sentence.slice(claim, backward))
    ) {
      return true
    }

    // "the other half of what made it Y is X"
    const [first, second] = cause < claim ? [cause, claim] : [claim, cause]
    if (
      ATTRIBUTION.test(sentence) &&
      !CONTRAST.test(sentence.slice(first, second))
    ) {
      return true
    }
    return false
  })
}

/** Another edge runtime named nearby, which makes "Workers" unambiguous. */
const EDGE_RUNTIME_CONTEXT = /\bDeno\b|\bEdge Functions?\b|\bedge runtimes?\b/i

/**
 * Uses of "Worker" that do not identify the runtime family.
 *
 * Two ways to qualify one, because the property is whether a reader can tell
 * which runtime is meant — not whether a particular word was typed. "Cloudflare
 * Workers" says it outright; "On Workers, Deno isolates and Edge Functions"
 * says it by the company it keeps, and `create.ts` already writes it that way.
 *
 * `worker_threads` is not a match: `_` is a word character, so `\bworkers?\b`
 * cannot end inside it — which is the distinction the whole guard is about.
 */
function unqualifiedWorkerMentions(text) {
  const hits = []
  for (const sentence of sentences(text)) {
    if (EDGE_RUNTIME_CONTEXT.test(sentence)) continue
    for (const match of sentence.matchAll(/\bworkers?\b/gi)) {
      const preceding = sentence.slice(
        Math.max(0, match.index - 16),
        match.index,
      )
      if (!/Cloudflare\s+$/.test(preceding)) hits.push(sentence)
    }
  }
  return hits
}

/**
 * Sentences blaming `@cipherstash/protect-ffi` for an import-time native load.
 *
 * The negation escape is load-bearing: correcting this text means being able to
 * say what protect-ffi does *not* do, and a bare "names it near a load verb"
 * rule would forbid the correction along with the error.
 */
const LOAD_VERB = /\b(?:loads?|loading|loaded|dlopen)\b/i
const NEGATED_LOAD =
  /\b(?:not|never|n't|no|nothing|avoids?|defers?|deferred|without|until|lazily|lazy)\b[\s\S]{0,60}?\b(?:loads?|loading|loaded|dlopen)\b/i

function protectFfiImportLoadClaims(text) {
  return sentences(text).filter(
    (sentence) =>
      /@cipherstash\/protect-ffi/.test(sentence) &&
      LOAD_VERB.test(sentence) &&
      !NEGATED_LOAD.test(sentence),
  )
}

describe('false-runtime-cause detection', () => {
  it.each([
    'Introspection needs a direct Postgres connection, so this entry cannot run in a Worker.',
    'They differ only in how the wrapper learns the schema, and therefore in where it can run.',
    'The other half is introspection, which opens a Postgres connection, so the entry is Node-only.',
    'This entry is Node-only because it introspects the database.',
    // `create.ts`'s exported-factory TSDoc, verbatim. Note what carries it: the
    // bare "Declare your schemas and it runs anywhere" half states the false
    // claim by implication rather than by connective, and no pattern that
    // treats "and" as causal could stay usable. The clause that follows is
    // what makes this one mechanically reachable.
    'Declare your schemas and it runs anywhere; omit them and we discover them for you, which needs a database connection and is therefore Node-only.',
    // `wasm-inline.ts`, verbatim: apposition, no connective anywhere.
    'The engine is only half of what made the default entry Node-only; the other half is introspection, which opens a Postgres connection.',
  ])('flags %s', (sentence) => {
    expect(falseRuntimeCause(sentence)).toHaveLength(1)
  })

  it.each([
    // The correction: the restriction is attributed to the engine, and the
    // schema half is explicitly separated from it.
    'This entry binds the native engine, so it is Node-only.',
    'Passing schemas removes the Postgres dependency, so no databaseUrl is needed, but the entry is still Node-only.',
    'It cannot run on an edge runtime because it binds the native engine.',
    'Only the native entry can introspect, and that is a separate axis from where it runs.',
    'The reason it is Node-only is the native engine, not introspection.',
    'This entry is Node-only, and not because it introspects.',
    'The entry point decides where this runs; schemas decides only whether Postgres is involved.',
  ])('does not flag %s', (sentence) => {
    expect(falseRuntimeCause(sentence)).toEqual([])
  })
})

describe('unqualified-Worker detection', () => {
  it('flags a bare Worker', () => {
    expect(
      unqualifiedWorkerMentions('this entry cannot run in a Worker.'),
    ).toHaveLength(1)
  })

  it('accepts the runtime family spelled out', () => {
    expect(
      unqualifiedWorkerMentions(
        'edge (Deno, Supabase Edge Functions, Cloudflare Workers)',
      ),
    ).toEqual([])
  })

  it('does not flag Node worker_threads, which is the reading that makes the bare word false', () => {
    expect(
      unqualifiedWorkerMentions('runs fine in Node worker_threads.'),
    ).toEqual([])
  })

  it('accepts Workers named alongside the other edge runtimes', () => {
    expect(
      unqualifiedWorkerMentions(
        'On Workers, Deno isolates and Edge Functions there is no process.',
      ),
    ).toEqual([])
  })
})

describe('protect-ffi import-load misattribution detection', () => {
  it.each([
    'Binds the factory to Encryption from the native @cipherstash/stack entry, which loads @cipherstash/protect-ffi — a Node-API binary.',
    'The native entry statically imports @cipherstash/protect-ffi — a Node-API binary that cannot load on an edge runtime.',
  ])('flags %s', (sentence) => {
    expect(protectFfiImportLoadClaims(sentence)).toHaveLength(1)
  })

  it.each([
    '@cipherstash/protect-ffi deliberately does not load its platform binary at module evaluation.',
    '@cipherstash/protect-ffi is the Rust core the native engine encrypts through.',
    '@cipherstash/auth loads its platform binding at module evaluation.',
  ])('does not flag %s', (sentence) => {
    expect(protectFfiImportLoadClaims(sentence)).toEqual([])
  })
})

describe('the Supabase two-entry runtime story, as written', () => {
  it('guards the files it means to (a silently-empty read passes everything)', () => {
    for (const file of GUARDED) {
      expect(
        prose(file, read(file)).length,
        `${file} yielded no prose`,
      ).toBeGreaterThan(500)
    }
  })

  it.each(GUARDED)(
    '%s does not derive the runtime from schema discovery',
    (file) => {
      expect(
        falseRuntimeCause(prose(file, read(file))),
        `${file} attributes a runtime restriction to introspection or to declaring \`schemas\`. The native entry is Node-only because it binds the native engine and because its emitted bundle carries an import("pg") specifier — both true whether or not \`schemas\` is passed. See packages/stack-supabase/__tests__/wasm-entry-edge-safety.test.ts.`,
      ).toEqual([])
    },
  )

  it.each(GUARDED)(
    '%s names the edge runtimes rather than "a Worker"',
    (file) => {
      expect(
        unqualifiedWorkerMentions(prose(file, read(file))),
        `${file} says "Worker" without naming the runtime family. The native entry works in Node worker_threads; what it cannot do is run on Deno, Supabase Edge Functions, or Cloudflare Workers — the list docs/reference/supabase-sdk.md's own table already spells out.`,
      ).toEqual([])
    },
  )

  it.each(GUARDED)(
    '%s does not blame protect-ffi for an import-time load',
    (file) => {
      expect(
        protectFfiImportLoadClaims(prose(file, read(file))),
        `${file} says importing \`@cipherstash/protect-ffi\` loads a native binary. It does not: packages/protect-ffi/src/index.cts uses \`import native = require('./load.cjs')\` so the @neon-rs/load proxy is never enumerated into resolving the platform binary, guarded by packages/protect-ffi/src/nativeLoading.test.ts. The module-evaluation-time load in that graph is \`@cipherstash/auth\`'s.`,
      ).toEqual([])
    },
  )
})

describe('both entries carry a browser prohibition', () => {
  /** The Quick start prose, paragraph by paragraph, up to its first example. */
  function quickStartParagraphs() {
    const doc = read('docs/reference/supabase-sdk.md')
    const start = doc.indexOf('## Quick start')
    expect(
      start,
      'docs/reference/supabase-sdk.md has no "## Quick start" heading',
    ).toBeGreaterThan(-1)
    const fence = doc.indexOf('\n```', start)
    expect(
      fence,
      '"## Quick start" is followed by no code example',
    ).toBeGreaterThan(start)
    return doc
      .slice(start, fence)
      .split(/\n\s*\n/)
      .map((p) => p.trim())
      .filter((p) => p && !p.startsWith('#'))
  }

  /**
   * PR #952 rewrote this section into two entry-point paragraphs and moved the
   * browser caveat onto the edge one only, so a reader of the native paragraph
   * saw no browser prohibition at all. Both need one, for different reasons —
   * the native entry wants a `databaseUrl` and workspace credentials, the WASM
   * client requires a workspace `clientKey` on every auth path (#804).
   */
  it('the native-entry prose says it is not browser-safe', () => {
    const native = quickStartParagraphs().filter((p) => !/wasm-inline/.test(p))
    expect(
      native,
      'no Quick start paragraph describes the native entry',
    ).not.toHaveLength(0)
    expect(
      native.some((p) => /browser/i.test(p)),
      'No Quick start paragraph about the default entry mentions the browser. #952 dropped "or the browser" from the native restriction and attached the caveat to the edge entry alone.',
    ).toBe(true)
  })

  it('the edge-entry prose keeps its clientKey grounding', () => {
    const edge = quickStartParagraphs().filter((p) => /wasm-inline/.test(p))
    expect(
      edge,
      'no Quick start paragraph describes the edge entry',
    ).not.toHaveLength(0)
    const body = edge.join('\n')
    expect(
      body,
      'the edge entry must still be called out as not browser-safe',
    ).toMatch(/browser/i)
    expect(
      body,
      'the #804 clientKey grounding is what makes that claim checkable',
    ).toMatch(/clientKey/)
    expect(body).toMatch(/804/)
  })
})

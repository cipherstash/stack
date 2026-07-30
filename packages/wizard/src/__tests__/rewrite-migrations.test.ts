import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  describeSkipReason,
  describeStagedReconciliation,
  rewriteEncryptedAlterColumns,
  sweepMigrationDirs,
} from '../lib/rewrite-migrations.js'

const fsPromisesWrite = vi.hoisted(() => ({
  real: (() => {
    throw new Error('fsPromisesWrite.real not initialised')
  }) as typeof import('node:fs/promises').writeFile,
  spy: vi.fn(),
}))
vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  fsPromisesWrite.real = actual.writeFile
  return { ...actual, writeFile: fsPromisesWrite.spy }
})

describe('rewriteEncryptedAlterColumns', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wizard-rewrite-'))
    fsPromisesWrite.spy.mockImplementation(fsPromisesWrite.real)
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  /**
   * Declare `columns` on `tableRef` as PLAINTEXT, in a migration that sorts
   * before every fixture below.
   *
   * The sweep is fail-closed: it rewrites a column only when the corpus shows
   * the column exists and is not already encrypted. A fixture that is just an
   * ALTER declares nothing, so it is `source-unknown` by design — a test that
   * exercises the REWRITE has to supply the `CREATE TABLE` a real drizzle
   * corpus would carry.
   *
   * `tableRef` is written exactly as it appears in the ALTER, so a pgSchema()
   * table passes `'"app"."users"'` and the declaration lands on the same key.
   */
  const declarePlaintext = (tableRef: string, ...columns: string[]): void => {
    const file = path.join(tmpDir, '0000_declare.sql')
    const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf-8') : ''
    const defs = columns.map((column) => `"${column}" text`).join(', ')
    fs.writeFileSync(file, `${existing}CREATE TABLE ${tableRef} (${defs});\n`)
  }

  it('rewrites an in-place ALTER COLUMN with the bare v2 type name', async () => {
    declarePlaintext('"transactions"', 'amount')
    const original = `ALTER TABLE "transactions" ALTER COLUMN "amount" SET DATA TYPE eql_v2_encrypted;\n`
    const filePath = path.join(tmpDir, '0002_alter.sql')
    fs.writeFileSync(filePath, original)

    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([filePath])
    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      'ALTER TABLE "transactions" ADD COLUMN "amount_encrypted" "public"."eql_v2_encrypted";',
    )
    expect(updated).not.toContain(
      'ALTER TABLE "transactions" DROP COLUMN "amount";',
    )
    expect(updated).not.toContain(
      'ALTER TABLE "transactions" RENAME COLUMN "amount_encrypted" TO "amount";',
    )
    expect(updated).not.toContain('SET DATA TYPE')
    // Wizard-branded header.
    expect(updated).toContain('-- Rewritten by @cipherstash/wizard')
  })

  it('rewrites a bare v3 domain (the generation the wizard now scaffolds)', async () => {
    declarePlaintext('"users"', 'email')
    const original = `ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n`
    const filePath = path.join(tmpDir, '0002_v3.sql')
    fs.writeFileSync(filePath, original)

    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([filePath])
    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      'ALTER TABLE "users" ADD COLUMN "email_encrypted" "public"."eql_v3_text_search";',
    )
    expect(updated).not.toContain('SET DATA TYPE')
  })

  it('rewrites the schema-qualified form produced by drizzle-kit', async () => {
    declarePlaintext('"users"', 'email')
    const original =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "public"."eql_v3_text_search";\n'
    const filePath = path.join(tmpDir, '0003_alter.sql')
    fs.writeFileSync(filePath, original)

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      'ALTER TABLE "users" ADD COLUMN "email_encrypted" "public"."eql_v3_text_search";',
    )
    expect(updated).not.toContain('SET DATA TYPE')
  })

  it('rewrites a schema-qualified table produced by pgSchema()', async () => {
    // drizzle-kit emits `"app"."users"` for a table declared in a pgSchema();
    // the old `\s+` between the table and ALTER COLUMN could never cross the `.`.
    declarePlaintext('"app"."users"', 'email')
    const original =
      'ALTER TABLE "app"."users" ALTER COLUMN "email" SET DATA TYPE "undefined"."eql_v3_text_search";\n'
    const filePath = path.join(tmpDir, '0014_qualified.sql')
    fs.writeFileSync(filePath, original)

    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([filePath])
    const updated = fs.readFileSync(filePath, 'utf-8')
    // Every emitted statement keeps the schema qualifier.
    expect(updated).toContain(
      'ALTER TABLE "app"."users" ADD COLUMN "email_encrypted" "public"."eql_v3_text_search";',
    )
    expect(updated).not.toContain(
      'ALTER TABLE "app"."users" DROP COLUMN "email";',
    )
    expect(updated).not.toContain(
      'ALTER TABLE "app"."users" RENAME COLUMN "email_encrypted" TO "email";',
    )
    expect(updated).not.toContain('SET DATA TYPE')
  })

  it('rewrites the "undefined" schema form drizzle-kit emits for bare custom types', async () => {
    declarePlaintext('"transactions"', 'amount')
    const original =
      'ALTER TABLE "transactions" ALTER COLUMN "amount" SET DATA TYPE "undefined"."eql_v2_encrypted";\n'
    const filePath = path.join(tmpDir, '0005_undef.sql')
    fs.writeFileSync(filePath, original)

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      'ALTER TABLE "transactions" ADD COLUMN "amount_encrypted" "public"."eql_v2_encrypted";',
    )
    expect(updated).not.toContain('SET DATA TYPE')
  })

  it('rewrites the double-quoted form produced by stack 0.15.0', async () => {
    declarePlaintext('"transactions"', 'description')
    const original =
      'ALTER TABLE "transactions" ALTER COLUMN "description" SET DATA TYPE "undefined".""public"."eql_v2_encrypted"";\n'
    const filePath = path.join(tmpDir, '0006_double.sql')
    fs.writeFileSync(filePath, original)

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      'ALTER TABLE "transactions" ADD COLUMN "description_encrypted" "public"."eql_v2_encrypted";',
    )
    expect(updated).not.toContain('SET DATA TYPE')
  })

  it('leaves unrelated migrations untouched', async () => {
    const original =
      'CREATE TABLE "widgets" ("id" integer PRIMARY KEY, "name" text);\n'
    const filePath = path.join(tmpDir, '0001_init.sql')
    fs.writeFileSync(filePath, original)

    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([])
    expect(fs.readFileSync(filePath, 'utf-8')).toBe(original)
  })

  it('skips the file passed in options.skip', async () => {
    declarePlaintext('"t"', 'c')
    const install = path.join(tmpDir, '0000_install-eql.sql')
    const alter = path.join(tmpDir, '0002_alter.sql')
    fs.writeFileSync(install, 'CREATE SCHEMA eql_v2;\n')
    fs.writeFileSync(
      alter,
      'ALTER TABLE "t" ALTER COLUMN "c" SET DATA TYPE eql_v2_encrypted;',
    )

    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir, {
      skip: install,
    })
    expect(rewritten).toEqual([alter])
    expect(fs.readFileSync(install, 'utf-8')).toBe('CREATE SCHEMA eql_v2;\n')
  })

  it('returns an empty result when the directory does not exist', async () => {
    const missing = path.join(tmpDir, 'does-not-exist')
    const { rewritten, skipped } = await rewriteEncryptedAlterColumns(missing)
    expect(rewritten).toEqual([])
    expect(skipped).toEqual([])
  })

  // Every concrete `eql_v3_*` domain shipped by `@cipherstash/stack/eql/v3`
  // (see `packages/stack/src/eql/v3/columns.ts`). Eight scalar bases carry the
  // four storage/eq/ord flavours; text adds `_match`/`_search`; boolean and json
  // stand alone.
  const V3_SCALAR_BASES = [
    'integer',
    'smallint',
    'bigint',
    'numeric',
    'real',
    'double',
    'date',
    'timestamp',
  ]
  const V3_DOMAINS = [
    ...V3_SCALAR_BASES.flatMap((base) =>
      ['', '_eq', '_ord', '_ord_ore'].map(
        (flavour) => `eql_v3_${base}${flavour}`,
      ),
    ),
    'eql_v3_text',
    'eql_v3_text_eq',
    'eql_v3_text_match',
    'eql_v3_text_ord',
    'eql_v3_text_ord_ore',
    'eql_v3_text_search',
    'eql_v3_boolean',
    'eql_v3_json',
  ]

  it.each(V3_DOMAINS)('rewrites an ALTER COLUMN to %s', async (domain) => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0007_v3.sql')
    fs.writeFileSync(
      filePath,
      `ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "undefined"."${domain}";\n`,
    )

    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([filePath])
    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      `ALTER TABLE "users" ADD COLUMN "email_encrypted" "public"."${domain}";`,
    )
    expect(updated).not.toContain('ALTER TABLE "users" DROP COLUMN "email";')
    expect(updated).not.toContain(
      'ALTER TABLE "users" RENAME COLUMN "email_encrypted" TO "email";',
    )
    expect(updated).not.toContain('SET DATA TYPE')
  })

  // DOMAIN_RE is derived from ENCRYPTED_DOMAIN, so drift between the two can't
  // silently leave a domain unrewritten. Prove every domain the alternation
  // recognises is actually extracted into the emitted ADD COLUMN.
  it.each([
    ...V3_DOMAINS,
    'eql_v2_encrypted',
  ])('extracts the bare domain %s from a mangled ALTER', async (domain) => {
    declarePlaintext('"t"', 'c')
    const filePath = path.join(tmpDir, '0015_drift.sql')
    fs.writeFileSync(
      filePath,
      `ALTER TABLE "t" ALTER COLUMN "c" SET DATA TYPE "undefined"."${domain}";\n`,
    )

    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([filePath])
    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      `ALTER TABLE "t" ADD COLUMN "c_encrypted" "public"."${domain}";`,
    )
    expect(updated).not.toContain('SET DATA TYPE')
  })

  // The mangled forms are the cross product of what `dataType()` returns and
  // which drizzle-kit era renders it (see the file's comment table).
  const MANGLED_FORMS: Array<[label: string, emitted: string]> = [
    ['plain, drizzle-kit <=0.30.6', 'eql_v3_text_search'],
    [
      '"undefined"-prefixed, drizzle-kit >=0.31.0',
      '"undefined"."eql_v3_text_search"',
    ],
    ['dotted, drizzle-kit <=0.30.6', 'public.eql_v3_text_search'],
    [
      'dotted inside "undefined", drizzle-kit >=0.31.0',
      '"undefined"."public.eql_v3_text_search"',
    ],
    ['pre-quoted, drizzle-kit <=0.30.6', '"public"."eql_v3_text_search"'],
    [
      'pre-quoted inside "undefined", drizzle-kit >=0.31.0',
      '"undefined".""public"."eql_v3_text_search""',
    ],
    ['bare-quoted (speculative)', '"eql_v3_text_search"'],
  ]

  it.each(MANGLED_FORMS)('rewrites the v3 %s form', async (_label, emitted) => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0008_form.sql')
    fs.writeFileSync(
      filePath,
      `ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE ${emitted};\n`,
    )

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      'ALTER TABLE "users" ADD COLUMN "email_encrypted" "public"."eql_v3_text_search";',
    )
    expect(updated).not.toContain('SET DATA TYPE')
  })

  it('names the target domain in the guidance comment', async () => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0010_comment.sql')
    fs.writeFileSync(
      filePath,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "undefined"."eql_v3_integer_ord";\n',
    )

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain('-- eql_v3_integer_ord.')
  })

  it('explains that the source column is preserved for the staged lifecycle', async () => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0016_warn.sql')
    fs.writeFileSync(
      filePath,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain('source column "email" is deliberately preserved')
    expect(updated).toContain('staged `stash encrypt` lifecycle')
    expect(updated).toContain('switch the application to the')
    expect(updated).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)
  })

  it('emits one executable ADD and no cutover statements', async () => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0018_breakpoint.sql')
    fs.writeFileSync(
      filePath,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8').trimEnd()
    const execLines = updated
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('--'))
    expect(execLines).toEqual([
      'ALTER TABLE "users" ADD COLUMN "email_encrypted" "public"."eql_v3_text_search";',
    ])
    expect(updated).not.toContain('--> statement-breakpoint')
  })

  it('rewrites each statement to its own domain when v2 and v3 are mixed', async () => {
    declarePlaintext('"a"', 'x', 'y')
    const filePath = path.join(tmpDir, '0011_mixed.sql')
    fs.writeFileSync(
      filePath,
      [
        'ALTER TABLE "a" ALTER COLUMN "x" SET DATA TYPE eql_v2_encrypted;',
        'ALTER TABLE "a" ALTER COLUMN "y" SET DATA TYPE "undefined"."eql_v3_json";',
      ].join('\n'),
    )

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      'ALTER TABLE "a" ADD COLUMN "x_encrypted" "public"."eql_v2_encrypted";',
    )
    expect(updated).toContain(
      'ALTER TABLE "a" ADD COLUMN "y_encrypted" "public"."eql_v3_json";',
    )
  })

  it.each([
    ['a plaintext type', 'text'],
    ['jsonb', 'jsonb'],
    ['a lookalike from another EQL major', 'eql_v4_text_search'],
    ['a lookalike prefix', 'not_eql_v3_text_search'],
  ])('leaves an ALTER COLUMN to %s untouched', async (_label, type) => {
    const original = `ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE ${type};\n`
    const filePath = path.join(tmpDir, '0012_other.sql')
    fs.writeFileSync(filePath, original)

    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([])
    expect(fs.readFileSync(filePath, 'utf-8')).toBe(original)
  })

  it('leaves a hand-authored SET DATA TYPE ... USING conversion untouched but flags it', async () => {
    const original =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;\n'
    const filePath = path.join(tmpDir, '0013_using.sql')
    fs.writeFileSync(filePath, original)

    const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([])
    expect(skipped).toHaveLength(1)
    expect(skipped[0].file).toBe(filePath)
    expect(skipped[0].statement).toContain('SET DATA TYPE')
    expect(skipped[0].statement).toContain('eql_v3_text_search')
    // Left untouched on disk — we flag, we don't guess.
    expect(fs.readFileSync(filePath, 'utf-8')).toBe(original)
  })

  it('reports no skipped statements when the strict rewrite fully handled the file', async () => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0021_handled.sql')
    fs.writeFileSync(
      filePath,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([filePath])
    expect(skipped).toEqual([])
  })

  // A near-miss is quoted back to the user verbatim, so it must read as the
  // offending statement alone. NEAR_MISS_RE opens with a lazy `[^;]*?`, which
  // can only be bounded by the previous `;` — so without an explicit trim the
  // reported "statement" drags in every comment and blank line since then.
  it('reports a near-miss without the file-leading comment block', async () => {
    const statement =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;'
    const original = [
      '-- Custom SQL migration file, put your code below! --',
      '-- Hand-converts the email column in place.',
      '',
      statement,
      '',
    ].join('\n')
    const filePath = path.join(tmpDir, '0022_preamble.sql')
    fs.writeFileSync(filePath, original)

    const { skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(skipped).toHaveLength(1)
    expect(skipped[0].statement).toBe(statement)
  })

  // A statement the STRICT matcher already matched but skipped (here:
  // source-unknown) is left on disk unchanged, so it still contains
  // `SET DATA TYPE` and the broad near-miss scan finds it again. Before the
  // preamble regex stripped a leading block comment, that second pass reported
  // a DIFFERENT statement string (comment glued to the front) than the strict
  // pass's `match.trim()`, so the dedup key never matched and the same
  // statement came back twice: once correctly as `source-unknown`, once as
  // `unrecognised-form` — contradictory advice (look for a hand-authored
  // `USING` clause) for a statement that has none.
  //
  // The block comment must NOT sit at the very start of the file — that is
  // the one shape a previous, narrower version of the preamble regex happened
  // to handle. A realistic migration file has a preceding statement, so
  // NEAR_MISS_RE's match starts at THAT statement's `;`, dragging the newline
  // before the comment in too; a regex that only strips a comment anchored to
  // the very start of the match fails here.
  it('reports a block-comment-prefixed statement once, not twice', async () => {
    const alterSql =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
    const filePath = path.join(tmpDir, '0040_block-preamble.sql')
    fs.writeFileSync(
      filePath,
      [
        'CREATE TABLE "users" ("id" integer PRIMARY KEY);',
        '/* note */',
        alterSql,
        '',
      ].join('\n'),
    )

    const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([])
    expect(skipped).toEqual([
      { file: filePath, statement: alterSql, reason: 'source-unknown' },
    ])
  })

  // Same bug, but the comment sits on the ALTER's own line rather than its
  // own — the preceding statement's `;` still starts the near-miss match
  // before the (indented) comment, not at it.
  it('reports an indented block-comment-prefixed statement once, not twice', async () => {
    const alterSql =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
    const filePath = path.join(tmpDir, '0041_block-preamble-indented.sql')
    fs.writeFileSync(
      filePath,
      [
        'CREATE TABLE "users" ("id" integer PRIMARY KEY);',
        `  /* note */ ${alterSql}`,
        '',
      ].join('\n'),
    )

    const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([])
    expect(skipped).toEqual([
      { file: filePath, statement: alterSql, reason: 'source-unknown' },
    ])
  })

  // Same bug again, this time on the OTHER correct reason a near-miss can
  // carry: the column is already encrypted, not merely undeclared.
  it('reports a block-comment-prefixed statement once, not twice, for an already-encrypted column', async () => {
    const alterSql =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
    const filePath = path.join(tmpDir, '0042_block-preamble-encrypted.sql')
    fs.writeFileSync(
      filePath,
      [
        'CREATE TABLE "users" ("id" integer PRIMARY KEY, "email" "public"."eql_v3_text_eq");',
        '/* note */',
        alterSql,
        '',
      ].join('\n'),
    )

    const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([])
    expect(skipped).toEqual([
      { file: filePath, statement: alterSql, reason: 'already-encrypted' },
    ])
  })

  it('reports a near-miss without a preceding statement-breakpoint marker', async () => {
    const statement =
      'ALTER TABLE "users" ALTER COLUMN "meta" SET DATA TYPE eql_v3_json USING (meta)::jsonb;'
    const original = [
      'CREATE TABLE "users" ("id" integer PRIMARY KEY);',
      '--> statement-breakpoint',
      statement,
      '',
    ].join('\n')
    const filePath = path.join(tmpDir, '0023_breakpoint-preamble.sql')
    fs.writeFileSync(filePath, original)

    const { skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(skipped).toHaveLength(1)
    expect(skipped[0].statement).toBe(statement)
  })

  it('keeps a multi-line near-miss statement intact after the preamble trim', async () => {
    const statement = [
      'ALTER TABLE "users"',
      '  ALTER COLUMN "email"',
      '  SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;',
    ].join('\n')
    const filePath = path.join(tmpDir, '0024_multiline.sql')
    fs.writeFileSync(filePath, `-- leading note\n\n${statement}\n`)

    const { skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(skipped).toHaveLength(1)
    expect(skipped[0].statement).toBe(statement)
  })

  // A multi-line replacement inherits the author's `-- ` on line 1 ONLY, so
  // rewriting a commented-out ALTER turns lines 2+ — including DROP COLUMN —
  // into live SQL. Commented SQL never runs; leave it exactly as written.
  describe('commented-out statements', () => {
    it.each([
      ['a line comment', '-- '],
      ['an indented line comment', '  --  '],
      ['a drizzle statement-breakpoint style prefix', '--> '],
    ])('leaves an ALTER behind %s untouched', async (_label, prefix) => {
      const original = `${prefix}ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n`
      const filePath = path.join(tmpDir, '0030_commented.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toBe(original)
      expect(updated).not.toContain('DROP COLUMN')
    })

    it('leaves an ALTER inside a block comment untouched', async () => {
      const original = [
        '/* superseded by 0031',
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
        '*/',
        '',
      ].join('\n')
      const filePath = path.join(tmpDir, '0030_block.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      expect(fs.readFileSync(filePath, 'utf-8')).toBe(original)
    })

    it('leaves an ALTER inside a NESTED block comment untouched', async () => {
      const original = [
        '/* outer /* inner */',
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
        '*/',
        '',
      ].join('\n')
      const filePath = path.join(tmpDir, '0030_nested.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      expect(fs.readFileSync(filePath, 'utf-8')).toBe(original)
    })

    it('does not report a commented-out near-miss', async () => {
      const filePath = path.join(tmpDir, '0030_commented-using.sql')
      fs.writeFileSync(
        filePath,
        '-- ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;\n',
      )

      const { skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(skipped).toEqual([])
    })

    // The comment scan must not be fooled by `--` inside a string literal, or
    // it would skip a live statement and leave broken SQL to fail at migrate.
    it('still rewrites an ALTER that follows a "--" inside a string literal', async () => {
      declarePlaintext('"users"', 'email')
      const filePath = path.join(tmpDir, '0030_literal.sql')
      fs.writeFileSync(
        filePath,
        [
          `INSERT INTO "notes" ("body") VALUES ('a -- b');`,
          'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
          '',
        ].join('\n'),
      )

      const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([filePath])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toContain('ADD COLUMN "email_encrypted"')
      expect(updated).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)
    })

    // An apostrophe inside a DOUBLE-QUOTED identifier is not a string
    // delimiter. Reading it as one opens a phantom literal whose "closing"
    // quote is the apostrophe in the SAME identifier further down the file —
    // PAST the commented-out ALTER — so the scan concludes the ALTER is live
    // and rewrites it into a real DROP COLUMN. The CREATE that declared the
    // column always sits above the ALTER, so a real corpus produces exactly
    // this shape.
    it('leaves a commented-out ALTER untouched when an earlier identifier holds an apostrophe', async () => {
      const original = [
        'CREATE TABLE "users" (',
        '\t"id" serial PRIMARY KEY NOT NULL,',
        '\t"o\'brien_data" text',
        ');',
        '--> statement-breakpoint',
        '-- ALTER TABLE "users" ALTER COLUMN "o\'brien_data" SET DATA TYPE eql_v3_text_search;',
        '',
      ].join('\n')
      const filePath = path.join(tmpDir, '0031_apostrophe.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toBe(original)
      expect(updated).not.toContain('DROP COLUMN')
    })

    // A statement inside a single-quoted literal is DATA, not SQL. Rewriting it
    // splices `--> statement-breakpoint` markers INSIDE the literal, so
    // splitting the file the way drizzle's migrator does yields a bare, live
    // `ALTER TABLE ... DROP COLUMN ...;` as a chunk of its own.
    it('leaves an ALTER inside a string literal untouched', async () => {
      const original = [
        `INSERT INTO "audit_log" ("note") VALUES ('the reverted migration read:`,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
        `(do not run it again)');`,
        '',
      ].join('\n')
      const filePath = path.join(tmpDir, '0032_string-literal.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toBe(original)
      expect(updated).not.toContain('DROP COLUMN')
      expect(updated).not.toContain('--> statement-breakpoint')
    })

    // An UNTERMINATED quoted identifier must fail the same way an unterminated
    // string literal does — by swallowing the rest of the file as inert. If it
    // instead runs the scan cursor to the end, the loop exits and every
    // commented-out ALTER below it is reported live and rewritten: the same
    // destructive outcome as the apostrophe case above, one branch over.
    it('leaves a commented-out ALTER untouched after an unterminated quoted identifier', async () => {
      const original = [
        'CREATE TABLE "users" ("id" serial PRIMARY KEY NOT NULL, "email" text);',
        '--> statement-breakpoint',
        'SELECT "unclosed FROM users;',
        '--> statement-breakpoint',
        '-- ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
        '',
      ].join('\n')
      const filePath = path.join(tmpDir, '0033_unterminated-identifier.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toBe(original)
      expect(updated).not.toContain('DROP COLUMN')
    })

    // Regression pin, not a bug fix — this already behaves. A commented-out
    // ALTER in a CRLF file must come back byte-identical.
    it('leaves a commented-out ALTER with CRLF line endings byte-identical', async () => {
      const original = [
        'CREATE TABLE "users" ("id" integer PRIMARY KEY);',
        '--> statement-breakpoint',
        '-- ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
        '',
      ].join('\r\n')
      const filePath = path.join(tmpDir, '0033_crlf.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      expect(fs.readFileSync(filePath, 'utf-8')).toBe(original)
    })

    // #772 review, finding 1. Quote parity is a whole-file property: anything
    // that makes the scanner disagree with Postgres about where a literal ENDS
    // shifts every following token, so a commented-out ALTER downstream reads
    // as live and is rewritten into a live DROP COLUMN.
    //
    // The two shapes below both do that. A `$$ … $$` body was documented as
    // safe on the grounds that mis-reading one can only make us SKIP — that
    // holds for an unterminated literal, but an odd apostrophe count inside the
    // body ends a literal EARLY, which is the opposite direction.
    it('leaves a commented-out ALTER alone after a dollar-quoted body with an odd apostrophe count', async () => {
      declarePlaintext('"users"', 'email')
      const original = [
        "CREATE FUNCTION note() RETURNS text AS $$ don't $$ LANGUAGE sql;",
        '--> statement-breakpoint',
        '-- it\'s ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
        '',
      ].join('\n')
      const filePath = path.join(tmpDir, '0033_dollar-quoted.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toBe(original)
      expect(updated).not.toContain('DROP COLUMN')
    })

    it('leaves a commented-out ALTER alone after a tagged dollar-quoted body', async () => {
      declarePlaintext('"users"', 'email')
      const original = [
        "CREATE FUNCTION note() RETURNS text AS $fn$ don't $fn$ LANGUAGE sql;",
        '--> statement-breakpoint',
        '-- it\'s ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
        '',
      ].join('\n')
      const filePath = path.join(tmpDir, '0033_tagged-dollar.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      expect(fs.readFileSync(filePath, 'utf-8')).toBe(original)
    })

    // A backslash-escaped quote inside an E'' string does not close it. Reading
    // it as a close shifts parity for the rest of the file the same way.
    it('leaves a commented-out ALTER alone after an E-string with a backslash-escaped quote', async () => {
      declarePlaintext('"users"', 'email')
      const original = [
        'CREATE TABLE "notes" ("body" text);',
        '--> statement-breakpoint',
        "INSERT INTO \"notes\" VALUES (E'a\\'b');",
        '--> statement-breakpoint',
        '-- it\'s ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
        '',
      ].join('\n')
      const filePath = path.join(tmpDir, '0033_estring.sql')
      fs.writeFileSync(filePath, original)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toBe(original)
      expect(updated).not.toContain('DROP COLUMN')
    })

    // The dollar-quote skip must not swallow live SQL: a `$$` body sitting
    // BEFORE a genuine plaintext ALTER still leaves that ALTER rewritable.
    it('still rewrites a live ALTER that follows a dollar-quoted body', async () => {
      declarePlaintext('"users"', 'email')
      const filePath = path.join(tmpDir, '0033_dollar-then-live.sql')
      fs.writeFileSync(
        filePath,
        [
          "CREATE FUNCTION note() RETURNS text AS $$ don't $$ LANGUAGE sql;",
          '--> statement-breakpoint',
          'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
          '',
        ].join('\n'),
      )

      const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([filePath])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toContain('ADD COLUMN "email_encrypted"')
      expect(updated).not.toContain('DROP COLUMN')
    })

    it.each([
      ['tagged', 'price$usd$cents'],
      ['untagged', 'price$$cents'],
    ])('does not treat a %s dollar delimiter inside an unquoted identifier as a dollar-quoted body', async (_kind, identifier) => {
      declarePlaintext('"users"', 'email')
      const filePath = path.join(tmpDir, `0033_${_kind}-identifier.sql`)
      fs.writeFileSync(
        filePath,
        [
          `SELECT ${identifier} FROM "prices";`,
          'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
          '',
        ].join('\n'),
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([filePath])
      expect(skipped).toEqual([])
      const updated = fs.readFileSync(filePath, 'utf-8')
      expect(updated).toContain('ADD COLUMN "email_encrypted"')
      expect(updated).not.toContain('SET DATA TYPE')
    })
  })

  /**
   * #823 closed #811 by removing the blast radius — the rewrite became add-only
   * — not by closing the MECHANISM. #836 item 1 closed the mechanism: the index
   * now reads dollar-quoted bodies for the encrypted side, so these corpora are
   * recognised as already-encrypted instead of being handed an empty twin.
   *
   * Two expectations here therefore tightened, both toward fail-closed:
   * `already-encrypted` replaces `target-exists` on the rename corpora (after
   * those renames `email` IS the ciphertext, and `target-exists`'s "review the
   * existing encrypted twin" pointed at a column the rename had just consumed),
   * and the `DO $$` ADD COLUMN case no longer rewrites at all.
   */
  describe('issue #811 dollar-quoted DDL regression', () => {
    const domainChange =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "eql_v3_text_eq";'

    it('does not emit destructive SQL for the reported two-file DO $$ rename corpus', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("id" serial PRIMARY KEY NOT NULL, "email" text NOT NULL);',
          'ALTER TABLE "users" ADD COLUMN "email_encrypted" "eql_v3_text_search";',
          'DO $$ BEGIN',
          '  ALTER TABLE "users" RENAME COLUMN "email" TO "email_old";',
          '  ALTER TABLE "users" RENAME COLUMN "email_encrypted" TO "email";',
          'END $$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(fs.readFileSync(change, 'utf-8')).toBe(`${domainChange}\n`)
      expect(skipped).toEqual([
        { file: change, statement: domainChange, reason: 'already-encrypted' },
      ])
    })

    // The case #823's own test codified backwards (#836, item 1): the `DO $$`
    // body really does leave `email` encrypted, so staging a twin beside the
    // ciphertext was wrong. It is now recognised and flagged.
    it('flags an encrypted ADD COLUMN inside DO $$ instead of staging a twin', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("email" text NOT NULL);',
          'DO $$ BEGIN',
          '  ALTER TABLE "users" DROP COLUMN "email";',
          '  ALTER TABLE "users" ADD COLUMN "email" "eql_v3_text_search";',
          'END $$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(fs.readFileSync(change, 'utf-8')).toBe(`${domainChange}\n`)
      expect(skipped).toEqual([
        { file: change, statement: domainChange, reason: 'already-encrypted' },
      ])
    })

    it('does not emit destructive SQL for a rename inside a custom dollar tag', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("email" text NOT NULL);',
          'ALTER TABLE "users" ADD COLUMN "email_encrypted" "eql_v3_text_search";',
          'DO $stash$ BEGIN',
          '  ALTER TABLE "users" RENAME COLUMN "email" TO "email_old";',
          '  ALTER TABLE "users" RENAME COLUMN "email_encrypted" TO "email";',
          'END $stash$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(fs.readFileSync(change, 'utf-8')).toBe(`${domainChange}\n`)
      expect(skipped).toEqual([
        { file: change, statement: domainChange, reason: 'already-encrypted' },
      ])
    })

    // An unterminated `$$` makes the whole file unparseable, so Postgres never
    // ran any of it and nothing after the opener is proven. The index reads that
    // remainder for the encrypted side anyway (see `dollarQuotedBodies`), which
    // is why the twin is now seen and the statement flagged rather than
    // rewritten — the fail-closed way to be wrong about a broken file.
    it('flags rather than rewrites when an unterminated $$ hides an encrypted declaration', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("email" text NOT NULL);',
          'SELECT $$unterminated;',
          'ALTER TABLE "users" ADD COLUMN "email_encrypted" "eql_v3_text_search";',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(fs.readFileSync(change, 'utf-8')).toBe(`${domainChange}\n`)
      expect(skipped).toEqual([
        { file: change, statement: domainChange, reason: 'target-exists' },
      ])
    })
  })

  /**
   * Issue #836, item 1. `isInsideCommentOrString` skips a dollar-quoted body
   * WHOLE — correct for the rewrite pass, wrong for the index pass. DDL inside
   * `DO $$ … END $$;` is executed SQL: the column really is encrypted in the
   * database. Skipping it meant the column never entered `encrypted`, fell to
   * "plaintext by residue", and the sweep added an empty `<col>_encrypted` twin
   * beside the real ciphertext — `rewritten` listing the file, `skipped` empty,
   * exit code 0.
   *
   * The index now reads dollar-quoted bodies for the ENCRYPTED side only. The
   * `declared` side stays gated: a `DO $$` body is conditional PL/pgSQL, so a
   * plaintext declaration inside one may never have run, and over-detecting
   * `declared` is the fail-OPEN direction. The rewrite pass is untouched — an
   * ALTER inside a dollar body is still inert and still not rewritten.
   */
  describe('encrypted DDL inside a dollar-quoted body', () => {
    const domainChange =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "eql_v3_text_eq";'

    it('indexes an encrypted CREATE TABLE column inside DO $$', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'DO $$ BEGIN',
          '  CREATE TABLE "users" ("email" "public"."eql_v3_text_search");',
          'END $$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: change, statement: domainChange, reason: 'already-encrypted' },
      ])
    })

    it('carries encryptedness through a RENAME inside DO $$', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("email" text NOT NULL);',
          'ALTER TABLE "users" ADD COLUMN "email_tmp" "eql_v3_text_search";',
          'DO $$ BEGIN',
          '  ALTER TABLE "users" DROP COLUMN "email";',
          '  ALTER TABLE "users" RENAME COLUMN "email_tmp" TO "email";',
          'END $$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: change, statement: domainChange, reason: 'already-encrypted' },
      ])
    })

    // The staged twin exists in the database but only inside a dollar body, so
    // it is `encrypted` without ever being `declared`. Emitting another
    // ADD COLUMN for it fails at migrate time with "column already exists".
    it('treats an encrypted twin added inside DO $$ as an existing target', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("email" text NOT NULL);',
          'DO $$ BEGIN',
          '  ALTER TABLE "users" ADD COLUMN "email_encrypted" "eql_v3_text_search";',
          'END $$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      const alter =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "eql_v3_text_search";'
      fs.writeFileSync(change, `${alter}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: change, statement: alter, reason: 'target-exists' },
      ])
    })

    // The fail-OPEN direction, deliberately not taken. A `DO $$` body is
    // conditional, so a PLAINTEXT declaration inside one is not proof the
    // column exists — it stays undeclared and the statement stays flagged.
    it('does not let a plaintext declaration inside DO $$ count as declared', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'DO $$ BEGIN',
          '  ALTER TABLE "users" ADD COLUMN "email" text;',
          'END $$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: change, statement: domainChange, reason: 'source-unknown' },
      ])
    })

    // Reading dollar bodies must not resurrect INERT ones. A `DO $$` block
    // sitting inside a `--` comment or a string literal never runs, so the
    // encrypted declaration in it is not evidence of anything.
    it('ignores a dollar-quoted body inside a line comment', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("email" text NOT NULL);',
          '-- DO $$ BEGIN ALTER TABLE "users" ADD COLUMN "email" "eql_v3_text_search"; END $$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([change])
      expect(skipped).toEqual([])
      expect(fs.readFileSync(change, 'utf-8')).toContain(
        'ADD COLUMN "email_encrypted"',
      )
    })

    it('ignores a dollar-quoted body inside a string literal', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("email" text NOT NULL);',
          `INSERT INTO "audit" ("sql") VALUES ('DO $$ BEGIN ALTER TABLE "users" ADD COLUMN "email" "eql_v3_text_search"; END $$;');`,
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([change])
      expect(skipped).toEqual([])
    })

    // The rewrite pass keeps treating a dollar body as inert: `renderSafeAlter`
    // returns MULTIPLE lines, and splicing them into a PL/pgSQL body would
    // rewrite code the sweep cannot reason about.
    it('still refuses to rewrite an ALTER that sits inside DO $$', async () => {
      const file = path.join(tmpDir, '0000_setup.sql')
      const sql = [
        'CREATE TABLE "users" ("email" text NOT NULL);',
        'DO $$ BEGIN',
        `  ${domainChange}`,
        'END $$;',
        '',
      ].join('\n')
      fs.writeFileSync(file, sql)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([])
      expect(fs.readFileSync(file, 'utf-8')).toBe(sql)
    })

    // drizzle-kit's own enum idiom. It touches no table, so widening the index
    // must not turn every corpus containing one into a wall of flagged
    // statements — the reason a blanket "fail closed on any dollar-quoted body"
    // was rejected in favour of indexing the encrypted side.
    it('leaves the drizzle-kit CREATE TYPE enum idiom rewritable', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_setup.sql'),
        [
          'CREATE TABLE "users" ("email" text NOT NULL);',
          'DO $$ BEGIN CREATE TYPE "public"."role" AS ENUM(\'admin\'); EXCEPTION WHEN duplicate_object THEN null; END $$;',
          '',
        ].join('\n'),
      )
      const change = path.join(tmpDir, '0001_change_domain.sql')
      fs.writeFileSync(change, `${domainChange}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([change])
      expect(skipped).toEqual([])
    })
  })

  /**
   * #836, item 2. The sweep repairs SQL and nothing else, so a successful
   * rewrite leaves schema.ts, the drizzle-kit snapshot and the database
   * three-way divergent — and `drizzle-kit generate` cannot surface it, because
   * it diffs schema.ts against the snapshot and those two still agree. The
   * rewriter therefore reports exactly what it staged so the caller can name it.
   */
  describe('staged reconciliation reporting', () => {
    it('names the table, both columns and the domain it staged', async () => {
      const create = path.join(tmpDir, '0000_create.sql')
      fs.writeFileSync(
        create,
        'CREATE TABLE "users" ("email" text NOT NULL);\n',
      )
      const filePath = path.join(tmpDir, '0001_alter.sql')
      fs.writeFileSync(
        filePath,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { staged } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(staged).toEqual([
        {
          file: filePath,
          schema: undefined,
          table: 'users',
          column: 'email',
          encryptedColumn: 'email_encrypted',
          domain: 'eql_v3_text_search',
        },
      ])
    })

    it('keeps the schema qualifier for a pgSchema() table', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        'CREATE TABLE "app"."users" ("email" text NOT NULL);\n',
      )
      const filePath = path.join(tmpDir, '0001_alter.sql')
      fs.writeFileSync(
        filePath,
        'ALTER TABLE "app"."users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { staged } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(staged).toEqual([
        {
          file: filePath,
          schema: 'app',
          table: 'users',
          column: 'email',
          encryptedColumn: 'email_encrypted',
          domain: 'eql_v3_text_search',
        },
      ])
    })

    // Finer-grained than `rewritten`, which lists FILES: one file can carry
    // several ALTERs and each one stages its own twin.
    it('records one entry per staged column, not per file', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        'CREATE TABLE "users" ("email" text, "phone" text);\n',
      )
      const filePath = path.join(tmpDir, '0001_alter.sql')
      fs.writeFileSync(
        filePath,
        [
          'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
          'ALTER TABLE "users" ALTER COLUMN "phone" SET DATA TYPE eql_v3_text_eq;',
          '',
        ].join('\n'),
      )

      const { rewritten, staged } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([filePath])
      expect(staged.map((s) => s.encryptedColumn)).toEqual([
        'email_encrypted',
        'phone_encrypted',
      ])
      expect(staged.map((s) => s.domain)).toEqual([
        'eql_v3_text_search',
        'eql_v3_text_eq',
      ])
    })

    // A statement the sweep refused to rewrite changed nothing on disk, so
    // there is no divergence to reconcile and no notice to print.
    it('stages nothing when every statement was skipped', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0001_alter.sql'),
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped, staged } =
        await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toHaveLength(1)
      expect(staged).toEqual([])
    })

    it('describes the divergence, the silence, and the snapshot trap', async () => {
      const lines = describeStagedReconciliation([
        {
          file: '/tmp/0001_alter.sql',
          table: 'users',
          column: 'email',
          encryptedColumn: 'email_encrypted',
          domain: 'eql_v3_text_search',
        },
      ]).join('\n')

      expect(lines).toContain('"email_encrypted" eql_v3_text_search')
      expect(lines).toContain('users:')
      // The three things a user cannot discover on their own.
      expect(lines).toContain('drizzle-kit generate` will NOT warn you')
      expect(lines).toContain('column already exists')
      expect(lines).toContain('SUCCEED')
    })

    // Names the migration the twin was staged in, so the user can go read the
    // statement rather than hunt the directory for it.
    it('names the migration file each twin was staged in', async () => {
      const lines = describeStagedReconciliation([
        {
          file: '/tmp/drizzle/0001_alter.sql',
          table: 'users',
          column: 'email',
          encryptedColumn: 'email_encrypted',
          domain: 'eql_v3_text_search',
        },
      ]).join('\n')

      expect(lines).toContain('/tmp/drizzle/0001_alter.sql')
    })

    /**
     * The remediation has to be followed to a working end state, and the
     * obvious reading of it does not get there.
     *
     * After a sweep, `schema.ts` declares the SOURCE column as the encrypted
     * domain — that declaration is what made drizzle-kit emit the invalid
     * ALTER — and the snapshot agrees with it. So the guidance must say to set
     * the source column BACK to plaintext, not to "keep" it.
     *
     * And the snapshot has never seen the twin, so `drizzle-kit generate`
     * ALWAYS emits an `ADD COLUMN` for it — the swept migration already adds
     * that column, so applying both fails with "column already exists". That
     * is not avoidable by editing the schema more carefully; the generated
     * statement has to be removed. Guidance that stops at "run generate" walks
     * the user into the very error it warns about.
     */
    it('tells the user to revert the source column and drop the regenerated ADD COLUMN', async () => {
      const lines = describeStagedReconciliation([
        {
          file: '/tmp/0001_alter.sql',
          table: 'users',
          column: 'email',
          encryptedColumn: 'email_encrypted',
          domain: 'eql_v3_text_search',
        },
      ]).join('\n')

      // Revert, not "keep": the schema currently declares it as the domain.
      expect(lines).toMatch(/\bback to its plaintext type\b/i)
      expect(lines).not.toContain('keep the source column as its plaintext')
      // The step that makes the difference between working and failing.
      expect(lines).toMatch(/\b(?:DELETE|delete|remove)\b[^\n]*ADD COLUMN/)
      // And it must not blame partial editing for the duplicate.
      expect(lines).not.toContain('Do not hand-edit only the schema')
    })
  })

  /**
   * `dollarQuotedBodies` must track comment/string state itself. Asking
   * `isInsideCommentOrString` about each `$` is the obvious implementation and
   * is quadratic, because that predicate rescans from index 0 every call.
   *
   * This corpus is the shape that makes it bite — thousands of small `$$`
   * PL/pgSQL bodies, which is exactly the ~2.6 MB EQL install migration sitting
   * in a real drizzle output directory next to the ALTER being swept. So this is
   * shipped-command latency, not a microbenchmark: on that corpus the whole
   * sweep measures ~0.4 s in one pass and ~8.5 s per-opener.
   *
   * Sized so the two are unambiguous rather than marginal. Over this ~2.1 MB
   * corpus the body scan alone measures ~3 ms in one pass and ~41 s per-opener,
   * and the whole sweep runs in well under a second when linear. The 15 s bound
   * therefore sits ~30x above the linear time (so a slow shared runner is still
   * comfortable) and ~3x below the regressed time — it catches an
   * order-of-magnitude regression and does not police milliseconds.
   */
  it('scans a dollar-quote-heavy corpus in a single pass', async () => {
    const bodies = Array.from(
      { length: 32_000 },
      (_, n) =>
        `DO $$ BEGIN PERFORM ${n}; EXCEPTION WHEN others THEN null; END $$;`,
    ).join('\n')
    fs.writeFileSync(path.join(tmpDir, '0000_install.sql'), bodies)
    fs.writeFileSync(
      path.join(tmpDir, '0001_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    const alter = path.join(tmpDir, '0002_alter.sql')
    fs.writeFileSync(
      alter,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    const started = Date.now()
    const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)
    const elapsed = Date.now() - started

    // Still correct: the dollar bodies declare nothing, so the ALTER rewrites.
    expect(rewritten).toEqual([alter])
    expect(elapsed).toBeLessThan(15_000)
  }, 180_000)

  // A domain change on a column that is ALREADY encrypted needs staged
  // re-encryption; there is no plaintext source to backfill from.
  describe('columns that are already encrypted', () => {
    it('refuses to rewrite a domain change on a column created encrypted', async () => {
      const create = path.join(tmpDir, '0000_create.sql')
      fs.writeFileSync(
        create,
        [
          'CREATE TABLE "users" (',
          '\t"id" integer PRIMARY KEY,',
          '\t"email" "public"."eql_v3_text_eq"',
          ');',
          '',
        ].join('\n'),
      )
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_domain-change.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(fs.readFileSync(alter, 'utf-8')).toBe(`${alterSql}\n`)
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'already-encrypted' },
      ])
    })

    it('refuses to rewrite a domain change on a column ADDed encrypted', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_add.sql'),
        'ALTER TABLE "users" ADD COLUMN "email" eql_v3_text_eq;\n',
      )
      const alter = path.join(tmpDir, '0001_domain-change.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toHaveLength(1)
      expect(skipped[0].reason).toBe('already-encrypted')
    })

    // An EQL domain installed into a NON-`public` schema is still ciphertext.
    // The mangled forms special-case the literal `public`, so without the
    // extra alternative this column falls to the plaintext residue and the
    // ALTER drops a column full of ciphertext.
    it('refuses to rewrite a domain change on a column encrypted in a non-public schema', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "users" (',
          '\t"id" integer PRIMARY KEY,',
          '\t"email" "app"."eql_v3_text_eq"',
          ');',
          '',
        ].join('\n'),
      )
      const alter = path.join(tmpDir, '0001_domain-change.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toHaveLength(1)
      expect(skipped[0].reason).toBe('already-encrypted')
    })

    // An ARRAY of an EQL domain is still ciphertext. The trailing delimiter
    // lookahead must admit `[` or the column falls to the plaintext residue.
    it('refuses to rewrite a domain change on a column encrypted as a domain array', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_add.sql'),
        'ALTER TABLE "users" ADD COLUMN "email" public.eql_v3_text_eq[];\n',
      )
      const alter = path.join(tmpDir, '0001_domain-change.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toHaveLength(1)
      expect(skipped[0].reason).toBe('already-encrypted')
    })

    // A previous sweep of this directory leaves ADD tmp + RENAME behind. The
    // column it renamed onto is encrypted, so a later domain change on it is
    // just as destructive.
    it('follows a RENAME from a previous sweep', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_swept.sql'),
        [
          'ALTER TABLE "users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_eq";',
          '--> statement-breakpoint',
          'ALTER TABLE "users" DROP COLUMN "email";',
          '--> statement-breakpoint',
          'ALTER TABLE "users" RENAME COLUMN "email__cipherstash_tmp" TO "email";',
          '',
        ].join('\n'),
      )
      const alter = path.join(tmpDir, '0001_domain-change.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toHaveLength(1)
      expect(skipped[0].reason).toBe('already-encrypted')
    })

    it('reports the destructive statement once, not twice', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_add.sql'),
        'ALTER TABLE "users" ADD COLUMN "email" eql_v3_text_eq;\n',
      )
      fs.writeFileSync(
        path.join(tmpDir, '0001_domain-change.sql'),
        [
          '-- Custom SQL migration file, put your code below! --',
          '',
          'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
          '',
        ].join('\n'),
      )

      const { skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(skipped).toHaveLength(1)
      expect(skipped[0].reason).toBe('already-encrypted')
    })

    // The scoping matters: encrypting `contacts.email` must not be blocked by
    // an unrelated `users.email` that happens to share a column name.
    it('scopes the check to the table', async () => {
      declarePlaintext('"contacts"', 'email')
      fs.writeFileSync(
        path.join(tmpDir, '0000_add.sql'),
        'ALTER TABLE "users" ADD COLUMN "email" eql_v3_text_eq;\n',
      )
      const alter = path.join(tmpDir, '0001_contacts.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "contacts" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([alter])
      expect(skipped).toEqual([])
    })

    // The ordinary case this rewrite exists for: plaintext today, encrypted
    // after the ALTER. Nothing to preserve, so rewrite it.
    it('still rewrites a plaintext column created in an earlier migration', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        'CREATE TABLE "users" (\n\t"id" integer PRIMARY KEY,\n\t"email" text\n);\n',
      )
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([alter])
      expect(skipped).toEqual([])
    })

    // A commented-out ADD never ran, so it says nothing about the live schema.
    it('ignores an encrypted ADD COLUMN that is commented out', async () => {
      declarePlaintext('"users"', 'email')
      fs.writeFileSync(
        path.join(tmpDir, '0000_add.sql'),
        '-- ALTER TABLE "users" ADD COLUMN "email" eql_v3_text_eq;\n',
      )
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([alter])
    })

    // `options.skip` excludes a file from being EDITED, not from describing the
    // schema the other files are altering.
    it('honours an encrypted column defined in the skipped file', async () => {
      const skipPath = path.join(tmpDir, '0000_install.sql')
      fs.writeFileSync(
        skipPath,
        'ALTER TABLE "users" ADD COLUMN "email" eql_v3_text_eq;\n',
      )
      fs.writeFileSync(
        path.join(tmpDir, '0001_domain-change.sql'),
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(
        tmpDir,
        {
          skip: skipPath,
        },
      )

      expect(rewritten).toEqual([])
      expect(skipped[0]?.reason).toBe('already-encrypted')
    })

    // Ordering pin: this column is BOTH declared plaintext (0000) and made
    // encrypted by a previous sweep (0001). `already-encrypted` is the more
    // specific reason and must win over `source-unknown`.
    it('reports already-encrypted even when the column was also declared plaintext', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        'CREATE TABLE "users" ("id" integer PRIMARY KEY, "email" text);\n',
      )
      fs.writeFileSync(
        path.join(tmpDir, '0001_swept.sql'),
        [
          'ALTER TABLE "users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_eq";',
          '--> statement-breakpoint',
          'ALTER TABLE "users" DROP COLUMN "email";',
          '--> statement-breakpoint',
          'ALTER TABLE "users" RENAME COLUMN "email__cipherstash_tmp" TO "email";',
          '',
        ].join('\n'),
      )
      const alter = path.join(tmpDir, '0002_domain-change.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toHaveLength(1)
      expect(skipped[0].reason).toBe('already-encrypted')
    })

    // A commented-out encrypted column line inside an otherwise LIVE
    // CREATE TABLE must still count as encrypted. The comment check applies
    // only to the DECLARED scan (over-detecting plaintext costs data); the
    // ENCRYPTED scan never re-checks comments inside a live CREATE TABLE, so
    // this stays over-detecting — the safe direction — exactly as it was
    // before the corpus learned to track declarations at all.
    it('still counts a commented-out encrypted column inside a live CREATE TABLE as encrypted', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "users" (',
          '\t"id" integer,',
          '\t-- "email" "public"."eql_v3_text_eq",',
          '\t"email" text',
          ');',
          '',
        ].join('\n'),
      )
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toHaveLength(1)
      expect(skipped[0].reason).toBe('already-encrypted')
    })

    it('fails closed when the staged encrypted twin already exists', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        'CREATE TABLE "users" ("email" text, "email_encrypted" eql_v3_text_eq);\n',
      )
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(fs.readFileSync(alter, 'utf-8')).toBe(`${alterSql}\n`)
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'target-exists' },
      ])
    })

    // #772 review, finding 3. The index reads CREATE TABLE, ADD COLUMN and
    // RENAME, but never the strict matcher's OWN target. So a corpus where an
    // earlier migration already converted the column — realistic wherever a
    // previous stack version's ALTER ran before this sweep existed — leaves
    // that column looking plaintext, and the SECOND conversion rewrites a
    // column that now holds ciphertext. `declared` cannot catch it: the column
    // IS declared, as plaintext, by the original CREATE TABLE.
    it('rewrites only the first conversion when two ALTERs chain on one column', async () => {
      declarePlaintext('"users"', 'email')
      const first = path.join(tmpDir, '0002_v2.sql')
      fs.writeFileSync(
        first,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v2_encrypted;\n',
      )
      const secondSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const second = path.join(tmpDir, '0003_v3.sql')
      fs.writeFileSync(second, `${secondSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      // The first conversion is the legitimate plaintext -> encrypted one and
      // must still happen — flagging it too would be the naive fix.
      expect(rewritten).toEqual([first])
      expect(fs.readFileSync(first, 'utf-8')).toContain(
        'ADD COLUMN "email_encrypted"',
      )
      // The second would add the same target again. Left byte-identical.
      expect(fs.readFileSync(second, 'utf-8')).toBe(`${secondSql}\n`)
      expect(skipped).toEqual([
        { file: second, statement: secondSql, reason: 'target-exists' },
      ])
    })

    it('flags the second of two chained ALTERs inside a single file', async () => {
      declarePlaintext('"users"', 'email')
      const secondSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const filePath = path.join(tmpDir, '0002_chain.sql')
      fs.writeFileSync(
        filePath,
        [
          'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v2_encrypted;',
          secondSql,
          '',
        ].join('\n'),
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([filePath])
      const updated = fs.readFileSync(filePath, 'utf-8')
      // Exactly one target was staged, and the v3 statement survives verbatim.
      expect(updated.match(/ADD COLUMN/g)?.length).toBe(1)
      expect(updated).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)
      expect(updated).toContain(secondSql)
      expect(skipped).toEqual([
        { file: filePath, statement: secondSql, reason: 'target-exists' },
      ])
    })

    // A chain on DIFFERENT columns is not a chain — each is its own first
    // conversion and both must be rewritten.
    it('rewrites both when chained ALTERs target different columns', async () => {
      declarePlaintext('"users"', 'email', 'name')
      const first = path.join(tmpDir, '0002_email.sql')
      fs.writeFileSync(
        first,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )
      const second = path.join(tmpDir, '0003_name.sql')
      fs.writeFileSync(
        second,
        'ALTER TABLE "users" ALTER COLUMN "name" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([first, second])
      expect(skipped).toEqual([])
    })

    // A commented-out first conversion never ran, so the column is still
    // plaintext and the live second conversion is the legitimate one.
    it('does not treat a commented-out earlier ALTER as having encrypted the column', async () => {
      declarePlaintext('"users"', 'email')
      fs.writeFileSync(
        path.join(tmpDir, '0002_v2.sql'),
        '-- ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v2_encrypted;\n',
      )
      const live = path.join(tmpDir, '0003_v3.sql')
      fs.writeFileSync(
        live,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([live])
      const updated = fs.readFileSync(live, 'utf-8')
      expect(updated).toContain('ADD COLUMN "email_encrypted"')
      expect(updated).not.toContain('DROP COLUMN')
    })

    // #772 review, finding 4. `columnKey` keys on the schema exactly as written,
    // but Postgres resolves an unqualified name through `search_path` — so
    // `"users"` and `"public"."users"` are the SAME table. drizzle-kit emits
    // unqualified; hand-written SQL and this sweep's own output are qualified.
    // A corpus mixing the two split the index across two keys.
    it('treats "public"."users" and "users" as the same table when checking encryption', async () => {
      // 0000 declares the column unqualified — drizzle-kit's default output.
      fs.writeFileSync(
        path.join(tmpDir, '0000_declare.sql'),
        'CREATE TABLE "users" ("email" text);\n',
      )
      // 0001 is a previous sweep's output, schema-qualified. The RENAME leaves
      // `email` holding ciphertext, recorded under the QUALIFIED key.
      fs.writeFileSync(
        path.join(tmpDir, '0001_encrypt.sql'),
        [
          'ALTER TABLE "public"."users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_eq";',
          'ALTER TABLE "public"."users" DROP COLUMN "email";',
          'ALTER TABLE "public"."users" RENAME COLUMN "email__cipherstash_tmp" TO "email";',
          '',
        ].join('\n'),
      )
      // 0002 changes the domain, written unqualified.
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0002_domain-change.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(fs.readFileSync(alter, 'utf-8')).toBe(`${alterSql}\n`)
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'already-encrypted' },
      ])
    })

    // The mirror direction: declared/encrypted unqualified, altered qualified.
    // Before the fix this reported `source-unknown` — a WRONG reason, telling
    // the user the corpus never declares a column it declares two files up.
    it('resolves an unqualified declaration against a schema-qualified ALTER', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        'CREATE TABLE "users" ("email" "public"."eql_v3_text_eq");\n',
      )
      const alterSql =
        'ALTER TABLE "public"."users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_domain-change.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'already-encrypted' },
      ])
    })

    // #772 review, finding 2. CREATE_TABLE_RE's body is lazy up to the first
    // `)\s*;`, which can sit inside a `--` comment or a string DEFAULT. The
    // body is then truncated and every column declared after that point is
    // lost from BOTH indexes — so an encrypted column reads as undeclared.
    it('indexes columns declared after a ");" inside a comment in the CREATE TABLE body', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "users" (',
          '\t"id" text, -- pk (uuid);',
          '\t"email" "public"."eql_v3_text_eq"',
          ');',
          '',
        ].join('\n'),
      )
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_domain-change.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'already-encrypted' },
      ])
    })

    it('indexes columns declared after a ");" inside a string DEFAULT', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "users" (',
          '\t"note" text DEFAULT \'see (ticket);\',',
          '\t"email" "public"."eql_v3_text_eq"',
          ');',
          '',
        ].join('\n'),
      )
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_domain-change.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'already-encrypted' },
      ])
    })

    // The destructive composition: the truncated body loses the encrypted
    // column, but a LATER migration re-declares the table so `declared` is
    // satisfied from elsewhere — the fail-closed rule passes and the ALTER
    // drops a column full of ciphertext.
    it('does not drop ciphertext when a truncated CREATE TABLE body hides the encrypted column', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_declare.sql'),
        'CREATE TABLE "users" ("email" text);\n',
      )
      fs.writeFileSync(
        path.join(tmpDir, '0001_recreate.sql'),
        [
          'DROP TABLE "users";',
          '--> statement-breakpoint',
          'CREATE TABLE "users" (',
          '\t"id" text, -- pk (uuid);',
          '\t"email" "public"."eql_v3_text_eq"',
          ');',
          '',
        ].join('\n'),
      )
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0002_domain-change.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(fs.readFileSync(alter, 'utf-8')).toBe(`${alterSql}\n`)
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'already-encrypted' },
      ])
    })

    // Only the IMPLICIT schema collapses. A real non-public schema is a
    // genuinely different table and must not be conflated with the bare name.
    it('does not conflate a non-public schema with the unqualified table', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_app.sql'),
        'CREATE TABLE "app"."users" ("email" "public"."eql_v3_text_eq");\n',
      )
      fs.writeFileSync(
        path.join(tmpDir, '0001_public.sql'),
        'CREATE TABLE "users" ("email" text);\n',
      )
      const alter = path.join(tmpDir, '0002_encrypt.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      // public.users.email is plaintext — app.users.email being encrypted is
      // about a different table entirely.
      expect(rewritten).toEqual([alter])
      expect(skipped).toEqual([])
    })
  })

  it('handles multiple ALTER statements in one file', async () => {
    declarePlaintext('"a"', 'x', 'y')
    const original = [
      'ALTER TABLE "a" ALTER COLUMN "x" SET DATA TYPE eql_v3_text_search;',
      'ALTER TABLE "a" ALTER COLUMN "y" SET DATA TYPE eql_v3_text_search;',
      'CREATE INDEX "a_z" ON "a" ("z");',
    ].join('\n')
    const filePath = path.join(tmpDir, '0004_multi.sql')
    fs.writeFileSync(filePath, original)

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated.match(/ADD COLUMN/g)?.length).toBe(2)
    expect(updated).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)
    // Non-matching statement preserved
    expect(updated).toContain('CREATE INDEX "a_z" ON "a" ("z");')
  })

  it('reports files rewritten before a later write failure', async () => {
    declarePlaintext('"users"', 'email', 'name')
    const first = path.join(tmpDir, '0001_email.sql')
    const failing = path.join(tmpDir, '0002_name.sql')
    fs.writeFileSync(
      first,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )
    fs.writeFileSync(
      failing,
      'ALTER TABLE "users" ALTER COLUMN "name" SET DATA TYPE eql_v3_text_search;\n',
    )
    fsPromisesWrite.spy.mockImplementation(async (file, data, options) => {
      if (file === failing) {
        fs.unlinkSync(failing)
        fs.mkdirSync(failing)
      }
      return fsPromisesWrite.real(file, data, options)
    })

    try {
      await rewriteEncryptedAlterColumns(tmpDir)
      throw new Error('expected rewriteEncryptedAlterColumns to throw')
    } catch (error) {
      const partial = error as {
        rewritten?: string[]
        skipped?: unknown[]
        staged?: { column: string }[]
      }
      expect(partial.rewritten).toEqual([first])
      expect(partial.skipped).toEqual([])
      expect(fs.readFileSync(first, 'utf-8')).toContain(
        'ADD COLUMN "email_encrypted"',
      )
      // `staged` drives a notice telling the user the database now HAS these
      // columns, so it must only list twins that reached disk. `name`'s twin was
      // staged in memory during the string replace and then lost when the write
      // threw — reporting it would send the user reconciling a column that
      // exists nowhere.
      expect(partial.staged?.map((s) => s.column)).toEqual(['email'])
    } finally {
      if (fs.statSync(failing).isDirectory()) fs.rmdirSync(failing)
    }
  })

  // Regression pin, not a bug fix — the matchers carry `/gi`, so a
  // hand-lowercased migration is rewritten just like drizzle-kit's output.
  it('rewrites a lowercase alter table ... set data type', async () => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0034_lowercase.sql')
    fs.writeFileSync(
      filePath,
      'alter table "users" alter column "email" set data type eql_v3_text_search;\n',
    )

    const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([filePath])
    expect(skipped).toEqual([])
    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain(
      'ALTER TABLE "users" ADD COLUMN "email_encrypted" "public"."eql_v3_text_search";',
    )
    expect(updated).not.toContain('ALTER TABLE "users" DROP COLUMN "email";')
    expect(updated).not.toMatch(/set data type/i)
  })

  // A-2: the sweep is FAIL-CLOSED. A column the corpus never declares is
  // UNKNOWN, not plaintext — it may already hold ciphertext, with its
  // declaration sitting in a migration directory this sweep never sees.
  describe('columns the corpus does not declare', () => {
    it('refuses to rewrite a column the corpus never declares', async () => {
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      const updated = fs.readFileSync(alter, 'utf-8')
      expect(updated).toBe(`${alterSql}\n`)
      expect(updated).not.toContain('DROP COLUMN')
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'source-unknown' },
      ])
    })

    it('rewrites a column declared plaintext by an ADD COLUMN', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_add.sql'),
        'ALTER TABLE "users" ADD COLUMN "email" text;\n',
      )
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([alter])
      expect(skipped).toEqual([])
    })

    // The skipped file is still part of the corpus: a column's current type
    // comes from the migrations that ran before this one, edit-eligible or not.
    it('counts a declaration living in the file passed to options.skip', async () => {
      const install = path.join(tmpDir, '0000_install-eql.sql')
      fs.writeFileSync(
        install,
        'CREATE TABLE "users" ("id" integer PRIMARY KEY, "email" text);\n',
      )
      const alter = path.join(tmpDir, '0002_encrypt.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(
        tmpDir,
        {
          skip: install,
        },
      )

      expect(rewritten).toEqual([alter])
      expect(skipped).toEqual([])
    })

    it('follows a RENAME when deciding a column is declared', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "users" ("id" integer PRIMARY KEY, "email_address" text);',
          '--> statement-breakpoint',
          'ALTER TABLE "users" RENAME COLUMN "email_address" TO "email";',
          '',
        ].join('\n'),
      )
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([alter])
      expect(skipped).toEqual([])
    })

    // A name inside a table/key constraint is a MENTION, not a declaration.
    // Here every mention is followed by `)` or `,`, which the declaration
    // regex's tail alone already rejects. A mention followed by a SQL keyword
    // instead (e.g. `CHECK ("email" IS NOT NULL)`) is a separate case, closed
    // by the regex's keyword lookahead and pinned by its own tests below.
    // Counting either would put the rewrite back on the fail-open path.
    it('does not treat a name inside PRIMARY KEY / REFERENCES as a declaration', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "sessions" (',
          '\t"id" integer,',
          '\t"user_id" integer,',
          '\tPRIMARY KEY ("id", "email"),',
          '\tFOREIGN KEY ("user_id") REFERENCES "users"("email")',
          ');',
          '',
        ].join('\n'),
      )
      const alterSql =
        'ALTER TABLE "sessions" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'source-unknown' },
      ])
    })

    // A column line commented out INSIDE a live CREATE TABLE never ran, so it
    // declares nothing.
    it('does not count a column commented out inside a live CREATE TABLE', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "users" (',
          '\t"id" integer PRIMARY KEY,',
          '\t-- "email" text,',
          '\t"name" text',
          ');',
          '',
        ].join('\n'),
      )
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(
        alter,
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toHaveLength(1)
      expect(skipped[0].reason).toBe('source-unknown')
    })

    // A CHECK predicate mentioning a column has the same `"name" <letter>`
    // shape as a declaration — `"email" IS` — but IS is a predicate keyword,
    // not a type token. Without the keyword lookahead this would read as a
    // declaration and rewrite the column, dropping any ciphertext it already
    // holds via a declaration this sweep never sees.
    it('does not treat a CHECK predicate mention as a declaration', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "users" (',
          '\t"id" integer PRIMARY KEY,',
          '\tCONSTRAINT "c1" CHECK ("email" IS NOT NULL)',
          ');',
          '',
        ].join('\n'),
      )
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      const updated = fs.readFileSync(alter, 'utf-8')
      expect(updated).toBe(`${alterSql}\n`)
      expect(updated).not.toContain('DROP COLUMN')
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'source-unknown' },
      ])
    })

    // A constraint's NAME can coincide with a column's name — drizzle's
    // `<table>_<col>_unique` convention makes this contrived, but the keyword
    // lookahead closes it regardless: a constraint name is always followed
    // immediately by its constraint-type keyword (UNIQUE here), which the
    // lookahead excludes.
    it('does not let a same-named constraint declare the column', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        [
          'CREATE TABLE "users" (',
          '\t"id" integer PRIMARY KEY,',
          '\tCONSTRAINT "email" UNIQUE("id")',
          ');',
          '',
        ].join('\n'),
      )
      const alterSql =
        'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(alter, `${alterSql}\n`)

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
      expect(skipped).toEqual([
        { file: alter, statement: alterSql, reason: 'source-unknown' },
      ])
    })

    // The keyword lookahead is pinned to a word boundary specifically so it
    // does not eat real type names that merely START WITH a blocked
    // keyword's letters: `interval`/`inet` both start "in" (colliding with
    // IN) but must still count as genuine declarations.
    it('still declares a column whose type name starts with a blocked keyword', async () => {
      fs.writeFileSync(
        path.join(tmpDir, '0000_create.sql'),
        'CREATE TABLE "events" ("email" interval, "note" inet);\n',
      )
      const alter = path.join(tmpDir, '0001_encrypt.sql')
      fs.writeFileSync(
        alter,
        [
          'ALTER TABLE "events" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
          'ALTER TABLE "events" ALTER COLUMN "note" SET DATA TYPE eql_v3_text_search;',
          '',
        ].join('\n'),
      )

      const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([alter])
      expect(skipped).toEqual([])
    })
  })
})

describe('sweepMigrationDirs', () => {
  let tmpDir: string

  const ALTER = [
    // Fail-closed: the sweep rewrites only a column the corpus DECLARES, and a
    // real drizzle corpus carries the CREATE that declared it.
    'CREATE TABLE "users" ("id" integer PRIMARY KEY, "email" text);',
    '--> statement-breakpoint',
    'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;',
    '',
  ].join('\n')

  /**
   * Create a drizzle-kit OUTPUT directory under the sandbox, optionally seeding
   * `name` with `sql`.
   *
   * The `meta/_journal.json` is what makes it drizzle-kit's: the sweep now
   * requires it, because `migrations/` and `src/db/migrations/` are generic
   * names that Knex, Flyway, node-pg-migrate and raw psql also use. Use
   * {@link seedForeignDir} for the other case.
   */
  const seedDir = (dir: string, name?: string, sql?: string): string => {
    const abs = seedForeignDir(dir, name, sql)
    fs.mkdirSync(path.join(abs, 'meta'), { recursive: true })
    fs.writeFileSync(
      path.join(abs, 'meta', '_journal.json'),
      JSON.stringify({ version: '7', dialect: 'postgresql', entries: [] }),
    )
    return abs
  }

  /** A migration directory belonging to some OTHER tool — no drizzle journal. */
  const seedForeignDir = (dir: string, name?: string, sql?: string): string => {
    const abs = path.join(tmpDir, dir)
    fs.mkdirSync(abs, { recursive: true })
    if (name) fs.writeFileSync(path.join(abs, name), sql ?? ALTER)
    return abs
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wizard-sweep-'))
    // This describe shares the module-level writeFile spy with the one above,
    // so restore the real implementation rather than inherit whatever the last
    // test left behind.
    fsPromisesWrite.spy.mockImplementation(fsPromisesWrite.real)
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it('skips candidate directories that do not exist', async () => {
    const abs = seedDir('migrations', '0001_alter.sql')

    const results = await sweepMigrationDirs(tmpDir, ['drizzle', 'migrations'])

    expect(results.map((r) => r.dir)).toEqual(['migrations'])
    expect(results[0].rewritten).toEqual([path.join(abs, '0001_alter.sql')])
  })

  // The regression this test locks in: the old loop `return`ed after the FIRST
  // existing candidate, so a project with an empty `drizzle/` alongside a real
  // `migrations/` had its actual migrations silently left unrepaired.
  it('keeps sweeping when an earlier candidate directory yields no matches', async () => {
    seedDir('drizzle')
    const abs = seedDir('migrations', '0002_alter.sql')

    const results = await sweepMigrationDirs(tmpDir, ['drizzle', 'migrations'])

    expect(results.map((r) => r.dir)).toEqual(['drizzle', 'migrations'])
    expect(results[0].rewritten).toEqual([])
    expect(results[1].rewritten).toEqual([path.join(abs, '0002_alter.sql')])
    expect(
      fs.readFileSync(path.join(abs, '0002_alter.sql'), 'utf-8'),
    ).not.toContain('SET DATA TYPE')
  })

  it('rewrites every candidate directory that holds encrypted alters', async () => {
    const drizzle = seedDir('drizzle', '0001_alter.sql')
    const nested = seedDir('src/db/migrations', '0002_alter.sql')

    const results = await sweepMigrationDirs(tmpDir, [
      'drizzle',
      'src/db/migrations',
    ])

    expect(results.flatMap((r) => r.rewritten)).toEqual([
      path.join(drizzle, '0001_alter.sql'),
      path.join(nested, '0002_alter.sql'),
    ])
  })

  it('is idempotent — a second sweep rewrites nothing', async () => {
    const abs = seedDir('drizzle', '0001_alter.sql')

    await sweepMigrationDirs(tmpDir, ['drizzle'])
    const afterFirst = fs.readFileSync(
      path.join(abs, '0001_alter.sql'),
      'utf-8',
    )
    const results = await sweepMigrationDirs(tmpDir, ['drizzle'])

    expect(results[0].rewritten).toEqual([])
    expect(fs.readFileSync(path.join(abs, '0001_alter.sql'), 'utf-8')).toBe(
      afterFirst,
    )
  })

  it('surfaces a failing directory as an error and still sweeps the rest', async () => {
    // A directory named `*.sql` makes readFile throw EISDIR mid-sweep.
    const broken = seedDir('drizzle')
    fs.mkdirSync(path.join(broken, '0001_alter.sql'))
    const abs = seedDir('migrations', '0002_alter.sql')

    const results = await sweepMigrationDirs(tmpDir, ['drizzle', 'migrations'])

    expect(results[0].dir).toBe('drizzle')
    expect(results[0].error).toBeDefined()
    expect(results[1].rewritten).toEqual([path.join(abs, '0002_alter.sql')])
  })

  /**
   * #836, item 3. The catch block used to read `err.rewritten` off an unchecked
   * `err as Partial<RewriteSweepError>`. For a non-object throw that property
   * read raises a `TypeError` INSIDE the catch, so `results.push` never runs and
   * the throw escapes `sweepMigrationDirs` — the per-directory fail-closed
   * report the catch exists to produce simply does not happen, and the later
   * directories are never swept either.
   *
   * `fs/promises` does not throw non-Errors, so this is reached by forcing it.
   * The CLI path was hardened against exactly this; the wizard was not.
   */
  it('still reports a directory whose sweep throws a non-object', async () => {
    const broken = seedDir('drizzle', '0001_alter.sql')
    const abs = seedDir('migrations', '0002_alter.sql')
    fsPromisesWrite.spy.mockImplementation(async (file) => {
      if (String(file).startsWith(broken)) throw null
      return fsPromisesWrite.real(file, '')
    })

    const results = await sweepMigrationDirs(tmpDir, ['drizzle', 'migrations'])

    // Reported, not escaped: the directory appears with an error…
    expect(results[0].dir).toBe('drizzle')
    expect(results[0].error).toBe('null')
    expect(results[0].rewritten).toEqual([])
    expect(results[0].skipped).toEqual([])
    expect(results[0].staged).toEqual([])
    // …and the sweep carried on to the remaining candidates.
    expect(results[1].dir).toBe('migrations')
    expect(results[1].rewritten).toEqual([path.join(abs, '0002_alter.sql')])
  })

  /**
   * A directory whose sweep threw part way through has real twins on disk, and
   * `sweepMigrationDirs` has to carry them out so the caller can print the
   * reconciliation notice for them. `partial.staged` was threaded but never
   * asserted.
   */
  it('carries staged twins out of a directory whose sweep threw', async () => {
    const abs = seedDir('drizzle')
    fs.writeFileSync(
      path.join(abs, '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text, "name" text);\n',
    )
    const first = path.join(abs, '0001_email.sql')
    const failing = path.join(abs, '0002_name.sql')
    fs.writeFileSync(
      first,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )
    fs.writeFileSync(
      failing,
      'ALTER TABLE "users" ALTER COLUMN "name" SET DATA TYPE eql_v3_text_search;\n',
    )
    fsPromisesWrite.spy.mockImplementation(async (file, data, options) => {
      if (String(file) === failing) throw new Error('EISDIR')
      return fsPromisesWrite.real(file, data, options)
    })

    const results = await sweepMigrationDirs(tmpDir, ['drizzle'])

    expect(results[0].error).toBeDefined()
    // Only the twin that reached disk — `name`'s write threw.
    expect(results[0].staged.map((s) => s.column)).toEqual(['email'])
    expect(results[0].staged[0].encryptedColumn).toBe('email_encrypted')
  })

  it('reports near-misses per directory', async () => {
    const abs = seedDir(
      'drizzle',
      '0001_using.sql',
      'ALTER TABLE "t" ALTER COLUMN "c" SET DATA TYPE eql_v3_json USING (c)::jsonb;\n',
    )

    const results = await sweepMigrationDirs(tmpDir, ['drizzle'])

    expect(results[0].skipped).toHaveLength(1)
    expect(results[0].skipped[0].file).toBe(path.join(abs, '0001_using.sql'))
  })

  // A-2 trigger (b). The wizard ships scanning three candidate directories and
  // indexes each separately, so a declaration in `drizzle/` is invisible to the
  // sweep of `migrations/`. That column is already ciphertext; rewriting it
  // must remain source-unknown rather than choosing a lifecycle by assumption.
  it('does not rewrite an ALTER whose column is declared in a sibling directory', async () => {
    seedDir(
      'drizzle',
      '0000_create.sql',
      'CREATE TABLE "users" ("id" integer PRIMARY KEY, "email" "public"."eql_v3_text_eq");\n',
    )
    const alterSql =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;'
    const migrations = seedDir(
      'migrations',
      '0001_domain-change.sql',
      `${alterSql}\n`,
    )
    const alter = path.join(migrations, '0001_domain-change.sql')

    const results = await sweepMigrationDirs(tmpDir, ['drizzle', 'migrations'])

    const swept = results.find((result) => result.dir === 'migrations')
    expect(swept?.rewritten).toEqual([])
    expect(swept?.skipped).toEqual([
      { file: alter, statement: alterSql, reason: 'source-unknown' },
    ])
    const updated = fs.readFileSync(alter, 'utf-8')
    expect(updated).toBe(`${alterSql}\n`)
    expect(updated).not.toContain('DROP COLUMN')
  })

  // #772 review, finding 5. `migrations/` and `src/db/migrations/` are generic
  // names — Knex, node-pg-migrate, Flyway and hand-rolled psql all use them.
  // Sweeping every candidate that merely EXISTS meant a project whose drizzle
  // `out` is `drizzle/` but which also keeps a hand-maintained `migrations/`
  // had that second directory rewritten in a directory this tool was never
  // pointed at. The fail-closed `declared` rule does not
  // help: a real migration history declares its own columns.
  //
  // drizzle-kit always writes `meta/_journal.json` into its output directory;
  // none of the other tools do. That is the discriminator.
  it('does not sweep a directory that is not a drizzle-kit output', async () => {
    const foreign = seedForeignDir('migrations', '0001_alter.sql')
    const alter = path.join(foreign, '0001_alter.sql')

    const results = await sweepMigrationDirs(tmpDir, ['migrations'])

    expect(results.find((r) => r.dir === 'migrations')?.rewritten).toEqual([])
    const updated = fs.readFileSync(alter, 'utf-8')
    expect(updated).toBe(ALTER)
    expect(updated).not.toContain('DROP COLUMN')
  })

  // Silence would be its own failure: a genuine drizzle directory whose meta/
  // was deleted must not simply do nothing without saying so.
  it('reports a skipped directory that holds SQL but no drizzle journal', async () => {
    seedForeignDir('migrations', '0001_alter.sql')

    const results = await sweepMigrationDirs(tmpDir, ['migrations'])

    expect(results.find((r) => r.dir === 'migrations')?.notDrizzleOutput).toBe(
      true,
    )
  })

  // An empty foreign directory is not worth mentioning — there is nothing in it
  // the sweep could have repaired.
  it('does not report a journal-less directory that holds no SQL', async () => {
    seedForeignDir('migrations')

    const results = await sweepMigrationDirs(tmpDir, ['migrations'])

    expect(results.find((r) => r.dir === 'migrations')?.notDrizzleOutput).toBe(
      undefined,
    )
  })

  // The blast-radius fix must not shrink the legitimate reach: a real drizzle
  // output directory that is NOT the first candidate is still swept.
  it('still sweeps a drizzle output directory that is not the first candidate', async () => {
    seedDir(
      'drizzle',
      '0000_noop.sql',
      'CREATE TABLE "widgets" ("id" integer);\n',
    )
    const migrations = seedDir('migrations', '0001_alter.sql')

    const results = await sweepMigrationDirs(tmpDir, ['drizzle', 'migrations'])

    expect(results.find((r) => r.dir === 'migrations')?.rewritten).toEqual([
      path.join(migrations, '0001_alter.sql'),
    ])
  })
})

// The three reasons drive very different user action — re-encrypt through the
// staged lifecycle, fix a hand-authored cast, or go check the database. A
// switch with no `default` arm means a missing case fails the build, but a
// mis-MAPPED case (wiring `source-unknown` to the `already-encrypted` string)
// compiles fine and ships wrong remediation into a data-loss decision. Pin the
// mapping so that swap is caught.
describe('describeSkipReason', () => {
  it('describes already-encrypted as a re-encrypt-through-the-lifecycle action', () => {
    const text = describeSkipReason('already-encrypted')
    expect(text).toContain('ALREADY encrypted')
    expect(text).toContain('re-encrypted')
    expect(text).toContain('`stash encrypt` lifecycle')
  })

  it('describes an existing target as a duplicate-column failure', () => {
    const text = describeSkipReason('target-exists')
    expect(text).toContain('already exists')
    expect(text).toContain('another ADD COLUMN would fail')
  })

  it('describes unrecognised-form as a hand-authored / unknown cast', () => {
    const text = describeSkipReason('unrecognised-form')
    expect(text).toContain('SET DATA TYPE ... USING')
    expect(text).toContain('fails at migrate time')
  })

  it('describes source-unknown as a go-check-the-database action', () => {
    const text = describeSkipReason('source-unknown')
    expect(text).toContain('could not find where this column was declared')
    expect(text).toContain("Check the column's current type in the database")
    expect(text).toContain('staged `stash encrypt` lifecycle')
    expect(text).not.toContain('table is empty')
  })

  it('gives each reason a distinct description', () => {
    const reasons = [
      'already-encrypted',
      'target-exists',
      'unrecognised-form',
      'source-unknown',
    ] as const
    const described = reasons.map(describeSkipReason)
    expect(new Set(described).size).toBe(reasons.length)
  })
})

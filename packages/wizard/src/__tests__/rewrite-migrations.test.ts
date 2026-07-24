import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  rewriteEncryptedAlterColumns,
  sweepMigrationDirs,
} from '../lib/rewrite-migrations.js'

describe('rewriteEncryptedAlterColumns', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wizard-rewrite-'))
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
      'ALTER TABLE "transactions" ADD COLUMN "amount__cipherstash_tmp" "public"."eql_v2_encrypted";',
    )
    expect(updated).toContain(
      'ALTER TABLE "transactions" DROP COLUMN "amount";',
    )
    expect(updated).toContain(
      'ALTER TABLE "transactions" RENAME COLUMN "amount__cipherstash_tmp" TO "amount";',
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
      'ALTER TABLE "users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_search";',
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
      'ALTER TABLE "users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_search";',
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
      'ALTER TABLE "app"."users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_search";',
    )
    expect(updated).toContain('ALTER TABLE "app"."users" DROP COLUMN "email";')
    expect(updated).toContain(
      'ALTER TABLE "app"."users" RENAME COLUMN "email__cipherstash_tmp" TO "email";',
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
      'ALTER TABLE "transactions" ADD COLUMN "amount__cipherstash_tmp" "public"."eql_v2_encrypted";',
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
      'ALTER TABLE "transactions" ADD COLUMN "description__cipherstash_tmp" "public"."eql_v2_encrypted";',
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
      `ALTER TABLE "users" ADD COLUMN "email__cipherstash_tmp" "public"."${domain}";`,
    )
    expect(updated).toContain('ALTER TABLE "users" DROP COLUMN "email";')
    expect(updated).toContain(
      'ALTER TABLE "users" RENAME COLUMN "email__cipherstash_tmp" TO "email";',
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
      `ALTER TABLE "t" ADD COLUMN "c__cipherstash_tmp" "public"."${domain}";`,
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
      'ALTER TABLE "users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_search";',
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

  it('warns that the rewrite is data-destroying / empty-table-only', async () => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0016_warn.sql')
    fs.writeFileSync(
      filePath,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8')
    expect(updated).toContain('safe ONLY if')
    expect(updated).toContain('constraints, defaults, and indexes')
    expect(updated).toContain('stash encrypt')
  })

  it('separates ADD/DROP/RENAME with --> statement-breakpoint', async () => {
    declarePlaintext('"users"', 'email')
    const filePath = path.join(tmpDir, '0018_breakpoint.sql')
    fs.writeFileSync(
      filePath,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    await rewriteEncryptedAlterColumns(tmpDir)

    const updated = fs.readFileSync(filePath, 'utf-8').trimEnd()
    const chunks = updated.split('--> statement-breakpoint')
    expect(chunks).toHaveLength(3)
    expect(chunks[0]).toContain('ADD COLUMN')
    expect(chunks[1]).toContain('DROP COLUMN')
    expect(chunks[2]).toContain('RENAME COLUMN')
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
      'ALTER TABLE "a" ADD COLUMN "x__cipherstash_tmp" "public"."eql_v2_encrypted";',
    )
    expect(updated).toContain(
      'ALTER TABLE "a" ADD COLUMN "y__cipherstash_tmp" "public"."eql_v3_json";',
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

      const { rewritten } = await rewriteEncryptedAlterColumns(tmpDir)

      expect(rewritten).toEqual([])
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
      expect(fs.readFileSync(filePath, 'utf-8')).toContain(
        'ALTER TABLE "users" DROP COLUMN "email";',
      )
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
  })

  // ADD+DROP+RENAME on a column that is ALREADY encrypted drops CIPHERTEXT, and
  // unlike the plaintext case there is nothing left anywhere to backfill from.
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
    expect(updated.match(/DROP COLUMN/g)?.length).toBe(2)
    // Non-matching statement preserved
    expect(updated).toContain('CREATE INDEX "a_z" ON "a" ("z");')
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
      'ALTER TABLE "users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_search";',
    )
    expect(updated).toContain('ALTER TABLE "users" DROP COLUMN "email";')
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

  /** Create `dir` under the sandbox, optionally seeding `name` with `sql`. */
  const seedDir = (dir: string, name?: string, sql?: string): string => {
    const abs = path.join(tmpDir, dir)
    fs.mkdirSync(abs, { recursive: true })
    if (name) fs.writeFileSync(path.join(abs, name), sql ?? ALTER)
    return abs
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wizard-sweep-'))
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
  // emits a live DROP COLUMN with nothing anywhere to backfill from.
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
})

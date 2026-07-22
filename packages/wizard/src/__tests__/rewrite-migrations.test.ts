import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { rewriteEncryptedAlterColumns } from '../lib/rewrite-migrations.js'

describe('rewriteEncryptedAlterColumns', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wizard-rewrite-'))
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it('rewrites an in-place ALTER COLUMN with the bare v2 type name', async () => {
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
    const filePath = path.join(tmpDir, '0021_handled.sql')
    fs.writeFileSync(
      filePath,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    const { rewritten, skipped } = await rewriteEncryptedAlterColumns(tmpDir)

    expect(rewritten).toEqual([filePath])
    expect(skipped).toEqual([])
  })

  it('handles multiple ALTER statements in one file', async () => {
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
})

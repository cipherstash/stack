/**
 * `cipherstashFromStackV3` — the v3-only entry point's validation
 * paths, all of which throw BEFORE any `EncryptionV3` client is
 * constructed (so no live CipherStash credentials are needed here; the
 * happy path is exercised by the live suite).
 *
 * Decision 1b pins: a v3 client is v3-only — a contract carrying a v2
 * cipherstash codec id is a hard error, never a silently-ignored
 * column; and the v2 `cipherstashFromStack` is a separate, untouched
 * entry point.
 */

import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { describe, expect, it } from 'vitest'
import { cipherstashFromStackV3 } from '../../src/stack/from-stack-v3'

function contract(
  columns: Record<string, { codecId: string; nativeType?: string }>,
) {
  return {
    storage: {
      namespaces: {
        public: { entries: { table: { user: { columns } } } },
      },
    },
  }
}

describe('cipherstashFromStackV3 — v3-only hard errors', () => {
  it('rejects a contract carrying v2 cipherstash codec ids', async () => {
    await expect(
      cipherstashFromStackV3({
        contractJson: contract({
          email: {
            codecId: 'cipherstash/string@1',
            nativeType: 'eql_v2_encrypted',
          },
          score: {
            codecId: 'cipherstash/eql-v3/eql_v3_integer_ord@1',
            nativeType: 'public.eql_v3_integer_ord',
          },
        }),
      }),
    ).rejects.toThrow(/non-v3 cipherstash codec ids \[cipherstash\/string@1\]/)
  })

  it('rejects a contract with no v3 cipherstash columns', async () => {
    await expect(
      cipherstashFromStackV3({
        contractJson: contract({
          id: { codecId: 'pg/text@1', nativeType: 'text' },
        }),
      }),
    ).rejects.toThrow(/no v3 cipherstash columns/)
  })

  it('rejects an override diverging from the contract on exact domain identity', async () => {
    await expect(
      cipherstashFromStackV3({
        contractJson: contract({
          score: {
            codecId: 'cipherstash/eql-v3/eql_v3_integer_ord@1',
            nativeType: 'public.eql_v3_integer_ord',
          },
        }),
        schemasV3: [
          encryptedTable('user', { score: types.IntegerOrdOre('score') }),
        ],
      }),
    ).rejects.toThrow(/schema divergence on column "user"\."score"/)
  })
})

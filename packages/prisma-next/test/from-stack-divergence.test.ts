/**
 * Pin the divergence-check semantics of `cipherstashFromStackV2`.
 *
 * The full `cipherstashFromStackV2` path is not exercisable in unit
 * tests because it calls `Encryption({ schemas })` which talks to
 * ZeroKMS at module-evaluation time. We instead pull out the
 * divergence check by calling `cipherstashFromStackV2` with an
 * intentionally-broken override; the assertion fires before any
 * SDK round-trip is attempted, so the test stays hermetic.
 *
 * The happy end-to-end path is covered by the example app's live
 * `pnpm start` flow.
 */

import { encryptedColumn, encryptedTable } from '@cipherstash/stack/schema'
import { describe, expect, it } from 'vitest'

import {
  CIPHERSTASH_BOOLEAN_CODEC_ID,
  CIPHERSTASH_STRING_CODEC_ID,
} from '../src/extension-metadata/constants'
import { cipherstashFromStackV2 } from '../src/stack/from-stack'

function makeContract() {
  return {
    storage: {
      namespaces: {
        __unbound__: {
          entries: {
            table: {
              users: {
                columns: {
                  email: {
                    codecId: CIPHERSTASH_STRING_CODEC_ID,
                    typeParams: { equality: true, freeTextSearch: true },
                  },
                  verified: {
                    codecId: CIPHERSTASH_BOOLEAN_CODEC_ID,
                    typeParams: { equality: true },
                  },
                },
              },
            },
          },
        },
      },
    },
  }
}

describe('cipherstashFromStackV2 — divergence check', () => {
  it('throws when an override drops a column the contract declares', async () => {
    const override = encryptedTable('users', {
      email: encryptedColumn('email').equality().freeTextSearch(),
      // `verified` dropped from override
    })

    await expect(
      cipherstashFromStackV2({
        contractJson: makeContract(),
        schemas: [override],
      }),
    ).rejects.toThrow(/schema divergence on table "users"/)
  })

  it('throws when an override adds a column the contract does not declare', async () => {
    const override = encryptedTable('users', {
      email: encryptedColumn('email').equality().freeTextSearch(),
      verified: encryptedColumn('verified').dataType('boolean').equality(),
      phantom: encryptedColumn('phantom').equality(),
    })

    await expect(
      cipherstashFromStackV2({
        contractJson: makeContract(),
        schemas: [override],
      }),
    ).rejects.toThrow(/schema divergence on table "users"/)
  })

  it("throws when an override changes a column's cast_as", async () => {
    const override = encryptedTable('users', {
      email: encryptedColumn('email').dataType('number').equality(),
      verified: encryptedColumn('verified').dataType('boolean').equality(),
    })

    await expect(
      cipherstashFromStackV2({
        contractJson: makeContract(),
        schemas: [override],
      }),
    ).rejects.toThrow(
      /schema divergence on column "users"\."email".*cast_as="string".*cast_as="number"/s,
    )
  })

  it("throws when an override changes a column's installed index set", async () => {
    const override = encryptedTable('users', {
      // dropped `.freeTextSearch()` — contract declared it
      email: encryptedColumn('email').equality(),
      verified: encryptedColumn('verified').dataType('boolean').equality(),
    })

    await expect(
      cipherstashFromStackV2({
        contractJson: makeContract(),
        schemas: [override],
      }),
    ).rejects.toThrow(/schema divergence on column "users"\."email".*indexes/s)
  })

  it('throws when the contract has no cipherstash columns and no override is supplied', async () => {
    const emptyContract = {
      storage: {
        namespaces: {
          __unbound__: { entries: { table: { users: { columns: {} } } } },
        },
      },
    }
    await expect(
      cipherstashFromStackV2({ contractJson: emptyContract }),
    ).rejects.toThrow(/no cipherstash columns found/)
  })
})

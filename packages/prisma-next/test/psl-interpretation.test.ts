/**
 * Full PSL→ColumnTypeDescriptor lowering for the argument-less v3
 * `cipherstash.<Domain>()` constructors.
 *
 * Exercises the interpreter end-to-end (parser → authoring contributions
 * → SQL contract IR) so the assertions are about *what users observe*
 * in the emitted contract, not about the descriptor template metadata.
 *
 * Pinned behaviour: argument-less v3 constructors lower to their
 * STATIC `{ castAs, capabilities }` typeParams block (no `AuthoringArgRef`
 * resolution involved), carrying the domain's concrete
 * `cipherstash/eql-v3/*@1` codec id and `public.eql_v3_*` native type;
 * `?` produces `nullable: true`; and passing options is rejected.
 */

import type { Contract } from '@prisma-next/contract/types'
import { parsePslDocument } from '@prisma-next/psl-parser'
import { interpretPslDocumentToSqlContract } from '@prisma-next/sql-contract-psl'
import { describe, expect, it } from 'vitest'
import cipherstashControl from '../src/exports/control'
import cipherstashPack from '../src/exports/pack'

const postgresTarget = {
  kind: 'target' as const,
  familyId: 'sql' as const,
  targetId: 'postgres' as const,
  defaultNamespaceId: 'public',
  id: 'postgres',
  version: '0.0.1',
  capabilities: {},
}

const postgresScalarTypeDescriptors = new Map([
  ['String', { codecId: 'pg/text@1', nativeType: 'text' }],
  ['Boolean', { codecId: 'pg/bool@1', nativeType: 'bool' }],
  ['Int', { codecId: 'pg/int4@1', nativeType: 'int4' }],
])

function interpret(schema: string) {
  return interpretPslDocumentToSqlContract({
    document: parsePslDocument({ schema, sourceId: 'schema.prisma' }),
    target: postgresTarget,
    scalarTypeDescriptors: postgresScalarTypeDescriptors,
    composedExtensionPacks: [cipherstashControl.id],
    composedExtensionContracts: new Map([
      [
        cipherstashControl.id,
        cipherstashControl.contractSpace!.contractJson as unknown as Contract,
      ],
    ]),
    authoringContributions: { type: cipherstashPack.authoring.type, field: {} },
  })
}

// The interpreter returns `Result<Contract, ContractSourceDiagnostics>` and
// `Contract.storage` is the opaque `StorageBase<string>`. Tests treat it as
// the structural shape it actually is (tables / types) — same pattern used
// by `packages/2-sql/2-authoring/contract-psl/test/interpreter.relations.test.ts`.
type StorageView = {
  readonly tables: Record<
    string,
    {
      readonly columns: Record<string, Record<string, unknown>>
    }
  >
  readonly types?: Record<string, Record<string, unknown>>
}
// Since 0.10 the storage IR is namespace-enveloped: tables live under
// `storage.namespaces.<ns>` (the target-owned default namespace —
// `public` for Postgres since 0.12), while `types` stays at the root.
const asStorage = (storage: unknown): StorageView => {
  const s = storage as {
    readonly namespaces?: Record<
      string,
      { entries?: { table?: StorageView['tables'] } }
    >
    readonly types?: StorageView['types']
  }
  const tables: StorageView['tables'] = {}
  for (const ns of Object.values(s.namespaces ?? {})) {
    Object.assign(tables, ns.entries?.table)
  }
  return {
    tables,
    ...(s.types !== undefined ? { types: s.types } : {}),
  }
}

describe('PSL interpretation: v3 argument-less constructors (static typeParams)', () => {
  it('lowers cipherstash.TextSearch() to the static v3 descriptor', () => {
    const result = interpret(`model User {
  id Int @id
  email cipherstash.TextSearch()
}
`)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(
      asStorage(result.value.storage).tables['user']?.columns['email'],
    ).toEqual(
      expect.objectContaining({
        codecId: 'cipherstash/eql-v3/eql_v3_text_search@1',
        nativeType: 'public.eql_v3_text_search',
        typeParams: {
          castAs: 'string',
          capabilities: {
            equality: true,
            orderAndRange: true,
            freeTextSearch: true,
          },
        },
        nullable: false,
      }),
    )
  })

  it('lowers cipherstash.Boolean() to the storage-only v3 descriptor', () => {
    const result = interpret(`model User {
  id Int @id
  enabled cipherstash.Boolean()
}
`)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(
      asStorage(result.value.storage).tables['user']?.columns['enabled'],
    ).toEqual(
      expect.objectContaining({
        codecId: 'cipherstash/eql-v3/eql_v3_boolean@1',
        nativeType: 'public.eql_v3_boolean',
        typeParams: {
          castAs: 'boolean',
          capabilities: {
            equality: false,
            orderAndRange: false,
            freeTextSearch: false,
          },
        },
      }),
    )
  })

  it('lowers cipherstash.Json() with searchableJson-only capabilities', () => {
    const result = interpret(`model User {
  id Int @id
  payload cipherstash.Json()
}
`)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(
      asStorage(result.value.storage).tables['user']?.columns['payload'],
    ).toEqual(
      expect.objectContaining({
        codecId: 'cipherstash/eql-v3/eql_v3_json_search@1',
        nativeType: 'public.eql_v3_json_search',
        typeParams: {
          castAs: 'json',
          capabilities: {
            equality: false,
            orderAndRange: false,
            freeTextSearch: false,
            searchableJson: true,
          },
        },
      }),
    )
  })

  it('rejects options on a v3 constructor (they take no arguments)', () => {
    const result = interpret(`model User {
  id Int @id
  email cipherstash.TextSearch({ equality: false })
}
`)
    expect(result.ok).toBe(false)
  })
})

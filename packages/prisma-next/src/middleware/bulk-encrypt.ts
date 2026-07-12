/**
 * Bulk-encrypt middleware for cipherstash envelopes.
 *
 * The middleware sits in the SQL runtime's `beforeExecute` chain and:
 *
 * 1. Walks the lowered query AST (`InsertAst` / `UpdateAst`) and stamps
 *    `(table, column)` routing context onto every cipherstash envelope
 *    (any `EncryptedEnvelopeBase` subclass) embedded in a `ParamRef`.
 *    The handle's `(table, column)` slots are the canonical input to
 *    {@link groupByRoutingKey}; this walk is the single place the AST's
 *    structural column metadata gets attached to the envelopes the SDK
 *    will see.
 *
 * 2. Iterates `params.entries()` to collect every cipherstash-codec'd
 *    `ParamRef` (matched against the closed
 *    {@link CIPHERSTASH_CODEC_ID_SET} — see the rationale on the
 *    constant in `extension-metadata/constants.ts`), groups them by
 *    routing key, and issues exactly one `sdk.bulkEncrypt(...)` call
 *    per group. Routing-key derivation is `(table, column)`; per-group
 *    homogeneity-by-column means each batch is naturally typed (every
 *    cell in a `(table, column)` group has the same codec id, hence
 *    the same plaintext type), so the SDK's polymorphic `values:
 *    ReadonlyArray<unknown>` surface does not need narrowing inside
 *    this middleware.
 *
 * 3. Stamps each returned ciphertext onto the envelope's handle via
 *    `setHandleCiphertext` AND writes the **encoded wire-format
 *    string** (the `eql_v2_encrypted` composite-text literal produced
 *    by {@link encodeEqlV2EncryptedWire}) into the param slot via
 *    `params.replaceValues`. The wire format is what the pg driver
 *    can serialise directly — passing the envelope object itself
 *    would fail at the driver boundary. The handle's `plaintext` and
 *    `ciphertext` slots are both **retained** post-replacement so
 *    `envelope.decrypt()` continues to return the plaintext
 *    synchronously without consulting the SDK, and any follow-on
 *    query that reuses the same envelope skips the re-encrypt
 *    round-trip.
 *
 * Lifecycle: the codec's `encode` runs first (in `lower`/
 * `encodeParams`) and returns the envelope as a sentinel when no
 * ciphertext is set; this middleware then runs in `beforeExecute`
 * and replaces the param slot with the wire-format string before
 * the driver reads `currentParams()`. See the comment on
 * `CipherstashCellCodec#encode` in `../execution/cell-codec-factory.ts`
 * for the full two-pass design.
 *
 * Cancellation: `ctx.signal` is forwarded by identity to every
 * `bulkEncrypt` call via `ifDefined`; the SDK is responsible for
 * honoring it. The awaiting middleware also races the SDK promise
 * against `ctx.signal` via `raceCipherstashAbort` so a caller-side
 * abort surfaces a `RUNTIME.ABORTED { phase: 'bulk-encrypt' }`
 * envelope promptly even when the SDK body itself ignores the signal.
 * A pre-flight `checkCipherstashAborted` short-circuits before any
 * SDK round-trip is scheduled when the signal is already aborted at
 * entry.
 */

import type {
  AnyExpression,
  AnyQueryAst,
  InsertAst,
  InsertValue,
  UpdateAst,
} from '@prisma-next/sql-relational-core/ast'
import type {
  ParamRefHandle,
  SqlParamRefMutator,
} from '@prisma-next/sql-relational-core/middleware'
import type { SqlMiddleware } from '@prisma-next/sql-runtime'
import { ifDefined } from '@prisma-next/utils/defined'
import {
  checkCipherstashAborted,
  raceCipherstashAbort,
} from '../execution/abort'
import { encodeEqlV2EncryptedWire } from '../execution/cell-codec-factory'
import {
  EncryptedEnvelopeBase,
  setHandleCiphertext,
  setHandleRoutingKey,
} from '../execution/envelope-base'
import { markBulkEncryptMiddlewareRegistered } from '../execution/middleware-registry'
import { type BulkEncryptTarget, groupByRoutingKey } from '../execution/routing'
import type { CipherstashSdk } from '../execution/sdk'
import { CIPHERSTASH_CODEC_ID_SET } from '../extension-metadata/constants'

/**
 * Construct the bulk-encrypt middleware. The returned middleware is
 * stateless aside from the captured `sdk` reference; one instance per
 * runtime extension is the expected pattern.
 */
export function bulkEncryptMiddleware(sdk: CipherstashSdk): SqlMiddleware {
  // Mark this sdk as wired up so the codec's `encode` can distinguish
  // "happy path: middleware will run later and fill in the ciphertext"
  // from "misconfig: this sdk has no middleware registered". See
  // `../execution/middleware-registry.ts`.
  markBulkEncryptMiddlewareRegistered(sdk)
  return {
    name: 'cipherstash.bulk-encrypt',
    familyId: 'sql',
    async beforeExecute(plan, ctx, params) {
      if (!params) {
        return
      }

      stampRoutingKeysFromAst(plan.ast)

      const targets = collectTargets(params)
      if (targets.length === 0) {
        return
      }

      const groups = groupByRoutingKey(targets)
      for (const [groupKey, group] of groups) {
        const first = group[0]
        if (!first) continue
        const routingKey = first.routingKey

        checkCipherstashAborted(ctx.signal, 'bulk-encrypt')
        const ciphertexts = await raceCipherstashAbort(
          sdk.bulkEncrypt({
            routingKey,
            values: group.map((t) => t.plaintext),
            ...ifDefined('signal', ctx.signal),
          }),
          ctx.signal,
          'bulk-encrypt',
        )

        if (ciphertexts.length !== group.length) {
          throw new Error(
            `cipherstash bulk-encrypt: SDK returned ${ciphertexts.length} ciphertexts ` +
              `for routing key ${groupKey} but ${group.length} were requested.`,
          )
        }

        // Replace each ParamRef's value with the **wire-format**
        // string that the pg driver can serialise directly. Passing
        // the envelope itself (an `EncryptedEnvelopeBase` instance)
        // would fail at the pg layer with `could not serialize`
        // because the driver only knows how to marshal primitives /
        // arrays / Buffers. We also keep the envelope's ciphertext
        // slot stamped via `setHandleCiphertext` so subsequent reads
        // off the same envelope (e.g. immediately reusing it in a
        // follow-on query) work without a re-encrypt round-trip.
        params.replaceValues(
          group.map((t, i) => {
            const ciphertext = ciphertexts[i]
            setHandleCiphertext(t.envelope, ciphertext)
            return {
              ref: t.ref,
              newValue: encodeEqlV2EncryptedWire(ciphertext),
            }
          }),
        )
      }
    },
  }
}

function collectTargets(
  params: SqlParamRefMutator,
): BulkEncryptTarget<ParamRefHandle<string | undefined>>[] {
  const targets: BulkEncryptTarget<ParamRefHandle<string | undefined>>[] = []
  for (const entry of params.entries()) {
    if (
      entry.codecId === undefined ||
      !CIPHERSTASH_CODEC_ID_SET.has(entry.codecId)
    )
      continue
    const value = entry.value
    if (!(value instanceof EncryptedEnvelopeBase)) continue
    const handle = value.expose()
    if (handle.plaintext === undefined) {
      throw new Error(
        'cipherstash bulk-encrypt: encountered an envelope with no plaintext on the write path. ' +
          'Use the relevant `Encrypted*.from(plaintext)` factory to construct write-side envelopes.',
      )
    }
    if (handle.table === undefined || handle.column === undefined) {
      throw new Error(
        'cipherstash bulk-encrypt: envelope reached the bulk-encrypt phase without a (table, column) ' +
          "routing context. The middleware's AST walk only handles `InsertAst` and `UpdateAst`; " +
          'cipherstash envelopes embedded in other plan shapes (e.g. raw SQL) must stamp routing ' +
          'context explicitly via `setHandleRoutingKey` before execute.',
      )
    }
    targets.push({
      ref: entry.ref,
      plaintext: handle.plaintext,
      envelope: value,
      routingKey: { table: handle.table, column: handle.column },
    })
  }
  return targets
}

function stampRoutingKeysFromAst(ast: AnyQueryAst | undefined): void {
  if (!ast) return
  switch (ast.kind) {
    case 'insert':
      stampInsert(ast)
      return
    case 'update':
      stampUpdate(ast)
      return
    default:
      return
  }
}

function stampInsert(ast: InsertAst): void {
  const tableName = ast.table.name
  for (const row of ast.rows) {
    for (const [column, value] of Object.entries(row)) {
      stampParamRefIfEnvelope(value, tableName, column)
    }
  }
  if (ast.onConflict?.action.kind === 'do-update-set') {
    for (const [column, value] of Object.entries(ast.onConflict.action.set)) {
      stampParamRefIfEnvelope(value, tableName, column)
    }
  }
}

function stampUpdate(ast: UpdateAst): void {
  const tableName = ast.table.name
  for (const [column, value] of Object.entries(ast.set)) {
    stampParamRefIfEnvelope(value, tableName, column)
  }
}

function stampParamRefIfEnvelope(
  value: AnyExpression | InsertValue,
  table: string,
  column: string,
): void {
  if (value.kind !== 'param-ref') return
  const inner = value.value
  if (inner instanceof EncryptedEnvelopeBase) {
    setHandleRoutingKey(inner, table, column)
  }
}

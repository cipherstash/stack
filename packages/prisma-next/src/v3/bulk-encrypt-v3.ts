/**
 * v3 bulk-encrypt middleware — the plain-JSONB twin of the v2
 * `../middleware/bulk-encrypt.ts`. Same `beforeExecute` lifecycle and
 * batching contract, with two deliberate differences:
 *
 *   - **Jurisdiction**: params are matched against the closed v3
 *     codec-id set ({@link CIPHERSTASH_V3_CODEC_ID_SET}), never the v2
 *     set — the two middlewares partition the param space by codec id,
 *     so a plan whose params carry v2 codec ids is invisible here.
 *   - **Wire**: the param slot is replaced with the plain JSONB text of
 *     the EQL payload ({@link v3ToDriver} — v3 columns are PG domains
 *     over `jsonb`), never the v2 `eql_v2_encrypted` composite literal.
 *     This module MUST NOT import `encodeEqlV2EncryptedWire`.
 *   - **Query terms**: v3 additionally collects QUERY-TERM params —
 *     envelopes marked by the v3 operators (`markV3QueryTerm`) and
 *     bound under the bare-rendering `pg/text@1` codec, so they carry
 *     no v3 codec id. The ENVELOPE itself is forwarded through
 *     `sdk.bulkEncrypt` as the value, so the mark survives the SDK
 *     boundary; the v3 SDK adapter (`./sdk-adapter-v3`) reads the mark
 *     and routes the operand through the client's `encryptQuery`
 *     (a ciphertext-free term), never the storage encrypt. The
 *     resulting term is written back as JSONB text — exactly what the
 *     operator's `$N::eql_v3.query_<domain>` template expects — but is
 *     NOT stamped into the envelope's ciphertext slot (a query term is
 *     not the cell's storage ciphertext; stamping it would poison
 *     later write-path reuse of the same envelope).
 *
 * The `(table, column)` routing-key stamping is NOT forked: the AST walk
 * is version-neutral (it touches only the shared envelope base) and is
 * reused from the v2 module via the exported
 * {@link stampRoutingKeysFromAst}.
 *
 * Everything else — one `sdk.bulkEncrypt` per `(table, column)` group,
 * `setHandleCiphertext` stamping with plaintext retention, `ctx.signal`
 * forwarding by identity plus the pre-flight abort check and the abort
 * race, and the ciphertext-count diagnostic — mirrors the v2 middleware;
 * see its module doc for the full lifecycle rationale.
 */

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
import {
  EncryptedEnvelopeBase,
  setHandleCiphertext,
} from '../execution/envelope-base'
import { markBulkEncryptMiddlewareRegistered } from '../execution/middleware-registry'
// Version-neutral AST routing-key stamping — reused, not the v2 encode path.
import {
  type BulkEncryptTarget,
  groupByRoutingKey,
  stampRoutingKeysFromAst,
} from '../execution/routing'
import type { CipherstashSdk } from '../execution/sdk'
import { CIPHERSTASH_V3_CODEC_ID_SET } from '../extension-metadata/constants-v3'
import { v3QueryTermTypeOf } from './query-term'
import { v3ToDriver } from './wire-v3'

/**
 * Construct the v3 bulk-encrypt middleware. The returned middleware is
 * stateless aside from the captured `sdk` reference; one instance per
 * (v3) runtime extension is the expected pattern.
 */
export function bulkEncryptMiddlewareV3(sdk: CipherstashSdk): SqlMiddleware {
  // Mark this sdk as wired up so the codec's `encode` can distinguish
  // "happy path: middleware will run later and fill in the ciphertext"
  // from "misconfig: this sdk has no middleware registered". See
  // `../execution/middleware-registry.ts`.
  markBulkEncryptMiddlewareRegistered(sdk)
  return {
    name: 'cipherstash.bulk-encrypt-v3',
    familyId: 'sql',
    async beforeExecute(plan, ctx, params) {
      if (!params) {
        return
      }

      stampRoutingKeysFromAst(plan.ast)

      const targets = collectV3Targets(params)
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
            `cipherstash v3 bulk-encrypt: SDK returned ${ciphertexts.length} ciphertexts ` +
              `for routing key ${groupKey} but ${group.length} were requested.`,
          )
        }

        // Replace each ParamRef's value with the plain JSONB text the
        // pg driver can serialise directly (the envelope instance
        // itself would fail at the driver boundary). For STORAGE
        // targets the envelope's ciphertext slot is also stamped via
        // `setHandleCiphertext` and its plaintext slot retained, so
        // follow-on reuse of the same envelope skips the re-encrypt
        // round-trip. QUERY-TERM targets skip the stamp: the returned
        // value is a ciphertext-free query term, not the cell's
        // storage ciphertext.
        params.replaceValues(
          group.map((t, i) => {
            const ciphertext = ciphertexts[i]
            if (v3QueryTermTypeOf(t.envelope) === undefined) {
              setHandleCiphertext(t.envelope, ciphertext)
            }
            return {
              ref: t.ref,
              newValue: v3ToDriver(ciphertext),
            }
          }),
        )
      }
    },
  }
}

function collectV3Targets(
  params: SqlParamRefMutator,
): BulkEncryptTarget<ParamRefHandle<string | undefined>>[] {
  const targets: BulkEncryptTarget<ParamRefHandle<string | undefined>>[] = []
  for (const entry of params.entries()) {
    const entryValue = entry.value
    if (
      entryValue instanceof EncryptedEnvelopeBase &&
      v3QueryTermTypeOf(entryValue) !== undefined
    ) {
      // v3 QUERY TERM — marked by a v3 operator at lowering time and
      // bound under `pg/text@1` (no v3 codec id, so the storage arm
      // below never sees it). The envelope itself travels through the
      // SDK seam as the "plaintext" value so the v3 SDK adapter can
      // read the mark and mint an `encryptQuery` term.
      const handle = entryValue.expose()
      if (handle.table === undefined || handle.column === undefined) {
        throw new Error(
          'cipherstash v3 bulk-encrypt: query-term envelope reached the bulk-encrypt phase without a ' +
            '(table, column) routing context. Operators stamp routing from the column-bound self ' +
            'expression; envelopes embedded in raw SQL must stamp routing context explicitly via ' +
            '`setHandleRoutingKey` before execute.',
        )
      }
      targets.push({
        ref: entry.ref,
        plaintext: entryValue,
        envelope: entryValue,
        routingKey: { table: handle.table, column: handle.column },
      })
      continue
    }
    if (
      entry.codecId === undefined ||
      !CIPHERSTASH_V3_CODEC_ID_SET.has(entry.codecId)
    )
      continue
    const value = entry.value
    if (!(value instanceof EncryptedEnvelopeBase)) continue
    const handle = value.expose()
    if (handle.plaintext === undefined) {
      throw new Error(
        'cipherstash v3 bulk-encrypt: encountered an envelope with no plaintext on the write path. ' +
          'Use the relevant `Encrypted*.from(plaintext)` factory to construct write-side envelopes.',
      )
    }
    if (handle.table === undefined || handle.column === undefined) {
      throw new Error(
        'cipherstash v3 bulk-encrypt: envelope reached the bulk-encrypt phase without a (table, column) ' +
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

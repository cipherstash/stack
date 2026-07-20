/**
 * The v3 QUERY-TERM seam — the tiny contract between three modules:
 *
 *   - `./operators-v3` MARKS: every v3 predicate operator wraps its
 *     operand in a per-castAs envelope and stamps the query flavour it
 *     needs (`markV3QueryTerm`) before binding the envelope as a
 *     `pg/text@1` param.
 *   - `./bulk-encrypt-v3` COLLECTS: the middleware recognises marked
 *     envelopes among the plan params (they carry no v3 codec id — the
 *     `pg/text@1` binding keeps them out of the storage jurisdiction)
 *     and forwards the envelope itself through `CipherstashSdk.bulkEncrypt`
 *     so the mark survives the SDK boundary.
 *   - `./sdk-adapter-v3` ROUTES: the SDK adapter reads the mark
 *     (`v3QueryTermTypeOf`) and encrypts marked envelopes via the stack
 *     client's `encryptQuery({ queryType })` — a ciphertext-free term —
 *     instead of the storage `bulkEncrypt` path.
 *
 * Extracted from `./operators-v3` so the middleware and SDK adapter can
 * consume the seam without importing the operator registry (and its
 * `@prisma-next/sql-operations` / expression machinery). The operator
 * module re-exports everything here, so its public surface is unchanged.
 */

import type { QueryTypeName } from '@cipherstash/stack/types'
import { EncryptedEnvelopeBase } from '../execution/envelope-base'

/**
 * A dedicated error for v3 operator gating, operand-coercion, and
 * misuse failures, carrying the offending column/table/operator for
 * diagnostics.
 *
 * INTENTIONAL FORK of `@cipherstash/stack-drizzle`'s error of the same
 * name (same shape, same rationale): sharing it would couple two
 * independently-versioned public packages. v3-owned — the v2 operator
 * surface keeps throwing plain `TypeError`s.
 */
export class EncryptionOperatorError extends Error {
  constructor(
    message: string,
    public readonly context?: {
      columnName?: string
      tableName?: string
      operator?: string
    },
  ) {
    super(message)
    this.name = 'EncryptionOperatorError'
  }
}

/**
 * The query-term flavours a v3 operator can mint — the subset of the
 * stack's `QueryTypeName` union used by the v3 operators. JSON selector
 * predicates use the explicit SteVec flavours because path hashing,
 * value-selector equality, and scalar ordering have distinct wire shapes.
 */
export type V3QueryTermType = Extract<
  QueryTypeName,
  | 'equality'
  | 'orderAndRange'
  | 'freeTextSearch'
  | 'searchableJson'
  | 'steVecSelector'
  | 'steVecValueSelector'
  | 'steVecTerm'
>

/**
 * Query-term marks, keyed by envelope identity. A WeakMap sidecar
 * rather than a handle slot so the version-neutral
 * `EncryptedEnvelopeHandle` (shared with v2, which has no query-term
 * concept) stays untouched.
 */
const V3_QUERY_TERM_TYPES = new WeakMap<
  EncryptedEnvelopeBase<unknown>,
  V3QueryTermType
>()

/**
 * Mark an envelope as a v3 QUERY TERM of the given flavour. Stamped by
 * every operator at lowering time; consumed by the v3 SDK boundary
 * (Task 7), which must encrypt marked envelopes via
 * `encryptQuery({ queryType })` — a ciphertext-free term — instead of
 * the storage `bulkEncrypt` path. Write-once-wins with a conflict
 * check, mirroring `setHandleRoutingKey`: one envelope instance feeds
 * one query flavour.
 */
export function markV3QueryTerm(
  envelope: EncryptedEnvelopeBase<unknown>,
  queryType: V3QueryTermType,
): void {
  const existing = V3_QUERY_TERM_TYPES.get(envelope)
  if (existing !== undefined && existing !== queryType) {
    throw new EncryptionOperatorError(
      `cipherstash v3 operator: envelope is already marked as a "${existing}" query term, refusing to remark as "${queryType}". Construct a fresh envelope per operator call.`,
    )
  }
  V3_QUERY_TERM_TYPES.set(envelope, queryType)
}

/**
 * Read an envelope's query-term mark. `undefined` means the envelope
 * is a storage value (write path), not a query term.
 */
export function v3QueryTermTypeOf(
  envelope: unknown,
): V3QueryTermType | undefined {
  return envelope instanceof EncryptedEnvelopeBase
    ? V3_QUERY_TERM_TYPES.get(envelope)
    : undefined
}

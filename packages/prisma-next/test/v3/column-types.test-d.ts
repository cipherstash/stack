/**
 * Type-level tests for the v3 TS factories' literal spine (design "Type
 * Discipline"). A runtime suite cannot protect this: if the bundled stack
 * `.d.ts` ever widens the getters (see the `EqlTypeFromGetter` rationale in
 * `src/exports/column-types.ts`), every factory still RETURNS the right
 * values at runtime — only the compile-time discrimination silently
 * disappears. These assertions fail `tsc --noEmit` the moment that happens.
 */

import type { QueryCapabilities } from '@cipherstash/stack/eql/v3'
import { expectTypeOf } from 'vitest'
import {
  encryptedBigIntOrd,
  encryptedText,
  encryptedTextEq,
} from '../../src/exports/column-types'

// 1. Factories are mutually non-assignable — distinct type per domain.
expectTypeOf(encryptedTextEq()).not.toMatchTypeOf(encryptedText())
expectTypeOf(encryptedBigIntOrd()).not.toMatchTypeOf(encryptedText())
expectTypeOf(encryptedText()).not.toMatchTypeOf(encryptedBigIntOrd())

// 2. codecId is the literal union member, not `string`.
expectTypeOf(
  encryptedTextEq().codecId,
).toEqualTypeOf<'cipherstash/eql-v3/eql_v3_text_eq@1'>()
expectTypeOf(
  encryptedBigIntOrd().codecId,
).toEqualTypeOf<'cipherstash/eql-v3/eql_v3_bigint_ord@1'>()

// 3. nativeType is the `public.eql_v3_*` literal, not `string`.
expectTypeOf(
  encryptedTextEq().nativeType,
).toEqualTypeOf<'public.eql_v3_text_eq'>()
expectTypeOf(
  encryptedBigIntOrd().nativeType,
).toEqualTypeOf<'public.eql_v3_bigint_ord'>()

// 4. capabilities is (at least) the concrete QueryCapabilities, never `unknown`.
//    (The stack types each domain's capabilities as literal booleans, so this
//    also narrows further — the point is it is NOT `unknown`.)
expectTypeOf(
  encryptedTextEq().typeParams.capabilities,
).toMatchTypeOf<QueryCapabilities>()
expectTypeOf(encryptedTextEq().typeParams.capabilities).not.toBeUnknown()

/**
 * EQL v3 bulk-encrypt middleware.
 *
 * Like {@link bulkEncryptMiddleware} but for `cipherstash/string-v3@1` params,
 * with one extra concern: v3 splits the param path by CONTEXT.
 *
 *   - **Storage values** (INSERT/UPDATE writes, no `queryType` marker) →
 *     `sdk.bulkEncrypt` → a full payload `{v,i,c,…}` → plain-jsonb wire.
 *   - **Search terms** (WHERE needles, stamped with a `queryType` by the v3
 *     operators) → `sdk.bulkEncryptQuery` → an index-only term (NO ciphertext
 *     `c`) → plain-jsonb wire.
 *
 * Both encode through {@link encodeEqlV3Wire} (plain jsonb), NOT the v2
 * composite literal. The two middlewares (v2 + v3) coexist over one sdk: each
 * filters a DISJOINT codec-id set, so order is irrelevant and each ignores the
 * other's params.
 */

import type { ParamRefHandle, SqlParamRefMutator } from '@prisma-next/sql-relational-core/middleware';
import type { SqlMiddleware } from '@prisma-next/sql-runtime';
import { ifDefined } from '@prisma-next/utils/defined';
import { checkCipherstashAborted, raceCipherstashAbort } from '../execution/abort';
import {
  EncryptedEnvelopeBase,
  readHandleQueryType,
  setHandleCiphertext,
} from '../execution/envelope-base';
import { markBulkEncryptMiddlewareRegistered } from '../execution/middleware-registry';
import { type BulkEncryptTarget, groupByRoutingKey } from '../execution/routing';
import type { CipherstashSdk } from '../execution/sdk';
import { encodeEqlV3Wire } from '../v3/wire-codec';
import { CIPHERSTASH_V3_CODEC_ID_SET } from '../extension-metadata/constants';
import { stampRoutingKeysFromAst } from './bulk-encrypt';

// v3 target = a v2 target plus the optional query-type marker (undefined ⇒ a
// storage value; set ⇒ a search term routed to encryptQuery).
type V3Target = BulkEncryptTarget<ParamRefHandle<string | undefined>> & { readonly queryType: string | undefined };

export function bulkEncryptV3Middleware(sdk: CipherstashSdk): SqlMiddleware {
  // Same sdk-keyed WeakSet as v2 (idempotent if both middlewares share an sdk);
  // the v3 codec's encode sentinel consults it to distinguish "middleware will
  // fill ciphertext" from a misconfig.
  markBulkEncryptMiddlewareRegistered(sdk);
  return {
    name: 'cipherstash.bulk-encrypt-v3',
    familyId: 'sql',
    async beforeExecute(plan, ctx, params) {
      if (!params) return;

      // Storage writes need the INSERT/UPDATE routing stamp (search params were
      // already stamped at lowering time by the v3 operators).
      stampRoutingKeysFromAst(plan.ast);

      const { storage, query } = collectV3Targets(params);
      if (storage.length === 0 && query.length === 0) return;

      // --- storage values → bulkEncrypt -------------------------------------
      // groupByRoutingKey is generic over TRef and widens its return to
      // BulkEncryptTarget (dropping our queryType field); the elements are the
      // V3Targets we passed in, so the re-narrow is sound.
      for (const [groupKey, group] of groupByRoutingKey(storage) as Map<string, V3Target[]>) {
        const routingKey = group[0]?.routingKey;
        if (!routingKey) continue;
        checkCipherstashAborted(ctx.signal, 'bulk-encrypt');
        const results = await raceCipherstashAbort(
          sdk.bulkEncrypt({
            routingKey,
            values: group.map((t) => t.plaintext),
            ...ifDefined('signal', ctx.signal),
          }),
          ctx.signal,
          'bulk-encrypt',
        );
        applyResults(params, group, results, groupKey, 'bulkEncrypt');
      }

      // --- search terms → bulkEncryptQuery ----------------------------------
      for (const [groupKey, group] of groupByRoutingKey(query) as Map<string, V3Target[]>) {
        const routingKey = group[0]?.routingKey;
        const queryType = group[0]?.queryType;
        if (!routingKey || queryType === undefined) continue;
        if (group.some((t) => t.queryType !== queryType)) {
          throw new Error(
            `cipherstash bulk-encrypt-v3: routing key ${groupKey} mixes queryTypes ` +
              `(${[...new Set(group.map((t) => String(t.queryType)))].join(', ')}); ` +
              'a single (table, column) search group must share one queryType.',
          );
        }
        if (typeof sdk.bulkEncryptQuery !== 'function') {
          throw new Error(
            'cipherstash bulk-encrypt-v3: a v3 search term needs `sdk.bulkEncryptQuery`, but the ' +
              'configured SDK does not implement it. Use `createCipherstashSdk(...)` (the stack adapter), ' +
              'which maps it to the client\'s `encryptQuery`.',
          );
        }
        checkCipherstashAborted(ctx.signal, 'bulk-encrypt');
        const results = await raceCipherstashAbort(
          sdk.bulkEncryptQuery({
            routingKey,
            queryType,
            values: group.map((t) => t.plaintext),
            ...ifDefined('signal', ctx.signal),
          }),
          ctx.signal,
          'bulk-encrypt',
        );
        applyResults(params, group, results, groupKey, 'bulkEncryptQuery');
      }
    },
  };
}

function applyResults(
  params: SqlParamRefMutator,
  group: ReadonlyArray<V3Target>,
  results: ReadonlyArray<unknown>,
  groupKey: string,
  op: string,
): void {
  if (results.length !== group.length) {
    throw new Error(
      `cipherstash bulk-encrypt-v3: ${op} returned ${results.length} results for routing key ${groupKey} ` +
        `but ${group.length} were requested.`,
    );
  }
  params.replaceValues(
    group.map((t, i) => {
      const result = results[i];
      // Storage values carry a ciphertext we cache back onto the handle; search
      // terms have none, but caching the term is harmless and keeps the slot shape
      // uniform. The wire is plain jsonb for both.
      setHandleCiphertext(t.envelope, result);
      return { ref: t.ref, newValue: encodeEqlV3Wire(result) };
    }),
  );
}

function collectV3Targets(params: SqlParamRefMutator): {
  storage: V3Target[];
  query: V3Target[];
} {
  const storage: V3Target[] = [];
  const query: V3Target[] = [];
  for (const entry of params.entries()) {
    if (entry.codecId === undefined || !CIPHERSTASH_V3_CODEC_ID_SET.has(entry.codecId)) continue;
    const value = entry.value;
    if (!(value instanceof EncryptedEnvelopeBase)) continue;
    const handle = value.expose();
    if (handle.plaintext === undefined) {
      throw new Error(
        'cipherstash bulk-encrypt-v3: encountered an envelope with no plaintext on the write/search path. ' +
          'Use `EncryptedString.from(plaintext)` to construct envelopes.',
      );
    }
    if (handle.table === undefined || handle.column === undefined) {
      throw new Error(
        'cipherstash bulk-encrypt-v3: envelope reached the bulk-encrypt phase without a (table, column) ' +
          'routing context. Storage writes are stamped from the INSERT/UPDATE AST; search params are stamped ' +
          'by the v3 operators at lowering time.',
      );
    }
    const target: V3Target = {
      ref: entry.ref,
      plaintext: handle.plaintext,
      envelope: value,
      routingKey: { table: handle.table, column: handle.column },
      queryType: readHandleQueryType(value),
    };
    if (target.queryType === undefined) storage.push(target);
    else query.push(target);
  }
  return { storage, query };
}

import type { ColumnMap } from './column-map'
import { parseOrString } from './helpers'
import type {
  DbConflictList,
  DbMutationOp,
  DbMutationOptions,
  DbPendingOrCondition,
  DbPendingOrFilter,
  DbQuerySpace,
  DbTransformOp,
  MutationOp,
  PendingOrCondition,
  PendingOrFilter,
  RecordedOps,
  TransformOp,
} from './types'

/**
 * Resolve the column names carried by a mutation's options. `onConflict` is a
 * comma-separated column list, so it needs the same property→DB mapping as a
 * filter. Returns the original object when nothing changed.
 */
export function resolveMutationOptions<
  O extends { onConflict?: string } | undefined,
>(options: O, columns: ColumnMap): DbMutationOptions | undefined {
  if (!options?.onConflict) return options as DbMutationOptions | undefined
  const mapped = options.onConflict
    .split(',')
    .map((column) => columns.filterColumnName(column.trim()))
    .join(',') as DbConflictList
  return (
    mapped === options.onConflict ? options : { ...options, onConflict: mapped }
  ) as DbMutationOptions
}

/** Column names only. Which conditions were encrypted is never decided here:
 * it stays derived at apply time from the substitution maps, so this pass
 * never has to agree with the encryption predicate. The operator token is
 * settled later still, in `rebuildOrString`, where `contains` becomes `cs`
 * for encrypted and plaintext conditions alike. */
function orFilterToDbSpace(
  of_: PendingOrFilter,
  columns: ColumnMap,
): DbPendingOrFilter {
  const toDbCondition = (c: PendingOrCondition): DbPendingOrCondition => ({
    ...c,
    column: columns.filterColumnName(c.column),
  })

  if (of_.kind === 'string') {
    return {
      kind: 'string',
      original: of_.value,
      conditions: parseOrString(of_.value).map(toDbCondition),
      referencedTable: of_.referencedTable,
    }
  }
  return { kind: 'structured', conditions: of_.conditions.map(toDbCondition) }
}

function transformToDbSpace(t: TransformOp, columns: ColumnMap): DbTransformOp {
  switch (t.kind) {
    case 'order':
      return { ...t, column: columns.orderColumnName(t.column) }
    // `returns` is in the union but never pushed (`returns()` is a cast).
    case 'limit':
    case 'range':
    case 'single':
    case 'maybeSingle':
    case 'csv':
    case 'abortSignal':
    case 'throwOnError':
    case 'returns':
      return t
    default: {
      const exhaustive: never = t
      return exhaustive
    }
  }
}

function mutationToDbSpace(m: MutationOp, columns: ColumnMap): DbMutationOp {
  switch (m.kind) {
    case 'insert':
    case 'upsert':
      return { ...m, options: resolveMutationOptions(m.options, columns) }
    case 'update':
    case 'delete':
      return m // options carry no column names
    default: {
      const exhaustive: never = m
      return exhaustive
    }
  }
}

/**
 * Translate every recorded column name from JS property space into DB space,
 * once. Downstream (`encryptFilterValues`, `applyFilters`,
 * `buildAndExecuteQuery`) consumes only the branded result, so a column can
 * no longer reach PostgREST untranslated — that is a compile error.
 *
 * Total: `filterColumnName`, `parseOrString`, and `resolveMutationOptions`
 * never throw, so this introduces no new early-throw point and cannot perturb
 * the order in which capability errors surface.
 *
 * Safe to run BEFORE encryption: the column map is keyed by both property and
 * DB name, so column lookup resolves identically either side of the
 * translation, and `tableColumns[prop]` is the very same builder object as
 * `tableColumns[db]`.
 */
export function toDbSpace(
  recorded: RecordedOps,
  columns: ColumnMap,
): DbQuerySpace {
  return {
    filters: recorded.filters.map((f) => ({
      ...f,
      column: columns.filterColumnName(f.column),
    })),
    matchFilters: recorded.matchFilters.map((mf) => ({
      entries: Object.entries(mf.query).map(([column, value]) => ({
        column: columns.filterColumnName(column),
        value,
      })),
    })),
    notFilters: recorded.notFilters.map((nf) => ({
      ...nf,
      column: columns.filterColumnName(nf.column),
    })),
    rawFilters: recorded.rawFilters.map((rf) => ({
      ...rf,
      column: columns.filterColumnName(rf.column),
    })),
    orFilters: recorded.orFilters.map((of_) => orFilterToDbSpace(of_, columns)),
    transforms: recorded.transforms.map((t) => transformToDbSpace(t, columns)),
    mutation: recorded.mutation
      ? mutationToDbSpace(recorded.mutation, columns)
      : null,
  }
}

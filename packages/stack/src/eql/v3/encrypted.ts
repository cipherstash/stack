import type { MatchIndexOpts } from '@/schema'
import type {
  EncryptedDateColumn,
  EncryptedDateEqColumn,
  EncryptedDateOrdColumn,
  EncryptedFloat4Column,
  EncryptedFloat4EqColumn,
  EncryptedFloat4OrdColumn,
  EncryptedFloat8Column,
  EncryptedFloat8EqColumn,
  EncryptedFloat8OrdColumn,
  EncryptedInt2Column,
  EncryptedInt2EqColumn,
  EncryptedInt2OrdColumn,
  EncryptedInt4Column,
  EncryptedInt4EqColumn,
  EncryptedInt4OrdColumn,
  EncryptedNumericColumn,
  EncryptedNumericEqColumn,
  EncryptedNumericOrdColumn,
  EncryptedTextColumn,
  EncryptedTextEqColumn,
  EncryptedTextMatchColumn,
  EncryptedTextOrdColumn,
  EncryptedTextSearchColumn,
  EncryptedTimestamptzColumn,
  EncryptedTimestamptzEqColumn,
  EncryptedTimestamptzOrdColumn,
} from './columns'
import { types } from './types'

type TextSearchFluent = EncryptedTextSearchColumn & {
  equality(): TextSearchFluent
  orderAndRange(): TextSearchFluent
}

type TextOrdFluent = EncryptedTextOrdColumn & {
  equality(): TextOrdFluent
  freeTextSearch(opts?: MatchIndexOpts): TextSearchFluent
}

type TextMatchFluent = EncryptedTextMatchColumn & {
  equality(): TextSearchFluent
  orderAndRange(): TextSearchFluent
}

type TextEqFluent = EncryptedTextEqColumn & {
  freeTextSearch(opts?: MatchIndexOpts): TextSearchFluent
  orderAndRange(): TextOrdFluent
}

type TextFluent = EncryptedTextColumn & {
  equality(): TextEqFluent
  freeTextSearch(opts?: MatchIndexOpts): TextMatchFluent
  orderAndRange(): TextOrdFluent
}

type OrderedFluent<Ord> = Ord & {
  equality(): OrderedFluent<Ord>
}

type EqualityFluent<Ord, Eq> = Eq & {
  orderAndRange(): OrderedFluent<Ord>
}

type ScalarFluent<Base, Eq, Ord> = Base & {
  equality(): EqualityFluent<Ord, Eq>
  orderAndRange(): OrderedFluent<Ord>
}

function textSearch(name: string, opts?: MatchIndexOpts): TextSearchFluent {
  const column = types.TextSearch(name)
  if (opts) {
    column.freeTextSearch(opts)
  }
  return Object.assign(column, {
    equality: () => column,
    orderAndRange: () => column,
  }) as TextSearchFluent
}

function textOrd(name: string): TextOrdFluent {
  const column = types.TextOrd(name)
  return Object.assign(column, {
    equality: () => column,
    freeTextSearch: (opts?: MatchIndexOpts) => textSearch(name, opts),
  }) as TextOrdFluent
}

function textEq(name: string): TextEqFluent {
  return Object.assign(types.TextEq(name), {
    freeTextSearch: (opts?: MatchIndexOpts) => textSearch(name, opts),
    orderAndRange: () => textOrd(name),
  }) as TextEqFluent
}

function textMatch(name: string, opts?: MatchIndexOpts): TextMatchFluent {
  const column = types.TextMatch(name).freeTextSearch(opts)
  return Object.assign(column, {
    equality: () => textSearch(name, opts),
    orderAndRange: () => textSearch(name, opts),
  }) as TextMatchFluent
}

function text(name: string): TextFluent {
  return Object.assign(types.Text(name), {
    equality: () => textEq(name),
    freeTextSearch: (opts?: MatchIndexOpts) => textMatch(name, opts),
    orderAndRange: () => textOrd(name),
  }) as TextFluent
}

function scalar<Base, Eq, Ord>(
  base: () => Base,
  eq: () => Eq,
  ord: () => Ord,
): ScalarFluent<Base, Eq, Ord> {
  const ordered = (): OrderedFluent<Ord> => {
    const column = ord()
    return Object.assign(column as object, {
      equality: () => column,
    }) as OrderedFluent<Ord>
  }

  return Object.assign(base() as object, {
    equality: () =>
      Object.assign(eq() as object, {
        orderAndRange: ordered,
      }) as EqualityFluent<Ord, Eq>,
    orderAndRange: ordered,
  }) as ScalarFluent<Base, Eq, Ord>
}

function integer(
  name: string,
): ScalarFluent<
  EncryptedInt4Column,
  EncryptedInt4EqColumn,
  EncryptedInt4OrdColumn
> {
  return scalar(
    () => types.Int4(name),
    () => types.Int4Eq(name),
    () => types.Int4Ord(name),
  )
}

function smallint(
  name: string,
): ScalarFluent<
  EncryptedInt2Column,
  EncryptedInt2EqColumn,
  EncryptedInt2OrdColumn
> {
  return scalar(
    () => types.Int2(name),
    () => types.Int2Eq(name),
    () => types.Int2Ord(name),
  )
}

function date(
  name: string,
): ScalarFluent<
  EncryptedDateColumn,
  EncryptedDateEqColumn,
  EncryptedDateOrdColumn
> {
  return scalar(
    () => types.Date(name),
    () => types.DateEq(name),
    () => types.DateOrd(name),
  )
}

function timestamptz(
  name: string,
): ScalarFluent<
  EncryptedTimestamptzColumn,
  EncryptedTimestamptzEqColumn,
  EncryptedTimestamptzOrdColumn
> {
  return scalar(
    () => types.Timestamptz(name),
    () => types.TimestamptzEq(name),
    () => types.TimestamptzOrd(name),
  )
}

function numeric(
  name: string,
): ScalarFluent<
  EncryptedNumericColumn,
  EncryptedNumericEqColumn,
  EncryptedNumericOrdColumn
> {
  return scalar(
    () => types.Numeric(name),
    () => types.NumericEq(name),
    () => types.NumericOrd(name),
  )
}

function real(
  name: string,
): ScalarFluent<
  EncryptedFloat4Column,
  EncryptedFloat4EqColumn,
  EncryptedFloat4OrdColumn
> {
  return scalar(
    () => types.Float4(name),
    () => types.Float4Eq(name),
    () => types.Float4Ord(name),
  )
}

function doublePrecision(
  name: string,
): ScalarFluent<
  EncryptedFloat8Column,
  EncryptedFloat8EqColumn,
  EncryptedFloat8OrdColumn
> {
  return scalar(
    () => types.Float8(name),
    () => types.Float8Eq(name),
    () => types.Float8Ord(name),
  )
}

/**
 * SQL-aligned, fluent authoring namespace for EQL v3 columns.
 *
 * This is a thin layer over the concrete `types.*` factories: every terminal
 * chain returns the same concrete column class that `types.*` would have
 * returned, preserving v3 plaintext and query-capability inference.
 */
export const encrypted = {
  text,
  integer,
  smallint,
  date,
  timestamptz,
  timestamp: timestamptz,
  numeric,
  boolean: types.Bool,
  real,
  doublePrecision,
} as const

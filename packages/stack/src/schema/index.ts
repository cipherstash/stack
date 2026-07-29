/**
 * Low-level encryption configuration primitives.
 *
 * Schema authoring is EQL v3-only; import `encryptedTable` and `types` from
 * `@cipherstash/stack/v3`. This subpath remains for packages that inspect or
 * validate the generated protect-ffi configuration.
 */

export type {
  CastAs,
  ColumnSchema,
  EncryptConfig,
  EqlCastAs,
  MatchIndexOpts,
  OpeIndexOpts,
  OreIndexOpts,
  SteVecIndexOpts,
  TokenFilter,
  UniqueIndexOpts,
} from './internal'
export {
  castAsEnum,
  encryptConfigSchema,
  eqlCastAsEnum,
  toEqlCastAs,
} from './internal'

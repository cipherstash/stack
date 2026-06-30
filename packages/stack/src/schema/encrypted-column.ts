import type {
  CastAs,
  MatchIndexOpts,
  OreIndexOpts,
  SteVecIndexOpts,
  TokenFilter,
  UniqueIndexOpts,
} from './index'

/**
 * Abstract base for all encrypted column builders.
 *
 * Holds the shared column state (`cast_as` and configured indexes), the
 * `build()`/`getName()` accessors, and the protected index mutators whose
 * bodies define how each index is configured.
 *
 * Concrete subclasses expose only the builder methods that make sense for their
 * data type:
 * - {@link EncryptedColumnBuilder} — the dynamic column returned by
 *   {@link encryptedColumn}, exposing the full set of builder methods.
 * - The strongly-typed columns ({@link EncryptedNumber}, {@link EncryptedDate},
 *   {@link EncryptedTimestampTz}, {@link EncryptedText}, {@link EncryptedBool}),
 *   each exposing only the methods valid for its plaintext type.
 *
 * All subclasses are `instanceof EncryptedColumn`, so the schema and encryption
 * machinery can treat them uniformly.
 */
export abstract class EncryptedColumn {
  protected castAsValue: CastAs = 'string'
  protected indexesValue: {
    ore?: OreIndexOpts
    unique?: UniqueIndexOpts
    match?: Required<MatchIndexOpts>
    ste_vec?: SteVecIndexOpts
  } = {}

  constructor(protected columnName: string) {}

  /** Set the plaintext data type for this column. */
  protected setCastAs(castAs: CastAs) {
    this.castAsValue = castAs
  }

  /** Enable Order-Revealing Encryption (ORE) indexing on this column. */
  protected addOreIndex() {
    this.indexesValue.ore = {}
  }

  /** Enable an exact-match (unique) index on this column. */
  protected addUniqueIndex(tokenFilters?: TokenFilter[]) {
    this.indexesValue.unique = {
      token_filters: tokenFilters ?? [],
    }
  }

  /** Enable a full-text / fuzzy search (match) index on this column. */
  protected addMatchIndex(opts?: MatchIndexOpts) {
    // Provide defaults
    this.indexesValue.match = {
      tokenizer: opts?.tokenizer ?? { kind: 'ngram', token_length: 3 },
      token_filters: opts?.token_filters ?? [
        {
          kind: 'downcase',
        },
      ],
      k: opts?.k ?? 6,
      m: opts?.m ?? 2048,
      include_original: opts?.include_original ?? true,
    }
  }

  /**
   * Configure this column for searchable encrypted JSON (STE-Vec).
   * Automatically switches the data type to `'json'`.
   */
  protected addSteVecIndex() {
    this.castAsValue = 'json'
    this.indexesValue.ste_vec = { prefix: 'enabled', array_index_mode: 'all' }
  }

  build() {
    return {
      cast_as: this.castAsValue,
      indexes: this.indexesValue,
    }
  }

  getName() {
    return this.columnName
  }
}

/**
 * Dynamic encrypted column builder returned by {@link encryptedColumn}.
 *
 * Exposes the full set of builder methods regardless of data type. Prefer the
 * strongly-typed columns ({@link EncryptedNumber}, {@link EncryptedText}, etc.)
 * which only allow the index methods that are valid for their plaintext type.
 */
export class EncryptedColumnBuilder extends EncryptedColumn {
  /**
   * Set or override the plaintext data type for this column.
   *
   * By default all columns are treated as `'string'`. Use this method to specify
   * a different type so the encryption layer knows how to encode the plaintext
   * before encrypting.
   *
   * @param castAs - The plaintext data type: `'string'`, `'number'`, `'boolean'`, `'date'`, `'bigint'`, or `'json'`.
   * @returns This `EncryptedColumnBuilder` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const dateOfBirth = encryptedColumn("date_of_birth").dataType("date")
   * ```
   */
  dataType(castAs: CastAs) {
    this.setCastAs(castAs)
    return this
  }

  /**
   * Enable Order-Revealing Encryption (ORE) indexing on this column.
   *
   * ORE allows sorting, comparison, and range queries on encrypted data.
   * Use with `encryptQuery` and `queryType: 'orderAndRange'`.
   *
   * @returns This `EncryptedColumnBuilder` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const users = encryptedTable("users", {
   *   email: encryptedColumn("email").orderAndRange(),
   * })
   * ```
   */
  orderAndRange() {
    this.addOreIndex()
    return this
  }

  /**
   * Enable an exact-match (unique) index on this column.
   *
   * Allows equality queries on encrypted data. Use with `encryptQuery`
   * and `queryType: 'equality'`.
   *
   * @param tokenFilters - Optional array of token filters (e.g. `[{ kind: 'downcase' }]`).
   *   When omitted, no token filters are applied.
   * @returns This `EncryptedColumnBuilder` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const users = encryptedTable("users", {
   *   email: encryptedColumn("email").equality(),
   * })
   * ```
   */
  equality(tokenFilters?: TokenFilter[]) {
    this.addUniqueIndex(tokenFilters)
    return this
  }

  /**
   * Enable a full-text / fuzzy search (match) index on this column.
   *
   * Uses n-gram tokenization by default for substring and fuzzy matching.
   * Use with `encryptQuery` and `queryType: 'freeTextSearch'`.
   *
   * @param opts - Optional match index configuration. Defaults to 3-character ngram
   *   tokenization with a downcase filter, `k=6`, `m=2048`, and `include_original=true`.
   * @returns This `EncryptedColumnBuilder` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const users = encryptedTable("users", {
   *   email: encryptedColumn("email").freeTextSearch(),
   * })
   *
   * // With custom options
   * const posts = encryptedTable("posts", {
   *   body: encryptedColumn("body").freeTextSearch({
   *     tokenizer: { kind: "ngram", token_length: 4 },
   *     k: 8,
   *     m: 4096,
   *   }),
   * })
   * ```
   */
  freeTextSearch(opts?: MatchIndexOpts) {
    this.addMatchIndex(opts)
    return this
  }

  /**
   * Configure this column for searchable encrypted JSON (STE-Vec).
   *
   * Enables encrypted JSONPath selector queries (e.g. `'$.user.email'`) and
   * containment queries (e.g. `{ role: 'admin' }`). Automatically sets the
   * data type to `'json'`.
   *
   * When used with `encryptQuery`, the query operation is auto-inferred from
   * the plaintext type: strings become selector queries, objects/arrays become
   * containment queries.
   *
   * @returns This `EncryptedColumnBuilder` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const documents = encryptedTable("documents", {
   *   metadata: encryptedColumn("metadata").searchableJson(),
   * })
   * ```
   */
  searchableJson() {
    this.addSteVecIndex()
    return this
  }
}

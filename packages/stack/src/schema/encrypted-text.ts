import { EncryptedColumn } from './encrypted-column'
import type { MatchIndexOpts, TokenFilter } from './index'

/**
 * Strongly-typed encrypted column for text values (`cast_as: 'text'`).
 *
 * Supports exact-match ({@link equality}), order/range ({@link orderAndRange}),
 * and full-text / fuzzy search ({@link freeTextSearch}) indexes. Create with
 * {@link encryptedText}.
 *
 * For searchable encrypted JSON, use {@link EncryptedJson} instead.
 */
export class EncryptedText extends EncryptedColumn {
  constructor(columnName: string) {
    super(columnName)
    this.setCastAs('text')
  }

  /**
   * Enable an exact-match (unique) index for equality queries.
   *
   * @param tokenFilters - Optional array of token filters (e.g. `[{ kind: 'downcase' }]`).
   *   When omitted, no token filters are applied.
   * @returns This `EncryptedText` instance for method chaining.
   */
  equality(tokenFilters?: TokenFilter[]) {
    this.addUniqueIndex(tokenFilters)
    return this
  }

  /**
   * Enable Order-Revealing Encryption (ORE) for sorting, comparison, and range queries.
   *
   * @returns This `EncryptedText` instance for method chaining.
   */
  orderAndRange() {
    this.addOreIndex()
    return this
  }

  /**
   * Enable a full-text / fuzzy search (match) index.
   *
   * Uses n-gram tokenization by default for substring and fuzzy matching.
   *
   * @param opts - Optional match index configuration. Defaults to 3-character ngram
   *   tokenization with a downcase filter, `k=6`, `m=2048`, and `include_original=true`.
   * @returns This `EncryptedText` instance for method chaining.
   */
  freeTextSearch(opts?: MatchIndexOpts) {
    this.addMatchIndex(opts)
    return this
  }
}

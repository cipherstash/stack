import { EncryptedColumn } from './encrypted-column'
import type { TokenFilter } from './index'

/**
 * Strongly-typed encrypted column for numeric values (`cast_as: 'number'`).
 *
 * Supports exact-match ({@link equality}) and order/range ({@link orderAndRange})
 * indexes. Create with {@link encryptedNumber}.
 */
export class EncryptedNumber extends EncryptedColumn {
  constructor(columnName: string) {
    super(columnName)
    this.setCastAs('number')
  }

  /**
   * Enable an exact-match (unique) index for equality queries.
   *
   * @param tokenFilters - Optional array of token filters. When omitted, no token filters are applied.
   * @returns This `EncryptedNumber` instance for method chaining.
   */
  equality(tokenFilters?: TokenFilter[]) {
    this.addUniqueIndex(tokenFilters)
    return this
  }

  /**
   * Enable Order-Revealing Encryption (ORE) for sorting, comparison, and range queries.
   *
   * @returns This `EncryptedNumber` instance for method chaining.
   */
  orderAndRange() {
    this.addOreIndex()
    return this
  }
}

import { EncryptedColumn } from './encrypted-column'
import type { TokenFilter } from './index'

/**
 * Strongly-typed encrypted column for timestamp-with-time-zone values
 * (`cast_as: 'timestamp'` — the canonical timestamp cast accepted by the
 * encryption layer; there is no separate `timestamptz` cast).
 *
 * Supports exact-match ({@link equality}) and order/range ({@link orderAndRange})
 * indexes. Create with {@link encryptedTimestampTz}.
 */
export class EncryptedTimestampTz extends EncryptedColumn {
  constructor(columnName: string) {
    super(columnName)
    this.setCastAs('timestamp')
  }

  /**
   * Enable an exact-match (unique) index for equality queries.
   *
   * @param tokenFilters - Optional array of token filters. When omitted, no token filters are applied.
   * @returns This `EncryptedTimestampTz` instance for method chaining.
   */
  equality(tokenFilters?: TokenFilter[]) {
    this.addUniqueIndex(tokenFilters)
    return this
  }

  /**
   * Enable Order-Revealing Encryption (ORE) for sorting, comparison, and range queries.
   *
   * @returns This `EncryptedTimestampTz` instance for method chaining.
   */
  orderAndRange() {
    this.addOreIndex()
    return this
  }
}

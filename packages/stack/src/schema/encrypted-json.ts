import { EncryptedColumn } from './encrypted-column'

/**
 * Strongly-typed encrypted column for JSON values (`cast_as: 'json'`).
 *
 * Supports searchable encrypted JSON ({@link searchableJson}) via STE-Vec.
 * Create with {@link encryptedJson}.
 */
export class EncryptedJson extends EncryptedColumn {
  constructor(columnName: string) {
    super(columnName)
    this.setCastAs('json')
  }

  /**
   * Configure this column for searchable encrypted JSON (STE-Vec).
   *
   * Enables encrypted JSONPath selector queries (e.g. `'$.user.email'`) and
   * containment queries (e.g. `{ role: 'admin' }`).
   *
   * When used with `encryptQuery`, the query operation is auto-inferred from
   * the plaintext type: strings become selector queries, objects/arrays become
   * containment queries.
   *
   * @returns This `EncryptedJson` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedJson } from "@cipherstash/stack/schema"
   *
   * const documents = encryptedTable("documents", {
   *   metadata: encryptedJson("metadata").searchableJson(),
   * })
   * ```
   */
  searchableJson() {
    this.addSteVecIndex()
    return this
  }
}

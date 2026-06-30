import { EncryptedColumn } from './encrypted-column'

/**
 * Strongly-typed encrypted column for boolean values (`cast_as: 'boolean'`).
 *
 * Boolean columns are encrypted but not searchable, so no index methods are
 * exposed. Create with {@link encryptedBool}.
 */
export class EncryptedBool extends EncryptedColumn {
  constructor(columnName: string) {
    super(columnName)
    this.setCastAs('boolean')
  }
}

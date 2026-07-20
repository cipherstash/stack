#!/usr/bin/env -S node
import {
  col,
  Migration,
  MigrationCLI,
  primaryKey,
} from '@prisma-next/postgres/migration'

export default class M extends Migration {
  override describe() {
    return {
      from: null,
      to: 'sha256:deb36a1ab7e51717f5ca822a32ff09a18cf3a0aaf1189262852c8953adba1720',
    }
  }

  override get operations() {
    return [
      this.createTable({
        schema: 'public',
        table: 'users',
        columns: [
          col('accountid', 'eql_v3_bigint_ord', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/eql-v3/eql_v3_bigint_ord@1',
              typeParams: {
                capabilities: { equality: true, orderAndRange: true },
                castAs: 'bigint',
              },
            },
          }),
          col('birthday', 'eql_v3_date_ord', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/eql-v3/eql_v3_date_ord@1',
              typeParams: {
                capabilities: { equality: true, orderAndRange: true },
                castAs: 'date',
              },
            },
          }),
          col('email', 'eql_v3_text_search', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/eql-v3/eql_v3_text_search@1',
              typeParams: {
                capabilities: {
                  equality: true,
                  freeTextSearch: true,
                  orderAndRange: true,
                },
                castAs: 'string',
              },
            },
          }),
          col('emailverified', 'eql_v3_boolean', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/eql-v3/eql_v3_boolean@1',
              typeParams: { capabilities: {}, castAs: 'boolean' },
            },
          }),
          col('id', 'text', {
            notNull: true,
            codecRef: { codecId: 'pg/text@1' },
          }),
          col('preferences', 'eql_v3_json_search', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/eql-v3/eql_v3_json_search@1',
              typeParams: {
                capabilities: { searchableJson: true },
                castAs: 'json',
              },
            },
          }),
          col('salary', 'eql_v3_double_ord', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/eql-v3/eql_v3_double_ord@1',
              typeParams: {
                capabilities: { equality: true, orderAndRange: true },
                castAs: 'number',
              },
            },
          }),
        ],
        constraints: [primaryKey(['id'])],
      }),
    ]
  }
}

MigrationCLI.run(import.meta.url, M)

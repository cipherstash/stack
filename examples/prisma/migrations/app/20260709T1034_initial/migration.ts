#!/usr/bin/env -S node
import { cipherstashAddSearchConfig } from '@prisma-next/extension-cipherstash/migration';
import { Migration, MigrationCLI, col, primaryKey } from '@prisma-next/postgres/migration';

export default class M extends Migration {
  override describe() {
    return {
      from: null,
      to: 'sha256:b8c4febc9397cf1b68293cdb3b2afe9f568db6967f428e3f207e32575a2bc2fa',
    };
  }

  override get operations() {
    return [
      this.createTable({
        schema: 'public',
        table: 'users',
        columns: [
          col('accountid', 'eql_v2_encrypted', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/bigint@1',
              typeParams: { equality: true, orderAndRange: true },
            },
          }),
          col('birthday', 'eql_v2_encrypted', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/date@1',
              typeParams: { equality: true, orderAndRange: true },
            },
          }),
          col('email', 'eql_v2_encrypted', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/string@1',
              typeParams: { equality: true, freeTextSearch: true, orderAndRange: true },
            },
          }),
          col('emailverified', 'eql_v2_encrypted', {
            notNull: true,
            codecRef: { codecId: 'cipherstash/boolean@1', typeParams: { equality: true } },
          }),
          col('id', 'text', { notNull: true, codecRef: { codecId: 'pg/text@1' } }),
          col('preferences', 'eql_v2_encrypted', {
            notNull: true,
            codecRef: { codecId: 'cipherstash/json@1', typeParams: { searchableJson: true } },
          }),
          col('salary', 'eql_v2_encrypted', {
            notNull: true,
            codecRef: {
              codecId: 'cipherstash/double@1',
              typeParams: { equality: true, orderAndRange: true },
            },
          }),
        ],
        constraints: [primaryKey(['id'])],
      }),
      cipherstashAddSearchConfig({
        table: 'users',
        column: 'accountid',
        index: 'unique',
        castAs: 'big_int',
      }),
      cipherstashAddSearchConfig({
        table: 'users',
        column: 'accountid',
        index: 'ore',
        castAs: 'big_int',
      }),
      cipherstashAddSearchConfig({
        table: 'users',
        column: 'birthday',
        index: 'unique',
        castAs: 'date',
      }),
      cipherstashAddSearchConfig({
        table: 'users',
        column: 'birthday',
        index: 'ore',
        castAs: 'date',
      }),
      cipherstashAddSearchConfig({ table: 'users', column: 'email', index: 'unique' }),
      cipherstashAddSearchConfig({ table: 'users', column: 'email', index: 'match' }),
      cipherstashAddSearchConfig({ table: 'users', column: 'email', index: 'ore' }),
      cipherstashAddSearchConfig({
        table: 'users',
        column: 'emailverified',
        index: 'unique',
        castAs: 'boolean',
      }),
      cipherstashAddSearchConfig({
        table: 'users',
        column: 'preferences',
        index: 'ste_vec',
        castAs: 'jsonb',
      }),
      cipherstashAddSearchConfig({
        table: 'users',
        column: 'salary',
        index: 'unique',
        castAs: 'double',
      }),
      cipherstashAddSearchConfig({
        table: 'users',
        column: 'salary',
        index: 'ore',
        castAs: 'double',
      }),
    ];
  }
}

MigrationCLI.run(import.meta.url, M);

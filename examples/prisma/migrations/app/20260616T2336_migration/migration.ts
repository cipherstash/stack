#!/usr/bin/env -S node
import { Migration, MigrationCLI, createTable } from '@prisma-next/target-postgres/migration';

export default class M extends Migration {
  override describe() {
    return {
      from: 'sha256:7475191ce0d78258ce5586265bcdfd12202f5daf90690b902890e58eb7508373',
      to: 'sha256:4e951512096c6bb3dbfa55779a34474176fc6f925f97087ca341b28681a1e7e3',
    };
  }

  override get operations() {
    return [
      createTable(
        'public',
        'user_v3',
        [
          { name: 'bio', typeSql: 'eql_v3.text_match', defaultSql: '', nullable: false },
          { name: 'email', typeSql: 'eql_v3.text_eq', defaultSql: '', nullable: false },
          { name: 'id', typeSql: 'text', defaultSql: '', nullable: false },
          { name: 'name', typeSql: 'eql_v3.text_ord', defaultSql: '', nullable: false },
        ],
        { columns: ['id'] },
      ),
    ];
  }
}

MigrationCLI.run(import.meta.url, M);

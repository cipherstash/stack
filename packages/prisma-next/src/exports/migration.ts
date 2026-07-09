/**
 * Public migration-time entry point for the cipherstash extension.
 *
 * Re-exports the user-callable factory functions used in hand-written
 * migrations (or auto-imported by the planner-generated `migration.ts`)
 * to wire EQL search-config rows alongside structural DDL:
 *
 * ```ts
 * import { Migration, MigrationCLI } from '@prisma-next/target-postgres/migration';
 * import { cipherstashAddSearchConfig } from '@cipherstash/prisma-next/migration';
 *
 * export default class M extends Migration {
 *   override get operations() {
 *     return [
 *       this.createTable({
 *         schema: 'public',
 *         table: 'user',
 *         columns: [
 *           { name: 'email', typeSql: 'eql_v2_encrypted', defaultSql: '', nullable: false },
 *           { name: 'id', typeSql: 'text', defaultSql: '', nullable: false },
 *         ],
 *       }),
 *       cipherstashAddSearchConfig({ table: 'user', column: 'email', index: 'unique' }),
 *     ];
 *   }
 * }
 *
 * MigrationCLI.run(import.meta.url, M);
 * ```
 *
 * Identical ergonomics to the `this.createTable` / `this.setNotNull`
 * methods on the `Migration` base class from
 * `@prisma-next/target-postgres/migration` (the bare op factory
 * functions were removed in Prisma Next 0.14). The codec lifecycle hook
 * for `Encrypted<string>` columns calls these factories automatically
 * when planning a contract diff.
 */

export type {
  CipherstashSearchConfigArgs,
  CipherstashSearchIndex,
} from '../migration/call-classes'
export {
  cipherstashAddSearchConfig,
  cipherstashRemoveSearchConfig,
} from '../migration/call-classes'

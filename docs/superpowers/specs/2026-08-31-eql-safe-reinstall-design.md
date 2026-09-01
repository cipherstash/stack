# EQL safe reinstall — durable data and reconstructed indexes

Status: proposed
Date: 2026-08-31
Issues: cipherstash/stack#959, cipherstash/stack#918
ADR: `docs/adr/0001-eql-data-survives-disposable-schema-reinstall.md`

## 1. Goal

Make the existing drop-and-reinstall lifecycle safe without introducing
object-by-object upgrade scripts. Every encrypted application table, column,
domain type, and stored value must survive. Functional search indexes are
captured and rebuilt as derived state. Dependencies that cannot be reconstructed
mechanically stop the operation before the first destructive statement.

## 2. Persistence boundary

### Durable

- Application tables and rows.
- Columns typed with any data-bearing `public.eql_v3_*` domain.
- The bytes stored in those columns.
- The data-bearing public domains themselves.

### Disposable

- `eql_v3` and `eql_v3_internal`.
- Query-operand domains, functions, operators, aggregates, and internal term
  types owned by those schemas.

### Reconstructable

- Functional indexes whose complete definitions can be obtained with
  `pg_get_indexdef()`.

### Fail-closed

- RLS policies, constraints, views, generated expressions, triggers, and any
  other customer-owned object depending on disposable EQL machinery.
- Unknown dependency classes.

## 3. EQL artifact requirements

The installer and uninstaller may continue dropping the EQL-owned schemas with
`CASCADE`. They must never explicitly drop a `public.eql_v3_*` data-bearing
domain. Every data-bearing domain must be idempotently retained when it already
exists.

The SQLx lifecycle suite must discover every installed data-bearing public EQL
domain from PostgreSQL's catalog. For each domain it must create an application
table, insert a real cipherstash-client-generated payload accepted by that
domain, uninstall, reinstall, and prove that the table, column type, row count,
and JSONB value are unchanged.

## 4. CLI reinstall protocol

`stash eql upgrade` and force-install use one protocol:

The protocol runs inside a schema-migration maintenance window. Its advisory
lock serializes cooperating EQL lifecycle commands; it cannot serialize
arbitrary DDL issued by unrelated PostgreSQL sessions without superuser-only
event triggers. Application migrations must not run concurrently.

1. Acquire an advisory lock preventing concurrent EQL lifecycle operations.
2. Discover every customer-owned object with a dependency path to
   `eql_v3` or `eql_v3_internal`.
3. Partition dependencies into reconstructable functional indexes and
   fail-closed objects.
4. If any fail-closed or unknown dependency exists, print an inventory and exit
   before executing installer SQL.
5. Capture each index's identity and `pg_get_indexdef()` output, including
   schema-qualified table and index names.
6. Begin one transaction, execute the shipped installer, and recreate captured
   indexes before commit. Use the original definition by default; any
   concurrent-rebuild mode must account explicitly for PostgreSQL's transaction
   restrictions.
7. `ANALYZE` affected tables.
8. Verify every captured index exists, is valid and ready, and still has the
   exact server-rendered definition captured before replacement. Query-level
   engagement remains the responsibility of `stash eql validate`, which has
   the application schema needed to construct representative predicates.
9. Commit only after verification, then release the advisory lock.

If installer execution or index reconstruction fails, the transaction rolls
back to the previous schemas and indexes. The command exits non-zero and prints
the exact captured definition. It must never report a successful upgrade while
an index is absent or invalid.

## 5. Dependency discovery

Discovery follows `pg_depend` transitively from objects in the two disposable
schemas to customer-owned objects. It must not rely only on `pg_indexes`, because
that misses policies, views, constraints, generated expressions, and indirect
dependencies.

The classifier is an allowlist: only ordinary functional indexes with a complete
server-rendered definition are automatically reconstructable. Every unrecognised
class is fail-closed.

Uniqueness, predicates, included columns, tablespaces,
storage parameters, quoting, and non-`public` application schemas require test
coverage before their corresponding index form enters the allowlist.

## 6. Acceptance criteria

- The lifecycle test covers every installed data-bearing public EQL domain with
  real encrypted fixtures and passes on every supported PostgreSQL version.
- Uninstall and reinstall preserve table OIDs, column identities, domain types,
  row counts, and stored JSONB values.
- A reinstall with no external dependencies succeeds normally.
- A reinstall with supported functional indexes rebuilds and validates them.
- Unique, partial, expression, quoted-name, and non-public-schema
  index cases are either proven safe or rejected before mutation.
- Partitioned indexes are rejected before mutation. Rebuilding their attachment
  tree can exhaust PostgreSQL's default lock table inside the bundle transaction.
- A policy, constraint, view, generated column, trigger, or unknown dependency
  aborts before schema drop and appears in the diagnostic inventory.
- Installer failure leaves the previous installation and indexes intact.
- Index reconstruction failure is non-zero, names the index and rolls back the
  entire replacement.
- Re-running after a failed reconstruction is safe and deterministic.

## 7. Explicit non-goals

- Versioned object-by-object EQL upgrade scripts.
- Immutable per-release implementation schemas.
- Preserving functional index OIDs across reinstall.
- Automatically rewriting customer policies, constraints, or views.

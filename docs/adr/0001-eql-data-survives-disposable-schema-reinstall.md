---
status: accepted
---

# Keep encrypted data durable and EQL schemas disposable

EQL data-bearing domains live in `public` and must survive install, uninstall,
and reinstall, while the `eql_v3` and `eql_v3_internal` schemas remain disposable
and may be dropped with `CASCADE`. Search indexes are derived state: tooling must
capture, rebuild, and verify them around reinstall. Tooling must refuse before
mutation when it finds customer-owned dependencies such as policies,
constraints, or views that it cannot reconstruct safely. This follows the EQL
v2 persistence boundary and deliberately rejects brittle object-by-object
in-place upgrades and permanently versioned implementation schemas.

Schema replacement, index reconstruction, and verification are one PostgreSQL
transaction. A failed reconstruction therefore restores the previous EQL
schemas and indexes instead of leaving a partially upgraded database.

## Consequences

- Losing an encrypted application column or stored encrypted value during any
  EQL lifecycle operation is a correctness failure.
- Reinstall may incur an explicit, potentially expensive index rebuild.
- Index restoration failures are loud and actionable; they never degrade
  silently to sequential scans.
- Changes that make an existing index definition invalid require operator
  intervention rather than guessed migration semantics.
- Reinstall requires a schema-migration maintenance window: the advisory lock
  serializes EQL lifecycle commands, but ordinary PostgreSQL roles cannot block
  arbitrary application DDL globally. Do not create, alter, or drop EQL-backed
  indexes while reinstall is running.

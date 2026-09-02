---
"stash": minor
---

Preserve encrypted data and reconstruct functional indexes when reinstalling EQL v3, while refusing unsupported external dependencies before mutation.

`stash eql install` and `stash eql upgrade` now capture dependent functional
indexes before replacing the disposable EQL schemas, then restore and verify
their definitions, clustering, replica-identity role, comments, explicit
statistics targets, and health in the same transaction. A
reconstruction failure rolls the replacement back.
PostgreSQL derives index ownership from the table owner, so reinstall verifies
the resulting owner and rolls back on a mismatch rather than independently
restoring ownership.
Unsupported dependencies—including views, policies, constraints, and
partitioned indexes—are named and refused before mutation.

Reinstall remains a maintenance-window operation: its advisory lock serializes
`stash` lifecycle commands, not unrelated database DDL. Generated EQL migrations
contain the raw bundle and do not include these reinstall protections.

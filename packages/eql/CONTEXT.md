# Encrypt Query Language

EQL defines the PostgreSQL representation and query surface for searchable
encrypted values.

## Language

**Encrypted data**:
Ciphertext and search terms stored in an application table column. Its continued
existence is the primary persistence guarantee.
_Avoid_: EQL machinery, index state

**Data-bearing domain**:
A durable `public.eql_v3_*` PostgreSQL domain used as an application column type.
It must survive EQL install, uninstall, and reinstall.
_Avoid_: Query domain, EQL schema type

**EQL machinery**:
Disposable functions, query-operand types, operators, aggregates, and internal
types owned by the `eql_v3` and `eql_v3_internal` schemas.
_Avoid_: Encrypted data

**Derived search index**:
A reconstructable functional index over EQL machinery. It accelerates encrypted
queries but is not the authoritative copy of encrypted data.
_Avoid_: Encrypted data, durable data

**Non-reconstructable dependency**:
A customer-owned constraint, policy, view, or other database object whose
meaning cannot be safely inferred and recreated by the EQL installer.
_Avoid_: Derived search index

**EQL installation state**:
A consistent observation of installed EQL generations, their versions, the
health of comparable EQL machinery, and the ORE state. When the installed EQL
version differs from the observing tool's pinned bundle, health is not
comparable; version skew is not evidence of damage.
_Avoid_: Installation status, database state

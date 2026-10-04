# Context Map

## Contexts

- [EQL](./packages/eql/CONTEXT.md) — defines the PostgreSQL objects that store
  and query encrypted values.
- [Stack Encrypt](./packages/stack-encrypt/CONTEXT.md) — encrypts values under
  per-value ZeroKMS data keys and derives searchable terms from them, for Rust
  and, through a WASI guest, Go.

## Relationships

- **EQL → Stack CLI**: EQL ships install and uninstall artifacts; the Stack CLI
  applies them and preserves reconstructable database objects across reinstall.
- **EQL → ORM adapters**: EQL defines durable encrypted column domains and
  disposable query machinery; adapters create application columns and derived
  search indexes against that surface.
- **Stack Encrypt → EQL**: Stack Encrypt seals values and renders the ZeroKMS
  descriptor; EQL's `eql-bindings` transcodes those into EQL payloads, and its
  `Identifier` (a table and a column) is a two-segment Stack Encrypt `Label`.

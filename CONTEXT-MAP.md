# Context Map

## Contexts

- [EQL](./packages/eql/CONTEXT.md) — defines the PostgreSQL objects that store
  and query encrypted values.

## Relationships

- **EQL → Stack CLI**: EQL ships install and uninstall artifacts; the Stack CLI
  applies them and preserves reconstructable database objects across reinstall.
- **EQL → ORM adapters**: EQL defines durable encrypted column domains and
  disposable query machinery; adapters create application columns and derived
  search indexes against that surface.

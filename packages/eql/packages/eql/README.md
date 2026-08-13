# @cipherstash/eql

Canonical EQL v3 TypeScript wire types, JSON Schemas, and SQL release assets.

```ts
import type { IntegerEq, TextSearch } from '@cipherstash/eql'
import { schemaId } from '@cipherstash/eql/schema'
import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
```

The generated TypeScript types and JSON Schemas come from the Rust
`eql-bindings` crate. The SQL files bundled in a published package are built
from the same repository commit and release identity as the generated bindings.

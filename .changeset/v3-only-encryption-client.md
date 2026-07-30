---
'@cipherstash/stack': major
'@cipherstash/stack-supabase': major
'@cipherstash/stack-prisma': major
'stash': patch
---

Make `Encryption` and schema authoring EQL v3-only. The client now always writes
EQL v3, exposes the single generic `EncryptionClient<S>` type, and removes the
legacy v2 builders, client aliases, `config.eqlVersion`, and `./client` subpath.

Native decrypt operations continue to read stored EQL v2 payloads. DynamoDB
legacy reads now use a v3 table descriptor with `{ storedEqlVersion: 2 }`.
Update the Supabase and Prisma Next integrations and the bundled agent skills
for the consolidated API.

# EQL — Encrypt Query Language

Index and search encrypted data in PostgreSQL with SQL.

EQL provides the database-side types, operators, and index machinery for CipherStash searchable encryption. Encryption and decryption are performed by an encryption client — [CipherStash Stack](https://github.com/cipherstash/stack) or [CipherStash Proxy](https://github.com/cipherstash/proxy) — while EQL makes the resulting ciphertext queryable (equality, ordering, text search, JSONB containment) without decrypting it.

> **Note:** The version published to dbdev may lag the [GitHub releases](https://github.com/cipherstash/encrypt-query-language/releases). For the latest version, install the SQL bundle directly from a GitHub release.

## Links

- [Full documentation and installation guide](https://github.com/cipherstash/encrypt-query-language#readme)
- [Releases](https://github.com/cipherstash/encrypt-query-language/releases)
- [Issues](https://github.com/cipherstash/encrypt-query-language/issues)
- [CipherStash documentation](https://cipherstash.com/docs)

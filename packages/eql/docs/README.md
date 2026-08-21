# EQL documentation

This directory contains the documentation for the Encrypt Query Language (EQL).

## About

- [Postgres data security with CipherStash](concepts/WHY.md)

## Reference

- [EQL Functions Reference](reference/eql-functions.md) - Complete API reference for all EQL functions
- [SQL support matrix](reference/sql-support.md) - Which SQL operators and features each encrypted-domain variant enables
- [Database Indexes for Encrypted Columns](reference/database-indexes.md) - Index recipes (hash / btree / GIN), engagement rules, and build performance for encrypted columns
- [Writing fast queries against EQL columns](reference/query-performance.md) - Performance overview (points to Database Indexes)
- [Adding a Scalar Encrypted-Domain Type](reference/adding-a-scalar-encrypted-domain-type.md) - How the `eql_v3.<T>` domain families are generated
- [EQL with JSON and JSONB](reference/json-support.md)
- [EQL payload / wire format](../crates/eql-bindings/README.md) - Canonical wire types for the encrypted payload (envelope `v`/`i`/`c` and the `hm`/`op`/`ob`/`bf` index terms)
- [Client-side index configuration](https://cipherstash.com/docs/stack/cipherstash/encryption/schema) - Configuring searchable encryption in CipherStash Stack / CipherStash Proxy

## Tutorials

- [CipherStash Proxy Configuration with EQL functions](tutorials/proxy-configuration.md)

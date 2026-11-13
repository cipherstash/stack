---
'stash': minor
---

Add `stash keyset create` and `stash keyset rewrap`, for keysets held by a key vendor backend (AWS KMS, Google Cloud KMS, Azure Managed HSM, HashiCorp Vault Transit, or the static key backend). ZeroKMS users never need them.

- `stash keyset create --backend <aws|gcp|azure|vault|static> --vendor-key <ref> [--name <name>]` makes a keyset record and prints it as `CS_KEYSET_RECORD` (or `CS_KEYSET_RECORD_<NAME>`). `--backend` also takes the full names that the output gives (`aws-kms`, `gcp-kms`, `azure-managed-hsm`, `vault-transit`). The record is not secret. Pass its value to `encrypt.WithKeysetRecords` (Go) or `KeysetRecord::parse` (Rust).
- `--mode` is optional. `derived` is the default and the only key mode in this release.
- `stash keyset rewrap <record | --in file> [--vendor-key <ref>]` wraps a record's root key again, after a key rotation in the vendor or to move to another vendor key of the same backend. The keyset id does not change. Stored data is not re-keyed, and every stored value still opens.
- Credentials come from each vendor's environment chain, never from a flag. A static key is named by its environment variable (`--key-env`); without one, a new key is generated and printed as `CS_STATIC_KEY`.
- `--out <file>` writes the block with mode 0600 (`--force` to overwrite), and `--json` emits one NDJSON event.

The `stash-cli` skill documents both commands, and the `stash-zerokms` skill says that key vendor backends exist for the Rust crates and the Go SDK, and that TypeScript does not support them yet.

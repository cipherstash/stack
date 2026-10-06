# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- **`DataKeySource`, `IndexKeySource` and `FakeDataKeySource` are deleted.**
  A client library is generic over the `vitaminc-kms` key provider traits
  instead (`KeyProvider`, `IndexKeyProvider`), which `ZeroKmsKeyset`
  implements. stack-encrypt 0.3 resolves keysets through its own
  `KeysetRegistry`, and its `test-support` feature provides the fake that
  replaces `FakeDataKeySource` (`stack_encrypt::registry::fake`).
- The `test-support` feature no longer provides `FakeDataKeySource`. It
  provides `test_connection` (see Added).

### Added

- `ZeroKmsKeyset`: one ZeroKMS keyset, resolved once over a shared
  `Arc<StackKms>`, as a `vitaminc-kms` `KeyProvider<32>` and
  `IndexKeyProvider<32>`. A client library can be generic over those traits
  and run on ZeroKMS or on another data key source. It reconstructs keys
  client-and-server, isolates them per value, and binds each key to its
  descriptor. Its `KeyId` is the IV followed by the tag.
- `Error::BindingNotUtf8` and `Error::MalformedKeyId`, for a binding or a
  key id that `ZeroKmsKeyset` cannot use.
- `test_connection` (with `test-support`): the in-memory
  `ZeroKMSConnection` the crate's own tests use, with its client-key and
  load-keyset fixtures. stack-encrypt owns `impl KeysetRegistry for
  Arc<StackKms>` and tests it through this, without a network.

### Changed

- `vitaminc-kms` is a git dependency until vitaminc releases the key
  provider traits (cipherstash/vitaminc#352). Until then this crate cannot
  be published.

## [0.1.0] - 2026-10-04

The first crates.io release.

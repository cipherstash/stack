# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ZeroKmsKeyset`: one ZeroKMS keyset, resolved once over a shared
  `Arc<StackKms>`, as a `vitaminc-kms` `KeyProvider<32>` and
  `IndexKeyProvider<32>`. A client library can be generic over those traits
  and run on ZeroKMS or on another data key source. It reconstructs keys
  client-and-server, isolates them per value, and binds each key to its
  descriptor. Its `KeyId` is the IV followed by the tag.
- `Error::BindingNotUtf8` and `Error::MalformedKeyId`, for a binding or a
  key id that `ZeroKmsKeyset` cannot use.

### Changed

- `vitaminc-kms` is a git dependency until vitaminc releases the key
  provider traits (cipherstash/vitaminc#352). Until then this crate cannot
  be published.

## [0.1.0] - 2026-10-04

The first crates.io release.

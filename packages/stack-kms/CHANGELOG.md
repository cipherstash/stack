# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-27

### Breaking

- Requires stack-auth 0.44 and stack-profile 0.44.

### Features

- Every error carries a `stack_kms::*` miette code (listed in
  `ERROR_CODES`), help, and structured fields through the shared
  `ErrorPayload`. Re-exports `diagnostic` and `ErrorPayload`.
- `DeterministicSource` (behind `test-support`), a key source whose keys are
  a function of a seed and the descriptor, for fixtures that hold real sealed
  bytes. It refuses a wrong context as ZeroKMS does, as `Forbidden`.

### Fixes

- The HTTP client refuses TLS chains carrying the compromised eMudhra CA
  keys, through stack-auth's `tls::client_config`.

## [0.1.0] - 2026-10-04

- First release.

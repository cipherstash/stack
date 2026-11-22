# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-27

### Breaking

- Requires stack-auth 0.44 and stack-profile 0.44.
- A key source states which kind it is, with the new `KeySourceKind`
  trait. `DataKeySource` and `IndexKeySource` require the kind
  `OwnIdentity`, and `CredentialKeySource` requires the kind
  `CredentialPerCall`. A type states one kind, so a key source of both
  kinds does not compile. Before, only the docs said a key source is one
  kind or the other. To migrate, add one impl to each key source of your
  own, such as a test double:

  ```rust
  impl stack_kms::KeySourceKind for MyKeySource {
      type Kind = stack_kms::OwnIdentity;
  }
  ```

  `StackKms` needs no change: its kind is the kind of its auth strategy
  (`stack_auth::StrategyKind`). The test doubles of this crate state
  theirs. Re-exports `CredentialPerCall` beside `OwnIdentity`.

### Features

- Every error carries a `stack_kms::*` miette code (listed in
  `ERROR_CODES`), help, and structured fields through the shared
  `ErrorPayload`. Re-exports `diagnostic` and `ErrorPayload`.
- `ProfileKeyProvider`, a key provider that reads `secretkey.json` from the
  CLI's profile directory. `for_workspace(&crn)` reads the key of the
  workspace you name. `for_detected_workspace()` reads the key of the
  workspace `CS_WORKSPACE_CRN` names, or of the CLI's current workspace if
  that variable is not set. Native targets with the `profile` feature.
- `ClientKey::generate_for_test()` (behind `test-support`) returns a random,
  well-formed client key for tests.
- Re-exports `UnverifiedContextValue`, the type of one value in an
  `UnverifiedContext`. A crate that builds an unverified context no longer
  needs its own dependency on `zerokms-protocol`.
- `DeterministicSource` (behind `test-support`), a key source whose keys are
  a function of a seed and the descriptor, for fixtures that hold real sealed
  bytes. It refuses a wrong context as ZeroKMS does, as `Forbidden`.
- `CredentialKeySource`, a key source that makes each request with a
  credential handed in with the call: `generate_keys_with_credential`,
  `retrieve_keys_with_credential` and `load_index_key_with_credential`.
  ZeroKMS then serves and logs the request as that caller. Re-exports
  `SecretToken`, the type of a credential, and `OwnIdentity`, the identity
  of a key source that has one of its own. Both are stack-auth's types.
- A key source is one kind or the other. One with an identity of its own
  implements `DataKeySource` and `IndexKeySource`. One that takes a
  credential with each call implements `CredentialKeySource`, and has no
  request without one. So code that forgets a credential does not compile,
  and neither does code that passes one to a key source that would ignore
  it. `StackKms` is the first kind over a `stack_auth::AuthStrategy`, and
  the second over a `stack_auth::CredentialAuthStrategy`, where it has the
  inherent methods `generate_keys_with_credential`,
  `retrieve_keys_with_credential` and `load_keyset_with_credential`
  instead of the plain ones.
- `StackKmsBuilder` and `StackKms::connect` no longer require the auth
  strategy to be an `AuthStrategy`, so that they also build a client over
  a `CredentialAuthStrategy`.
- `FakeCredentialKeySource` (behind `test-support`), the test double of a
  `CredentialKeySource`. It records the credential of each request, and
  `credentials_seen()` lists them. `FakeDataKeySource` is unchanged.

### Fixes

- The HTTP client refuses TLS chains carrying the compromised eMudhra CA
  keys, through stack-auth's `tls::client_config`.

## [0.1.0] - 2026-10-04

- First release.

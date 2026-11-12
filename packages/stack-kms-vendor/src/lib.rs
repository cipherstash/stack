#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! Key vendor backends for Stack Encrypt (ADR-0013, ADR-0014).
//!
//! A **key vendor backend** is a key backend that is not ZeroKMS: AWS KMS,
//! Azure Key Vault, HashiCorp Vault Transit, Google Cloud KMS, or a static
//! key. This crate holds what every vendor shares, so that a vendor crate
//! implements one small trait and nothing else:
//!
//! * [`KeyVendorBackend`]: the vendor seam. A vendor wraps and unwraps a
//!   key under its vendor key, with associated data. That is all.
//! * [`KeysetRecord`]: the customer-held description of a keyset in a key
//!   vendor backend. It is an opaque, versioned string that the customer
//!   keeps in config or in an environment variable.
//! * [`VendorKeySource`]: the adapter that turns one vendor and its keyset
//!   records into a [`DataKeySource`](stack_kms::DataKeySource) and an
//!   [`IndexKeySource`](stack_kms::IndexKeySource). Vendor crates never
//!   implement the stack-kms traits themselves.
//! * [`KeyRouter`]: ZeroKMS and at most one key vendor backend in one key
//!   source, routed by keyset.
//! * [`StaticKeyVendor`]: the static key backend, for development or for
//!   customers who manage the key themselves.
//! * [`bound`]: associated data bound by us, for a vendor key that has
//!   none of its own. The Vault Transit and Azure Key Vault clients use it
//!   for every key.
//! * [`retry`]: one vendor call, with backoff on
//!   [`Throttled`](stack_kms::BackendErrorKind::Throttled).
//! * [`CachedToken`]: keeps the credential a login returns, and gets a new
//!   one before it expires. Every vendor crate caches its credentials with
//!   it, and shares [`AccessToken`] and [`CredentialError`] too.
//! * [`VendorTransport`]: the HTTP seam a vendor client sends through, of
//!   the same shape as [`ZeroKMSConnection`](stack_kms::ZeroKMSConnection),
//!   so the same vendor code runs on native Rust and in the WASI guest.
//!   `HttpVendorTransport` (feature `http`, native only) is the native
//!   implementation; the WASI guest's lives in `stack-guest-abi`.
//!
//! The crate changes nothing in `stack-encrypt`. A cipher uses a key vendor
//! backend through the `stack-kms` traits it already uses for ZeroKMS, and
//! seals the same v1 leaf.
//!
//! # The key mode
//!
//! This release has one key mode, **derived data key**
//! ([`KeyMode::Derived`](stack_kms::KeyMode::Derived)). The keyset record
//! holds the wrapped root key. The adapter unwraps it and keeps it for a
//! TTL ([`DEFAULT_ROOT_KEY_TTL`]). Each data key is `HKDF-SHA256(root key,
//! salt = iv, info = keyset id ‖ vendor ‖ mode ‖ descriptor)`, and the index
//! key is derived from the root key under a separate label.
//!
//! See [`derive`](mod@derive) for the exact derivations and associated data.
//!
//! # Capability matrix
//!
//! A key vendor backend works at less than ZeroKMS parity. This section
//! states each difference. It describes the code of this crate, of the
//! vendor crates (`stack-kms-aws`, `stack-kms-gcp`, `stack-kms-azure`,
//! `stack-kms-vault`) and of the Go module, whose WASI guest runs the same
//! vendor code.
//!
//! **The trade-off.** The root key is cached for the TTL, and the index key
//! for as long as the cipher keeps the keyset. Postgres holds no usable key
//! material.
//!
//! ## Key lifetime and refusal
//!
//! | | ZeroKMS | Derived data key |
//! |---|---|---|
//! | Keys in application memory | The index key of a keyset, until the cipher's bounded cache evicts it. Each data key, for one settle. | The root key of a keyset, for the root key TTL ([`DEFAULT_ROOT_KEY_TTL`], 5 minutes; set it with [`VendorKeySource::with_root_key_ttl`]). The index key of a keyset, until the cipher's bounded cache evicts it, as for ZeroKMS. Each data key, for one settle. |
//! | Key backend calls for a settle of N values in one keyset | One request for each 500 keys (`stack_kms::DEFAULT_KEYS_PER_REQ`). The index key loads once, then stays in the cache. | 0 while the root key is cached, else 1 root key unwrap. The index key loads once, then stays in the cache. |
//! | What the key backend can refuse | Each request. ZeroKMS also checks the key context (lock context) and the decryption policy of each data key. | The root key unwrap only. A running process sees a refusal when its cached root key expires: at most one TTL later. After that it can no longer seal or open a value of the keyset, but a cipher that holds the keyset's index key can still build its query terms until the cache evicts the keyset. |
//!
//! A root key unwrap is tried up to 5 times, with backoff on
//! [`Throttled`](stack_kms::BackendErrorKind::Throttled) ([`RetryOptions`]).
//! Every other failure fails the request.
//!
//! ## Backends
//!
//! | Backend ([`KeyVendor::name`](stack_kms::KeyVendor::name)) | The root key unwrap | How the associated data is bound |
//! |---|---|---|
//! | ZeroKMS (`zerokms`) | n/a | n/a |
//! | AWS KMS (`aws-kms`) | 1 `Decrypt` | Natively, as the encryption context: `cipherstash:aad` is all of the associated data; `cipherstash:purpose` and `cipherstash:keyset-id` are readable copies. |
//! | Google Cloud KMS (`gcp-kms`) | 1 `decrypt` | Natively, as `additionalAuthenticatedData`, with CRC32C checks on every field. |
//! | Azure Key Vault, RSA key (`azure-key-vault`) | 1 `unwrapkey` (RSA-OAEP-256) | By us ([`bound`]): Azure wraps the key with a digest of the associated data, and the client checks the digest after the unwrap. |
//! | Azure Managed HSM, `oct-HSM` key (`azure-key-vault`) | 1 `unwrapkey` (A256KW) | By us ([`bound`]), as for an RSA key. |
//! | Vault Transit, derived key (`vault-transit`) | 1 `decrypt` | By us ([`bound`]), and also natively: the client sends all of the associated data as the key derivation `context`. |
//! | Vault Transit, non-derived key (`vault-transit`) | 1 `decrypt` | By us ([`bound`]) only. Vault ignores `context` on a non-derived key. |
//! | Static key (`static`) | in the process | Natively, as the AES-256-GCM associated data. |
//!
//! Creating or rewrapping a record costs one wrap call (and one unwrap for
//! a rewrap). First use of a key costs one more call: with the default
//! `KeyDerivation::Detect`, the Vault client reads each Transit key once
//! per process; the Azure client reads each key once per client to learn
//! its current version and type, unless the key reference names a version
//! and `AzureKeyVaultConfig::with_algorithm` is set.
//!
//! **What the vendor sees.** A vendor sees each root key it wraps or
//! unwraps. It holds the vendor key, so it could unwrap that key anyway. No
//! vendor ever sees a data key, a plaintext value or a search term. Of the
//! associated data, AWS KMS gets all of it, with the keyset id and the
//! purpose in readable form for CloudTrail and for
//! `kms:EncryptionContext:` key policy conditions. Google Cloud KMS gets
//! all of it. Vault gets all of it as `context` for a derived key, and only
//! its digest inside the wrapped plaintext for a non-derived key. Azure
//! gets only its digest inside the wrapped plaintext: Azure does not see or
//! log the binding, so a wrapped root key moved to another record unwraps
//! at Azure and is then refused by the client as
//! [`InvalidCiphertext`](stack_kms::BackendErrorKind::InvalidCiphertext).
//! The static key backend runs in the process: nothing outside it can see,
//! refuse or audit a use of the key.
//!
//! ## ZeroKMS-only features
//!
//! A key vendor backend refuses these with
//! [`Error::ZeroKmsOnly`](stack_kms::Error::ZeroKmsOnly). It never ignores
//! them ([`ZeroKmsFeature`](stack_kms::ZeroKmsFeature)):
//!
//! * a non-empty key context: a lock context, or tags and identity claims
//!   bound into the data key;
//! * a decryption policy;
//! * a non-empty unverified context.
//!
//! A cipher holds ZeroKMS and at most one key vendor backend ([`KeyRouter`]).
//! A sealed leaf names its keyset and no backend, so the router sends it to
//! the backend that holds that keyset. A value sealed under one backend
//! never opens under another, and there is no migration between backends.
//!
//! ## Credentials
//!
//! | Backend | Native Rust (`from_env`) | Go (the host supplies short-lived credentials before each request) |
//! |---|---|---|
//! | AWS KMS | Static keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), then web identity (IRSA), then the ECS or EKS container endpoint, then IMDSv2. Not read: `~/.aws` config and credentials files, profiles, SSO, `credential_process`. | `AWSCredentialSource`: `AWSCredentialsFunc` over the AWS SDK's chain, or `AWSCredentialsFromEnv`. |
//! | Google Cloud KMS | `GOOGLE_OAUTH_ACCESS_TOKEN`, then a service account key file (`GOOGLE_APPLICATION_CREDENTIALS`, feature `service-account`), then the metadata server. Not supported: `authorized_user` and `external_account` files, impersonation. | `AccessTokenSource` for the Cloud KMS scope: `OAuth2AccessTokens` or `AccessTokenFunc`. |
//! | Azure Key Vault and Managed HSM | `AZURE_KEY_VAULT_ACCESS_TOKEN`, then a client secret, then workload identity (`AZURE_FEDERATED_TOKEN_FILE`), then managed identity (App Service, else IMDS). Not supported: client certificates, Azure CLI, Azure Arc, Service Fabric. | `AccessTokenSource` for the scope the client names (Key Vault or Managed HSM): `AccessTokenFunc` over azidentity. |
//! | Vault Transit | `VAULT_TOKEN`, then AppRole (`VAULT_APPROLE_ROLE_ID` and `VAULT_APPROLE_SECRET_ID`), then Kubernetes auth (`VAULT_KUBERNETES_ROLE`). | `AccessTokenSource` with an empty scope: `AccessTokenFunc` over the Vault API client. |
//! | Static key | [`StaticKeyVendor::new`] takes the key. | `StaticKey.Key`, which `NewClient` wipes. |
//!
//! The web identity, container, IMDS, metadata server, workload identity,
//! managed identity and Kubernetes sources read files or reach instance
//! metadata, so they are native only. The Go guest holds no credential
//! between requests and never signs with a long-lived key: it does no RSA
//! and reads no service account key. `stash keyset` uses the native chains,
//! except for Google Cloud, where it reads `GOOGLE_OAUTH_ACCESS_TOKEN` or the
//! metadata server and refuses a service account key file.
//!
//! ## Rotation
//!
//! * **AWS KMS.** AWS rotates the key material behind one key ARN. A stored
//!   wrapped key names the material that made it, so nothing changes in the
//!   records or the data.
//! * **Google Cloud KMS.** `encrypt` uses the primary version, or the
//!   version a `…/cryptoKeyVersions/{n}` key reference names. Each stored
//!   wrapped key holds its version (`stack_kms_gcp::wrapped_key_version`).
//!   Keep a version enabled while stored keys use it.
//! * **Azure.** Each stored wrapped key holds its version and algorithm
//!   (`stack_kms_azure::wrapped_key_version`). A client reads the current
//!   version of an unversioned key reference once and wraps under it for
//!   its life, so it sees a new version after a restart, or after a wrap
//!   fails and it reads the key again. Keep a version enabled while stored
//!   keys use it.
//! * **Vault Transit.** `encrypt` uses the latest key version. Each stored
//!   wrapped key holds its version. `VaultTransit::rewrap` moves one wrapped
//!   key to the latest version inside Vault. Do not raise the key's minimum
//!   decryption version past a version that stored keys still use.
//! * **Static key.** Hold the old and the new key
//!   ([`StaticKeyVendor::with_key`]), rewrap every record under the new
//!   key reference, then drop the old key.
//!
//! [`KeysetRecord::rewrap`] (and `stash keyset rewrap`) wraps the root key
//! of a record again. It does not re-key stored values. A record may move
//! to any key of its backend: every data key comes from the root key.
//!
//! ## Known limits
//!
//! * **All vendors.** TypeScript (`@cipherstash/stack`) cannot use a key
//!   vendor backend yet; only Rust and Go can. No SDK reads the
//!   `CS_KEYSET_RECORD*` variables that `stash keyset` prints: pass the
//!   record to [`KeysetRecord::parse`] or Go's `WithKeysetRecords`.
//! * **AWS KMS.** An AWS error code with no fixed mapping on a 4xx status is
//!   [`AccessDenied`](stack_kms::BackendErrorKind::AccessDenied), so a
//!   malformed request reads as a refusal. `LimitExceededException` is a
//!   quota, not a throttle, and is not retried.
//! * **Google Cloud KMS.** The service account login (feature
//!   `service-account`, a default feature) signs a JWT with the `rsa` crate,
//!   which has the open advisory RUSTSEC-2023-0071 (the Marvin timing
//!   attack). A build without default features has no RSA code; the Go
//!   guest and `@cipherstash/auth` build it that way. Cloud KMS answers
//!   `PERMISSION_DENIED` for a key the caller may not see, so a missing key
//!   often reads as `AccessDenied`, not `NotFound`. The fixtures are
//!   written by hand, and the live test has not run yet.
//! * **Azure.** A 400 `BadParameter` on an `unwrapkey` is
//!   [`InvalidCiphertext`](stack_kms::BackendErrorKind::InvalidCiphertext),
//!   because Azure gives no finer code; a `BadParameter` for another reason
//!   reads the same. A key reference must be on one of the six Azure Key
//!   Vault and Managed HSM DNS suffixes. A 429 waits for `Retry-After`, at
//!   most 30 seconds, before the retry. The fixtures are written by hand,
//!   and the live test has not run yet.
//! * **Vault Transit.** The native transport trusts the operating system's
//!   certificate store only. It does not read `VAULT_CACERT` and sends no
//!   mTLS client certificate, so a Vault with a private CA works only when
//!   that CA is in the system store (or with your own [`VendorTransport`];
//!   in Go, the client's `WithTransport` round tripper). A 400 maps to a
//!   kind by Vault's error text. Do not give the token `create` on
//!   `<mount>/encrypt/<key>`: Transit then creates a missing key.
//! * **Static key.** The key is always in memory.

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
#![warn(clippy::mem_forget)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
#![warn(unreachable_pub)]
#![warn(unused_results)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]

pub mod bound;
mod credential;
pub mod derive;
mod error;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod http;
mod record;
mod retry;
mod router;
mod source;
mod static_key;
mod transport;
mod vendor;

#[cfg(feature = "test-support")]
pub mod contract;
#[cfg(feature = "test-support")]
mod fake;
#[cfg(feature = "test-support")]
pub mod replay;

pub use credential::{
    system_clock, AccessToken, CachedToken, Clock, CredentialError, CredentialKind, Expiring,
    Expiry, FetchCredential, DEFAULT_REFRESH_BEFORE_EXPIRY,
};
pub use error::RecordError;
pub use record::{KeysetRecord, RECORD_FORMAT_VERSION, RECORD_PREFIX};
pub use retry::{retry, RetryOptions};
pub use router::KeyRouter;
pub use source::{VendorKeySource, DEFAULT_ROOT_KEY_TTL};
pub use static_key::StaticKeyVendor;
pub use transport::{
    classify_status, TransportError, VendorRequest, VendorResponse, VendorTransport,
};
pub use vendor::{KeyBytes, KeyVendorBackend};

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use http::{HttpVendorTransport, HttpVendorTransportOptions, DEFAULT_REQUEST_TIMEOUT};

#[cfg(feature = "test-support")]
pub use fake::{FakeVendor, FakeVendorCalls};

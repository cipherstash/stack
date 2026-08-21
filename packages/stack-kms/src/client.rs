use std::borrow::Cow;
use uuid::Uuid;
use zerokms_protocol::{
    GenerateKeyRequest, GenerateKeySpec, GeneratedKey, IdentifiedBy, Keyset, LoadKeysetRequest,
    LoadKeysetResponse, RetrieveKeyRequest, RetrieveKeyRequestFallible, RetrieveKeySpec,
    RetrievedKey, UnverifiedContext, ViturRequest, ViturRequestError,
};

use recipher::key::Iv;
use stack_auth::{AuthStrategy, AuthStrategyBounds};
use vitaminc::random::{Generatable, SafeRand};

use crate::connection::{HttpConnection, HttpConnectionOpts, ZeroKMSConnection};
use crate::errors::{Error, GenerateKeyError, LoadKeysetError, RetrieveKeyError};
use crate::futures::map_async_chunked;
use crate::key::{ClientKey, DataKey, DataKeyWithTag, IndexKey};
use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};

/// Default [`ClientOpts::max_keys_per_req`].
pub const DEFAULT_KEYS_PER_REQ: usize = 500;
/// Default [`ClientOpts::max_concurrent_reqs`].
pub const DEFAULT_CONCURRENT_REQS: usize = 5;

/// Returned when a [`ClientOpts`] limit is set to a value the client can't
/// operate with (currently: a zero `max_keys_per_req` or `max_concurrent_reqs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Invalid client options: {0}")]
pub struct InvalidClientOpts(&'static str);

/// Options for configuring certain behaviours of the [`Client`].
///
/// You should generally use the [`StackKmsBuilder`](crate::StackKmsBuilder) to
/// create a configured instance rather than instantiating this struct directly.
///
/// The limits are validated by the `with_*` setters, so a `ClientOpts` value
/// is always usable: a zero `max_keys_per_req` would panic in `slice::chunks`
/// and a zero `max_concurrent_reqs` would leave the request stream pending
/// forever, so both are rejected at construction rather than at call time.
pub struct ClientOpts<CONNOPTS> {
    max_keys_per_req: usize,
    max_concurrent_reqs: usize,
    connection_opts: CONNOPTS,
}

impl<CONNOPTS> ClientOpts<CONNOPTS> {
    /// Options with the default limits ([`DEFAULT_KEYS_PER_REQ`] keys per
    /// request, [`DEFAULT_CONCURRENT_REQS`] concurrent requests) and the given
    /// connection options.
    pub fn new(connection_opts: CONNOPTS) -> Self {
        Self {
            max_keys_per_req: DEFAULT_KEYS_PER_REQ,
            max_concurrent_reqs: DEFAULT_CONCURRENT_REQS,
            connection_opts,
        }
    }

    /// The maximum number of key specs in each generate or retrieve request to
    /// ZeroKMS. Too large a number can exceed reqwest's max body size. Must be
    /// at least 1.
    pub fn with_max_keys_per_req(mut self, max_keys: usize) -> Result<Self, InvalidClientOpts> {
        if max_keys == 0 {
            return Err(InvalidClientOpts("max_keys_per_req must be at least 1"));
        }
        self.max_keys_per_req = max_keys;
        Ok(self)
    }

    /// The maximum number of requests spun up per call to `generate_keys` or
    /// `retrieve_keys`. Too many concurrent requests can result in dropped
    /// connections which fail the calls. Must be at least 1.
    pub fn with_max_concurrent_reqs(
        mut self,
        max_concurrent: usize,
    ) -> Result<Self, InvalidClientOpts> {
        if max_concurrent == 0 {
            return Err(InvalidClientOpts("max_concurrent_reqs must be at least 1"));
        }
        self.max_concurrent_reqs = max_concurrent;
        Ok(self)
    }

    /// The maximum number of key specs per request.
    pub fn max_keys_per_req(&self) -> usize {
        self.max_keys_per_req
    }

    /// The maximum number of concurrent requests per key operation.
    pub fn max_concurrent_reqs(&self) -> usize {
        self.max_concurrent_reqs
    }

    /// The connection options used to initialize the ZeroKMS connection.
    pub fn connection_opts(&self) -> &CONNOPTS {
        &self.connection_opts
    }
}

/// Low-level client for ZeroKMS key generation and retrieval.
///
/// The client is generic over the transport [`ZeroKMSConnection`]; the default
/// [`HttpConnection`] talks to a real ZeroKMS endpoint. Each method takes an
/// access token directly — see [`StackKms`] for the high-level wrapper that
/// fetches and refreshes tokens via [`stack_auth`].
pub struct Client<C = HttpConnection> {
    connection: C,
    max_keys_per_req: usize,
    max_concurrent_reqs: usize,
}

/// Returned by the [`Client::retrieve_keys_fallible`] method.
pub type FallibleDataKeyVec = Vec<Result<DataKey, RetrieveKeyError>>;

impl<C> Client<C> {
    /// Returns a reference to the underlying connection.
    pub(crate) fn connection(&self) -> &C {
        &self.connection
    }
}

impl<C: ZeroKMSConnection + Send + Sync> Client<C> {
    pub fn init_opts(opts: ClientOpts<C::ConnectionOpts>) -> Result<Self, C::Error> {
        let connection = C::init(opts.connection_opts)?;

        Ok(Self {
            connection,
            max_keys_per_req: opts.max_keys_per_req,
            max_concurrent_reqs: opts.max_concurrent_reqs,
        })
    }

    /// Shared scaffolding for the batch operations: split `specs` into chunks
    /// of at most `max_keys_per_req`, send up to `max_concurrent_reqs` chunks
    /// to ZeroKMS at once, check that every response carries exactly one entry
    /// per spec, and zip the entries back onto their specs — in order — with
    /// `map_key`.
    ///
    /// `operation` is recorded as a field on the per-chunk trace lines, so
    /// operators can filter by operation (`retrieve_keys`,
    /// `retrieve_keys_fallible`, `generate_keys`). It is a field rather than a
    /// `tracing` target because `tracing` targets are baked into static
    /// callsite metadata and so must be literals.
    #[allow(clippy::too_many_arguments)]
    async fn send_chunked<'a, Spec, Req, Item, Out, E>(
        &self,
        operation: &'static str,
        specs: &'a [Spec],
        access_token: &str,
        make_request: impl Fn(&'a [Spec]) -> Req + Sync,
        response_keys: impl Fn(Req::Response) -> Vec<Item> + Sync,
        map_key: impl Fn(&'a Spec, Item) -> Out + Sync,
        count_mismatch: impl Fn(usize, usize) -> E + Sync,
    ) -> Result<Vec<Out>, E>
    where
        Spec: Send + Sync,
        Req: ViturRequest,
        E: From<ViturRequestError> + std::fmt::Display,
    {
        let result = map_async_chunked(
            specs,
            |chunk| async {
                tracing::trace!(target: "stack_kms::client", operation, "sending request with {} keys", chunk.len());

                let keys = self
                    .connection
                    .send(make_request(chunk), access_token)
                    .await
                    .map(&response_keys)
                    .map_err(E::from)?;

                // This should never happen with ZeroKMS but check just to be sure.
                if keys.len() != chunk.len() {
                    return Err(count_mismatch(chunk.len(), keys.len()));
                }

                tracing::trace!(target: "stack_kms::client", operation, "received {} keys - creating data keys", keys.len());

                Ok(chunk
                    .iter()
                    .zip(keys)
                    .map(|(spec, item)| map_key(spec, item))
                    .collect())
            },
            self.max_keys_per_req,
            self.max_concurrent_reqs,
        )
        .await;

        match &result {
            Err(x) => {
                tracing::trace!(target: "stack_kms::client", operation, "failed with error: {x}")
            }
            Ok(x) => {
                tracing::trace!(target: "stack_kms::client", operation, "successfully processed {} keys", x.len())
            }
        }

        result
    }

    /// Retrieve multiple data keys for an iterator of [`RetrieveKeyPayload`].
    pub async fn retrieve_keys(
        &self,
        keys: impl IntoIterator<Item = RetrieveKeyPayload<'_>>,
        key: &ClientKey,
        keyset_id: Option<Uuid>,
        access_token: &str,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, RetrieveKeyError> {
        tracing::trace!(target: "stack_kms::retrieve_keys", "preparing payloads");

        let keys = keys
            .into_iter()
            .map(RetrieveKeySpec::from)
            .collect::<Vec<_>>();

        tracing::trace!(target: "stack_kms::retrieve_keys", max_keys_per_req = self.max_keys_per_req, max_parallel_reqs = self.max_concurrent_reqs);

        self.send_chunked(
            "retrieve_keys",
            &keys,
            access_token,
            |keys| RetrieveKeyRequest {
                keys: keys.into(),
                keyset_id: keyset_id.map(Into::into),
                client_id: key.key_id,
                unverified_context: unverified_context.cloned().unwrap_or_default(),
            },
            |res| res.keys,
            |RetrieveKeySpec { iv, .. }, RetrievedKey { key_material }| {
                DataKey::from_key_material(key, iv.into_inner(), &key_material)
            },
            |expected, received| RetrieveKeyError::InvalidNumberOfKeys { expected, received },
        )
        .await
    }

    /// Retrieve multiple data keys, returning a per-key result so partial failures
    /// don't fail the whole batch.
    pub async fn retrieve_keys_fallible<'a>(
        &self,
        keys: impl IntoIterator<Item = RetrieveKeyPayload<'_>>,
        client_key: &ClientKey,
        keyset_id: Option<Uuid>,
        access_token: &str,
        unverified_context: Option<Cow<'a, UnverifiedContext>>,
    ) -> Result<FallibleDataKeyVec, RetrieveKeyError> {
        tracing::trace!(target: "stack_kms::retrieve_keys_fallible", "preparing payloads");

        let keys = keys
            .into_iter()
            .map(RetrieveKeySpec::from)
            .collect::<Vec<_>>();

        tracing::trace!(target: "stack_kms::retrieve_keys_fallible", max_keys_per_req = self.max_keys_per_req, max_parallel_reqs = self.max_concurrent_reqs);

        self.send_chunked(
            "retrieve_keys_fallible",
            &keys,
            access_token,
            |keys| RetrieveKeyRequestFallible {
                keys: keys.into(),
                keyset_id: keyset_id.map(Into::into),
                client_id: client_key.key_id,
                unverified_context: unverified_context.clone().unwrap_or_default(),
            },
            |res| res.keys,
            |RetrieveKeySpec { iv, .. }, result| {
                result
                    .map(|key| {
                        // If the key retrieval was successful, we create a DataKey from the key material
                        DataKey::from_key_material(client_key, iv.into_inner(), &key.key_material)
                    })
                    .map_err(RetrieveKeyError::FailedRetrieval)
            },
            |expected, received| RetrieveKeyError::InvalidNumberOfKeys { expected, received },
        )
        .await
    }

    /// Load a keyset and derive its [`IndexKey`] from the returned partial
    /// keyset-root key material. If `keyset_id` is `None`, the client's default
    /// keyset is loaded.
    pub async fn load_keyset(
        &self,
        client_key: &ClientKey,
        keyset_id: Option<IdentifiedBy>,
        access_token: &str,
    ) -> Result<(Keyset, IndexKey), LoadKeysetError> {
        let req = LoadKeysetRequest {
            client_id: client_key.key_id,
            keyset_id,
        };

        let LoadKeysetResponse {
            keyset,
            partial_index_key,
        } = self.connection.send(req, access_token).await?;

        let index_key = IndexKey::from_key_material(client_key, &partial_index_key.key_material);

        Ok((keyset, index_key))
    }

    /// Generate multiple data keys for an iterator of [`GenerateKeyPayload`].
    pub async fn generate_keys<'a>(
        &self,
        keys: impl IntoIterator<Item = GenerateKeyPayload<'_>>,
        client_key: &ClientKey,
        keyset_id: Option<Uuid>,
        access_token: &str,
        unverified_context: Option<Cow<'a, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, GenerateKeyError> {
        let keys = {
            // Security: use vitaminc's `SafeRand` (CSPRNG) for IV generation
            // rather than `rand::thread_rng()`.
            let mut rng = SafeRand::from_entropy().map_err(GenerateKeyError::GenerateIv)?;

            keys.into_iter()
                .map(
                    |GenerateKeyPayload {
                         descriptor,
                         context,
                         decryption_policy,
                     }| {
                        let iv: Iv =
                            Generatable::random(&mut rng).map_err(GenerateKeyError::GenerateIv)?;
                        Ok(if let Some(policy) = decryption_policy {
                            GenerateKeySpec::new_with_policy(iv, descriptor, policy)
                        } else {
                            // `context` is owned by this closure and used once — move it.
                            GenerateKeySpec::new_with_context(iv, descriptor, context)
                        })
                    },
                )
                .collect::<Result<Vec<_>, GenerateKeyError>>()?
        };

        tracing::trace!(target: "stack_kms::generate_keys", "generated {} key payloads", keys.len());
        tracing::trace!(target: "stack_kms::generate_keys", max_keys_per_req = self.max_keys_per_req, max_parallel_reqs = self.max_concurrent_reqs);

        self.send_chunked(
            "generate_keys",
            &keys,
            access_token,
            |keys| GenerateKeyRequest {
                keys: keys.into(),
                keyset_id: keyset_id.map(Into::into),
                client_id: client_key.key_id,
                unverified_context: unverified_context.clone().unwrap_or_default(),
            },
            |res| res.keys,
            |GenerateKeySpec { iv, .. },
             GeneratedKey {
                 key_material,
                 tag,
                 decryption_policy,
             }| {
                DataKeyWithTag::from_key_material(
                    client_key,
                    iv.into_inner(),
                    &key_material,
                    tag,
                    decryption_policy,
                )
            },
            |expected, received| GenerateKeyError::InvalidNumberOfKeys { expected, received },
        )
        .await
    }
}

/// High-level client for generating and retrieving ZeroKMS data keys.
///
/// `StackKms` owns the transport [`Client`], a [`stack_auth`] credential
/// provider, and a [`ClientKey`]. Each operation fetches a fresh access token
/// (refreshing as needed), resolves the ZeroKMS endpoint from the token's
/// `services` claim on first use, and delegates to the low-level client.
///
/// Build one with [`StackKmsBuilder`](crate::StackKmsBuilder).
pub struct StackKms<C> {
    client: Client<HttpConnection>,
    credentials: C,
    client_key: ClientKey,
}

impl<C> StackKms<C>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: AuthStrategy,
{
    pub(crate) fn connect(
        opts: ClientOpts<HttpConnectionOpts>,
        credentials: C,
        client_key: ClientKey,
    ) -> Result<Self, Error> {
        let client = Client::init_opts(opts)?;
        Ok(Self {
            client,
            credentials,
            client_key,
        })
    }

    /// Fetch a token from the credentials provider and ensure the ZeroKMS base
    /// URL has been resolved on the connection (from the token's `services`
    /// claim). The URL is only resolved once; subsequent calls skip resolution.
    async fn get_token(&self) -> Result<stack_auth::ServiceToken, Error> {
        let token = (&self.credentials).get_token().await?;
        if !self.client.connection().has_base_url() {
            let endpoint = crate::endpoint::ZeroKmsEndpoint::try_from(token.zerokms_url()?)?;
            tracing::debug!(
                target: "stack_kms",
                %endpoint,
                "resolved ZeroKMS endpoint from the token's services claim"
            );
            self.client.connection().ensure_base_url(endpoint);
        }
        Ok(token)
    }

    /// The [`ClientKey`] this client uses to derive data keys.
    pub fn client_key(&self) -> &ClientKey {
        &self.client_key
    }

    /// Generate multiple data keys for an iterator of [`GenerateKeyPayload`].
    pub async fn generate_keys<'a>(
        &self,
        payloads: impl IntoIterator<Item = GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'a, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        let token = self.get_token().await?;

        self.client
            .generate_keys(
                payloads,
                &self.client_key,
                keyset_id,
                token.as_str(),
                unverified_context,
            )
            .await
            .map_err(Error::from)
    }

    /// Retrieve multiple data keys for an iterator of [`RetrieveKeyPayload`].
    pub async fn retrieve_keys(
        &self,
        payloads: impl IntoIterator<Item = RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        let token = self.get_token().await?;

        self.client
            .retrieve_keys(
                payloads,
                &self.client_key,
                keyset_id,
                token.as_str(),
                unverified_context,
            )
            .await
            .map_err(Error::from)
    }

    /// Load a keyset and derive its [`IndexKey`] — the deterministic per-keyset
    /// key used to generate index terms (Searchable Encrypted Metadata). If
    /// `keyset_id` is `None`, the client's default keyset is loaded; the
    /// returned [`Keyset`] carries the resolved id.
    pub async fn load_keyset(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Keyset, IndexKey), Error> {
        let token = self.get_token().await?;

        let (keyset, index_key) = self
            .client
            .load_keyset(&self.client_key, keyset_id, token.as_str())
            .await?;

        debug!(target: "stack_kms::load_keyset", "loaded keyset: [{}]({})", keyset.id, keyset.name);

        Ok((keyset, index_key))
    }

    /// Retrieve multiple data keys, returning a per-key result so partial
    /// failures don't fail the whole batch.
    pub async fn retrieve_keys_fallible<'a>(
        &self,
        payloads: impl IntoIterator<Item = RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'a, UnverifiedContext>>,
    ) -> Result<FallibleDataKeyVec, Error> {
        let token = self.get_token().await?;

        tracing::debug!(target: "stack_kms::retrieve_keys_fallible", "got token, retrieving keys");
        self.client
            .retrieve_keys_fallible(
                payloads,
                &self.client_key,
                keyset_id,
                token.as_str(),
                unverified_context,
            )
            .await
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod test_connection;

#[cfg(test)]
mod tests {
    use super::test_connection::*;
    use super::*;
    use crate::key::V1KeySet;
    use recipher::keyset::{EncryptionKeySet, ProxyKeySet};
    use std::borrow::Cow;
    use uuid::uuid;
    use zerokms_protocol::{
        GenerateKeyResponse, GeneratedKey, RetrieveKeyResponse, RetrievedKey, ViturKeyMaterial,
    };

    fn random_client_key() -> ClientKey {
        let domain_key = EncryptionKeySet::generate().unwrap();
        let authority_key = EncryptionKeySet::generate().unwrap();
        let keyset = ProxyKeySet::generate(&authority_key, &domain_key);

        ClientKey {
            key_id: uuid!("00000000-0000-0000-0000-000000000000"),
            keyset: V1KeySet(keyset),
        }
    }

    fn build_client(
        callback: impl FnOnce(TestConnectionBuilder) -> TestConnectionBuilder,
    ) -> Client<TestConnection> {
        let builder = callback(TestConnectionBuilder::new());
        let client_opts = ClientOpts::new(builder)
            .with_max_keys_per_req(10)
            .unwrap()
            .with_max_concurrent_reqs(5)
            .unwrap();
        Client::init_opts(client_opts).expect("Failed to initialize test client")
    }

    // 528 bytes is the size of the key material returned by ZeroKMS for the
    // recipher proxy re-encryption scheme.
    fn key_material() -> ViturKeyMaterial {
        ViturKeyMaterial::from(vec![7u8; 528])
    }

    fn generated_key(tag: Vec<u8>) -> GeneratedKey {
        GeneratedKey {
            key_material: key_material(),
            tag,
            decryption_policy: None,
        }
    }

    fn policy(claim: &str, value: &str) -> zerokms_protocol::DecryptionPolicy {
        zerokms_protocol::DecryptionPolicy {
            conditions: vec![zerokms_protocol::PolicyCondition {
                claim: claim.to_string(),
                value: Some(value.to_string()),
            }],
        }
    }

    mod client_opts {
        use super::*;

        #[test]
        fn defaults_to_the_documented_limits() {
            let opts = ClientOpts::new(());
            assert_eq!(opts.max_keys_per_req(), DEFAULT_KEYS_PER_REQ);
            assert_eq!(opts.max_concurrent_reqs(), DEFAULT_CONCURRENT_REQS);
        }

        #[test]
        fn rejects_zero_max_keys_per_req() {
            let err = ClientOpts::new(())
                .with_max_keys_per_req(0)
                .err()
                .expect("zero must be rejected");
            assert!(err.to_string().contains("max_keys_per_req"), "{err}");
        }

        #[test]
        fn rejects_zero_max_concurrent_reqs() {
            let err = ClientOpts::new(())
                .with_max_concurrent_reqs(0)
                .err()
                .expect("zero must be rejected");
            assert!(err.to_string().contains("max_concurrent_reqs"), "{err}");
        }

        #[test]
        fn accepts_positive_limits() {
            let opts = ClientOpts::new(())
                .with_max_keys_per_req(1)
                .unwrap()
                .with_max_concurrent_reqs(1)
                .unwrap();
            assert_eq!(opts.max_keys_per_req(), 1);
            assert_eq!(opts.max_concurrent_reqs(), 1);
        }
    }

    mod count_mismatch {
        use super::*;

        #[tokio::test]
        async fn generate_keys_rejects_a_short_response() {
            let client_key = random_client_key();
            // Ask for two, stub a response with only one.
            let client = build_client(|builder| {
                builder.add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                    keys: vec![generated_key(vec![1])],
                })
            });

            let err = client
                .generate_keys(
                    vec![
                        GenerateKeyPayload::new("a", Cow::Owned(vec![])),
                        GenerateKeyPayload::new("b", Cow::Owned(vec![])),
                    ],
                    &client_key,
                    None,
                    "token",
                    None,
                )
                .await
                .expect_err("count mismatch must be an error");

            assert!(
                matches!(
                    err,
                    GenerateKeyError::InvalidNumberOfKeys {
                        expected: 2,
                        received: 1
                    }
                ),
                "expected InvalidNumberOfKeys, got: {err:?}"
            );
        }

        #[tokio::test]
        async fn retrieve_keys_rejects_a_short_response() {
            let client_key = random_client_key();
            let client = build_client(|builder| {
                builder.add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                    keys: vec![],
                })
            });

            let err = client
                .retrieve_keys(
                    vec![RetrieveKeyPayload::new(Iv::default(), "a", &[1])],
                    &client_key,
                    None,
                    "token",
                    None,
                )
                .await
                .expect_err("count mismatch must be an error");

            assert!(
                matches!(
                    err,
                    RetrieveKeyError::InvalidNumberOfKeys {
                        expected: 1,
                        received: 0
                    }
                ),
                "expected InvalidNumberOfKeys, got: {err:?}"
            );
        }

        #[tokio::test]
        async fn retrieve_keys_fallible_rejects_a_short_response() {
            let client_key = random_client_key();
            let client = build_client(|builder| {
                builder.add_success_response::<RetrieveKeyRequestFallible>(
                    zerokms_protocol::RetrieveKeyResponseFallible { keys: vec![] },
                )
            });

            let err = client
                .retrieve_keys_fallible(
                    vec![RetrieveKeyPayload::new(Iv::default(), "a", &[1])],
                    &client_key,
                    None,
                    "token",
                    None,
                )
                .await
                .expect_err("count mismatch must be an error");

            assert!(
                matches!(
                    err,
                    RetrieveKeyError::InvalidNumberOfKeys {
                        expected: 1,
                        received: 0
                    }
                ),
                "expected InvalidNumberOfKeys, got: {err:?}"
            );
        }
    }

    mod transport_errors {
        use super::*;
        use zerokms_protocol::{ViturRequestError, ViturRequestErrorKind};

        fn vitur_error(kind: ViturRequestErrorKind) -> ViturRequestError {
            ViturRequestError::new(kind, "stubbed", std::io::Error::other("boom"))
        }

        #[tokio::test]
        async fn generate_keys_classifies_a_forbidden_response() {
            let client_key = random_client_key();
            let client = build_client(|builder| {
                builder.add_failed_response::<GenerateKeyRequest>(vitur_error(
                    ViturRequestErrorKind::Forbidden,
                ))
            });

            let err = client
                .generate_keys(
                    vec![GenerateKeyPayload::new("a", Cow::Owned(vec![]))],
                    &client_key,
                    None,
                    "token",
                    None,
                )
                .await
                .expect_err("a failed request must surface");

            assert!(
                matches!(err, GenerateKeyError::Forbidden),
                "expected Forbidden, got: {err:?}"
            );
        }

        #[tokio::test]
        async fn retrieve_keys_wraps_the_transport_error() {
            let client_key = random_client_key();
            let client = build_client(|builder| {
                builder.add_failed_response::<RetrieveKeyRequest>(vitur_error(
                    ViturRequestErrorKind::SendRequest,
                ))
            });

            let err = client
                .retrieve_keys(
                    vec![RetrieveKeyPayload::new(Iv::default(), "a", &[1])],
                    &client_key,
                    None,
                    "token",
                    None,
                )
                .await
                .expect_err("a failed request must surface");

            assert!(
                matches!(
                    &err,
                    RetrieveKeyError::RequestFailed(e)
                        if matches!(e.kind, ViturRequestErrorKind::SendRequest)
                ),
                "expected RequestFailed(SendRequest), got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn generate_keys_forwards_the_decryption_policy_and_returns_the_resolved_one() {
        use std::sync::{Arc, Mutex};

        let client_key = random_client_key();
        let requested = policy("sub", "alice");
        // ZeroKMS fills in `None` claim values; simulate a resolved policy that
        // differs from the request to prove the *response* policy is returned.
        let resolved = policy("sub", "alice-resolved");

        let seen: Arc<Mutex<Option<GenerateKeyRequest<'static>>>> = Arc::new(Mutex::new(None));
        let seen_in_effect = seen.clone();

        let client = build_client(|builder| {
            builder
                .add_effect::<GenerateKeyRequest, _>(move |req| {
                    *seen_in_effect.lock().unwrap() = Some(req);
                })
                .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                    keys: vec![
                        GeneratedKey {
                            key_material: key_material(),
                            tag: vec![1],
                            decryption_policy: Some(resolved.clone()),
                        },
                        generated_key(vec![2]),
                    ],
                })
        });

        let ctx = vec![zerokms_protocol::Context::Tag("dropped-with-policy".into())];
        let keys = client
            .generate_keys(
                vec![
                    GenerateKeyPayload::new("a", Cow::Borrowed(&ctx))
                        .with_decryption_policy(requested.clone()),
                    GenerateKeyPayload::new("b", Cow::Borrowed(&ctx)),
                ],
                &client_key,
                None,
                "token",
                None,
            )
            .await
            .expect("generate_keys should succeed");

        // Request side: the policy-bearing spec carries the policy and no
        // context; the plain spec carries the context and no policy.
        let req = seen
            .lock()
            .unwrap()
            .take()
            .expect("the effect should have captured the request");
        assert_eq!(req.keys.len(), 2);
        assert_eq!(req.keys[0].decryption_policy.as_ref(), Some(&requested));
        assert!(req.keys[0].context.is_empty());
        assert!(req.keys[1].decryption_policy.is_none());
        assert_eq!(req.keys[1].context.len(), 1);

        // Response side: the resolved policy lands on the returned key.
        assert_eq!(keys[0].decryption_policy.as_ref(), Some(&resolved));
        assert!(keys[1].decryption_policy.is_none());
    }

    #[tokio::test]
    async fn generate_keys_returns_a_key_per_payload() {
        let client_key = random_client_key();

        let client = build_client(|builder| {
            builder.add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                keys: vec![
                    GeneratedKey {
                        key_material: key_material(),
                        tag: vec![1, 2, 3],
                        decryption_policy: None,
                    },
                    GeneratedKey {
                        key_material: key_material(),
                        tag: vec![4, 5, 6],
                        decryption_policy: None,
                    },
                ],
            })
        });

        let payloads = vec![
            GenerateKeyPayload::new("a", Cow::Owned(vec![])),
            GenerateKeyPayload::new("b", Cow::Owned(vec![])),
        ];

        let keys = client
            .generate_keys(payloads, &client_key, None, "token", None)
            .await
            .expect("generate_keys should succeed");

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].tag, vec![1, 2, 3]);
        assert_eq!(keys[1].tag, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn retrieve_keys_returns_a_key_per_payload() {
        let client_key = random_client_key();

        let client = build_client(|builder| {
            builder.add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                keys: vec![RetrievedKey {
                    key_material: key_material(),
                }],
            })
        });

        let iv = Iv::default();
        let payloads = vec![RetrieveKeyPayload::new(iv, "a", &[1, 2, 3])];

        let keys = client
            .retrieve_keys(payloads, &client_key, None, "token", None)
            .await
            .expect("retrieve_keys should succeed");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].iv, iv);
    }

    #[tokio::test]
    async fn generate_then_retrieve_derives_the_same_data_key() {
        let client_key = random_client_key();
        // `ViturKeyMaterial` isn't `Clone`, so build two from the same bytes —
        // ZeroKMS returns the same underlying material for generate + retrieve.
        let shared_bytes = vec![7u8; 528];

        // Generate one key.
        let gen_client = build_client(|builder| {
            builder.add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                keys: vec![GeneratedKey {
                    key_material: ViturKeyMaterial::from(shared_bytes.clone()),
                    tag: vec![9, 9, 9],
                    decryption_policy: None,
                }],
            })
        });

        let generated = gen_client
            .generate_keys(
                vec![GenerateKeyPayload::new("desc", Cow::Owned(vec![]))],
                &client_key,
                None,
                "token",
                None,
            )
            .await
            .expect("generate should succeed");

        let generated_iv = generated[0].key.iv;

        // Retrieve using the IV that was generated; ZeroKMS returns the same
        // underlying key material, so the derived DataKey must match.
        let ret_client = build_client(|builder| {
            builder.add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                keys: vec![RetrievedKey {
                    key_material: ViturKeyMaterial::from(shared_bytes.clone()),
                }],
            })
        });

        let retrieved = ret_client
            .retrieve_keys(
                vec![RetrieveKeyPayload::new(generated_iv, "desc", &[9, 9, 9])],
                &client_key,
                None,
                "token",
                None,
            )
            .await
            .expect("retrieve should succeed");

        assert_eq!(generated[0].key.key(), retrieved[0].key());
    }

    #[tokio::test]
    async fn load_keyset_derives_a_deterministic_index_key() {
        let client_key = random_client_key();
        let keyset_id = uuid!("11111111-1111-1111-1111-111111111111");
        let shared_bytes = vec![7u8; 528];

        let keyset = |material: Vec<u8>| {
            build_client(|builder| {
                builder.add_success_response::<LoadKeysetRequest>(LoadKeysetResponse {
                    partial_index_key: RetrievedKey {
                        key_material: ViturKeyMaterial::from(material),
                    },
                    keyset: Keyset {
                        id: keyset_id,
                        name: "default".to_string(),
                        description: String::new(),
                        is_disabled: false,
                        is_default: true,
                    },
                })
            })
        };

        let (loaded_a, key_a) = keyset(shared_bytes.clone())
            .load_keyset(&client_key, None, "token")
            .await
            .expect("load_keyset should succeed");
        let (_, key_b) = keyset(shared_bytes)
            .load_keyset(&client_key, Some(keyset_id.into()), "token")
            .await
            .expect("load_keyset should succeed");

        assert_eq!(loaded_a.id, keyset_id);
        // Same key material derives the same index key — write-time and
        // query-time terms must agree.
        assert_eq!(key_a.key(), key_b.key());

        // Different key material derives a different index key.
        let (_, key_c) = keyset(vec![8u8; 528])
            .load_keyset(&client_key, None, "token")
            .await
            .expect("load_keyset should succeed");
        assert_ne!(key_a.key(), key_c.key());
    }

    #[tokio::test]
    async fn retrieve_keys_fallible_surfaces_per_key_results() {
        let client_key = random_client_key();

        // One key succeeds, one fails: the batch call itself succeeds and the
        // per-key results land in payload order.
        let client = build_client(|builder| {
            builder.add_success_response::<RetrieveKeyRequestFallible>(
                zerokms_protocol::RetrieveKeyResponseFallible {
                    keys: vec![
                        Ok(RetrievedKey {
                            key_material: key_material(),
                        }),
                        Err("key not found".to_string()),
                    ],
                },
            )
        });

        let iv = Iv::default();
        let keys = client
            .retrieve_keys_fallible(
                vec![
                    RetrieveKeyPayload::new(iv, "a", &[1]),
                    RetrieveKeyPayload::new(iv, "b", &[2]),
                ],
                &client_key,
                None,
                "token",
                None,
            )
            .await
            .expect("batch call itself should succeed");

        assert_eq!(keys.len(), 2);
        assert!(keys[0].is_ok());
        assert!(
            matches!(&keys[1], Err(RetrieveKeyError::FailedRetrieval(msg)) if msg == "key not found"),
            "a per-key failure must be surfaced as FailedRetrieval, got: {:?}",
            keys[1]
        );
    }
}

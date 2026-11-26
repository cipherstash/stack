use futures::StreamExt;
use std::borrow::Cow;
use uuid::Uuid;
use zerokms_protocol::{
    GenerateKeyRequest, GenerateKeySpec, GeneratedKey, IdentifiedBy, Keyset, LoadKeysetRequest,
    LoadKeysetResponse, RetrieveKeyRequest, RetrieveKeyRequestFallible, RetrieveKeySpec,
    RetrievedKey, UnverifiedContext, ViturRequest, ViturRequestError,
};

use stack_auth::{AuthStrategy, AuthStrategyBounds, CredentialAuthStrategy, SecretToken};
use vitaminc::random::{Generatable, SafeRand};
use zerokms_keyset::key::Iv;

#[cfg(feature = "http")]
use crate::connection::HttpConnection;
use crate::connection::ZeroKMSConnection;
use crate::errors::{Error, GenerateKeyError, LoadKeysetError, RetrieveKeyError};
use crate::futures::{map_chunks_buffered, yield_now, YIELD_EVERY};
use crate::key::{ClientKey, DataKey, DataKeyWithTag, IndexKey};
use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};

/// Default [`ClientOpts::max_keys_per_req`].
pub const DEFAULT_KEYS_PER_REQ: usize = 500;
/// Default [`ClientOpts::max_concurrent_reqs`].
pub const DEFAULT_CONCURRENT_REQS: usize = 5;

/// Returned when a [`ClientOpts`] limit is set to a value the client can't
/// operate with (currently: a zero `max_keys_per_req` or `max_concurrent_reqs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[error("Invalid client options: {0}")]
#[diagnostic(code(stack_kms::invalid_client_opts))]
pub struct InvalidClientOpts(&'static str);

impl stack_auth::ErrorPayload for InvalidClientOpts {}

/// Options for configuring certain behaviours of the [`Client`].
///
// The builder is the `http` feature's entry point; without it the host
// constructs `ClientOpts` for its own transport directly.
#[cfg_attr(
    feature = "http",
    doc = "You should generally use the [`StackKmsBuilder`](crate::StackKmsBuilder) to create a configured instance rather than instantiating this struct directly.\n"
)]
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
#[cfg(feature = "http")]
pub struct Client<C = HttpConnection> {
    connection: C,
    max_keys_per_req: usize,
    max_concurrent_reqs: usize,
}

/// Low-level client for ZeroKMS key generation and retrieval, generic over
/// the transport [`ZeroKMSConnection`]. (Without the `http` feature there is
/// no default connection: the host supplies one.)
#[cfg(not(feature = "http"))]
pub struct Client<C> {
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
    /// The keys are derived outside the requests' futures, one response at a
    /// time and in order, yielding to the runtime every [`YIELD_EVERY`] keys
    /// however many requests are in flight. (Inside the futures, `buffered`
    /// would poll every ready future before it passed a yield on, so a step
    /// would derive `YIELD_EVERY` keys for each response that had arrived.)
    /// The next request goes out once a response's keys are derived, while
    /// the others are still in flight, so at most `max_concurrent_reqs`
    /// responses' wrapped material is held at a time.
    ///
    /// A wasm guest's host performs every request of a step before it
    /// resumes the guest. So every response is in hand when the batch
    /// resumes, and `buffered` hands them over without polling the next
    /// requests' futures; those go out together, in one step, once the keys
    /// are derived. The `window_tests` pin this.
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
        map_key: impl Fn(&'a Spec, Item) -> Result<Out, E> + Sync,
        count_mismatch: impl Fn(usize, usize) -> E + Sync,
    ) -> Result<Vec<Out>, E>
    where
        Spec: Send + Sync,
        Req: ViturRequest,
        E: From<ViturRequestError> + std::fmt::Display,
    {
        let result: Result<Vec<Out>, E> = async {
            let mut out = Vec::with_capacity(specs.len());
            let mut responses = std::pin::pin!(map_chunks_buffered(
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
                    Ok(keys)
                },
                self.max_keys_per_req,
                self.max_concurrent_reqs,
            ));

            while let Some((chunk, keys)) = responses.next().await {
                let keys = keys?;
                tracing::trace!(target: "stack_kms::client", operation, "received {} keys - creating data keys", keys.len());

                for (spec, item) in chunk.iter().zip(keys) {
                    // `out.len()` counts across responses, so the yields keep
                    // their spacing.
                    if !out.is_empty() && out.len() % YIELD_EVERY == 0 {
                        yield_now().await;
                    }
                    out.push(map_key(spec, item)?);
                }
            }
            Ok(out)
        }
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
                    .map_err(RetrieveKeyError::from)
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
                // Both failure modes stay per-key so one bad entry doesn't
                // fail the whole fallible batch: a server-side retrieval
                // failure and invalid key material in an otherwise-successful
                // entry.
                Ok(result
                    .map_err(RetrieveKeyError::FailedRetrieval)
                    .and_then(|key| {
                        DataKey::from_key_material(client_key, iv.into_inner(), &key.key_material)
                            .map_err(RetrieveKeyError::from)
                    }))
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
        // Kept for the error: a refusal and a missing keyset name the
        // keyset the load asked for.
        let req = LoadKeysetRequest {
            client_id: client_key.key_id,
            keyset_id: keyset_id.clone(),
        };

        let LoadKeysetResponse {
            keyset,
            partial_index_key,
        } = self
            .connection
            .send(req, access_token)
            .await
            .map_err(|error| LoadKeysetError::from_request(keyset_id, error))?;

        let index_key = IndexKey::from_key_material(client_key, &partial_index_key.key_material)?;

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
                .map_err(GenerateKeyError::from)
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
/// Build one with [`StackKmsBuilder`](crate::StackKmsBuilder) (the default
/// HTTP transport, `http` feature), or with [`connect`](Self::connect) over
/// any [`ZeroKMSConnection`].
#[cfg(feature = "http")]
pub struct StackKms<C, Conn = HttpConnection> {
    client: Client<Conn>,
    credentials: C,
    client_key: ClientKey,
}

/// `StackKms` owns the transport [`Client`], a [`stack_auth`] credential
/// provider, and a [`ClientKey`]. Without the `http` feature there is no
/// default connection: build one with [`connect`](Self::connect) over the
/// host's [`ZeroKMSConnection`].
#[cfg(not(feature = "http"))]
pub struct StackKms<C, Conn> {
    client: Client<Conn>,
    credentials: C,
    client_key: ClientKey,
}

impl<C, Conn> StackKms<C, Conn>
where
    C: AuthStrategyBounds,
    Conn: ZeroKMSConnection + Send + Sync,
{
    /// Build a client over an explicit transport.
    ///
    /// This is the seam for hosts that provide their own transport (the
    /// WASI/wazero guest implements [`ZeroKMSConnection`] over a host-imported
    /// function) and the only constructor available without the `http`
    /// feature.
    #[cfg_attr(
        feature = "http",
        doc = "With it, [`StackKmsBuilder`](crate::StackKmsBuilder) is the usual way to configure the default [`HttpConnection`].\n"
    )]
    ///
    /// The connection is initialised from `opts`'s connection options; the
    /// ZeroKMS endpoint is taken from the access token's `services` claim on
    /// first use unless the connection already knows one.
    pub fn connect(
        opts: ClientOpts<Conn::ConnectionOpts>,
        credentials: C,
        client_key: ClientKey,
    ) -> Result<Self, Error> {
        let client = Client::init_opts(opts).map_err(|e| Error::ConnectionInit(Box::new(e)))?;
        Ok(Self {
            client,
            credentials,
            client_key,
        })
    }

    /// Ensure the ZeroKMS base URL has been resolved on the connection, from
    /// `token`'s `services` claim. Resolved once: every token of a workspace
    /// names the same endpoint, whichever caller it was issued for.
    fn resolve_endpoint(&self, token: &stack_auth::ServiceToken) -> Result<(), Error> {
        if !self.client.connection().has_base_url() {
            let endpoint = crate::endpoint::ZeroKmsEndpoint::try_from(token.zerokms_url()?)?;
            tracing::debug!(
                target: "stack_kms",
                %endpoint,
                "resolved ZeroKMS endpoint from the token's services claim"
            );
            self.client.connection().ensure_base_url(endpoint);
        }
        Ok(())
    }

    /// The [`ClientKey`] this client uses to derive data keys.
    pub fn client_key(&self) -> &ClientKey {
        &self.client_key
    }
}

/// Key requests made as the auth strategy's own identity
/// ([`AuthStrategy`]): an access key, a saved login, or the caller that an
/// [`OidcFederationStrategy`]'s provider names.
///
/// A client over a strategy that takes a credential with each call has none
/// of these methods, so a request cannot be made without one. It has the
/// `_with_credential` methods instead.
///
/// [`OidcFederationStrategy`]: stack_auth::OidcFederationStrategy
impl<C, Conn> StackKms<C, Conn>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: AuthStrategy,
    Conn: ZeroKMSConnection + Send + Sync,
{
    /// Fetch a token from the credentials provider and ensure the ZeroKMS base
    /// URL has been resolved on the connection (from the token's `services`
    /// claim). The URL is only resolved once; subsequent calls skip resolution.
    async fn get_token(&self) -> Result<stack_auth::ServiceToken, Error> {
        let token = (&self.credentials).get_token().await?;
        self.resolve_endpoint(&token)?;
        Ok(token)
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

        tracing::debug!(target: "stack_kms::load_keyset", "loaded keyset: [{}]({})", keyset.id, keyset.name);

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

/// Key requests made with a credential that comes with the call, for an auth
/// strategy that issues a token per credential
/// ([`CredentialAuthStrategy`]): an [`OidcFederationStrategy`] built with
/// `credential_per_call`, whose credential is the JWT of an end user. Each
/// method is its plain counterpart with one difference: the access token is
/// the one the strategy issues for `credential`, so ZeroKMS serves and logs
/// the request as that caller.
///
/// A client whose strategy has an identity of its own has none of these
/// methods, so a credential is never dropped on the way to a request.
///
/// [`OidcFederationStrategy`]: stack_auth::OidcFederationStrategy
impl<C, Conn> StackKms<C, Conn>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: CredentialAuthStrategy,
    Conn: ZeroKMSConnection + Send + Sync,
{
    /// The access token the strategy issues for `credential`, with the
    /// ZeroKMS endpoint resolved from it on first use.
    async fn get_token_with_credential(
        &self,
        credential: &SecretToken,
    ) -> Result<stack_auth::ServiceToken, Error> {
        // The strategy takes the credential by value, and keys its cache on
        // it. The copy wipes itself when the strategy drops it.
        let token = (&self.credentials)
            .get_token_with_credential(credential.clone())
            .await?;
        self.resolve_endpoint(&token)?;
        Ok(token)
    }

    /// [`generate_keys`](Self::generate_keys), made with `credential`.
    pub async fn generate_keys_with_credential<'a>(
        &self,
        credential: &SecretToken,
        payloads: impl IntoIterator<Item = GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'a, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        let token = self.get_token_with_credential(credential).await?;

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

    /// [`retrieve_keys`](Self::retrieve_keys), made with `credential`.
    pub async fn retrieve_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: impl IntoIterator<Item = RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        let token = self.get_token_with_credential(credential).await?;

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

    /// [`load_keyset`](Self::load_keyset), made with `credential`.
    pub async fn load_keyset_with_credential(
        &self,
        credential: &SecretToken,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Keyset, IndexKey), Error> {
        let token = self.get_token_with_credential(credential).await?;

        let (keyset, index_key) = self
            .client
            .load_keyset(&self.client_key, keyset_id, token.as_str())
            .await?;

        tracing::debug!(target: "stack_kms::load_keyset", "loaded keyset: [{}]({})", keyset.id, keyset.name);

        Ok((keyset, index_key))
    }
}

#[cfg(test)]
mod test_connection;

#[cfg(test)]
mod tests {
    use super::test_connection::*;
    use super::*;
    use crate::key::V1KeySet;
    use std::borrow::Cow;
    use uuid::uuid;
    use zerokms_keyset::keyset::{EncryptionKeySet, ProxyKeySet};
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
    // zerokms-keyset proxy re-encryption scheme.
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

    /// `StackKms` over an injected connection — the seam a host with its own
    /// transport (the WASI/wazero guest) builds through, and the only
    /// constructor without the `http` feature.
    mod connect_over_any_connection {
        use super::*;
        use stack_auth::StaticTokenStrategy;

        #[tokio::test]
        async fn generate_keys_round_trips_through_the_injected_connection() {
            let builder = TestConnectionBuilder::new()
                .add_effect::<GenerateKeyRequest, _>(|req| {
                    assert_eq!(req.keys.len(), 2, "both specs go to the connection");
                })
                .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                    keys: vec![generated_key(vec![1]), generated_key(vec![2])],
                });
            let opts = ClientOpts::new(builder);

            let kms = StackKms::<_, TestConnection>::connect(
                opts,
                StaticTokenStrategy::new("static-token"),
                random_client_key(),
            )
            .expect("connect over a test connection");

            let keys = kms
                .generate_keys(
                    vec![
                        GenerateKeyPayload::new("a", Cow::Owned(vec![])),
                        GenerateKeyPayload::new("b", Cow::Owned(vec![])),
                    ],
                    None,
                    None,
                )
                .await
                .expect("keys come back through the injected connection");

            assert_eq!(keys.len(), 2);
            assert_eq!(keys[0].tag, vec![1]);
            assert_eq!(keys[1].tag, vec![2]);
        }
    }

    /// Key requests that carry a credential: the access token on each
    /// request is the one the strategy issued for that request's credential.
    mod with_credential {
        use super::*;
        use crate::key_source::CredentialKeySource;
        use stack_auth::{
            AuthError, CredentialAuthStrategy, CredentialPerCall, SecretToken, ServiceToken,
            StrategyKind,
        };
        use std::sync::Mutex;

        /// A strategy with no identity of its own. It issues a token that
        /// names the credential it was handed, and records each credential.
        #[derive(Default)]
        struct PerCredential {
            asked_for: Mutex<Vec<String>>,
        }

        impl PerCredential {
            fn asked_for(&self) -> Vec<String> {
                self.asked_for.lock().unwrap().clone()
            }
        }

        impl StrategyKind for &PerCredential {
            type Kind = CredentialPerCall;
        }

        impl CredentialAuthStrategy for &PerCredential {
            async fn get_token_with_credential(
                self,
                credential: SecretToken,
            ) -> Result<ServiceToken, AuthError> {
                self.asked_for
                    .lock()
                    .unwrap()
                    .push(credential.as_str().to_string());
                Ok(ServiceToken::new(SecretToken::new(format!(
                    "token-for-{}",
                    credential.as_str()
                ))))
            }
        }

        fn load_keyset_response() -> LoadKeysetResponse {
            LoadKeysetResponse {
                partial_index_key: RetrievedKey {
                    key_material: key_material(),
                },
                keyset: Keyset {
                    id: uuid!("11111111-1111-1111-1111-111111111111"),
                    name: "default".to_string(),
                    description: String::new(),
                    is_disabled: false,
                    is_default: true,
                },
            }
        }

        fn kms(builder: TestConnectionBuilder) -> StackKms<PerCredential, TestConnection> {
            StackKms::connect(
                ClientOpts::new(builder),
                PerCredential::default(),
                random_client_key(),
            )
            .expect("connect over a test connection")
        }

        fn credential(name: &str) -> SecretToken {
            SecretToken::new(name)
        }

        /// Two callers interleaved on one client. Every kind of key request
        /// goes out under the token of the credential it was made with.
        #[tokio::test]
        async fn each_request_is_sent_with_the_token_of_its_own_credential() {
            let kms = kms(TestConnectionBuilder::new()
                .add_success_response::<LoadKeysetRequest>(load_keyset_response())
                .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                    keys: vec![generated_key(vec![1])],
                })
                .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                    keys: vec![RetrievedKey {
                        key_material: key_material(),
                    }],
                })
                .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                    keys: vec![generated_key(vec![2])],
                })
                .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                    keys: vec![RetrievedKey {
                        key_material: key_material(),
                    }],
                }));
            let (alice, bob) = (credential("alice"), credential("bob"));
            let generate = || vec![GenerateKeyPayload::new("a", Cow::Owned(vec![]))];
            let retrieve = || vec![RetrieveKeyPayload::new(Iv::default(), "a", &[1])];

            // Through the trait, as Stack Encrypt calls it.
            let _ = kms
                .load_index_key_with_credential(&alice, None)
                .await
                .expect("alice loads the keyset");
            let _ = CredentialKeySource::generate_keys_with_credential(
                &kms,
                &bob,
                generate(),
                None,
                None,
            )
            .await
            .expect("bob generates");
            let _ = CredentialKeySource::retrieve_keys_with_credential(
                &kms,
                &alice,
                retrieve(),
                None,
                None,
            )
            .await
            .expect("alice retrieves");
            let _ = CredentialKeySource::generate_keys_with_credential(
                &kms,
                &alice,
                generate(),
                None,
                None,
            )
            .await
            .expect("alice generates");
            let _ = CredentialKeySource::retrieve_keys_with_credential(
                &kms,
                &bob,
                retrieve(),
                None,
                None,
            )
            .await
            .expect("bob retrieves");

            let sent = kms.client.connection().sent().await;
            let sent: Vec<(&str, &str)> = sent
                .iter()
                .map(|(endpoint, token)| (endpoint.as_str(), token.as_str()))
                .collect();
            assert_eq!(
                sent,
                vec![
                    (LoadKeysetRequest::ENDPOINT, "token-for-alice"),
                    (GenerateKeyRequest::ENDPOINT, "token-for-bob"),
                    (RetrieveKeyRequest::ENDPOINT, "token-for-alice"),
                    (GenerateKeyRequest::ENDPOINT, "token-for-alice"),
                    (RetrieveKeyRequest::ENDPOINT, "token-for-bob"),
                ]
            );
            assert_eq!(
                kms.credentials.asked_for(),
                ["alice", "bob", "alice", "alice", "bob"],
                "the strategy is asked once per request, for that request's credential"
            );
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

        /// A data key ZeroKMS refuses (HTTP 403) carries a help that names
        /// both causes, keeping its code.
        #[tokio::test]
        async fn retrieve_keys_gives_a_refused_data_key_its_help() {
            use miette::Diagnostic;
            let client_key = random_client_key();
            let client = build_client(|builder| {
                builder.add_failed_response::<RetrieveKeyRequest>(vitur_error(
                    ViturRequestErrorKind::Forbidden,
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
                .expect_err("a refused request must surface");

            assert_eq!(
                err.code().map(|code| code.to_string()).as_deref(),
                Some("stack_kms::retrieve_key_failed")
            );
            let help = err.help().map(|help| help.to_string()).unwrap_or_default();
            assert!(help.contains("another context"), "{help}");
            assert!(help.contains("no grant for the keyset"), "{help}");
        }

        /// A keyset load ZeroKMS answers with 404 or 403 names the keyset it
        /// asked for, by name or by id, in the message.
        #[tokio::test]
        async fn load_keyset_names_the_keyset_it_asked_for() {
            let client_key = random_client_key();
            let named = Some(IdentifiedBy::Name(zerokms_protocol::Name::new_untrusted(
                "tenant-42",
            )));
            let by_id = Some(IdentifiedBy::Uuid(uuid!(
                "11111111-1111-1111-1111-111111111111"
            )));
            for (kind, keyset, shown) in [
                (
                    ViturRequestErrorKind::NotFound,
                    named.clone(),
                    r#"keyset name "tenant-42""#,
                ),
                (
                    ViturRequestErrorKind::NotFound,
                    by_id,
                    "keyset id 11111111-1111-1111-1111-111111111111",
                ),
                (
                    ViturRequestErrorKind::Forbidden,
                    named,
                    r#"keyset name "tenant-42""#,
                ),
            ] {
                let expected = format!("{kind:?}");
                let client = build_client(|builder| {
                    builder.add_failed_response::<LoadKeysetRequest>(vitur_error(kind))
                });
                let err = client
                    .load_keyset(&client_key, keyset, "token")
                    .await
                    .expect_err("a failed load must surface");
                let message = err.to_string();
                assert!(message.contains(shown), "{expected}: {message}");
                assert!(!message.contains("boom"), "{expected}: {message}");
                match err {
                    LoadKeysetError::KeysetNotFound { .. } => assert_eq!(expected, "NotFound"),
                    LoadKeysetError::Forbidden { .. } => assert_eq!(expected, "Forbidden"),
                    other => panic!("{expected}: {other:?}"),
                }
            }
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

/// How [`Client::send_chunked`] sends a batch and when it yields, polled one
/// step at a time, as a wasm guest polls it: each poll that returns pending
/// is one step, and either sends requests or yields.
#[cfg(test)]
mod window_tests {
    use super::*;
    use crate::connection::ZeroKMSConnectionInit;
    use crate::key::V1KeySet;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};
    use zerokms_keyset::keyset::{EncryptionKeySet, ProxyKeySet};
    use zerokms_protocol::{RetrieveKeyResponse, ViturKeyMaterial};

    /// Every request sent so far: how many keys it asked for, and whether
    /// the test has released it.
    #[derive(Default)]
    struct Sent {
        keys: Vec<usize>,
        released: Vec<bool>,
        wakers: Vec<Option<Waker>>,
    }

    /// A connection whose requests stay pending until the test releases
    /// them, then answer with [`material`] of the request's index for every
    /// key asked for.
    #[derive(Clone, Default)]
    struct Held(Arc<Mutex<Sent>>);

    impl Held {
        fn sent(&self) -> Vec<usize> {
            self.0.lock().unwrap().keys.clone()
        }

        /// The requests not yet released, oldest first.
        fn in_flight(&self) -> Vec<usize> {
            let sent = self.0.lock().unwrap();
            (0..sent.released.len())
                .filter(|&i| !sent.released[i])
                .collect()
        }

        fn release(&self, i: usize) {
            let mut sent = self.0.lock().unwrap();
            sent.released[i] = true;
            if let Some(waker) = sent.wakers[i].take() {
                waker.wake();
            }
        }
    }

    /// The key material in the response to the `i`th request: different for
    /// every request, so a key derived from another request's response
    /// is a different key.
    fn material(i: usize) -> ViturKeyMaterial {
        ViturKeyMaterial::from(
            (0..528)
                .map(|b| (b as u8).wrapping_mul(31).wrapping_add(i as u8))
                .collect::<Vec<u8>>(),
        )
    }

    impl ZeroKMSConnectionInit for Held {
        type ConnectionOpts = Held;
        type Error = std::convert::Infallible;

        fn init(held: Self) -> Result<Self, Self::Error> {
            Ok(held)
        }
    }

    impl ZeroKMSConnection for Held {
        async fn send<Request: ViturRequest>(
            &self,
            request: Request,
            _access_token: &str,
        ) -> Result<Request::Response, ViturRequestError> {
            let keys = serde_json::to_value(&request).unwrap()["keys"]
                .as_array()
                .expect("a request for keys")
                .len();
            let i = {
                let mut sent = self.0.lock().unwrap();
                sent.keys.push(keys);
                sent.released.push(false);
                sent.wakers.push(None);
                sent.keys.len() - 1
            };
            std::future::poll_fn(|cx| {
                let mut sent = self.0.lock().unwrap();
                if sent.released[i] {
                    Poll::Ready(())
                } else {
                    sent.wakers[i] = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
            let response = RetrieveKeyResponse {
                keys: (0..keys)
                    .map(|_| RetrievedKey {
                        key_material: material(i),
                    })
                    .collect(),
            };
            Ok(serde_json::from_value(serde_json::to_value(response).unwrap()).unwrap())
        }
    }

    struct Woken(AtomicBool);

    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// One poll of the batch that returned pending.
    #[derive(Debug, PartialEq)]
    enum Step {
        /// The poll sent requests for these numbers of keys.
        Requests(Vec<usize>),
        /// The poll sent nothing and woke itself.
        Yield,
        /// The poll sent nothing and waits for a response.
        Wait,
    }

    /// When the test answers the requests in flight.
    #[derive(Clone, Copy)]
    enum Answer {
        /// As a wasm guest's host does: every request a step sent, at once,
        /// before the next poll.
        EachStepAtOnce,
        /// Every request a step sent, before the next poll, but newest
        /// first, one at a time with a poll after each, so they finish in
        /// reverse order.
        EachStepsNewestFirst,
        /// As a network might: whenever the batch waits, the oldest request
        /// in flight.
        OldestWhenWaiting,
        /// Whenever the batch waits, the newest request in flight.
        NewestWhenWaiting,
    }

    fn iv(i: usize) -> Iv {
        let mut iv = Iv::default();
        iv[..8].copy_from_slice(&(i as u64).to_le_bytes());
        iv
    }

    /// Retrieve `keys` keys, polling one step at a time and answering
    /// requests as `answer` says. Returns the steps, and whether each key is
    /// the one derived from its own request's response.
    fn retrieve(
        answer: Answer,
        keys_per_req: usize,
        concurrent_reqs: usize,
        keys: usize,
    ) -> (Vec<Step>, Vec<bool>) {
        let held = Held::default();
        let opts = ClientOpts::new(held.clone())
            .with_max_keys_per_req(keys_per_req)
            .unwrap()
            .with_max_concurrent_reqs(concurrent_reqs)
            .unwrap();
        let client = Client::<Held>::init_opts(opts).unwrap();
        let client_key = ClientKey {
            key_id: Uuid::nil(),
            keyset: V1KeySet(ProxyKeySet::generate(
                &EncryptionKeySet::generate().unwrap(),
                &EncryptionKeySet::generate().unwrap(),
            )),
        };
        let payloads = (0..keys).map(|i| RetrieveKeyPayload::new(iv(i), "a", &[1, 2, 3]));

        let mut call = pin!(client.retrieve_keys(payloads, &client_key, None, "token", None));
        let woken = Arc::new(Woken(AtomicBool::new(false)));
        let waker = Waker::from(woken.clone());
        let mut cx = Context::from_waker(&waker);
        let mut steps = Vec::new();
        let mut seen = 0;
        let result = loop {
            woken.0.store(false, Ordering::SeqCst);
            if let Poll::Ready(result) = call.as_mut().poll(&mut cx) {
                break result;
            }
            // As a guest's step loop does: a poll that sent requests waits
            // for them; one that sent nothing yields if it woke itself.
            let sent = held.sent();
            let new = seen..sent.len();
            seen = sent.len();
            if !new.is_empty() {
                steps.push(Step::Requests(sent[new.clone()].to_vec()));
            } else if woken.0.load(Ordering::SeqCst) {
                steps.push(Step::Yield);
                continue;
            } else {
                steps.push(Step::Wait);
            }
            let in_flight = held.in_flight();
            match answer {
                Answer::EachStepAtOnce => {
                    assert!(
                        !new.is_empty(),
                        "a step that waits but sent nothing would never be resumed"
                    );
                    for i in new {
                        held.release(i);
                    }
                }
                Answer::EachStepsNewestFirst => {
                    assert!(
                        !new.is_empty(),
                        "a step that waits but sent nothing would never be resumed"
                    );
                    for i in new.clone().rev() {
                        held.release(i);
                        if i > new.start {
                            // An earlier request is still in flight, so the
                            // batch waits for it.
                            woken.0.store(false, Ordering::SeqCst);
                            assert!(call.as_mut().poll(&mut cx).is_pending());
                            assert!(!woken.0.load(Ordering::SeqCst), "nothing derived");
                            assert_eq!(held.sent().len(), seen, "nothing sent");
                        }
                    }
                }
                Answer::OldestWhenWaiting => held.release(in_flight[0]),
                Answer::NewestWhenWaiting => held.release(in_flight[in_flight.len() - 1]),
            }
        };
        let matches = result
            .expect("retrieve_keys succeeds")
            .iter()
            .enumerate()
            .map(|(k, key)| {
                let own =
                    DataKey::from_key_material(&client_key, iv(k), &material(k / keys_per_req))
                        .unwrap();
                *key == own
            })
            .collect();
        (steps, matches)
    }

    /// The requests of each step that sent any.
    fn requests(steps: &[Step]) -> Vec<&[usize]> {
        steps
            .iter()
            .filter_map(|s| match s {
                Step::Requests(r) => Some(&r[..]),
                _ => None,
            })
            .collect()
    }

    fn yields(steps: &[Step]) -> usize {
        steps.iter().filter(|s| **s == Step::Yield).count()
    }

    #[test]
    fn a_window_of_requests_goes_out_in_one_step() {
        // A guest's host answers a step's requests before resuming it. Then
        // 1,000 keys in requests of 100, 3 at a time, go out in windows of
        // 3, 3, 3 and 1 requests, each sent in one step, and each window's
        // keys are derived, yielding, before the next window is sent.
        for answer in [Answer::EachStepAtOnce, Answer::EachStepsNewestFirst] {
            let (steps, _) = retrieve(answer, 100, 3, 1000);
            assert_eq!(
                requests(&steps),
                [&[100; 3][..], &[100; 3], &[100; 3], &[100]]
            );
            let sends: Vec<usize> = steps
                .iter()
                .enumerate()
                .filter(|(_, s)| matches!(s, Step::Requests(_)))
                .map(|(i, _)| i)
                .collect();
            for pair in sends.windows(2) {
                assert!(
                    steps[pair[0] + 1..pair[1]]
                        .iter()
                        .all(|s| *s == Step::Yield)
                        && pair[1] > pair[0] + 1,
                    "a window's keys are derived, yielding, before the next window is sent: {steps:?}"
                );
            }
        }
    }

    #[test]
    fn otherwise_the_next_request_goes_out_once_a_responses_keys_are_derived() {
        // Natively, responses arrive one at a time. Then 1,000 keys in
        // requests of 100, 3 at a time, go out as 3 requests, then one more
        // as each response's keys are derived, while the other two are
        // still in flight.
        let (steps, _) = retrieve(Answer::OldestWhenWaiting, 100, 3, 1000);
        let mut expected = vec![&[100; 3][..]];
        expected.extend([&[100][..]; 7]);
        assert_eq!(requests(&steps), expected);
    }

    #[test]
    fn yields_every_yield_every_keys_however_many_requests_are_in_flight() {
        // A yield after every YIELD_EVERY keys derived, so 15 for 1,000
        // keys, whether one request is in flight or several.
        let keys = 1000;
        for concurrent_reqs in [1, 3, 5] {
            for steps in [
                retrieve(Answer::EachStepAtOnce, 100, concurrent_reqs, keys).0,
                retrieve(Answer::EachStepsNewestFirst, 100, concurrent_reqs, keys).0,
                retrieve(Answer::OldestWhenWaiting, 100, concurrent_reqs, keys).0,
                retrieve(Answer::NewestWhenWaiting, 100, concurrent_reqs, keys).0,
            ] {
                assert_eq!(
                    yields(&steps),
                    (keys - 1) / YIELD_EVERY,
                    "{concurrent_reqs} requests in flight: {steps:?}"
                );
            }
        }
    }

    #[test]
    fn each_key_comes_from_its_own_response_when_responses_arrive_in_reverse() {
        // Each response has its own key material, so a response paired with
        // another request's specs gives different keys.
        for (_, matches) in [
            retrieve(Answer::EachStepsNewestFirst, 100, 3, 1000),
            retrieve(Answer::NewestWhenWaiting, 100, 3, 1000),
        ] {
            assert_eq!(matches.len(), 1000);
            assert!(matches.iter().all(|m| *m), "{matches:?}");
        }
    }

    #[test]
    fn a_batch_smaller_than_one_request_is_one_step() {
        let (steps, matches) = retrieve(Answer::EachStepAtOnce, 500, 3, 10);
        assert_eq!(steps, [Step::Requests(vec![10])]);
        assert_eq!(matches.len(), 10);
    }
}

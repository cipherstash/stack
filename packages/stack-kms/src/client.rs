use log::{debug, trace};
use std::borrow::Cow;
use uuid::Uuid;
use zerokms_protocol::{
    GenerateKeyRequest, GenerateKeySpec, GeneratedKey, RetrieveKeyRequest,
    RetrieveKeyRequestFallible, RetrieveKeySpec, RetrievedKey, UnverifiedContext,
};

use recipher::key::{GenRandom, Iv};
use stack_auth::{AuthStrategy, AuthStrategyBounds};

use crate::connection::{HttpConnection, HttpConnectionOpts, ZeroKMSConnection};
use crate::errors::{Error, GenerateKeyError, RetrieveKeyError};
use crate::futures::map_async_chunked;
use crate::key::{ClientKey, DataKey, DataKeyWithTag};
use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};

pub(crate) const DEFAULT_KEYS_PER_REQ: usize = 500;
pub(crate) const DEFAULT_CONCURRENT_REQS: usize = 5;

/// Options for configuring certain behaviours of the [`Client`].
///
/// You should generally use the [`StackKmsBuilder`](crate::StackKmsBuilder) to create a
/// configured instance rather than instantiating this struct directly.
pub struct ClientOpts<CONNOPTS> {
    /// The maximum number of key specs that should be in each generate or retrieve request to
    /// ZeroKMS. Having too large a number of specs per request can panic by exceeding reqwest's max
    /// body size.
    pub max_keys_per_req: usize,

    /// The maximum number of requests that will be spun up per call to `generate_keys` or
    /// `retrieve_keys`. Having too large a number of concurrent requests can result in
    /// dropped connections which will fail the calls.
    pub max_concurrent_reqs: usize,

    /// The connection options to use when initializing the connection to ZeroKMS.
    pub connection_opts: CONNOPTS,
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

    /// Retrieve multiple data keys for an iterator of [`RetrieveKeyPayload`].
    pub async fn retrieve_keys(
        &self,
        keys: impl IntoIterator<Item = RetrieveKeyPayload<'_>>,
        key: &ClientKey,
        keyset_id: Option<Uuid>,
        access_token: &str,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, RetrieveKeyError> {
        trace!(target: "stack_kms::retrieve_keys", "preparing payloads");

        let keys = keys
            .into_iter()
            .map(RetrieveKeySpec::from)
            .collect::<Vec<_>>();

        tracing::trace!(target: "stack_kms::retrieve_keys", max_keys_per_req = self.max_keys_per_req, max_parallel_reqs = self.max_concurrent_reqs);

        // map_async_chunked will split the retrieve key requests up into chunks and send them to
        // ZeroKMS concurrently. The number of concurrent requests and size of the chunks are passed
        // through from ClientOpts.
        let result = map_async_chunked(
            &keys,
            |keys| async {
                let req = RetrieveKeyRequest {
                    keys: keys.into(),
                    keyset_id: keyset_id.map(Into::into),
                    client_id: key.key_id,
                    unverified_context: unverified_context.cloned().unwrap_or_default(),
                };

                trace!(target: "stack_kms::retrieve_keys", "sending request with {} keys", keys.len());

                self.connection
                    .send(req, access_token)
                    .await
                    .map_err(RetrieveKeyError::RequestFailed)
                    .and_then(|res| {
                        // This should never happen with ZeroKMS but check just to be sure.
                        if res.keys.len() != keys.len() {
                            return Err(RetrieveKeyError::InvalidNumberOfKeys {
                                expected: keys.len(),
                                received: res.keys.len(),
                            });
                        }

                        trace!(target: "stack_kms::retrieve_keys", "retrieved keys - creating data keys");

                        Ok(keys
                            .iter()
                            .zip(res.keys)
                            .map(
                                |(RetrieveKeySpec { iv, .. }, RetrievedKey { key_material })| {
                                    DataKey::from_key_material(key, iv.into_inner(), &key_material)
                                },
                            )
                            .collect())
                    })
            },
            self.max_keys_per_req,
            self.max_concurrent_reqs,
        )
        .await;

        match &result {
            Err(x) => {
                trace!(target: "stack_kms::retrieve_keys", "failed with error: {x}");
            }
            Ok(x) => {
                trace!(target: "stack_kms::retrieve_keys", "successfully retrieved {} keys", x.len());
            }
        }

        result
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
        trace!(target: "stack_kms::retrieve_keys", "preparing payloads");

        let keys = keys
            .into_iter()
            .map(RetrieveKeySpec::from)
            .collect::<Vec<_>>();

        tracing::trace!(target: "stack_kms::retrieve_keys", max_keys_per_req = self.max_keys_per_req, max_parallel_reqs = self.max_concurrent_reqs);

        // map_async_chunked will split the retrieve key requests up into chunks and send them to
        // ZeroKMS concurrently. The number of concurrent requests and size of the chunks are passed
        // through from ClientOpts.
        let result = map_async_chunked(
            &keys,
            |keys| async {
                let req = RetrieveKeyRequestFallible {
                    keys: keys.into(),
                    keyset_id: keyset_id.map(Into::into),
                    client_id: client_key.key_id,
                    unverified_context: unverified_context.clone().unwrap_or_default(),
                };

                trace!(target: "stack_kms::retrieve_keys", "sending request with {} keys", keys.len());

                self.connection
                    .send(req, access_token)
                    .await
                    .map_err(RetrieveKeyError::RequestFailed)
                    .and_then(|res| {
                        // This should never happen with ZeroKMS but check just to be sure.
                        if res.keys.len() != keys.len() {
                            return Err(RetrieveKeyError::InvalidNumberOfKeys {
                                expected: keys.len(),
                                received: res.keys.len(),
                            });
                        }

                        trace!(target: "stack_kms::retrieve_keys", "retrieved keys - creating data keys");

                        Ok(keys
                            .iter()
                            .zip(res.keys)
                            .map(|(RetrieveKeySpec { iv, .. }, result)| {
                                result
                                    .map(|key| {
                                        // If the key retrieval was successful, we create a DataKey from the key material
                                        DataKey::from_key_material(client_key, iv.into_inner(), &key.key_material)
                                    })
                                    .map_err(RetrieveKeyError::FailedRetrieval)
                            })
                            .collect())
                    })
            },
            self.max_keys_per_req,
            self.max_concurrent_reqs,
        )
        .await;

        match &result {
            Err(x) => {
                trace!(target: "stack_kms::retrieve_keys", "failed with error: {x}");
            }
            Ok(x) => {
                trace!(target: "stack_kms::retrieve_keys", "successfully retrieved {} keys", x.len());
            }
        }

        result
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
            let mut rng = rand::thread_rng();

            keys.into_iter()
                .map(
                    |GenerateKeyPayload {
                         descriptor,
                         context,
                         decryption_policy,
                     }| {
                        GenRandom::gen_random(&mut rng)
                            .map(|iv: Iv| {
                                if let Some(policy) = decryption_policy {
                                    GenerateKeySpec::new_with_policy(iv, descriptor, policy)
                                } else {
                                    GenerateKeySpec::new_with_context(
                                        iv,
                                        descriptor,
                                        context.clone(),
                                    )
                                }
                            })
                            .map_err(GenerateKeyError::GenerateIv)
                    },
                )
                .collect::<Result<Vec<_>, _>>()?
        };

        trace!(target: "stack_kms::generate_keys", "generated {} key payloads", keys.len());
        tracing::trace!(target: "stack_kms::generate_keys", max_keys_per_req = self.max_keys_per_req, max_parallel_reqs = self.max_concurrent_reqs);

        // map_async_chunked will split the generate key requests up into chunks and send them to
        // ZeroKMS concurrently. The number of concurrent requests and size of the chunks are passed
        // through from ClientOpts.
        let result = map_async_chunked(
            &keys,
            |keys| async {
                let req = GenerateKeyRequest {
                    keys: keys.into(),
                    keyset_id: keyset_id.map(Into::into),
                    client_id: client_key.key_id,
                    unverified_context: unverified_context.clone().unwrap_or_default(),
                };

                trace!(target: "stack_kms::generate_keys", "sending request with {} keys", keys.len());

                self.connection
                    .send(req, access_token)
                    .await
                    .map_err(GenerateKeyError::from)
                    .and_then(|res| {
                        // This should never happen with ZeroKMS but check just to be sure.
                        if res.keys.len() != keys.len() {
                            return Err(GenerateKeyError::InvalidNumberOfKeys {
                                expected: keys.len(),
                                received: res.keys.len(),
                            });
                        }

                        trace!(target: "stack_kms::generate_keys", "generated {} keys", keys.len());

                        Ok(keys
                            .iter()
                            .zip(res.keys)
                            .map(
                                |(
                                    GenerateKeySpec { iv, .. },
                                    GeneratedKey { key_material, tag, decryption_policy },
                                )| {
                                    DataKeyWithTag::from_key_material(client_key, iv.into_inner(), &key_material, tag, decryption_policy)
                                },
                            )
                            .collect())
                    })
            },
            self.max_keys_per_req,
            self.max_concurrent_reqs,
        )
        .await;

        match &result {
            Err(x) => {
                trace!(target: "stack_kms::generate_keys", "failed with error: {x}");
            }
            Ok(x) => {
                trace!(target: "stack_kms::generate_keys", "successfully generated {} keys", x.len());
            }
        }

        result
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
            let url = token.zerokms_url()?;
            self.client.connection().ensure_base_url(url);
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

    /// Retrieve multiple data keys, returning a per-key result so partial
    /// failures don't fail the whole batch.
    pub async fn retrieve_keys_fallible<'a>(
        &self,
        payloads: impl IntoIterator<Item = RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'a, UnverifiedContext>>,
    ) -> Result<FallibleDataKeyVec, Error> {
        let token = self.get_token().await?;

        debug!(target: "stack_kms::retrieve_keys_fallible", "got token, retrieving keys");
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
        let client_opts = ClientOpts {
            max_keys_per_req: 10,
            max_concurrent_reqs: 5,
            connection_opts: builder,
        };
        Client::init_opts(client_opts).expect("Failed to initialize test client")
    }

    // 528 bytes is the size of the key material returned by ZeroKMS for the
    // recipher proxy re-encryption scheme.
    fn key_material() -> ViturKeyMaterial {
        ViturKeyMaterial::from(vec![7u8; 528])
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
    async fn retrieve_keys_fallible_surfaces_per_key_failures() {
        let client_key = random_client_key();

        let client = build_client(|builder| {
            builder.add_success_response::<RetrieveKeyRequestFallible>(
                zerokms_protocol::RetrieveKeyResponseFallible {
                    keys: vec![Ok(RetrievedKey {
                        key_material: key_material(),
                    })],
                },
            )
        });

        let iv = Iv::default();
        let keys = client
            .retrieve_keys_fallible(
                vec![RetrieveKeyPayload::new(iv, "a", &[1])],
                &client_key,
                None,
                "token",
                None,
            )
            .await
            .expect("retrieve_keys_fallible should succeed");

        assert_eq!(keys.len(), 1);
        assert!(keys[0].is_ok());
    }
}

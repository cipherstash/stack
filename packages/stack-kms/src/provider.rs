//! ZeroKMS as a key provider: [`ZeroKmsKeyset`] implements
//! [`vitaminc_kms::KeyProvider`] and [`vitaminc_kms::IndexKeyProvider`]
//! over one resolved keyset, so a `StackCipher` generic over those traits
//! runs on ZeroKMS exactly as it runs on a vendor data key source.
//!
//! What ZeroKMS is, at the trait level:
//!
//! - `RECONSTRUCTION = ClientAndServer`: the server returns partial key
//!   material and the data key only exists after the client's own keyset
//!   re-enciphers it (`recipher`). A server-side compromise plus a stored
//!   key id does not recover a key.
//! - `ISOLATION = PerValue`: every value gets its own key, in one round
//!   trip per batch.
//! - `BINDING = Bound`: the binding is the descriptor. ZeroKMS binds it into
//!   the key server-side, refuses retrieval under a different one, and logs
//!   it per retrieval (ADR 0002 in `packages/stack-encrypt/docs/adr`).
//!
//! The [`KeyId`] is the ZeroKMS IV followed by the tag: the two halves the
//! service needs back to re-derive a key.

use std::borrow::Cow;
use std::sync::Arc;

use uuid::Uuid;
use vitaminc_kms::provider::{Binding, BindingSupport, IndexKeyProvider, KeyProvider};
use vitaminc_kms::{GeneratedDataKey, IndexKeyMaterial, KeyId, KeyIsolation, KeyReconstruction};
use vitaminc_protected_kms::Protected;
use zerokms_protocol::IdentifiedBy;

use crate::client::StackKms;
use crate::connection::ZeroKMSConnection;
use crate::errors::Error;
use crate::key::IndexKey;
use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};
use recipher::key::Iv;
use stack_auth::{AuthStrategy, AuthStrategyBounds};

/// Length of the ZeroKMS IV that leads every [`KeyId`] this provider mints.
const IV_LEN: usize = 16;

/// One ZeroKMS keyset, resolved once, as a key provider.
///
/// Holds an `Arc<StackKms>` so several keysets can share one client, its
/// credentials and its connection. Build it with [`ZeroKmsKeyset::new`].
pub struct ZeroKmsKeyset<C, Conn> {
    kms: Arc<StackKms<C, Conn>>,
    keyset_id: Uuid,
    index_key: IndexKey,
}

impl<C, Conn> ZeroKmsKeyset<C, Conn>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: AuthStrategy,
    Conn: ZeroKMSConnection + Send + Sync,
{
    /// Resolve `keyset` (by id or name; `None` is the client's default
    /// keyset) with one `load_keyset` call, which also yields the index key.
    pub async fn new(
        kms: Arc<StackKms<C, Conn>>,
        keyset: Option<IdentifiedBy>,
    ) -> Result<Self, Error> {
        let (keyset, index_key) = kms.load_keyset(keyset).await?;
        Ok(Self {
            kms,
            keyset_id: keyset.id,
            index_key,
        })
    }

    /// The resolved keyset id.
    pub fn keyset_id(&self) -> Uuid {
        self.keyset_id
    }

    /// The shared client. Several keysets can hold the same one — the
    /// sharing is this type's own business, so the borrow hands out the
    /// client, not the `Arc` around it.
    pub fn kms(&self) -> &StackKms<C, Conn> {
        &self.kms
    }

    /// ZeroKMS descriptors are strings; a binding that is not UTF-8 cannot
    /// be one.
    fn descriptor(binding: Binding<'_>) -> Result<&str, Error> {
        std::str::from_utf8(binding.as_bytes()).map_err(|_| Error::BindingNotUtf8)
    }

    /// Split a [`KeyId`] minted by this provider back into its IV and tag.
    fn split_key_id(key_id: &KeyId) -> Result<(Iv, &[u8]), Error> {
        let bytes = key_id.as_bytes();
        if bytes.len() < IV_LEN {
            return Err(Error::MalformedKeyId {
                len: bytes.len(),
                min: IV_LEN,
            });
        }
        let (iv_bytes, tag) = bytes.split_at(IV_LEN);
        let mut iv = Iv::default();
        iv.copy_from_slice(iv_bytes);
        Ok((iv, tag))
    }
}

impl<C, Conn> KeyProvider<32> for ZeroKmsKeyset<C, Conn>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: AuthStrategy,
    Conn: ZeroKMSConnection + Send + Sync,
{
    type Error = Error;

    const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ClientAndServer;
    const ISOLATION: KeyIsolation = KeyIsolation::PerValue;
    const BINDING: BindingSupport = BindingSupport::Bound;

    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<32>>, Error> {
        let payloads = bindings
            .iter()
            .map(|binding| {
                Ok(GenerateKeyPayload::new(
                    Self::descriptor(*binding)?,
                    Cow::Owned(Vec::new()),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let keys = self
            .kms
            .generate_keys(payloads, Some(self.keyset_id), None)
            .await?;

        Ok(keys
            .into_iter()
            .map(|key| {
                let mut key_id = Vec::with_capacity(IV_LEN + key.tag.len());
                key_id.extend_from_slice(&key.key.iv);
                key_id.extend_from_slice(&key.tag);
                GeneratedDataKey {
                    plaintext: Protected::new(key.key.key),
                    key_id: KeyId::new(key_id),
                }
            })
            .collect())
    }

    async fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; 32]>>, Error> {
        let payloads = keys
            .iter()
            .map(|(key_id, binding)| {
                let (iv, tag) = Self::split_key_id(key_id)?;
                Ok(RetrieveKeyPayload::new(
                    iv,
                    Self::descriptor(*binding)?,
                    tag,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let keys = self
            .kms
            .retrieve_keys(payloads, Some(self.keyset_id), None)
            .await?;

        Ok(keys
            .into_iter()
            .map(|key| Protected::new(key.key))
            .collect())
    }
}

impl<C, Conn> IndexKeyProvider<32> for ZeroKmsKeyset<C, Conn>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: AuthStrategy,
    Conn: ZeroKMSConnection + Send + Sync,
{
    type Error = Error;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<32>, Error> {
        Ok(IndexKeyMaterial(Protected::new(*self.index_key.key())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_connection::{
        generated_key, key_material, random_client_key, TestConnection, TestConnectionBuilder,
    };
    use crate::client::ClientOpts;
    use crate::key::DataKey;
    use stack_auth::StaticTokenStrategy;
    use std::sync::Mutex;
    use uuid::uuid;
    use vitaminc_protected_kms::Controlled;
    use zerokms_protocol::{
        GenerateKeyRequest, GenerateKeyResponse, Keyset, LoadKeysetRequest, LoadKeysetResponse,
        RetrieveKeyRequest, RetrieveKeyResponse, RetrievedKey,
    };

    const KEYSET_ID: Uuid = uuid!("11111111-1111-1111-1111-111111111111");

    type TestKeyset = ZeroKmsKeyset<StaticTokenStrategy, TestConnection>;

    /// The `load_keyset` response [`ZeroKmsKeyset::new`] consumes: the keyset
    /// this provider resolves to, plus the partial key material its index key
    /// is derived from.
    fn load_keyset_response() -> LoadKeysetResponse {
        LoadKeysetResponse {
            partial_index_key: RetrievedKey {
                key_material: key_material(),
            },
            keyset: Keyset {
                id: KEYSET_ID,
                name: "default".to_string(),
                description: String::new(),
                is_disabled: false,
                is_default: true,
            },
        }
    }

    /// A `StackKms` over a stub connection the callback configures. Every
    /// request a test expects must be stubbed up front — the stub panics on
    /// an unstubbed endpoint, which is what the "before any request"
    /// assertions below rely on.
    fn build_kms(
        callback: impl FnOnce(TestConnectionBuilder) -> TestConnectionBuilder,
    ) -> Arc<StackKms<StaticTokenStrategy, TestConnection>> {
        let opts = ClientOpts::new(callback(TestConnectionBuilder::new()));
        Arc::new(
            StackKms::<_, TestConnection>::connect(
                opts,
                StaticTokenStrategy::new("static-token"),
                random_client_key(),
            )
            .expect("connect over a test connection"),
        )
    }

    /// A provider whose one `load_keyset` call is already stubbed, over a
    /// connection the callback may stub further requests on.
    async fn build_keyset(
        callback: impl FnOnce(TestConnectionBuilder) -> TestConnectionBuilder,
    ) -> TestKeyset {
        let kms = build_kms(|builder| {
            callback(builder.add_success_response::<LoadKeysetRequest>(load_keyset_response()))
        });
        ZeroKmsKeyset::new(kms, None)
            .await
            .expect("the keyset resolves")
    }

    /// Captures the one request sent to an endpoint, for assertions after the
    /// call returns.
    struct Captured<R>(Arc<Mutex<Option<R>>>);

    impl<R: Send + 'static> Captured<R> {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(None)))
        }

        fn recorder(&self) -> impl FnOnce(R) + Send + 'static {
            let slot = Arc::clone(&self.0);
            move |request| *slot.lock().unwrap() = Some(request)
        }

        fn take(&self) -> R {
            self.0.lock().unwrap().take().expect("a request was sent")
        }
    }

    mod new {
        use super::*;

        #[tokio::test]
        async fn resolves_the_keyset_with_one_load_keyset_request() {
            // One `load-keyset` handler is stubbed and the stub removes it
            // once used, so a second request would panic.
            let keyset = build_keyset(|builder| builder).await;

            assert_eq!(keyset.keyset_id(), KEYSET_ID);
        }

        #[tokio::test]
        async fn load_index_key_returns_the_keysets_derived_index_key() {
            let keyset = build_keyset(|builder| builder).await;

            // The same derivation `load_keyset` performs — see
            // `load_keyset_derives_a_deterministic_index_key` in `client.rs`.
            let expected =
                IndexKey::from_key_material(keyset.kms().client_key(), &key_material()).unwrap();

            let material = keyset.load_index_key().await.unwrap();

            assert_eq!(&material.0.risky_unwrap(), expected.key());
        }

        #[tokio::test]
        async fn load_index_key_makes_no_further_request() {
            let keyset = build_keyset(|builder| builder).await;

            // The stub has no handler left, so a request here would panic.
            let first = keyset.load_index_key().await.unwrap();
            let second = keyset.load_index_key().await.unwrap();

            assert_eq!(first.0.risky_unwrap(), second.0.risky_unwrap());
        }

        #[tokio::test]
        async fn two_keysets_share_one_client() {
            let kms = build_kms(|builder| {
                builder
                    .add_success_response::<LoadKeysetRequest>(load_keyset_response())
                    .add_success_response::<LoadKeysetRequest>(load_keyset_response())
            });

            let by_default = ZeroKmsKeyset::new(Arc::clone(&kms), None).await.unwrap();
            let by_id = ZeroKmsKeyset::new(Arc::clone(&kms), Some(KEYSET_ID.into()))
                .await
                .unwrap();

            assert_eq!(by_default.keyset_id(), KEYSET_ID);
            assert_eq!(by_id.keyset_id(), KEYSET_ID);
            assert!(std::ptr::eq(by_default.kms(), by_id.kms()));
            // The two providers, plus the handle this test still holds.
            assert_eq!(Arc::strong_count(&kms), 3);
        }
    }

    mod generate_keys {
        use super::*;

        #[tokio::test]
        async fn sends_one_spec_per_binding_carrying_the_descriptor_and_keyset_id() {
            let captured = Captured::<GenerateKeyRequest<'static>>::new();
            let keyset = build_keyset(|builder| {
                builder
                    .add_effect::<GenerateKeyRequest, _>(captured.recorder())
                    .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                        keys: vec![generated_key(vec![1]), generated_key(vec![2])],
                    })
            })
            .await;

            let keys = keyset
                .generate_keys(&[Binding::from("users/email"), Binding::from("users/name")])
                .await
                .unwrap();

            let request = captured.take();
            assert_eq!(request.keys.len(), 2);
            assert_eq!(request.keys[0].descriptor, "users/email");
            assert_eq!(request.keys[1].descriptor, "users/name");
            assert_eq!(request.keyset_id, Some(IdentifiedBy::Uuid(KEYSET_ID)));
            assert_eq!(keys.len(), 2);
        }

        #[tokio::test]
        async fn key_ids_are_the_iv_followed_by_the_servers_tag() {
            let captured = Captured::<GenerateKeyRequest<'static>>::new();
            let keyset = build_keyset(|builder| {
                builder
                    .add_effect::<GenerateKeyRequest, _>(captured.recorder())
                    .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                        keys: vec![generated_key(vec![1, 2, 3]), generated_key(vec![4, 5])],
                    })
            })
            .await;

            let keys = keyset
                .generate_keys(&[Binding::from("a"), Binding::from("b")])
                .await
                .unwrap();

            let request = captured.take();
            let tags: [&[u8]; 2] = [&[1, 2, 3], &[4, 5]];
            for ((key, spec), tag) in keys.iter().zip(request.keys.iter()).zip(tags) {
                let bytes = key.key_id.as_bytes();
                assert_eq!(bytes.len(), IV_LEN + tag.len());
                assert_eq!(&bytes[..IV_LEN], spec.iv.as_ref());
                assert_eq!(&bytes[IV_LEN..], tag);
            }
        }

        #[tokio::test]
        async fn plaintext_is_what_data_key_derives_from_the_same_material() {
            let captured = Captured::<GenerateKeyRequest<'static>>::new();
            let keyset = build_keyset(|builder| {
                builder
                    .add_effect::<GenerateKeyRequest, _>(captured.recorder())
                    .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                        keys: vec![generated_key(vec![7])],
                    })
            })
            .await;

            let keys = keyset.generate_keys(&[Binding::from("a")]).await.unwrap();

            let iv = captured.take().keys[0].iv.into_inner();
            let expected =
                DataKey::from_key_material(keyset.kms().client_key(), iv, &key_material()).unwrap();

            assert_eq!(&keys[0].plaintext.clone().risky_unwrap(), expected.key());
        }

        #[tokio::test]
        async fn a_non_utf8_binding_fails_before_any_request() {
            // No `generate-data-key` handler is stubbed, so reaching the
            // connection would panic rather than return this error.
            let keyset = build_keyset(|builder| builder).await;

            // `let ... else` rather than `expect_err`: the success type
            // deliberately has no `Debug` (it holds key material).
            let Err(err) = keyset
                .generate_keys(&[Binding::from("ok"), Binding::new(&[0xff, 0xfe])])
                .await
            else {
                panic!("a non-UTF-8 binding cannot be a descriptor");
            };

            assert!(matches!(err, Error::BindingNotUtf8), "got: {err:?}");
        }
    }

    mod retrieve_keys {
        use super::*;

        fn key_id(iv: [u8; IV_LEN], tag: &[u8]) -> KeyId {
            let mut bytes = iv.to_vec();
            bytes.extend_from_slice(tag);
            KeyId::new(bytes)
        }

        #[tokio::test]
        async fn sends_the_split_iv_tag_and_binding_in_order() {
            let captured = Captured::<RetrieveKeyRequest<'static>>::new();
            let keyset = build_keyset(|builder| {
                builder
                    .add_effect::<RetrieveKeyRequest, _>(captured.recorder())
                    .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                        keys: vec![
                            RetrievedKey {
                                key_material: key_material(),
                            },
                            RetrievedKey {
                                key_material: key_material(),
                            },
                        ],
                    })
            })
            .await;

            let keys = keyset
                .retrieve_keys(&[
                    (key_id([1u8; IV_LEN], &[9, 9]), Binding::from("users/email")),
                    (key_id([2u8; IV_LEN], &[8]), Binding::from("users/name")),
                ])
                .await
                .unwrap();

            let request = captured.take();
            assert_eq!(request.keys.len(), 2);
            assert_eq!(request.keys[0].iv.as_ref(), &[1u8; IV_LEN]);
            assert_eq!(request.keys[0].tag.as_ref(), &[9, 9]);
            assert_eq!(request.keys[0].descriptor, "users/email");
            assert_eq!(request.keys[1].iv.as_ref(), &[2u8; IV_LEN]);
            assert_eq!(request.keys[1].tag.as_ref(), &[8]);
            assert_eq!(request.keys[1].descriptor, "users/name");
            assert_eq!(request.keyset_id, Some(IdentifiedBy::Uuid(KEYSET_ID)));
            assert_eq!(keys.len(), 2);
        }

        #[tokio::test]
        async fn generate_then_retrieve_derives_the_same_key() {
            // ZeroKMS returns the same underlying material for generate and
            // retrieve, so the derived data key must round-trip.
            let keyset = build_keyset(|builder| {
                builder
                    .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                        keys: vec![generated_key(vec![9, 9, 9])],
                    })
                    .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                        keys: vec![RetrievedKey {
                            key_material: key_material(),
                        }],
                    })
            })
            .await;

            let generated = keyset
                .generate_keys(&[Binding::from("desc")])
                .await
                .unwrap();

            let retrieved = keyset
                .retrieve_keys(&[(generated[0].key_id.clone(), Binding::from("desc"))])
                .await
                .unwrap();

            assert_eq!(
                generated[0].plaintext.clone().risky_unwrap(),
                retrieved[0].clone().risky_unwrap()
            );
        }

        /// The other side of the length check. A key id of exactly the IV
        /// length splits into an IV and an *empty* tag, which is a shape the
        /// split accepts — so the guard has to be `<`, not `<=`. Without
        /// this, tightening it by one byte would reject a key id the format
        /// permits and no test would notice.
        #[tokio::test]
        async fn a_key_id_that_is_exactly_the_iv_splits_with_an_empty_tag() {
            let captured = Captured::<RetrieveKeyRequest<'static>>::new();
            let keyset = build_keyset(|builder| {
                builder
                    .add_effect::<RetrieveKeyRequest, _>(captured.recorder())
                    .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                        keys: vec![RetrievedKey {
                            key_material: key_material(),
                        }],
                    })
            })
            .await;

            let keys = keyset
                .retrieve_keys(&[(KeyId::new(vec![7u8; IV_LEN]), Binding::from("users/email"))])
                .await
                .expect("a key id of exactly the IV length is splittable");
            assert_eq!(keys.len(), 1);

            let request = captured.take();
            assert_eq!(request.keys.len(), 1);
            assert_eq!(
                request.keys[0].iv.as_ref(),
                &[7u8; IV_LEN],
                "the whole key id is the IV"
            );
            assert!(
                request.keys[0].tag.is_empty(),
                "and the tag is what is left, which is nothing"
            );
        }

        #[tokio::test]
        async fn a_short_key_id_fails_before_any_request() {
            // No `retrieve-data-key` handler is stubbed, so reaching the
            // connection would panic rather than return this error.
            let keyset = build_keyset(|builder| builder).await;

            let Err(err) = keyset
                .retrieve_keys(&[(KeyId::new(vec![0u8; IV_LEN - 1]), Binding::EMPTY)])
                .await
            else {
                panic!("a key id shorter than the IV cannot be split");
            };

            assert!(
                matches!(
                    err,
                    Error::MalformedKeyId {
                        len: 15,
                        min: IV_LEN
                    }
                ),
                "got: {err:?}"
            );
        }

        #[tokio::test]
        async fn a_non_utf8_binding_fails_before_any_request() {
            let keyset = build_keyset(|builder| builder).await;

            let Err(err) = keyset
                .retrieve_keys(&[(key_id([0u8; IV_LEN], &[1]), Binding::new(&[0xff, 0xfe]))])
                .await
            else {
                panic!("a non-UTF-8 binding cannot be a descriptor");
            };

            assert!(matches!(err, Error::BindingNotUtf8), "got: {err:?}");
        }
    }

    /// What this provider promises a caller that reads the traits rather than
    /// the backend — see the module docs.
    #[test]
    fn declares_what_zerokms_is() {
        assert_eq!(
            <TestKeyset as KeyProvider<32>>::RECONSTRUCTION,
            KeyReconstruction::ClientAndServer
        );
        assert_eq!(
            <TestKeyset as KeyProvider<32>>::ISOLATION,
            KeyIsolation::PerValue
        );
        assert_eq!(
            <TestKeyset as KeyProvider<32>>::BINDING,
            BindingSupport::Bound
        );
    }
}

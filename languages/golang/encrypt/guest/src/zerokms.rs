//! The ZeroKMS side of the instance's key router, which a client with a key
//! vendor backend may leave out (CIP-5311).
//!
//! A client is ZeroKMS and at most one key vendor backend
//! (`stack_kms_vendor::KeyRouter`). A key vendor backend is an alternative to
//! ZeroKMS, so a client may also have the vendor alone: the host gives no
//! client id and no client key, and the router's ZeroKMS side is
//! [`MaybeZeroKms::Absent`]. The router then sends the default keyset to the
//! vendor (`KeyRouter::with_vendor_default`), and anything it still sends
//! here (a keyset no record names, a v1 leaf) is refused with
//! [`no_zerokms`], which the status layer reports as `STATUS_NO_ZEROKMS`.

use std::borrow::Cow;

use stack_kms::{
    BackendErrorKind, DataKey, DataKeySource, DataKeyWithTag, Error, GenerateKeyPayload,
    IdentifiedBy, IndexKey, IndexKeySource, KeyBackend, KeyMode, LoadedIndexKey,
    RetrieveKeyPayload, SelectedKeyset, UnverifiedContext,
};
use uuid::Uuid;

/// The ZeroKMS client, or none.
pub enum MaybeZeroKms<Z> {
    /// The client has ZeroKMS.
    Present(Z),
    /// The client has a key vendor backend and no ZeroKMS.
    Absent,
}

// MaybeZeroKms stands for ZeroKMS (present or not), never for a router.
impl<Z: stack_kms::ZeroKmsKeySource> stack_kms::ZeroKmsKeySource for MaybeZeroKms<Z> {}

/// The cause of [`no_zerokms`]: its type is what the status layer finds to
/// report `STATUS_NO_ZEROKMS`.
#[derive(Debug, Clone, Copy)]
pub struct NoZeroKms;

impl std::fmt::Display for NoZeroKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "this client has no ZeroKMS, only a key vendor backend, and no keyset record names this keyset",
        )
    }
}

impl std::error::Error for NoZeroKms {}

/// The refusal of every request that reaches [`MaybeZeroKms::Absent`].
pub fn no_zerokms() -> Error {
    Error::Backend {
        backend: KeyBackend::ZeroKms,
        kind: BackendErrorKind::NotFound,
        source: Box::new(NoZeroKms),
    }
}

/// Whether `error` is [`no_zerokms`].
pub fn is_no_zerokms(error: &Error) -> bool {
    matches!(error, Error::Backend { source, .. } if source.is::<NoZeroKms>())
}

impl<Z: DataKeySource + Sync> DataKeySource for MaybeZeroKms<Z> {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        match self {
            Self::Present(z) => {
                z.generate_keys(payloads, keyset_id, unverified_context)
                    .await
            }
            Self::Absent => Err(no_zerokms()),
        }
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        match self {
            Self::Present(z) => {
                z.retrieve_keys(payloads, keyset_id, unverified_context)
                    .await
            }
            Self::Absent => Err(no_zerokms()),
        }
    }

    fn key_backend(&self) -> KeyBackend {
        match self {
            Self::Present(z) => z.key_backend(),
            Self::Absent => KeyBackend::ZeroKms,
        }
    }

    fn keyset_backend(&self, keyset_id: Uuid) -> KeyBackend {
        match self {
            Self::Present(z) => z.keyset_backend(keyset_id),
            Self::Absent => KeyBackend::ZeroKms,
        }
    }

    fn key_mode(&self, keyset_id: Uuid) -> Option<KeyMode> {
        match self {
            Self::Present(z) => z.key_mode(keyset_id),
            Self::Absent => None,
        }
    }

    async fn load_settle_index_key(&self, keyset_id: Uuid) -> Result<IndexKey, Error> {
        match self {
            Self::Present(z) => z.load_settle_index_key(keyset_id).await,
            Self::Absent => Err(no_zerokms()),
        }
    }
}

impl<Z: IndexKeySource + Sync> IndexKeySource for MaybeZeroKms<Z> {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        match self {
            Self::Present(z) => z.load_index_key(keyset_id).await,
            Self::Absent => Err(no_zerokms()),
        }
    }

    async fn load_index_key_with_lifetime(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<LoadedIndexKey, Error> {
        match self {
            Self::Present(z) => z.load_index_key_with_lifetime(keyset_id).await,
            Self::Absent => Err(no_zerokms()),
        }
    }

    async fn select_keyset(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<SelectedKeyset, Error> {
        match self {
            Self::Present(z) => z.select_keyset(keyset_id).await,
            Self::Absent => Err(no_zerokms()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_kms::FakeDataKeySource;

    fn block<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    #[test]
    fn absent_refuses_every_request_with_the_typed_error() {
        let absent = MaybeZeroKms::<FakeDataKeySource>::Absent;
        let id = Uuid::from_u128(1);
        for error in [
            block(absent.generate_keys(vec![], Some(id), None)).unwrap_err(),
            block(absent.retrieve_keys(vec![], Some(id), None)).unwrap_err(),
            block(absent.load_settle_index_key(id)).unwrap_err(),
            block(absent.load_index_key(None)).unwrap_err(),
            block(absent.load_index_key_with_lifetime(None)).unwrap_err(),
            block(absent.select_keyset(None)).unwrap_err(),
        ] {
            assert!(is_no_zerokms(&error), "{error:?}");
        }
        assert_eq!(absent.key_backend(), KeyBackend::ZeroKms);
        assert_eq!(absent.key_mode(id), None);
        // Another backend error is not this one.
        assert!(!is_no_zerokms(&Error::Backend {
            backend: KeyBackend::ZeroKms,
            kind: BackendErrorKind::NotFound,
            source: "other".into(),
        }));
    }

    #[test]
    fn present_forwards() {
        let present = MaybeZeroKms::Present(FakeDataKeySource::new());
        let (id, _) = block(present.load_index_key(None)).unwrap();
        assert_eq!(present.keyset_backend(id), KeyBackend::ZeroKms);
    }
}

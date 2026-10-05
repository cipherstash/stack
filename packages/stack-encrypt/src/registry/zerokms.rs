//! ZeroKMS as a source of keysets.
//!
//! An `Arc<StackKms>` is the registry; a [`ZeroKmsKeyset`] is what it
//! resolves to. The `Arc` is the point: every keyset this cipher selects
//! shares one client, one set of credentials and one connection pool.
//!
//! This impl lives here rather than in `stack-kms` because the trait is
//! local and the type is foreign. Its mirror image —
//! `impl KeyProvider for ZeroKmsKeyset` — has to live in `stack-kms` for the
//! same rule read the other way.

use std::sync::Arc;

use stack_kms::{IdentifiedBy, StackKms, ZeroKmsKeyset};

use super::{KeysetId, KeysetRef, KeysetRegistry, Resolved};

/// How a [`KeysetRef`] reaches ZeroKMS.
///
/// `Default` becomes an absent id, which is what the protocol already means
/// by it: the server resolves the client's default keyset for the request.
fn identified_by(keyset: &KeysetRef) -> Option<IdentifiedBy> {
    match keyset {
        KeysetRef::Default => None,
        KeysetRef::Id(id) => Some(IdentifiedBy::Uuid(id.into_uuid())),
        KeysetRef::Name(name) => Some(IdentifiedBy::Name(name.clone().into())),
    }
}

impl<C, Conn> KeysetRegistry for Arc<StackKms<C, Conn>>
where
    C: stack_auth::AuthStrategyBounds,
    for<'a> &'a C: stack_auth::AuthStrategy,
    Conn: stack_kms::ZeroKMSConnection + Send + Sync,
{
    type Provider = ZeroKmsKeyset<C, Conn>;
    type Error = stack_kms::Error;

    /// One `load_keyset` round trip, which resolves the keyset *and* returns
    /// its index key — so loading the index key eagerly costs nothing extra
    /// here, and a keyset that cannot serve one fails now rather than at the
    /// first query.
    async fn resolve(
        &self,
        keyset: &KeysetRef,
    ) -> Result<Option<Resolved<Self::Provider>>, Self::Error> {
        let provider = match ZeroKmsKeyset::new(Arc::clone(self), identified_by(keyset)).await {
            Ok(provider) => provider,
            // ZeroKMS's own answer that it holds no such keyset, as opposed
            // to not answering at all.
            Err(stack_kms::Error::LoadKeyset(stack_kms::LoadKeysetError::KeysetNotFound(_))) => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };

        Ok(Some(Resolved {
            id: KeysetId::new(provider.keyset_id()),
            // The name asked for, not a property of the keyset: a selection
            // by id or by default looked nothing up and carries none.
            name: keyset.name().map(str::to_owned),
            provider,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// `None` means "the client's default keyset" on the wire, so every
    /// selector must map to its *own* `IdentifiedBy` or a caller that asked
    /// for one tenant silently gets another's. Only `Default` may be absent.
    #[test]
    fn every_selector_reaches_zerokms_as_itself() {
        assert!(
            identified_by(&KeysetRef::Default).is_none(),
            "the protocol already spells the default keyset as an absent id"
        );

        let id = Uuid::from_u128(7);
        assert!(
            matches!(
                identified_by(&KeysetRef::Id(KeysetId::new(id))),
                Some(IdentifiedBy::Uuid(sent)) if sent == id
            ),
            "an id selection must carry that id, not fall back to the default"
        );

        assert!(
            matches!(
                identified_by(&KeysetRef::Name("acme".to_owned())),
                Some(IdentifiedBy::Name(sent)) if &*sent == "acme"
            ),
            "a name selection must carry that name, not fall back to the default"
        );
    }
}

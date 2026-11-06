//! ZeroKMS and at most one key vendor backend in one key source.

use std::borrow::Cow;

use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, Error, GenerateKeyPayload, IdentifiedBy, IndexKey,
    IndexKeySource, KeyBackend, KeyMode, LoadedIndexKey, RetrieveKeyPayload, SelectedKeyset,
    UnverifiedContext,
};
use uuid::Uuid;

use crate::source::VendorKeySource;
use crate::vendor::KeyVendorBackend;

/// ZeroKMS and one key vendor backend, as one key source that routes each
/// request by its keyset (ADR-0009).
///
/// A cipher holds ZeroKMS and **at most one** key vendor backend. The type
/// has room for exactly one, and [`VendorKeySource::new`] refuses records
/// that name a second vendor
/// ([`RecordError::SecondVendor`](crate::RecordError::SecondVendor)).
///
/// Routing:
///
/// * A keyset id that one of the vendor's records names goes to the vendor.
///   Every other id goes to ZeroKMS.
/// * A keyset name that one of the vendor's records has goes to the vendor.
///   A local record name wins over a ZeroKMS keyset of the same name. Every
///   other name goes to ZeroKMS.
/// * Naming no keyset is ZeroKMS's default keyset, or the vendor's default
///   keyset after [`with_vendor_default`](Self::with_vendor_default).
///
/// The cipher reads [`keyset_backend`](DataKeySource::keyset_backend) to
/// refuse a leaf that names the wrong backend before any key call, and to
/// seal a vendor keyset's values as v2 leaves. There is no migration
/// between the two backends in either direction.
pub struct KeyRouter<Z, B> {
    zerokms: Z,
    vendor: VendorKeySource<B>,
    vendor_default: bool,
}

impl<Z, B> std::fmt::Debug for KeyRouter<Z, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRouter")
            .field("zerokms", &std::any::type_name::<Z>())
            .field("vendor", &self.vendor)
            .field("vendor_default", &self.vendor_default)
            .finish()
    }
}

impl<Z, B: KeyVendorBackend> KeyRouter<Z, B> {
    /// Route between `zerokms` and `vendor`.
    pub fn new(zerokms: Z, vendor: VendorKeySource<B>) -> Self {
        Self {
            zerokms,
            vendor,
            vendor_default: false,
        }
    }

    /// Make naming no keyset select the vendor's default keyset (its only
    /// record, or the one set with
    /// [`VendorKeySource::with_default_keyset`]), not ZeroKMS's. For a
    /// client that has a key vendor backend and no ZeroKMS credentials: its
    /// ZeroKMS side is then a source that refuses every request.
    pub fn with_vendor_default(mut self) -> Self {
        self.vendor_default = true;
        self
    }

    /// The ZeroKMS key source.
    pub fn zerokms(&self) -> &Z {
        &self.zerokms
    }

    /// The key vendor backend's key source.
    pub fn vendor(&self) -> &VendorKeySource<B> {
        &self.vendor
    }

    fn is_vendor_id(&self, keyset: Option<Uuid>) -> bool {
        match keyset {
            None => self.vendor_default,
            Some(keyset) => self.vendor.has_keyset(keyset),
        }
    }

    fn is_vendor_selection(&self, keyset: Option<&IdentifiedBy>) -> bool {
        match keyset {
            None => self.vendor_default,
            Some(IdentifiedBy::Uuid(id)) => self.vendor.has_keyset(*id),
            Some(IdentifiedBy::Name(name)) => self.vendor.has_name(name),
        }
    }
}

impl<Z, B> DataKeySource for KeyRouter<Z, B>
where
    Z: DataKeySource + Send + Sync,
    B: KeyVendorBackend,
{
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        if self.is_vendor_id(keyset_id) {
            self.vendor
                .generate_keys(payloads, keyset_id, unverified_context)
                .await
        } else {
            self.zerokms
                .generate_keys(payloads, keyset_id, unverified_context)
                .await
        }
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        if self.is_vendor_id(keyset_id) {
            self.vendor
                .retrieve_keys(payloads, keyset_id, unverified_context)
                .await
        } else {
            self.zerokms
                .retrieve_keys(payloads, keyset_id, unverified_context)
                .await
        }
    }

    /// The backend of the default keyset: ZeroKMS, or the vendor after
    /// [`with_vendor_default`](Self::with_vendor_default). Per keyset, see
    /// [`keyset_backend`](DataKeySource::keyset_backend).
    fn key_backend(&self) -> KeyBackend {
        if self.vendor_default {
            self.vendor.key_backend()
        } else {
            self.zerokms.key_backend()
        }
    }

    fn keyset_backend(&self, keyset_id: Uuid) -> KeyBackend {
        if self.vendor.has_keyset(keyset_id) {
            self.vendor.key_backend()
        } else {
            self.zerokms.keyset_backend(keyset_id)
        }
    }

    fn key_mode(&self, keyset_id: Uuid) -> Option<KeyMode> {
        if self.vendor.has_keyset(keyset_id) {
            self.vendor.key_mode(keyset_id)
        } else {
            self.zerokms.key_mode(keyset_id)
        }
    }

    async fn load_settle_index_key(&self, keyset_id: Uuid) -> Result<IndexKey, Error> {
        if self.vendor.has_keyset(keyset_id) {
            self.vendor.load_settle_index_key(keyset_id).await
        } else {
            self.zerokms.load_settle_index_key(keyset_id).await
        }
    }
}

impl<Z, B> IndexKeySource for KeyRouter<Z, B>
where
    Z: IndexKeySource + Send + Sync,
    B: KeyVendorBackend,
{
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        if self.is_vendor_selection(keyset_id.as_ref()) {
            self.vendor.load_index_key(keyset_id).await
        } else {
            self.zerokms.load_index_key(keyset_id).await
        }
    }

    async fn load_index_key_with_lifetime(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<LoadedIndexKey, Error> {
        if self.is_vendor_selection(keyset_id.as_ref()) {
            self.vendor.load_index_key_with_lifetime(keyset_id).await
        } else {
            self.zerokms.load_index_key_with_lifetime(keyset_id).await
        }
    }

    async fn select_keyset(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<SelectedKeyset, Error> {
        if self.is_vendor_selection(keyset_id.as_ref()) {
            self.vendor.select_keyset(keyset_id).await
        } else {
            self.zerokms.select_keyset(keyset_id).await
        }
    }
}

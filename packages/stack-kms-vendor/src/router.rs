//! ZeroKMS and at most one key vendor backend in one key source.

use std::borrow::Cow;

use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, Error, GenerateKeyPayload, IdentifiedBy, IndexKey,
    IndexKeySource, KeyBackend, KeyMode, LoadedIndexKey, RetrieveKeyPayload, SelectedKeyset,
    UnverifiedContext, ZeroKmsKeySource,
};
use uuid::Uuid;

use crate::source::VendorKeySource;
use crate::vendor::KeyVendorBackend;

/// ZeroKMS and at most one key vendor backend, as one key source that
/// routes each request by its keyset (ADR-0009).
///
/// A cipher holds ZeroKMS and **at most one** key vendor backend. The type
/// has room for one or none: [`new`](Self::new) gives it one, and
/// [`zerokms_only`](Self::zerokms_only) none. The ZeroKMS side must be a
/// [`ZeroKmsKeySource`], which a router is not, so a router cannot hold a
/// second router and its vendor:
///
/// ```compile_fail
/// use stack_kms::FakeDataKeySource;
/// use stack_kms_vendor::{FakeVendor, KeyRouter, VendorKeySource};
///
/// fn nested(
///     inner: KeyRouter<FakeDataKeySource, FakeVendor>,
///     vendor: VendorKeySource<FakeVendor>,
/// ) {
///     // A router is not a ZeroKmsKeySource.
///     let _ = KeyRouter::new(inner, vendor);
/// }
/// ```
///
/// [`VendorKeySource::new`] refuses records that name a second vendor
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
/// * With no vendor, every request goes to ZeroKMS.
///
/// The cipher reads [`keyset_backend`](DataKeySource::keyset_backend) to
/// refuse a leaf that names the wrong backend before any key call, and to
/// seal a vendor keyset's values as v2 leaves. There is no migration
/// between the two backends in either direction.
pub struct KeyRouter<Z, B> {
    zerokms: Z,
    vendor: Option<VendorKeySource<B>>,
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

impl<Z: ZeroKmsKeySource, B: KeyVendorBackend> KeyRouter<Z, B> {
    /// Route between `zerokms` and `vendor`.
    pub fn new(zerokms: Z, vendor: VendorKeySource<B>) -> Self {
        Self {
            zerokms,
            vendor: Some(vendor),
            vendor_default: false,
        }
    }

    /// Send every request to `zerokms`: a client with no key vendor
    /// backend.
    pub fn zerokms_only(zerokms: Z) -> Self {
        Self {
            zerokms,
            vendor: None,
            vendor_default: false,
        }
    }
}

impl<Z, B: KeyVendorBackend> KeyRouter<Z, B> {
    /// Make naming no keyset select the vendor's default keyset (its only
    /// record, or the one set with
    /// [`VendorKeySource::with_default_keyset`]), not ZeroKMS's. For a
    /// client that has a key vendor backend and no ZeroKMS credentials: its
    /// ZeroKMS side is then a source that refuses every request. A router
    /// with no vendor ([`zerokms_only`](Self::zerokms_only)) ignores it.
    pub fn with_vendor_default(mut self) -> Self {
        self.vendor_default = true;
        self
    }

    /// The ZeroKMS key source.
    pub fn zerokms(&self) -> &Z {
        &self.zerokms
    }

    /// The key vendor backend's key source, or `None` when the router has
    /// no vendor.
    pub fn vendor(&self) -> Option<&VendorKeySource<B>> {
        self.vendor.as_ref()
    }

    /// The vendor, when it is the default.
    fn default_vendor(&self) -> Option<&VendorKeySource<B>> {
        self.vendor.as_ref().filter(|_| self.vendor_default)
    }

    /// The vendor, when one of its records names `keyset`.
    fn vendor_with_keyset(&self, keyset: Uuid) -> Option<&VendorKeySource<B>> {
        self.vendor
            .as_ref()
            .filter(|vendor| vendor.has_keyset(keyset))
    }

    /// The vendor, when `keyset` routes to it.
    fn vendor_for_id(&self, keyset: Option<Uuid>) -> Option<&VendorKeySource<B>> {
        match keyset {
            None => self.default_vendor(),
            Some(keyset) => self.vendor_with_keyset(keyset),
        }
    }

    /// The vendor, when the selection `keyset` routes to it.
    fn vendor_for_selection(&self, keyset: Option<&IdentifiedBy>) -> Option<&VendorKeySource<B>> {
        match keyset {
            None => self.default_vendor(),
            Some(IdentifiedBy::Uuid(id)) => self.vendor_with_keyset(*id),
            Some(IdentifiedBy::Name(name)) => {
                self.vendor.as_ref().filter(|vendor| vendor.has_name(name))
            }
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
        match self.vendor_for_id(keyset_id) {
            Some(vendor) => {
                vendor
                    .generate_keys(payloads, keyset_id, unverified_context)
                    .await
            }
            None => {
                self.zerokms
                    .generate_keys(payloads, keyset_id, unverified_context)
                    .await
            }
        }
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        match self.vendor_for_id(keyset_id) {
            Some(vendor) => {
                vendor
                    .retrieve_keys(payloads, keyset_id, unverified_context)
                    .await
            }
            None => {
                self.zerokms
                    .retrieve_keys(payloads, keyset_id, unverified_context)
                    .await
            }
        }
    }

    /// The backend of the default keyset: ZeroKMS, or the vendor after
    /// [`with_vendor_default`](KeyRouter::with_vendor_default). Per keyset,
    /// see [`keyset_backend`](DataKeySource::keyset_backend).
    fn key_backend(&self) -> KeyBackend {
        match self.default_vendor() {
            Some(vendor) => vendor.key_backend(),
            None => self.zerokms.key_backend(),
        }
    }

    fn keyset_backend(&self, keyset_id: Uuid) -> KeyBackend {
        match self.vendor_with_keyset(keyset_id) {
            Some(vendor) => vendor.key_backend(),
            None => self.zerokms.keyset_backend(keyset_id),
        }
    }

    fn key_mode(&self, keyset_id: Uuid) -> Option<KeyMode> {
        match self.vendor_with_keyset(keyset_id) {
            Some(vendor) => vendor.key_mode(keyset_id),
            None => self.zerokms.key_mode(keyset_id),
        }
    }

    async fn load_settle_index_key(&self, keyset_id: Uuid) -> Result<IndexKey, Error> {
        match self.vendor_with_keyset(keyset_id) {
            Some(vendor) => vendor.load_settle_index_key(keyset_id).await,
            None => self.zerokms.load_settle_index_key(keyset_id).await,
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
        match self.vendor_for_selection(keyset_id.as_ref()) {
            Some(vendor) => vendor.load_index_key(keyset_id).await,
            None => self.zerokms.load_index_key(keyset_id).await,
        }
    }

    async fn load_index_key_with_lifetime(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<LoadedIndexKey, Error> {
        match self.vendor_for_selection(keyset_id.as_ref()) {
            Some(vendor) => vendor.load_index_key_with_lifetime(keyset_id).await,
            None => self.zerokms.load_index_key_with_lifetime(keyset_id).await,
        }
    }

    async fn select_keyset(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<SelectedKeyset, Error> {
        match self.vendor_for_selection(keyset_id.as_ref()) {
            Some(vendor) => vendor.select_keyset(keyset_id).await,
            None => self.zerokms.select_keyset(keyset_id).await,
        }
    }
}

//! The adapter from one key vendor backend and its keyset records to the
//! stack-kms key source traits.

use std::borrow::Cow;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use stack_kms::{
    refuse_zerokms_extensions, BackendErrorKind, DataKey, DataKeySource, DataKeyWithTag, Error,
    GenerateKeyPayload, IdentifiedBy, IndexKey, IndexKeySource, KeyBackend, KeyLifetime, KeyMode,
    KeyVendor, LoadedIndexKey, RetrieveKeyPayload, SelectedKeyset, UnverifiedContext,
};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};
use web_time::Instant;

use crate::batch::{run_batch, BatchOptions};
use crate::derive::{derived_data_key, derived_index_key, wrapped_data_key_aad};
use crate::error::RecordError;
use crate::record::KeysetRecord;
use crate::vendor::{random_bytes, random_key, KeyBytes, KeyVendorBackend, UnwrapItem, WrapItem};

/// How long the adapter keeps an unwrapped root key (derived data keys)
/// before it asks the vendor again: five minutes.
pub const DEFAULT_ROOT_KEY_TTL: Duration = Duration::from_secs(5 * 60);

/// A root key the adapter holds, and when it must drop it.
struct CachedRoot {
    key: KeyBytes,
    until: Instant,
}

/// One key vendor backend and its keyset records, as a
/// [`DataKeySource`] and an [`IndexKeySource`].
///
/// This is the adapter every vendor shares. A vendor crate implements
/// [`KeyVendorBackend`]; this type builds both key modes on it:
///
/// * **Wrapped data key.** Each generate makes one vendor call per value
///   ([`KeyVendorBackend::generate_wrapped`]) and puts the wrapped data key
///   in the leaf's tag. Each retrieve makes one vendor call per value. A
///   vendor with a batch operation ([`KeyVendorBackend::batch_limit`])
///   instead gets one call per chunk of values
///   ([`KeyVendorBackend::wrap_batch`], [`KeyVendorBackend::unwrap_batch`]).
///   The calls of one batch run through [`run_batch`]. The index key is
///   unwrapped from the record once per settle and never kept.
/// * **Derived data key.** The adapter unwraps the root key once, keeps it
///   for the root key TTL ([`DEFAULT_ROOT_KEY_TTL`]), and derives every data
///   key and the index key from it with no vendor call. The root key is
///   wiped when it expires or when the adapter drops.
///
/// Either way, a cipher holds no index key between settles: the adapter
/// answers [`select_keyset`](IndexKeySource::select_keyset) with
/// [`SelectedKeyset::PerSettle`], and the cipher asks
/// [`load_settle_index_key`](DataKeySource::load_settle_index_key) inside
/// each settle that builds a term.
///
/// Keyset names resolve locally from the loaded records, with no freshness
/// window: a record is the customer's statement of what the name means.
///
/// The adapter refuses every ZeroKMS-only input (a lock context, a
/// decryption policy, an unverified context) with
/// [`Error::ZeroKmsOnly`].
pub struct VendorKeySource<B> {
    backend: B,
    records: HashMap<Uuid, KeysetRecord>,
    names: HashMap<String, Uuid>,
    default: Option<Uuid>,
    root_ttl: Duration,
    batch: BatchOptions,
    roots: Mutex<HashMap<Uuid, CachedRoot>>,
}

impl<B> std::fmt::Debug for VendorKeySource<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VendorKeySource")
            .field("keysets", &self.records.keys().collect::<Vec<_>>())
            .field("default", &self.default)
            .field("root_ttl", &self.root_ttl)
            .finish_non_exhaustive()
    }
}

/// The one vendor a set of records names, or `None` for no records.
/// Two vendors is [`RecordError::SecondVendor`]: a cipher holds ZeroKMS and
/// at most one key vendor backend.
pub(crate) fn vendor_of<'a>(
    records: impl IntoIterator<Item = &'a KeysetRecord>,
) -> Result<Option<KeyVendor>, RecordError> {
    let mut found: Option<KeyVendor> = None;
    for record in records {
        match found {
            None => found = Some(record.vendor()),
            Some(first) if first != record.vendor() => {
                return Err(RecordError::SecondVendor {
                    first,
                    second: record.vendor(),
                })
            }
            Some(_) => {}
        }
    }
    Ok(found)
}

fn not_found(vendor: KeyVendor) -> Error {
    Error::Backend {
        vendor: vendor.name(),
        kind: BackendErrorKind::NotFound,
        source: "no keyset record for this keyset".into(),
    }
}

fn unavailable(vendor: KeyVendor, message: &'static str) -> Error {
    Error::Backend {
        vendor: vendor.name(),
        kind: BackendErrorKind::Unavailable,
        source: message.into(),
    }
}

fn invalid(vendor: KeyVendor, message: &'static str) -> Error {
    Error::Backend {
        vendor: vendor.name(),
        kind: BackendErrorKind::InvalidCiphertext,
        source: message.into(),
    }
}

impl<B: KeyVendorBackend> VendorKeySource<B> {
    /// The adapter over `backend` and `records`.
    ///
    /// Refuses records that name two vendors ([`RecordError::SecondVendor`]),
    /// a record of another vendor than `backend`
    /// ([`RecordError::ForeignVendor`]), a record whose mode the vendor
    /// does not offer ([`RecordError::ModeUnsupported`]), and two records
    /// with the same id or name.
    ///
    /// The default keyset (naming no keyset) is the only record when there
    /// is exactly one, else none until
    /// [`with_default_keyset`](Self::with_default_keyset) sets it.
    pub fn new(
        backend: B,
        records: impl IntoIterator<Item = KeysetRecord>,
    ) -> Result<Self, RecordError> {
        let records: Vec<KeysetRecord> = records.into_iter().collect();
        let vendor = backend.vendor();
        let _ = vendor_of(&records)?;
        let mut by_id = HashMap::with_capacity(records.len());
        let mut names = HashMap::new();
        for record in records {
            record.check_vendor(vendor)?;
            if !backend.supports_mode(record.mode()) {
                return Err(RecordError::ModeUnsupported {
                    vendor,
                    mode: record.mode(),
                });
            }
            if let Some(name) = record.name() {
                if names.insert(name.to_owned(), record.id()).is_some() {
                    return Err(RecordError::DuplicateName);
                }
            }
            let id = record.id();
            if by_id.insert(id, record).is_some() {
                return Err(RecordError::DuplicateKeyset(id));
            }
        }
        let default = match by_id.len() {
            1 => by_id.keys().next().copied(),
            _ => None,
        };
        Ok(Self {
            backend,
            records: by_id,
            names,
            default,
            root_ttl: DEFAULT_ROOT_KEY_TTL,
            batch: BatchOptions::default(),
            roots: Mutex::new(HashMap::new()),
        })
    }

    /// Parse each text record and build the adapter, as [`new`](Self::new)
    /// does. For records held in config or environment variables.
    pub fn from_texts<'t>(
        backend: B,
        texts: impl IntoIterator<Item = &'t str>,
    ) -> Result<Self, RecordError> {
        let records = texts
            .into_iter()
            .map(KeysetRecord::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(backend, records)
    }

    /// Make `keyset` the default keyset: the one naming no keyset selects.
    pub fn with_default_keyset(mut self, keyset: Uuid) -> Result<Self, RecordError> {
        if !self.records.contains_key(&keyset) {
            return Err(RecordError::UnknownDefault);
        }
        self.default = Some(keyset);
        Ok(self)
    }

    /// How long to keep an unwrapped root key (derived data keys). Default
    /// [`DEFAULT_ROOT_KEY_TTL`]. `Duration::ZERO` keeps none: every settle
    /// unwraps again.
    pub fn with_root_key_ttl(mut self, ttl: Duration) -> Self {
        self.root_ttl = ttl;
        self
    }

    /// How vendor calls are batched (wrapped data keys).
    pub fn with_batch_options(mut self, options: BatchOptions) -> Self {
        self.batch = options;
        self
    }

    /// The key vendor backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Whether a record for `keyset` is loaded.
    pub fn has_keyset(&self, keyset: Uuid) -> bool {
        self.records.contains_key(&keyset)
    }

    /// Whether a loaded record has the name `name`.
    pub fn has_name(&self, name: &str) -> bool {
        self.names.contains_key(name)
    }

    /// The record of `keyset`, if it is loaded.
    pub fn record(&self, keyset: Uuid) -> Option<&KeysetRecord> {
        self.records.get(&keyset)
    }

    fn vendor(&self) -> KeyVendor {
        self.backend.vendor()
    }

    /// The record a selection names: an id, a local name, or the default.
    fn resolve(&self, keyset: Option<&IdentifiedBy>) -> Result<&KeysetRecord, Error> {
        let id = match keyset {
            None => self.default,
            Some(IdentifiedBy::Uuid(id)) => Some(*id),
            Some(IdentifiedBy::Name(name)) => self.names.get(&**name).copied(),
        };
        id.and_then(|id| self.records.get(&id))
            .ok_or_else(|| not_found(self.vendor()))
    }

    /// The record a data-key request names (`None` is the default keyset).
    fn resolve_id(&self, keyset: Option<Uuid>) -> Result<&KeysetRecord, Error> {
        self.resolve(keyset.map(IdentifiedBy::Uuid).as_ref())
    }

    /// The root key of a derived-data-key record: from the cache while it
    /// is live, else unwrapped (one vendor call) and cached for the TTL.
    async fn root_key(&self, record: &KeysetRecord) -> Result<KeyBytes, Error> {
        let now = Instant::now();
        {
            let mut roots = self.roots.lock().unwrap_or_else(PoisonError::into_inner);
            // Every lookup drops every expired root key, so none outlives
            // its TTL by more than the time to the next lookup.
            roots.retain(|_, cached| now < cached.until);
            if let Some(cached) = roots.get(&record.id()) {
                return Ok(Protected::new(*cached.key.risky_ref()));
            }
        }
        let key = self.unwrap_record(record).await?;
        if !self.root_ttl.is_zero() {
            if let Some(until) = Instant::now().checked_add(self.root_ttl) {
                let mut roots = self.roots.lock().unwrap_or_else(PoisonError::into_inner);
                let _ = roots.insert(
                    record.id(),
                    CachedRoot {
                        key: Protected::new(*key.risky_ref()),
                        until,
                    },
                );
            }
        }
        Ok(key)
    }

    /// Unwrap the key in `record` (one vendor call), with the batch's
    /// backoff on a throttle.
    async fn unwrap_record(&self, record: &KeysetRecord) -> Result<KeyBytes, Error> {
        let mut keys = run_batch(
            &self.batch,
            1,
            |_| record.unwrap_key(&self.backend),
            |delay| self.backend.sleep(delay),
        )
        .await?;
        keys.pop()
            .ok_or_else(|| invalid(self.vendor(), "the vendor returned no key"))
    }

    /// The index key of `record`: derived from the root key, or unwrapped
    /// from the record.
    async fn index_key(&self, record: &KeysetRecord) -> Result<IndexKey, Error> {
        let key = match record.mode() {
            KeyMode::Derived => derived_index_key(&self.root_key(record).await?, record.id()),
            KeyMode::Wrapped => self.unwrap_record(record).await?,
        };
        Ok(IndexKey::from_key_bytes(key))
    }

    /// Generate one wrapped data key for each descriptor, in vendor batch
    /// calls of at most [`KeyVendorBackend::batch_limit`] keys. Each data key
    /// comes from the CSPRNG. The chunks run through [`run_batch`], so a
    /// throttled chunk backs off and is sent again whole.
    async fn generate_in_vendor_batches(
        &self,
        record: &KeysetRecord,
        descriptors: &[&str],
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        let vendor = self.vendor();
        let limit = self.backend.batch_limit().map_or(1, NonZeroUsize::get);
        let chunks: Vec<&[&str]> = descriptors.chunks(limit).collect();
        let results = run_batch(
            &self.batch,
            chunks.len(),
            |chunk| {
                let chunk = chunks[chunk];
                async move {
                    let mut ivs = Vec::with_capacity(chunk.len());
                    let mut keys = Vec::with_capacity(chunk.len());
                    let mut aads = Vec::with_capacity(chunk.len());
                    for descriptor in chunk {
                        let iv = random_bytes::<16>(vendor)?;
                        aads.push(wrapped_data_key_aad(record.id(), &iv, descriptor));
                        ivs.push(iv);
                        keys.push(random_key(vendor)?);
                    }
                    let items: Vec<WrapItem<'_>> = keys
                        .iter()
                        .zip(&aads)
                        .map(|(key, aad)| WrapItem { key, aad })
                        .collect();
                    let wrapped = self.backend.wrap_batch(record.key_ref(), &items).await?;
                    if wrapped.len() != chunk.len() {
                        return Err(unavailable(
                            vendor,
                            "a batch returned another count of keys",
                        ));
                    }
                    Ok(ivs
                        .into_iter()
                        .zip(keys)
                        .zip(wrapped)
                        .map(|((iv, key), tag)| DataKeyWithTag {
                            key: DataKey {
                                iv,
                                key: *key.risky_ref(),
                            },
                            tag,
                            decryption_policy: None,
                        })
                        .collect::<Vec<_>>())
                }
            },
            |delay| self.backend.sleep(delay),
        )
        .await?;
        Ok(results.into_iter().flatten().collect())
    }

    /// Unwrap the wrapped data key of each payload, in vendor batch calls
    /// of at most [`KeyVendorBackend::batch_limit`] keys.
    async fn retrieve_in_vendor_batches(
        &self,
        record: &KeysetRecord,
        payloads: &[RetrieveKeyPayload<'_>],
    ) -> Result<Vec<DataKey>, Error> {
        let vendor = self.vendor();
        let limit = self.backend.batch_limit().map_or(1, NonZeroUsize::get);
        let chunks: Vec<&[RetrieveKeyPayload<'_>]> = payloads.chunks(limit).collect();
        let results = run_batch(
            &self.batch,
            chunks.len(),
            |chunk| {
                let chunk = chunks[chunk];
                async move {
                    let ivs: Vec<[u8; 16]> = chunk.iter().map(|p| p.iv_bytes()).collect();
                    let aads: Vec<Vec<u8>> = chunk
                        .iter()
                        .zip(&ivs)
                        .map(|(payload, iv)| {
                            wrapped_data_key_aad(record.id(), iv, payload.descriptor)
                        })
                        .collect();
                    let items: Vec<UnwrapItem<'_>> = chunk
                        .iter()
                        .zip(&aads)
                        .map(|(payload, aad)| UnwrapItem {
                            wrapped: payload.tag,
                            aad,
                        })
                        .collect();
                    let keys = self.backend.unwrap_batch(record.key_ref(), &items).await?;
                    if keys.len() != chunk.len() {
                        return Err(unavailable(
                            vendor,
                            "a batch returned another count of keys",
                        ));
                    }
                    Ok(ivs
                        .into_iter()
                        .zip(keys)
                        .map(|(iv, key)| DataKey {
                            iv,
                            key: *key.risky_ref(),
                        })
                        .collect::<Vec<_>>())
                }
            },
            |delay| self.backend.sleep(delay),
        )
        .await?;
        Ok(results.into_iter().flatten().collect())
    }

    /// The lifetime of `record`'s index key, for a caller of
    /// [`IndexKeySource::load_index_key_with_lifetime`].
    fn lifetime(&self, record: &KeysetRecord) -> KeyLifetime {
        match record.mode() {
            KeyMode::Wrapped => KeyLifetime::Settle,
            KeyMode::Derived => KeyLifetime::Ttl(self.root_ttl),
        }
    }
}

impl<B: KeyVendorBackend> DataKeySource for VendorKeySource<B> {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        let vendor = self.vendor();
        refuse_zerokms_extensions(vendor.name(), &payloads, unverified_context.as_deref())?;
        let record = self.resolve_id(keyset_id)?;
        match record.mode() {
            KeyMode::Derived => {
                let root = self.root_key(record).await?;
                payloads
                    .iter()
                    .map(|payload| {
                        let iv = random_bytes::<16>(vendor)?;
                        let key = derived_data_key(&root, record.id(), &iv, payload.descriptor());
                        Ok(DataKeyWithTag {
                            key: DataKey {
                                iv,
                                key: *key.risky_ref(),
                            },
                            tag: Vec::new(),
                            decryption_policy: None,
                        })
                    })
                    .collect()
            }
            KeyMode::Wrapped if self.backend.batch_limit().is_some() => {
                let descriptors: Vec<&str> = payloads
                    .iter()
                    .map(GenerateKeyPayload::descriptor)
                    .collect();
                self.generate_in_vendor_batches(record, &descriptors).await
            }
            KeyMode::Wrapped => {
                run_batch(
                    &self.batch,
                    payloads.len(),
                    |index| {
                        let descriptor = payloads[index].descriptor();
                        async move {
                            let iv = random_bytes::<16>(vendor)?;
                            let aad = wrapped_data_key_aad(record.id(), &iv, descriptor);
                            let (key, wrapped) = self
                                .backend
                                .generate_wrapped(record.key_ref(), &aad)
                                .await?;
                            Ok(DataKeyWithTag {
                                key: DataKey {
                                    iv,
                                    key: *key.risky_ref(),
                                },
                                tag: wrapped,
                                decryption_policy: None,
                            })
                        }
                    },
                    |delay| self.backend.sleep(delay),
                )
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
        let vendor = self.vendor();
        refuse_zerokms_extensions(vendor.name(), &payloads, unverified_context)?;
        let record = self.resolve_id(keyset_id)?;
        if payloads
            .iter()
            .any(|payload| payload.key_mode.is_some_and(|mode| mode != record.mode()))
        {
            return Err(invalid(
                vendor,
                "the leaf names another key mode than its keyset",
            ));
        }
        match record.mode() {
            KeyMode::Derived => {
                if payloads.iter().any(|payload| !payload.tag.is_empty()) {
                    return Err(invalid(vendor, "a derived data key has an empty tag"));
                }
                let root = self.root_key(record).await?;
                Ok(payloads
                    .iter()
                    .map(|payload| {
                        let iv = payload.iv_bytes();
                        let key = derived_data_key(&root, record.id(), &iv, payload.descriptor);
                        DataKey {
                            iv,
                            key: *key.risky_ref(),
                        }
                    })
                    .collect())
            }
            KeyMode::Wrapped if self.backend.batch_limit().is_some() => {
                self.retrieve_in_vendor_batches(record, &payloads).await
            }
            KeyMode::Wrapped => {
                run_batch(
                    &self.batch,
                    payloads.len(),
                    |index| {
                        let payload = &payloads[index];
                        async move {
                            let iv = payload.iv_bytes();
                            let aad = wrapped_data_key_aad(record.id(), &iv, payload.descriptor);
                            let key = self
                                .backend
                                .unwrap(record.key_ref(), payload.tag, &aad)
                                .await?;
                            Ok(DataKey {
                                iv,
                                key: *key.risky_ref(),
                            })
                        }
                    },
                    |delay| self.backend.sleep(delay),
                )
                .await
            }
        }
    }

    fn key_backend(&self) -> KeyBackend {
        KeyBackend::Vendor(self.vendor())
    }

    fn key_mode(&self, keyset_id: Uuid) -> Option<KeyMode> {
        self.records.get(&keyset_id).map(KeysetRecord::mode)
    }

    async fn load_settle_index_key(&self, keyset_id: Uuid) -> Result<IndexKey, Error> {
        let record = self.resolve_id(Some(keyset_id))?;
        self.index_key(record).await
    }
}

impl<B: KeyVendorBackend> IndexKeySource for VendorKeySource<B> {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        let record = self.resolve(keyset_id.as_ref())?;
        Ok((record.id(), self.index_key(record).await?))
    }

    async fn load_index_key_with_lifetime(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<LoadedIndexKey, Error> {
        let record = self.resolve(keyset_id.as_ref())?;
        let key = self.index_key(record).await?;
        Ok(LoadedIndexKey::new(record.id(), key, self.lifetime(record)))
    }

    /// Resolve the keyset locally, with no vendor call. The cipher loads
    /// the index key inside each settle.
    async fn select_keyset(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<SelectedKeyset, Error> {
        let record = self.resolve(keyset_id.as_ref())?;
        Ok(SelectedKeyset::PerSettle {
            keyset_id: record.id(),
        })
    }
}

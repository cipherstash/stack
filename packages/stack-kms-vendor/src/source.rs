//! The adapter from one key vendor backend and its keyset records to the
//! stack-kms key source traits.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use stack_kms::{
    refuse_zerokms_extensions, BackendErrorKind, DataKey, DataKeySource, DataKeyWithTag, Error,
    GenerateKeyPayload, IdentifiedBy, IndexKey, IndexKeySource, KeyVendor, RetrieveKeyPayload,
    UnverifiedContext,
};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};
use web_time::Instant;

use crate::derive::{derived_data_key, derived_index_key};
use crate::error::RecordError;
use crate::record::KeysetRecord;
use crate::retry::{retry, RetryOptions};
use crate::vendor::{random_bytes, KeyBytes, KeyVendorBackend};

/// How long the adapter keeps an unwrapped root key before it asks the
/// vendor again: five minutes.
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
/// [`KeyVendorBackend`]; this type builds the derived data key mode on it.
/// The adapter unwraps a keyset's root key (one vendor call), keeps it for
/// the root key TTL ([`DEFAULT_ROOT_KEY_TTL`]), and derives every data key
/// and the index key from it with no vendor call. The root key is wiped
/// when it expires or when the adapter drops. After the TTL the next
/// request unwraps it again, so the vendor sees, and can refuse, one call
/// per keyset per TTL.
///
/// The TTL covers the root key and the data keys. It does not cover the
/// index key: a cipher keeps the index key it loaded until its keyset cache
/// evicts it, as it does for a ZeroKMS keyset. A cipher that already holds
/// a keyset's index key can thus still build query terms for that keyset
/// after the vendor refuses it, but it cannot seal or open a value. See
/// the [capability matrix](crate#capability-matrix).
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
    retry: RetryOptions,
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
        backend: vendor.into(),
        kind: BackendErrorKind::NotFound,
        source: "no keyset record for this keyset".into(),
    }
}

fn invalid(vendor: KeyVendor, message: &'static str) -> Error {
    Error::Backend {
        backend: vendor.into(),
        kind: BackendErrorKind::InvalidCiphertext,
        source: message.into(),
    }
}

impl<B: KeyVendorBackend> VendorKeySource<B> {
    /// The adapter over `backend` and `records`.
    ///
    /// Refuses records that name two vendors ([`RecordError::SecondVendor`]),
    /// a record of another vendor than `backend`
    /// ([`RecordError::ForeignVendor`]), and two records with the same id
    /// or name.
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
            retry: RetryOptions::default(),
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

    /// How long to keep an unwrapped root key. Default
    /// [`DEFAULT_ROOT_KEY_TTL`]. `Duration::ZERO` keeps none: every request
    /// unwraps again.
    pub fn with_root_key_ttl(mut self, ttl: Duration) -> Self {
        self.root_ttl = ttl;
        self
    }

    /// How a throttled vendor call is tried again.
    pub fn with_retry_options(mut self, options: RetryOptions) -> Self {
        self.retry = options;
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

    /// The root key of `record`: from the cache while it is live, else
    /// unwrapped (one vendor call) and cached for the TTL.
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

    /// Unwrap the root key in `record` (one vendor call), with backoff on
    /// a throttle.
    async fn unwrap_record(&self, record: &KeysetRecord) -> Result<KeyBytes, Error> {
        retry(
            &self.retry,
            || record.unwrap_key(&self.backend),
            |delay| self.backend.sleep(delay),
        )
        .await
    }

    /// The index key of `record`, derived from its root key.
    async fn index_key(&self, record: &KeysetRecord) -> Result<IndexKey, Error> {
        let root = self.root_key(record).await?;
        Ok(IndexKey::from_key_bytes(derived_index_key(
            &root,
            record.id(),
            record.vendor(),
            record.mode(),
        )))
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
        refuse_zerokms_extensions(vendor, &payloads, unverified_context.as_deref())?;
        let record = self.resolve_id(keyset_id)?;
        let root = self.root_key(record).await?;
        payloads
            .iter()
            .map(|payload| {
                let iv = random_bytes::<16>(vendor)?;
                let key = derived_data_key(
                    &root,
                    record.id(),
                    record.vendor(),
                    record.mode(),
                    &iv,
                    payload.descriptor(),
                );
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

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        let vendor = self.vendor();
        refuse_zerokms_extensions(vendor, &payloads, unverified_context)?;
        let record = self.resolve_id(keyset_id)?;
        if payloads.iter().any(|payload| !payload.tag.is_empty()) {
            return Err(invalid(vendor, "a derived data key has an empty tag"));
        }
        let root = self.root_key(record).await?;
        Ok(payloads
            .iter()
            .map(|payload| {
                let iv = payload.iv_bytes();
                let key = derived_data_key(
                    &root,
                    record.id(),
                    record.vendor(),
                    record.mode(),
                    &iv,
                    payload.descriptor,
                );
                DataKey {
                    iv,
                    key: *key.risky_ref(),
                }
            })
            .collect())
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
}

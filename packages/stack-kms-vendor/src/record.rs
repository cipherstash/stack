//! Keyset records: the customer-held description of a keyset in a key
//! vendor backend.

use std::fmt;
use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use stack_kms::{KeyMode, KeyVendor};
use uuid::Uuid;

use crate::derive::record_key_aad;
use crate::error::RecordError;
use crate::vendor::{random_key, KeyBytes, KeyVendorBackend};

/// The text every keyset record starts with.
pub const RECORD_PREFIX: &str = "stack-keyset:";

/// The format version of the keyset records this build writes. A record of
/// another version is refused ([`RecordError::UnknownVersion`]).
pub const RECORD_FORMAT_VERSION: u8 = 1;

/// The longest keyset name, in bytes.
const MAX_NAME_LEN: usize = u8::MAX as usize;

/// The customer-held description of a keyset in a key vendor backend: its
/// id, an optional name, its backend, its key mode, the vendor key that
/// protects it, and the wrapped key.
///
/// The wrapped key is the keyset's root key. Only the vendor key can
/// unwrap it, so a record is not secret: keep it in config or in an environment variable.
/// The wrapped key is bound to the id, the backend and the mode
/// ([`derive::record_key_aad`](crate::derive::record_key_aad)), so a record
/// edited in any of them does not unwrap. The name is a local label and is
/// not bound: rename a keyset by editing its record.
///
/// # Text form
///
/// [`RECORD_PREFIX`] followed by the unpadded base64url of:
///
/// ```text
/// version (1) ‖ backend (1) ‖ mode (1) ‖ keyset id (16)
///   ‖ name length (1, 0 = no name) ‖ name
///   ‖ key ref length (2, big-endian) ‖ key ref
///   ‖ wrapped key length (2, big-endian) ‖ wrapped key
/// ```
///
/// The backend and mode bytes are [`KeyVendor::byte`] and
/// [`KeyMode::byte`].
///
/// # Creating a record
///
/// [`KeysetRecord::create`] generates the keyset id and the key, and wraps
/// the key with the vendor. [`KeysetRecord::rewrap`] moves a record to
/// another vendor key. Both are what `stash keyset` calls.
#[derive(Clone, PartialEq, Eq)]
pub struct KeysetRecord {
    id: Uuid,
    name: Option<String>,
    vendor: KeyVendor,
    mode: KeyMode,
    key_ref: String,
    wrapped_key: Vec<u8>,
}

impl fmt::Debug for KeysetRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeysetRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("vendor", &self.vendor)
            .field("mode", &self.mode)
            .field("key_ref", &self.key_ref)
            .field("wrapped_key_len", &self.wrapped_key.len())
            .finish()
    }
}

impl KeysetRecord {
    /// Create a keyset in `backend`: generate a keyset id and a root key,
    /// and wrap the root key under the vendor key `key_ref`.
    ///
    /// One vendor call.
    pub async fn create<B: KeyVendorBackend>(
        backend: &B,
        key_ref: impl Into<String>,
        mode: KeyMode,
        name: Option<String>,
    ) -> Result<Self, RecordError> {
        let vendor = backend.vendor();
        let key_ref = key_ref.into();
        check_key_ref(&key_ref)?;
        if let Some(name) = &name {
            check_name(name)?;
        }
        let id = Uuid::new_v4();
        let key = random_key(vendor)?;
        let wrapped_key = backend
            .wrap(&key_ref, &key, &record_key_aad(id, vendor, mode))
            .await?;
        check_wrapped(&wrapped_key)?;
        Ok(Self {
            id,
            name,
            vendor,
            mode,
            key_ref,
            wrapped_key,
        })
    }

    /// Wrap this record's root key under a vendor key of the same backend.
    /// The keyset id, name and mode stay the same. Stored values are not
    /// re-keyed.
    ///
    /// `key_ref` may name any key of the backend. Every data key comes from
    /// the root key, so every value sealed under the keyset still opens.
    /// See the [capability matrix](crate#rotation).
    ///
    /// Two vendor calls: unwrap under the old key, wrap under the new one.
    pub async fn rewrap<B: KeyVendorBackend>(
        &self,
        backend: &B,
        key_ref: impl Into<String>,
    ) -> Result<Self, RecordError> {
        self.check_vendor(backend.vendor())?;
        let key_ref = key_ref.into();
        check_key_ref(&key_ref)?;
        let aad = self.key_aad();
        let key = self.unwrap_key(backend).await?;
        let wrapped_key = backend.wrap(&key_ref, &key, &aad).await?;
        check_wrapped(&wrapped_key)?;
        Ok(Self {
            key_ref,
            wrapped_key,
            ..self.clone()
        })
    }

    /// Build a record from its parts, as a vendor crate's own tests or a
    /// migration might. Prefer [`create`](Self::create).
    pub fn from_parts(
        id: Uuid,
        name: Option<String>,
        vendor: KeyVendor,
        mode: KeyMode,
        key_ref: String,
        wrapped_key: Vec<u8>,
    ) -> Result<Self, RecordError> {
        if let Some(name) = &name {
            check_name(name)?;
        }
        check_key_ref(&key_ref)?;
        check_wrapped(&wrapped_key)?;
        Ok(Self {
            id,
            name,
            vendor,
            mode,
            key_ref,
            wrapped_key,
        })
    }

    /// Parse a record from its text form. Refuses an unknown version,
    /// backend or mode, and a record whose length does not match its
    /// fields.
    pub fn parse(text: &str) -> Result<Self, RecordError> {
        let body = text
            .trim()
            .strip_prefix(RECORD_PREFIX)
            .ok_or(RecordError::NotARecord)?;
        let bytes = Base64UrlUnpadded::decode_vec(body).map_err(|_| RecordError::Encoding)?;
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut reader = Reader(bytes);
        let version = reader.u8()?;
        if version != RECORD_FORMAT_VERSION {
            return Err(RecordError::UnknownVersion(version));
        }
        let vendor_byte = reader.u8()?;
        let vendor =
            KeyVendor::from_byte(vendor_byte).ok_or(RecordError::UnknownBackend(vendor_byte))?;
        let mode_byte = reader.u8()?;
        let mode = KeyMode::from_byte(mode_byte).ok_or(RecordError::UnknownMode(mode_byte))?;
        let id = Uuid::from_bytes(reader.array::<16>()?);
        let name_len = usize::from(reader.u8()?);
        let name = match name_len {
            0 => None,
            len => Some(utf8(reader.take(len)?, "name")?),
        };
        let key_ref_len = usize::from(reader.u16()?);
        let key_ref = utf8(reader.take(key_ref_len)?, "key_ref")?;
        let wrapped_len = usize::from(reader.u16()?);
        let wrapped_key = reader.take(wrapped_len)?.to_vec();
        if !reader.0.is_empty() {
            return Err(RecordError::Length);
        }
        Self::from_parts(id, name, vendor, mode, key_ref, wrapped_key)
    }

    /// The binary form, before base64url.
    fn to_bytes(&self) -> Vec<u8> {
        let name = self.name.as_deref().unwrap_or("").as_bytes();
        let mut out = Vec::with_capacity(
            3 + 16 + 1 + name.len() + 2 + self.key_ref.len() + 2 + self.wrapped_key.len(),
        );
        out.extend_from_slice(&[RECORD_FORMAT_VERSION, self.vendor.byte(), self.mode.byte()]);
        out.extend_from_slice(self.id.as_bytes());
        // The lengths were checked at construction, so the casts are exact.
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.extend_from_slice(&(self.key_ref.len() as u16).to_be_bytes());
        out.extend_from_slice(self.key_ref.as_bytes());
        out.extend_from_slice(&(self.wrapped_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.wrapped_key);
        out
    }

    /// The keyset id.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// The keyset name, if it has one.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The key vendor backend that holds the keyset.
    pub fn vendor(&self) -> KeyVendor {
        self.vendor
    }

    /// The key mode of the keyset.
    pub fn mode(&self) -> KeyMode {
        self.mode
    }

    /// The versioned vendor key reference.
    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }

    /// The wrapped root key.
    pub fn wrapped_key(&self) -> &[u8] {
        &self.wrapped_key
    }

    /// The associated data the wrapped key is bound to.
    pub(crate) fn key_aad(&self) -> Vec<u8> {
        record_key_aad(self.id, self.vendor, self.mode)
    }

    /// Unwrap this record's key with `backend`.
    pub(crate) async fn unwrap_key<B: KeyVendorBackend>(
        &self,
        backend: &B,
    ) -> Result<KeyBytes, stack_kms::Error> {
        backend
            .unwrap(&self.key_ref, &self.wrapped_key, &self.key_aad())
            .await
    }

    pub(crate) fn check_vendor(&self, expected: KeyVendor) -> Result<(), RecordError> {
        if self.vendor == expected {
            Ok(())
        } else {
            Err(RecordError::ForeignVendor {
                keyset: self.id,
                expected,
                found: self.vendor,
            })
        }
    }
}

/// The text form: [`RECORD_PREFIX`] and the unpadded base64url of the
/// binary form.
impl fmt::Display for KeysetRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(RECORD_PREFIX)?;
        f.write_str(&Base64UrlUnpadded::encode_string(&self.to_bytes()))
    }
}

impl FromStr for KeysetRecord {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn check_name(name: &str) -> Result<(), RecordError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(RecordError::InvalidField { field: "name" });
    }
    Ok(())
}

fn check_key_ref(key_ref: &str) -> Result<(), RecordError> {
    if key_ref.is_empty() || key_ref.len() > usize::from(u16::MAX) {
        return Err(RecordError::InvalidField { field: "key_ref" });
    }
    Ok(())
}

fn check_wrapped(wrapped: &[u8]) -> Result<(), RecordError> {
    if wrapped.is_empty() || wrapped.len() > usize::from(u16::MAX) {
        return Err(RecordError::InvalidField {
            field: "wrapped_key",
        });
    }
    Ok(())
}

fn utf8(bytes: &[u8], field: &'static str) -> Result<String, RecordError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| RecordError::InvalidField { field })
}

/// A cursor over the binary form. Every read past the end is
/// [`RecordError::Length`].
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], RecordError> {
        if self.0.len() < len {
            return Err(RecordError::Length);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, RecordError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, RecordError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> KeysetRecord {
        KeysetRecord::from_parts(
            Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
            Some("acme".into()),
            KeyVendor::Aws,
            KeyMode::Derived,
            "arn:aws:kms:us-east-1:111122223333:key/k".into(),
            vec![1, 2, 3],
        )
        .unwrap()
    }

    #[test]
    fn a_record_round_trips_through_its_text_form() {
        let record = record();
        let text = record.to_string();
        assert!(text.starts_with(RECORD_PREFIX));
        assert_eq!(KeysetRecord::parse(&text).unwrap(), record);
        assert_eq!(text.parse::<KeysetRecord>().unwrap(), record);
        // Whitespace around a value pasted into an env var is not an error.
        assert_eq!(KeysetRecord::parse(&format!(" {text}\n")).unwrap(), record);

        let unnamed = KeysetRecord {
            name: None,
            ..record
        };
        assert_eq!(KeysetRecord::parse(&unnamed.to_string()).unwrap(), unnamed);
    }

    /// The text form is a storage commitment: this pin fails if it moves.
    #[test]
    fn the_text_form_is_pinned() {
        assert_eq!(record().to_string(), "stack-keyset:AQECAQIDBAUGBwgJCgsMDQ4PEARhY21lAChhcm46YXdzOmttczp1cy1lYXN0LTE6MTExMTIyMjIzMzMzOmtleS9rAAMBAgM");
    }

    fn reencode(bytes: &[u8]) -> String {
        format!("{RECORD_PREFIX}{}", Base64UrlUnpadded::encode_string(bytes))
    }

    #[test]
    fn parsing_refuses_what_it_does_not_know() {
        let bytes = record().to_bytes();
        let refuse = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = bytes.clone();
            edit(&mut bytes);
            KeysetRecord::parse(&reencode(&bytes)).unwrap_err()
        };
        assert!(matches!(
            refuse(&|b| b[0] = 2),
            RecordError::UnknownVersion(2)
        ));
        assert!(matches!(
            refuse(&|b| b[0] = 0),
            RecordError::UnknownVersion(0)
        ));
        assert!(matches!(
            refuse(&|b| b[1] = 0),
            RecordError::UnknownBackend(0)
        ));
        assert!(matches!(
            refuse(&|b| b[1] = 99),
            RecordError::UnknownBackend(99)
        ));
        assert!(matches!(refuse(&|b| b[2] = 3), RecordError::UnknownMode(3)));
        assert!(matches!(refuse(&|b| b[2] = 0), RecordError::UnknownMode(0)));
        assert!(matches!(refuse(&|b| b[2] = 1), RecordError::UnknownMode(1)));
        assert!(matches!(refuse(&|b| b.push(0)), RecordError::Length));
        assert!(matches!(
            refuse(&|b| {
                let _ = b.pop();
            }),
            RecordError::Length
        ));
        assert!(matches!(refuse(&|b| b.truncate(10)), RecordError::Length));
        assert!(matches!(
            KeysetRecord::parse("stack-keyset:***"),
            Err(RecordError::Encoding)
        ));
        assert!(matches!(
            KeysetRecord::parse("not-a-record"),
            Err(RecordError::NotARecord)
        ));
        assert!(matches!(
            KeysetRecord::parse(""),
            Err(RecordError::NotARecord)
        ));
    }

    #[test]
    fn fields_are_checked() {
        let base = record();
        let bad_name = KeysetRecord::from_parts(
            base.id,
            Some(String::new()),
            base.vendor,
            base.mode,
            base.key_ref.clone(),
            base.wrapped_key.clone(),
        );
        assert!(matches!(
            bad_name,
            Err(RecordError::InvalidField { field: "name" })
        ));
        let long_name = KeysetRecord::from_parts(
            base.id,
            Some("n".repeat(256)),
            base.vendor,
            base.mode,
            base.key_ref.clone(),
            base.wrapped_key.clone(),
        );
        assert!(long_name.is_err());
        assert!(KeysetRecord::from_parts(
            base.id,
            Some("n".repeat(255)),
            base.vendor,
            base.mode,
            base.key_ref.clone(),
            base.wrapped_key.clone(),
        )
        .is_ok());
        assert!(matches!(
            KeysetRecord::from_parts(
                base.id,
                None,
                base.vendor,
                base.mode,
                String::new(),
                vec![1]
            ),
            Err(RecordError::InvalidField { field: "key_ref" })
        ));
        assert!(matches!(
            KeysetRecord::from_parts(base.id, None, base.vendor, base.mode, "k".into(), vec![]),
            Err(RecordError::InvalidField {
                field: "wrapped_key"
            })
        ));
    }

    #[test]
    fn debug_shows_no_wrapped_key() {
        let shown = format!("{:?}", record());
        assert!(shown.contains("wrapped_key_len: 3"), "{shown}");
        assert!(!shown.contains("[1, 2, 3]"), "{shown}");
    }
}

//! Errors from keyset records and from building a key vendor backend.

use stack_kms::{diagnostic::payload, ErrorPayload, KeyVendor};
use uuid::Uuid;

/// A keyset record could not be parsed, created or loaded.
///
/// No message carries key material or a wrapped key. A parse error names
/// what is wrong with the record, not the record.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum RecordError {
    /// The text does not start with [`RECORD_PREFIX`](crate::RECORD_PREFIX).
    #[error("This is not a keyset record: it does not start with `stack-keyset:`")]
    #[diagnostic(
        code(stack_kms_vendor::record_prefix),
        help("Copy the whole keyset record, as `stash keyset create` printed it.")
    )]
    NotARecord,

    /// The text after the prefix is not unpadded base64url.
    #[error("The keyset record is not valid base64url")]
    #[diagnostic(code(stack_kms_vendor::record_encoding))]
    Encoding,

    /// The record has a format version this build does not know.
    #[error("The keyset record has format version {0}, which this build does not know")]
    #[diagnostic(
        code(stack_kms_vendor::record_version),
        help("Upgrade to a release that reads this record version.")
    )]
    UnknownVersion(u8),

    /// The record names a key backend this build does not know.
    #[error("The keyset record names key backend {0}, which this build does not know")]
    #[diagnostic(code(stack_kms_vendor::record_backend))]
    UnknownBackend(u8),

    /// The record names a key mode this build does not know.
    #[error("The keyset record names key mode {0}, which this build does not know")]
    #[diagnostic(code(stack_kms_vendor::record_mode))]
    UnknownMode(u8),

    /// The record is shorter than its fields say, or has bytes after them.
    #[error("The keyset record is damaged: its length does not match its fields")]
    #[diagnostic(code(stack_kms_vendor::record_length))]
    Length,

    /// A field holds a value it may not hold.
    #[error("The keyset record field `{field}` is not valid")]
    #[diagnostic(
        code(stack_kms_vendor::record_field),
        help("A name is 1 to 255 bytes of UTF-8. A vendor key reference and a wrapped key are 1 to 65535 bytes.")
    )]
    InvalidField {
        /// The field.
        field: &'static str,
    },

    /// A record names another key vendor backend than the one it was given
    /// to.
    #[error("The keyset record {keyset} names key backend {found}, not {expected}")]
    #[diagnostic(code(stack_kms_vendor::foreign_vendor))]
    ForeignVendor {
        /// The keyset.
        keyset: Uuid,
        /// The vendor of the backend.
        expected: KeyVendor,
        /// The vendor the record names.
        found: KeyVendor,
    },

    /// Two records name the same keyset id.
    #[error("Two keyset records have the id {0}")]
    #[diagnostic(code(stack_kms_vendor::duplicate_keyset))]
    DuplicateKeyset(Uuid),

    /// Two records have the same name.
    #[error("Two keyset records have the same name")]
    #[diagnostic(
        code(stack_kms_vendor::duplicate_name),
        help("A keyset name resolves locally, so it must be unique among the loaded records.")
    )]
    DuplicateName,

    /// The records name more than one key vendor backend. A cipher holds
    /// ZeroKMS and at most one key vendor backend (ADR-0013).
    #[error("The keyset records name two key vendor backends, {first} and {second}")]
    #[diagnostic(
        code(stack_kms_vendor::second_vendor),
        help("A cipher holds ZeroKMS and at most one key vendor backend. Load the records of one vendor.")
    )]
    SecondVendor {
        /// The vendor named first.
        first: KeyVendor,
        /// Another vendor.
        second: KeyVendor,
    },

    /// The default keyset is not one of the loaded records.
    #[error("The default keyset is not one of the loaded keyset records")]
    #[diagnostic(code(stack_kms_vendor::unknown_default))]
    UnknownDefault,

    /// The vendor call that created or rewrapped the record failed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Kms(#[from] stack_kms::Error),
}

impl ErrorPayload for RecordError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::UnknownVersion(byte) | Self::UnknownBackend(byte) | Self::UnknownMode(byte) => {
                payload([("byte", (*byte).into())])
            }
            Self::InvalidField { field } => payload([("field", (*field).into())]),
            Self::ForeignVendor {
                keyset,
                expected,
                found,
            } => payload([
                ("keyset", keyset.to_string().into()),
                ("expected", expected.name().into()),
                ("found", found.name().into()),
            ]),
            Self::DuplicateKeyset(keyset) => payload([("keyset", keyset.to_string().into())]),
            Self::SecondVendor { first, second } => payload([
                ("first", first.name().into()),
                ("second", second.name().into()),
            ]),
            Self::Kms(error) => error.payload(),
            Self::NotARecord
            | Self::Encoding
            | Self::Length
            | Self::DuplicateName
            | Self::UnknownDefault => serde_json::Map::new(),
        }
    }
}

//! Which key backend a key source is, and the key mode of a key vendor
//! backend's keyset.
//!
//! A keyset is in exactly one key backend. A sealed leaf names its keyset,
//! and the key source routes it by that id (`stack_kms_vendor::KeyRouter`),
//! so the leaf itself names no backend: every leaf is the v1 leaf.
//!
//! A key vendor backend's keyset record stores one byte for the vendor
//! ([`KeyVendor::byte`]) and one byte for the key mode ([`KeyMode::byte`]).
//! `stack-kms-vendor` binds both bytes into the associated data of the
//! record's wrapped key and into the derivation of every data key and
//! index key, so a record whose vendor or mode was changed opens nothing.
//!
//! # Stable byte values
//!
//! The byte values are a storage commitment: a keyset record holds them,
//! and the keys of stored values are derived under them. A value is never
//! reused and never renumbered. The value `0` is reserved as invalid for
//! both fields, so a zeroed field never decodes.
//!
//! | vendor               | byte |
//! |----------------------|------|
//! | (invalid)            | 0    |
//! | AWS KMS              | 1    |
//! | Google Cloud KMS     | 2    |
//! | Azure Managed HSM    | 3    |
//! | HashiCorp Vault      | 4    |
//! | static key           | 5    |
//!
//! | key mode             | byte |
//! |----------------------|------|
//! | (invalid)            | 0    |
//! | (reserved)           | 1    |
//! | derived data key     | 2    |

use std::fmt;

/// The service a keyset's data keys and index key come from: ZeroKMS, or
/// one key vendor backend.
///
/// The `backend` of [`Error::Backend`](crate::Error::Backend) names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyBackend {
    /// ZeroKMS.
    ZeroKms,
    /// A key vendor backend.
    Vendor(KeyVendor),
}

impl KeyBackend {
    /// A stable, lower-case name for logs and error payloads.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ZeroKms => "zerokms",
            Self::Vendor(vendor) => vendor.name(),
        }
    }
}

impl From<KeyVendor> for KeyBackend {
    fn from(vendor: KeyVendor) -> Self {
        Self::Vendor(vendor)
    }
}

impl fmt::Display for KeyBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A key vendor backend: a key backend that is not ZeroKMS.
///
/// Each variant has a stable byte ([`byte`](Self::byte)), which a keyset
/// record stores. See the module docs for the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum KeyVendor {
    /// AWS KMS.
    Aws = 1,
    /// Google Cloud KMS.
    Gcp = 2,
    /// Azure Managed HSM.
    Azure = 3,
    /// HashiCorp Vault Transit.
    Vault = 4,
    /// A static key, held in memory.
    Static = 5,
}

impl KeyVendor {
    /// Every vendor, in byte order.
    pub const ALL: [Self; 5] = [Self::Aws, Self::Gcp, Self::Azure, Self::Vault, Self::Static];

    /// The byte a keyset record stores for this vendor.
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// The vendor a record's vendor byte names, or `None` for a byte that
    /// names no vendor (`0` included).
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Aws),
            2 => Some(Self::Gcp),
            3 => Some(Self::Azure),
            4 => Some(Self::Vault),
            5 => Some(Self::Static),
            _ => None,
        }
    }

    /// A stable, lower-case name. It is the one spelling of the vendor: the
    /// `vendor` field of [`Error::Backend`](crate::Error::Backend) and
    /// [`Error::ZeroKmsOnly`](crate::Error::ZeroKmsOnly) payloads, the
    /// `key_vendor` value of the Go guest's config, and the `backend` that
    /// `stash keyset` reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aws => "aws-kms",
            Self::Gcp => "gcp-kms",
            Self::Azure => "azure-managed-hsm",
            Self::Vault => "vault-transit",
            Self::Static => "static",
        }
    }

    /// The vendor that [`name`](Self::name) spells `name`, or `None` for a
    /// name that is not one of them. The match is exact.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|vendor| vendor.name() == name)
    }
}

impl fmt::Display for KeyVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The key mode of a keyset in a key vendor backend (ADR-0014).
///
/// Each variant has a stable byte ([`byte`](Self::byte)), which a keyset
/// record stores. ZeroKMS has no key mode.
///
/// There is one mode today. The type is `#[non_exhaustive]`, so a mode
/// added later changes no format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum KeyMode {
    /// Derived data key: each data key is derived from the keyset's root
    /// key. The leaf's tag is empty, and its iv is the derivation salt.
    Derived = 2,
}

impl KeyMode {
    /// Every mode, in byte order.
    pub const ALL: [Self; 1] = [Self::Derived];

    /// The byte a keyset record stores for this mode.
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// The mode a record's mode byte names, or `None` for a byte that names
    /// no mode (`0` and the reserved `1` included).
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            2 => Some(Self::Derived),
            _ => None,
        }
    }

    /// A stable, lower-case name for logs and error payloads.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Derived => "derived",
        }
    }
}

impl fmt::Display for KeyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte values are a storage commitment. This pin fails if one
    /// moves.
    #[test]
    fn the_byte_values_are_pinned() {
        let vendors: Vec<(u8, &str)> = KeyVendor::ALL
            .iter()
            .map(|vendor| (vendor.byte(), vendor.name()))
            .collect();
        assert_eq!(
            vendors,
            [
                (1, "aws-kms"),
                (2, "gcp-kms"),
                (3, "azure-managed-hsm"),
                (4, "vault-transit"),
                (5, "static"),
            ]
        );
        for vendor in KeyVendor::ALL {
            assert_eq!(KeyVendor::from_name(vendor.name()), Some(vendor));
        }
        for name in ["aws", "AWS-KMS", "zerokms", ""] {
            assert_eq!(KeyVendor::from_name(name), None, "{name:?}");
        }
        let modes: Vec<(u8, &str)> = KeyMode::ALL
            .iter()
            .map(|mode| (mode.byte(), mode.name()))
            .collect();
        assert_eq!(modes, [(2, "derived")]);
    }

    #[test]
    fn from_byte_inverts_byte_and_refuses_every_other_value() {
        for byte in 0..=u8::MAX {
            match KeyVendor::from_byte(byte) {
                Some(vendor) => assert_eq!(vendor.byte(), byte),
                None => assert!(!KeyVendor::ALL.iter().any(|v| v.byte() == byte), "{byte}"),
            }
            match KeyMode::from_byte(byte) {
                Some(mode) => assert_eq!(mode.byte(), byte),
                None => assert!(!KeyMode::ALL.iter().any(|m| m.byte() == byte), "{byte}"),
            }
        }
        assert_eq!(KeyVendor::from_byte(0), None);
        assert_eq!(KeyMode::from_byte(0), None);
        assert_eq!(KeyMode::from_byte(1), None, "byte 1 is reserved");
    }

    #[test]
    fn names_display_as_themselves() {
        assert_eq!(KeyBackend::ZeroKms.to_string(), "zerokms");
        assert_eq!(KeyBackend::ZeroKms.name(), "zerokms");
        for vendor in KeyVendor::ALL {
            assert_eq!(vendor.to_string(), vendor.name());
            assert_eq!(KeyBackend::Vendor(vendor).to_string(), vendor.name());
        }
        for mode in KeyMode::ALL {
            assert_eq!(mode.to_string(), mode.name());
        }
    }
}

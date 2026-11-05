//! Which key backend a key source is, and the key mode of a key vendor
//! backend's keyset.
//!
//! A sealed leaf names its key backend so that a reader can route it, or
//! refuse it, before it asks for a key. A ZeroKMS leaf names its backend by
//! its format version alone (the v1 leaf). A leaf sealed by a key vendor
//! backend is a v2 leaf, and carries one byte for the vendor
//! ([`KeyVendor::byte`]) and one byte for the key mode ([`KeyMode::byte`]).
//! ADR-0010 has the layout.
//!
//! # Stable byte values
//!
//! The byte values are a storage commitment: a database column holds them.
//! A value is never reused and never renumbered. The value `0` is reserved
//! as invalid for both fields, so a zeroed header never decodes.
//!
//! | vendor               | byte |
//! |----------------------|------|
//! | (invalid)            | 0    |
//! | AWS KMS              | 1    |
//! | Google Cloud KMS     | 2    |
//! | Azure Key Vault      | 3    |
//! | HashiCorp Vault      | 4    |
//! | static key           | 5    |
//!
//! | key mode             | byte |
//! |----------------------|------|
//! | (invalid)            | 0    |
//! | wrapped data key     | 1    |
//! | derived data key     | 2    |

use std::fmt;

/// The service a keyset's data keys and index key come from: ZeroKMS, or
/// one key vendor backend.
///
/// [`DataKeySource::key_backend`](crate::DataKeySource::key_backend)
/// returns it, and a cipher compares it with the backend a sealed leaf
/// names before it asks for a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyBackend {
    /// ZeroKMS. Its leaves are v1 leaves, which have no backend byte.
    ZeroKms,
    /// A key vendor backend. Its leaves are v2 leaves.
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

impl fmt::Display for KeyBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A key vendor backend: a key backend that is not ZeroKMS.
///
/// Each variant has a stable byte ([`byte`](Self::byte)), which a v2 sealed
/// leaf stores. See the module docs for the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum KeyVendor {
    /// AWS KMS.
    Aws = 1,
    /// Google Cloud KMS.
    Gcp = 2,
    /// Azure Key Vault.
    Azure = 3,
    /// HashiCorp Vault Transit.
    Vault = 4,
    /// A static key, held in memory.
    Static = 5,
}

impl KeyVendor {
    /// Every vendor, in byte order.
    pub const ALL: [Self; 5] = [Self::Aws, Self::Gcp, Self::Azure, Self::Vault, Self::Static];

    /// The byte a v2 sealed leaf stores for this vendor.
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// The vendor a v2 leaf's backend byte names, or `None` for a byte that
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

    /// A stable, lower-case name. A key vendor backend uses it as the
    /// `vendor` of its [`Error::Backend`](crate::Error::Backend) and
    /// [`Error::ZeroKmsOnly`](crate::Error::ZeroKmsOnly).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aws => "aws-kms",
            Self::Gcp => "gcp-kms",
            Self::Azure => "azure-key-vault",
            Self::Vault => "vault-transit",
            Self::Static => "static",
        }
    }
}

impl fmt::Display for KeyVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The key mode of a keyset in a key vendor backend (ADR-0009).
///
/// Each variant has a stable byte ([`byte`](Self::byte)), which a v2 sealed
/// leaf stores. ZeroKMS has no key mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyMode {
    /// Wrapped data key: each value has its own data key, wrapped by the
    /// vendor key. The leaf's tag holds the wrapped data key.
    Wrapped = 1,
    /// Derived data key: each data key is derived from the keyset's root
    /// key. The leaf's tag is empty, and its iv is the derivation salt.
    Derived = 2,
}

impl KeyMode {
    /// Both modes, in byte order.
    pub const ALL: [Self; 2] = [Self::Wrapped, Self::Derived];

    /// The byte a v2 sealed leaf stores for this mode.
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// The mode a v2 leaf's mode byte names, or `None` for a byte that
    /// names no mode (`0` included).
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Wrapped),
            2 => Some(Self::Derived),
            _ => None,
        }
    }

    /// A stable, lower-case name for logs and error payloads.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wrapped => "wrapped",
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
                (3, "azure-key-vault"),
                (4, "vault-transit"),
                (5, "static"),
            ]
        );
        let modes: Vec<(u8, &str)> = KeyMode::ALL
            .iter()
            .map(|mode| (mode.byte(), mode.name()))
            .collect();
        assert_eq!(modes, [(1, "wrapped"), (2, "derived")]);
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

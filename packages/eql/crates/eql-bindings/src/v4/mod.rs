//! # `eql_v4` domain payload types
//!
//! EQL v4 is the v3 SQL installed under a second name (ADR-0002): `eql_v3`
//! holds terms written by cipherstash-client, `eql_v4` holds terms written by
//! Stack Encrypt. The structs here are generated from the same catalog as
//! [`crate::v3`], with `eql_v4_*` domain names and a `v` of `4`.
//!
//! **Only these structs derive Stack Encrypt's traits** (`EncryptFrom`,
//! `DecryptInto`). Only Stack Encrypt produces a v4 value, so this module
//! exists only with the `stack-encrypt` feature. Stack Encrypt's output
//! is not byte-for-byte compatible with cipherstash-client's, so no `eql_v3`
//! struct claims it. Which v4 types derive them is
//! `eql-codegen`'s `ENCRYPTION_DOMAINS`; the rest say why in
//! `crate::encryption::targets`.
//!
//! v4 has no SteVec bindings, payload enums, TypeScript export or
//! published JSON Schema yet; those follow in `@cipherstash/eql` 4.0. The
//! term newtypes and the [`DomainType`] trait are shared with v3: a v4
//! `Ciphertext` or `Hmac256` is v3's type, so a change to a term's validation
//! in `v3::terms` changes v4 too. What separates the two on the wire is the
//! envelope's [`SchemaVersion`], which refuses the other generation's `v`.

pub mod bigint;
pub mod boolean;
pub mod date;
pub mod double;
pub mod integer;
pub mod inventory;
/// Generated bindings for the `json` family's bare scalar storage domain
/// (`public.eql_v4_json`, the `Json` struct).
pub mod json;
pub mod numeric;
pub mod real;
pub mod smallint;
/// Generated: the table of EQL types a Stack Encrypt data plan may name as
/// a field target (`TARGETS`) and the by-name dispatch that runs a
/// producible type's own plan. The descriptor type, the errors and the
/// public entry points are hand-written in [`crate::encryption::targets`].
pub mod targets;
pub mod text;
pub mod timestamp;

pub use crate::v3::domain_type::{DomainType, SQL_SCHEMA};
pub use crate::v3::terms;
pub use inventory::{all, all_query};

/// The PostgreSQL typname prefix every `public` v4 domain carries.
pub const PUBLIC_TYPNAME_PREFIX: &str = "eql_v4_";

/// Base URL for the canonical `$id` of a v4 domain's JSON Schema.
pub const SCHEMA_ID_BASE: &str = "https://schemas.cipherstash.com/eql/v4/";

/// EQL v4 wire-format version: the `v` every v4 payload carries, and what the
/// `eql_v4_*` domain CHECKs assert.
pub const EQL_SCHEMA_VERSION: u16 = 4;

/// The envelope version field (`v`) of a v4 payload — always exactly
/// [`EQL_SCHEMA_VERSION`] on the wire.
///
/// Deserialization rejects any other value, so a v3 payload fails at the type
/// boundary instead of at INSERT. The same type as v3's, at version `4`: see
/// [`crate::SchemaVersion`].
pub type SchemaVersion = crate::SchemaVersion<EQL_SCHEMA_VERSION>;

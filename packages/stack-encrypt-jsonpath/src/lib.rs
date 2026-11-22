//! The JSONPath subset that `stack-encrypt`'s JSON index addresses.
//!
//! A [`JsonPath`] names a node of a JSON document: `$`, object members
//! (`.name` or `["name"]`), array elements by position (`[2]`) and every
//! element of an array (`[*]`). Nothing else: no filters, no recursive
//! descent, no slices.
//!
//! The index stores a value under terms derived from its path, so the
//! grammar is part of the stored format. It lives in its own crate so that
//! `stack-encrypt` and `stack-encrypt-derive` read a path the same way: the
//! engine when it seals and queries a document, and the derive when it
//! checks a field's declared paths at compile time. Use it through
//! `stack_encrypt::json`, which re-exports these types.
//!
//! ```
//! use stack_encrypt_jsonpath::{JsonPath, Segment};
//!
//! let path = JsonPath::parse("$.visits[*].place")?;
//! assert_eq!(
//!     path.segments(),
//!     &[
//!         Segment::Key("visits".into()),
//!         Segment::Wildcard,
//!         Segment::Key("place".into()),
//!     ]
//! );
//! assert!(!path.is_positional());
//! assert!(JsonPath::parse("visits").is_err(), "a path starts with `$`");
//! # Ok::<(), stack_encrypt_jsonpath::JsonPathError>(())
//! ```
#![forbid(unsafe_code)]

pub mod json_string;
mod path;

pub use path::{JsonPath, JsonPathError, Segment};

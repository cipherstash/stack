//! How deep a type nests, for [`Encrypt::DEPTH`](super::Encrypt::DEPTH).
//!
//! A depth counts containers below a value's own root, the way the
//! encrypting sink and the transport frame count them: a scalar is `0`, and
//! a sequence or map is one more than its deepest child. `None` means the
//! type alone does not fix it (a recursive type, a frame, a live host
//! value), so only the walk can check it.
//!
//! These are `const fn`s so a type's depth is worked out at compile time,
//! from its fields' depths.
//!
//! A generic type is checked where it is used at a concrete type, when that
//! use is built (`cargo build`, not `cargo check`). `Holder<V128<u32>>` nests
//! one level deeper than `MAX_DEPTH`, so building a use of it fails:
//!
//! ```compile_fail,E0080
//! #![recursion_limit = "512"]
//! use vitaminc_aead::{plan, Encrypt};
//!
//! type V2<T> = Vec<Vec<T>>;
//! type V4<T> = V2<V2<T>>;
//! type V8<T> = V4<V4<T>>;
//! type V16<T> = V8<V8<T>>;
//! type V32<T> = V16<V16<T>>;
//! type V64<T> = V32<V32<T>>;
//! type V128<T> = V64<V64<T>>;
//!
//! #[derive(Encrypt)]
//! struct Holder<T> {
//!     value: T,
//! }
//!
//! let _ = plan::<_, (), _>(Holder { value: V128::<u32>::new() }, "aad");
//! ```
//!
//! One level shallower, at exactly `MAX_DEPTH`, it builds:
//!
//! ```
//! #![recursion_limit = "512"]
//! use vitaminc_aead::{plan, Encrypt};
//!
//! type V2<T> = Vec<Vec<T>>;
//! type V4<T> = V2<V2<T>>;
//! type V8<T> = V4<V4<T>>;
//! type V16<T> = V8<V8<T>>;
//! type V32<T> = V16<V16<T>>;
//! type V64<T> = V32<V32<T>>;
//! type V127<T> = V64<V32<V16<V8<V4<V2<Vec<T>>>>>>>;
//!
//! #[derive(Encrypt)]
//! struct Holder<T> {
//!     value: T,
//! }
//!
//! assert!(plan::<_, (), _>(Holder { value: V127::<u32>::new() }, "aad").is_ok());
//! ```
//!
//! A type with only lifetime parameters is checked where it is defined, as
//! a type with none is, so no use is needed for the error:
//!
//! ```compile_fail,E0080
//! #![recursion_limit = "512"]
//! use vitaminc_aead::Encrypt;
//!
//! type V2<T> = Vec<Vec<T>>;
//! type V4<T> = V2<V2<T>>;
//! type V8<T> = V4<V4<T>>;
//! type V16<T> = V8<V8<T>>;
//! type V32<T> = V16<V16<T>>;
//! type V64<T> = V32<V32<T>>;
//! type V128<T> = V64<V64<T>>;
//!
//! #[derive(Encrypt)]
//! struct Row<'a> {
//!     name: &'a str,
//!     deep: V128<u32>,
//! }
//! ```
//!
//! So is a type whose field is another type of the same name, reached
//! through a path:
//!
//! ```compile_fail,E0080
//! #![recursion_limit = "512"]
//! use vitaminc_aead::Encrypt;
//!
//! type V2<T> = Vec<Vec<T>>;
//! type V4<T> = V2<V2<T>>;
//! type V8<T> = V4<V4<T>>;
//! type V16<T> = V8<V8<T>>;
//! type V32<T> = V16<V16<T>>;
//! type V64<T> = V32<V32<T>>;
//!
//! mod legacy {
//!     pub type User = super::V64<super::V64<u32>>;
//! }
//!
//! #[derive(Encrypt)]
//! struct User {
//!     id: u32,
//!     inner: legacy::User,
//! }
//! # fn main() {}
//! ```

use crate::frame::MAX_DEPTH;

/// A scalar: nothing below it.
pub const SCALAR: Option<usize> = Some(0);

/// A sequence or map whose deepest child nests `child` deep.
pub const fn container(child: Option<usize>) -> Option<usize> {
    match child {
        Some(depth) => Some(depth.saturating_add(1)),
        None => None,
    }
}

/// The deeper of two depths. Not fixed if either is not.
pub const fn max(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if a > b { a } else { b }),
        _ => None,
    }
}

/// A passthrough field whose value nests `value` deep. The frame that
/// carries it starts one level below the passthrough node, as the transport
/// decoder counts it.
pub const fn passthrough(value: Option<usize>) -> Option<usize> {
    container(value)
}

/// Whether a value this deep can be encrypted: at most
/// [`MAX_DEPTH`]. A depth that is not fixed passes, because the
/// walk checks it.
pub const fn within_limit(depth: Option<usize>) -> bool {
    match depth {
        Some(depth) => depth <= MAX_DEPTH,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_container_is_one_deeper_than_its_child() {
        assert_eq!(container(SCALAR), Some(1));
        assert_eq!(container(Some(4)), Some(5));
        assert_eq!(container(None), None);
        assert_eq!(container(Some(usize::MAX)), Some(usize::MAX));
    }

    #[test]
    fn max_is_not_fixed_if_either_side_is_not() {
        assert_eq!(max(Some(2), Some(5)), Some(5));
        assert_eq!(max(Some(5), Some(2)), Some(5));
        assert_eq!(max(Some(2), None), None);
        assert_eq!(max(None, Some(2)), None);
    }

    #[test]
    fn the_limit_is_max_depth_inclusive() {
        assert!(within_limit(Some(MAX_DEPTH)));
        assert!(!within_limit(Some(MAX_DEPTH + 1)));
        assert!(within_limit(None));
    }
}

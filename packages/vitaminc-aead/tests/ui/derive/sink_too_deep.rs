//! A struct whose fully populated values nest deeper than `MAX_DEPTH` would
//! be refused by the encrypting sink every time it held data that deep, so
//! it does not compile.

// A type this deep takes more than the default 128 steps for rustc to
// resolve; without this, its own recursion limit is hit first.
#![recursion_limit = "512"]

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Encrypt;

type V2<T> = Vec<Vec<T>>;
type V4<T> = V2<V2<T>>;
type V8<T> = V4<V4<T>>;
type V16<T> = V8<V8<T>>;
type V32<T> = V16<V16<T>>;
type V64<T> = V32<V32<T>>;
type V128<T> = V64<V64<T>>;

#[derive(Encrypt)]
#[aead(crate = "::vitaminc_aead")]
struct TooDeep {
    deep: V128<u32>,
}

fn main() {}

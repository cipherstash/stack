//! A type that nests deeper than any value Stack Encrypt encrypts. The
//! error names the limit by its `stack_encrypt` path.
#![recursion_limit = "512"]
use stack_encrypt::Encrypt;

type V2<T> = Vec<Vec<T>>;
type V4<T> = V2<V2<T>>;
type V8<T> = V4<V4<T>>;
type V16<T> = V8<V8<T>>;
type V32<T> = V16<V16<T>>;
type V64<T> = V32<V32<T>>;
type V128<T> = V64<V64<T>>;

#[derive(Encrypt)]
struct TooDeep {
    deep: V128<u32>,
}

fn main() {}

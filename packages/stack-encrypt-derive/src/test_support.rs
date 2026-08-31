//! Helpers shared by the expansion tests in `encrypt` and `decrypt`.
//!
//! Expansions are asserted as *tokens*, never as text: the expected fragment is
//! rendered through `quote!` as well, so it is written as ordinary Rust and the
//! comparison cannot fail on `TokenStream`'s spacing.
//!
//! Whitespace is stripped from both sides before comparing: `quote!` renders
//! a joint `>>` where a `parse_quote!`-built predicate renders `> >`, and
//! the two are the same tokens.
//!
//! One caveat: rustfmt formats inside `quote!` bodies and will add or strip a
//! trailing comma, which *does* change the tokens. Keep fragments short enough
//! that rustfmt leaves them alone, or mark the test `#[rustfmt::skip]`.

use proc_macro2::TokenStream;

fn squash(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

#[track_caller]
pub(crate) fn assert_contains(expansion: &str, fragment: TokenStream) {
    let fragment = fragment.to_string();
    assert!(
        squash(expansion).contains(&squash(&fragment)),
        "expansion is missing `{fragment}`:\n{expansion}"
    );
}

#[track_caller]
pub(crate) fn assert_lacks(expansion: &str, fragment: TokenStream) {
    let fragment = fragment.to_string();
    assert!(
        !squash(expansion).contains(&squash(&fragment)),
        "expansion unexpectedly contains `{fragment}`:\n{expansion}"
    );
}

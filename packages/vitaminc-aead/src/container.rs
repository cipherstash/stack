/// The recursive ciphertext container shared by tree-shaped [`Cipher`]
/// implementations.
///
/// The shape mirrors the structure of the plaintext that was encrypted: a
/// single value yields [`Single`](CipherText::Single), while non-empty `Vec`s
/// and `HashMap`s yield [`Sequence`](CipherText::Sequence) and
/// [`Map`](CipherText::Map). Empty composites use the authenticated marker
/// variants [`EmptySequence`](CipherText::EmptySequence) and
/// [`EmptyMap`](CipherText::EmptyMap), since they contain no element
/// ciphertexts to authenticate the supplied AAD. Nested structures are
/// represented recursively.
///
/// Concrete ciphers instantiate the two parameters:
///
/// - `Leaf` is the sealed leaf ciphertext (nonce + ciphertext + tag) — e.g.
///   [`LocalCipherText`](crate::LocalCipherText) for a local AES cipher, or an
///   envelope leaf that additionally carries a wrapped data key.
/// - `P` is the passthrough payload type, fixed by the cipher's
///   [`Cipher::Passthrough`](crate::Cipher::Passthrough) associated type.
///   Rust-native ciphers typically use `Box<dyn Any + Send>`; FFI-targeting
///   ciphers use an owned host-value type carried value-in/value-out.
///
/// Only the `Leaf` type carries a byte-level format commitment (and should
/// implement `serde` where ciphertexts are persisted). The container itself
/// has no canonical byte representation: hosts project it onto their native
/// structures (e.g. a JS object tree across an FFI boundary), with leaves as
/// opaque byte strings.
///
/// [`Cipher`]: crate::Cipher
#[derive(Debug)]
pub enum CipherText<Leaf, P> {
    /// A single sealed value.
    Single(Leaf),
    /// A sequence of ciphertexts produced from a `Vec`-shaped plaintext.
    Sequence(Vec<CipherText<Leaf, P>>),
    /// An empty sequence, authenticated under domain-separated AAD via the
    /// marker leaf produced at [`SeqCipher::end`](crate::SeqCipher::end).
    EmptySequence(Leaf),
    /// A map of (cleartext key, ciphertext value) pairs produced from a
    /// map-shaped plaintext. Keys are stored in the clear but are bound into
    /// each value's AAD via [`Aad::for_map_entry`](crate::Aad::for_map_entry),
    /// so they cannot be swapped or renamed undetected (passthrough entries
    /// excepted).
    Map(Vec<(String, CipherText<Leaf, P>)>),
    /// An empty map, authenticated under domain-separated AAD via the marker
    /// leaf produced at [`MapCipher::end`](crate::MapCipher::end).
    EmptyMap(Leaf),
    /// The authenticated absent marker produced by
    /// [`Cipher::encrypt_none`](crate::Cipher::encrypt_none). Stores a sealed
    /// empty plaintext whose tag binds the supplied AAD.
    None(Leaf),
    /// A value passed through the container **unencrypted and
    /// unauthenticated** via [`Cipher::passthrough`](crate::Cipher::passthrough).
    /// Non-sensitive data only — see the trait docs.
    Passthrough(P),
}

impl<Leaf, P> CipherText<Leaf, P> {
    /// Recursively convert the passthrough payload type, leaving the sealed
    /// structure untouched.
    ///
    /// This is the bridge between ciphers with different passthrough payload
    /// types — e.g. re-homing a tree between the Rust-native
    /// `Box<dyn Any + Send>` and an owned FFI value type at an FFI boundary.
    /// The conversion is fallible so payloads that cannot be represented in
    /// the target type surface an error instead of being silently dropped; a
    /// tree containing no passthrough values never invokes `f`.
    pub fn map_passthrough<Q, E, F>(self, f: &mut F) -> Result<CipherText<Leaf, Q>, E>
    where
        F: FnMut(P) -> Result<Q, E>,
    {
        Ok(match self {
            CipherText::Single(leaf) => CipherText::Single(leaf),
            CipherText::None(leaf) => CipherText::None(leaf),
            CipherText::EmptySequence(leaf) => CipherText::EmptySequence(leaf),
            CipherText::EmptyMap(leaf) => CipherText::EmptyMap(leaf),
            CipherText::Sequence(items) => CipherText::Sequence(
                items
                    .into_iter()
                    .map(|item| item.map_passthrough(f))
                    .collect::<Result<_, E>>()?,
            ),
            CipherText::Map(entries) => CipherText::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| value.map_passthrough(f).map(|value| (key, value)))
                    .collect::<Result<_, E>>()?,
            ),
            CipherText::Passthrough(value) => CipherText::Passthrough(f(value)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leaf stand-in — `map_passthrough` never inspects the leaf type, so
    /// the tests only need it to be distinguishable.
    type Leaf = &'static str;

    /// Render a tree's shape and payloads as a string, so a converted tree can
    /// be compared against the original structurally.
    fn shape<P: std::fmt::Debug>(ct: &CipherText<Leaf, P>) -> String {
        match ct {
            CipherText::Single(l) => format!("Single({l})"),
            CipherText::None(l) => format!("None({l})"),
            CipherText::EmptySequence(l) => format!("EmptySeq({l})"),
            CipherText::EmptyMap(l) => format!("EmptyMap({l})"),
            CipherText::Sequence(items) => {
                let inner: Vec<_> = items.iter().map(shape).collect();
                format!("Seq[{}]", inner.join(","))
            }
            CipherText::Map(entries) => {
                let inner: Vec<_> = entries
                    .iter()
                    .map(|(k, v)| format!("{k}:{}", shape(v)))
                    .collect();
                format!("Map{{{}}}", inner.join(","))
            }
            CipherText::Passthrough(p) => format!("Pass({p:?})"),
        }
    }

    /// A tree exercising every variant, with passthrough payloads nested at
    /// several depths (top level, inside a sequence, inside a map).
    fn sample() -> CipherText<Leaf, u32> {
        CipherText::Map(vec![
            ("single".into(), CipherText::Single("a")),
            ("none".into(), CipherText::None("b")),
            ("empty_seq".into(), CipherText::EmptySequence("c")),
            ("empty_map".into(), CipherText::EmptyMap("d")),
            ("pass".into(), CipherText::Passthrough(1)),
            (
                "seq".into(),
                CipherText::Sequence(vec![
                    CipherText::Single("e"),
                    CipherText::Passthrough(2),
                    CipherText::Sequence(vec![CipherText::Passthrough(3)]),
                ]),
            ),
        ])
    }

    #[test]
    fn converts_every_passthrough_and_preserves_structure() {
        let converted: CipherText<Leaf, String> = sample()
            .map_passthrough::<_, (), _>(&mut |p| Ok(format!("v{p}")))
            .expect("conversion should succeed");

        // Structure and leaves are untouched; only payloads changed.
        assert_eq!(
            shape(&converted),
            r#"Map{single:Single(a),none:None(b),empty_seq:EmptySeq(c),empty_map:EmptyMap(d),pass:Pass("v1"),seq:Seq[Single(e),Pass("v2"),Seq[Pass("v3")]]}"#
        );
    }

    #[test]
    fn visits_each_payload_exactly_once() {
        let mut seen = Vec::new();
        sample()
            .map_passthrough::<_, (), _>(&mut |p| {
                seen.push(p);
                Ok(p)
            })
            .expect("conversion should succeed");
        // Every passthrough in the tree, including the nested ones.
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn a_tree_without_passthrough_never_invokes_the_closure() {
        let ct: CipherText<Leaf, u32> = CipherText::Sequence(vec![
            CipherText::Single("a"),
            CipherText::None("b"),
            CipherText::EmptySequence("c"),
            CipherText::EmptyMap("d"),
            CipherText::Map(vec![("k".into(), CipherText::Single("e"))]),
        ]);
        let mut calls = 0;
        let converted: CipherText<Leaf, String> = ct
            .map_passthrough::<_, (), _>(&mut |_| {
                calls += 1;
                Ok(String::new())
            })
            .expect("conversion should succeed");
        assert_eq!(calls, 0);
        assert_eq!(
            shape(&converted),
            "Seq[Single(a),None(b),EmptySeq(c),EmptyMap(d),Map{k:Single(e)}]"
        );
    }

    // A payload the target type cannot represent must surface the error rather
    // than being dropped — the property the fallible signature exists for.

    #[test]
    fn a_failing_conversion_propagates_from_the_top_level() {
        let ct: CipherText<Leaf, u32> = CipherText::Passthrough(1);
        let result = ct.map_passthrough::<String, _, _>(&mut |_| Err("unrepresentable"));
        assert_eq!(result.err(), Some("unrepresentable"));
    }

    #[test]
    fn a_failing_conversion_propagates_from_inside_a_sequence() {
        let ct: CipherText<Leaf, u32> =
            CipherText::Sequence(vec![CipherText::Single("a"), CipherText::Passthrough(1)]);
        let result = ct.map_passthrough::<String, _, _>(&mut |_| Err("unrepresentable"));
        assert_eq!(result.err(), Some("unrepresentable"));
    }

    #[test]
    fn a_failing_conversion_propagates_from_inside_a_map() {
        let ct: CipherText<Leaf, u32> = CipherText::Map(vec![
            ("ok".into(), CipherText::Single("a")),
            ("bad".into(), CipherText::Passthrough(1)),
        ]);
        let result = ct.map_passthrough::<String, _, _>(&mut |_| Err("unrepresentable"));
        assert_eq!(result.err(), Some("unrepresentable"));
    }
}

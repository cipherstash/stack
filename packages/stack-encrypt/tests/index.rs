//! The engine pieces the plan builder lowers onto: indexes as types
//! (`Index`, `Indexes`, `indexed`, `Encrypted<Terms>`), `passthrough`, and
//! running a description held in a variable (`run`, `run_decryption`).
//!
//! The load-bearing claim is byte identity: `indexed` is the hand
//! composition `ciphertext().accepting().zip(..)` and what the derive emits,
//! composed once — same terms, a ciphertext either opens — so a field
//! written one way is found and opened the other.

mod common;

use std::sync::atomic::Ordering;

use common::{counting_cipher, stack_cipher};
use stack_encrypt::sem::{
    DefaultMatch, EqualityTerm, MatchConfig, MatchOptions, MatchTerms, OpeTerm, OreTerm, Tokenizer,
};
use stack_encrypt::target::{
    ciphertext, equality, indexed, matching, ope, ore, passthrough, AeadContext, Borrowed,
    CallerContext, DecryptFrom, Decryption, Encrypted, Encryption, Equality, Index, IndexSpec,
    Indexes, Match, Ope, Ore, Owned,
};
use stack_encrypt::{nonempty, DecryptInto, EncryptFrom, Error, StackCipherText};
use stack_kms::{FakeDataKeySource, IdentifiedBy};
use vitaminc_protected::{Controlled, Protected};

fn caller() -> CallerContext {
    CallerContext::from(nonempty!("users/email"))
}
fn aead() -> AeadContext {
    AeadContext::from(nonempty!("users/email"))
}

/// What the derive emits today for a field with equality and ORE beside its
/// ciphertext: the struct `indexed::<String>((Equality, Ore))` replaces.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String)]
struct DerivedEmail {
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<String>,
}

mod given_equality_and_ore_over_a_string {
    use super::*;

    #[tokio::test]
    async fn indexed_derives_the_terms_the_hand_composition_and_the_derive_derive() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let email = "bob@example.com".to_string();

        let out: Encrypted<(EqualityTerm, OreTerm<String>)> = keyset
            .run(
                indexed::<String, _, Borrowed, _>((Equality, Ore)),
                &email,
                caller(),
            )
            .await
            .expect("indexed");

        let hand = ciphertext::<String, _, Borrowed>()
            .accepting::<CallerContext>()
            .zip(equality::<String, _, Borrowed>())
            .zip(ore::<String, _, Borrowed>());
        let ((hand_c, hand_eq), hand_ore) = keyset.run(hand, &email, caller()).await.expect("hand");

        let derived: DerivedEmail = keyset.encrypt_as(&email, caller()).await.expect("derived");

        let (eq, ore) = out.terms;
        assert_eq!(eq, hand_eq, "equality term matches the hand composition");
        assert_eq!(ore, hand_ore, "ORE term matches the hand composition");
        assert_eq!(eq, derived.hm, "equality term matches the derive");
        assert_eq!(ore, derived.ob, "ORE term matches the derive");

        // A ciphertext is sealed under a fresh data key, so two seals are
        // never byte-equal; what must agree is that each opens under the
        // same context to the same value, by the other path's reader.
        let as_derived = DerivedEmail {
            c: out.ciphertext,
            hm: eq,
            ob: ore,
        };
        let opened: String = as_derived
            .decrypt_into(&cipher, caller())
            .await
            .expect("the derive's reader opens indexed's ciphertext");
        assert_eq!(opened, email);
        let opened: String = Encrypted {
            ciphertext: derived.c,
            terms: (),
        }
        .decrypt_into(&cipher, aead())
        .await
        .expect("Encrypted's reader opens the derive's ciphertext");
        assert_eq!(opened, email);
        let opened: String = keyset
            .decrypt_as(hand_c, aead())
            .await
            .expect("the hand composition's ciphertext opens");
        assert_eq!(opened, email);
    }

    #[tokio::test]
    async fn owned_mode_derives_the_same_terms_and_seals_from_one_key_request() {
        let (cipher, generates, _) = counting_cipher().await;
        let keyset = cipher.default_keyset();
        let email = "bob@example.com".to_string();

        let owned = keyset
            .run(
                indexed::<String, _, Owned, _>((Equality, Ore)),
                email.clone(),
                caller(),
            )
            .await
            .expect("owned");
        assert_eq!(generates.load(Ordering::SeqCst), 1, "one batched request");
        let borrowed = keyset
            .run(
                indexed::<String, _, Borrowed, _>((Equality, Ore)),
                &email,
                caller(),
            )
            .await
            .expect("borrowed");

        assert_eq!(
            owned.terms, borrowed.terms,
            "the mode does not change a term"
        );
        let opened: String = owned.decrypt_into(&cipher, aead()).await.expect("open");
        assert_eq!(opened, email);
    }
}

mod given_a_set_of_indexes {
    use super::*;

    /// A configuration other than the default, so a spec that dropped the
    /// options, or a term derived under the default ones, would show.
    struct Words;
    impl MatchConfig for Words {
        fn options() -> MatchOptions {
            MatchOptions {
                tokenizer: Tokenizer::Standard,
                downcase: false,
                k: 4,
                m: 512,
            }
        }
    }

    #[test]
    fn specs_list_each_index_in_order_with_its_parameters() {
        assert_eq!(
            <Equality as Indexes<u32>>::specs(&Equality),
            [IndexSpec::Equality]
        );
        assert_eq!(<Ore as Indexes<u32>>::specs(&Ore), [IndexSpec::Ore]);
        assert_eq!(<Ope as Indexes<u32>>::specs(&Ope), [IndexSpec::Ope]);
        assert_eq!(
            <Match as Indexes<String>>::specs(&Match::default()),
            [IndexSpec::Match(MatchOptions::default())]
        );
        assert_eq!(
            <Match<Words> as Indexes<String>>::specs(&Match::<Words>::new()),
            [IndexSpec::Match(Words::options())],
            "a match index lowers its own configuration"
        );
        assert_eq!(
            <(Ore, Equality) as Indexes<u32>>::specs(&(Ore, Equality)),
            [IndexSpec::Ore, IndexSpec::Equality]
        );
        assert_eq!(
            <(Ope, Ore, Equality) as Indexes<u32>>::specs(&(Ope, Ore, Equality)),
            [IndexSpec::Ope, IndexSpec::Ore, IndexSpec::Equality]
        );
        assert_eq!(
            <(Match<Words>, Ope, Ore, Equality) as Indexes<String>>::specs(&(
                Match::<Words>::new(),
                Ope,
                Ore,
                Equality
            )),
            [
                IndexSpec::Match(Words::options()),
                IndexSpec::Ope,
                IndexSpec::Ore,
                IndexSpec::Equality
            ]
        );
    }

    #[test]
    fn a_match_index_debugs_by_name_whatever_its_configuration() {
        assert_eq!(format!("{:?}", Match::default()), "Match");
        assert_eq!(format!("{:?}", Match::<Words>::new()), "Match");
        let copied = Match::<Words>::new();
        let again = copied;
        assert_eq!(
            <Match<Words> as Index<String>>::spec(&copied),
            <Match<Words> as Index<String>>::spec(&again),
            "a match index is a plain value: copying it keeps its configuration"
        );
    }

    #[test]
    fn a_spec_is_keyed_and_displayed_as_the_record_format_spells_it() {
        for (spec, key) in [
            (IndexSpec::Equality, "eq"),
            (IndexSpec::Match(MatchOptions::default()), "match"),
            (IndexSpec::Ore, "ore"),
            (IndexSpec::Ope, "ope"),
        ] {
            assert_eq!(spec.key(), key);
            assert_eq!(spec.to_string(), key);
        }
    }

    /// Each index's term is the standalone operation's, in the order the
    /// indexes were named, for every tuple size.
    #[tokio::test]
    async fn every_tuple_yields_the_standalone_terms_in_order() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let text = "Alice Smith".to_string();

        let eq: EqualityTerm = keyset
            .run(equality::<String, _, Borrowed>(), &text, caller())
            .await
            .unwrap();
        let ore_t: OreTerm<String> = keyset
            .run(ore::<String, _, Borrowed>(), &text, caller())
            .await
            .unwrap();
        let ope_t: OpeTerm<String> = keyset
            .run(ope::<String, _, Borrowed>(), &text, caller())
            .await
            .unwrap();
        let words: MatchTerms<Words> = keyset
            .run(matching::<String, _, Borrowed, Words>(), &text, caller())
            .await
            .unwrap();
        let default_match: MatchTerms<DefaultMatch> = keyset
            .run(
                matching::<String, _, Borrowed, DefaultMatch>(),
                &text,
                caller(),
            )
            .await
            .unwrap();
        assert_ne!(
            words.positions(),
            default_match.positions(),
            "the two configurations derive different terms, so the test can tell them apart"
        );

        let one = keyset
            .run(indexed::<String, _, Borrowed, _>(Ope), &text, caller())
            .await
            .unwrap();
        assert_eq!(one.terms, ope_t, "one index's terms are its term");

        let one = keyset
            .run(
                indexed::<String, _, Borrowed, _>(Match::<Words>::new()),
                &text,
                caller(),
            )
            .await
            .unwrap();
        assert_eq!(
            one.terms, words,
            "a match index derives under its own configuration"
        );

        let two = keyset
            .run(
                indexed::<String, _, Borrowed, _>((Ore, Equality)),
                &text,
                caller(),
            )
            .await
            .unwrap();
        assert_eq!(two.terms, (ore_t.clone(), eq.clone()));

        let three = keyset
            .run(
                indexed::<String, _, Borrowed, _>((Ope, Equality, Ore)),
                &text,
                caller(),
            )
            .await
            .unwrap();
        assert_eq!(three.terms, (ope_t.clone(), eq.clone(), ore_t.clone()));

        let four = keyset
            .run(
                indexed::<String, _, Borrowed, _>((Match::<Words>::new(), Ore, Ope, Equality)),
                &text,
                caller(),
            )
            .await
            .unwrap();
        let (m, o, p, e) = four.terms;
        assert_eq!((m, o, p, e), (words, ore_t, ope_t, eq));
        let opened: String = four.ciphertext.decrypt_into(&cipher, aead()).await.unwrap();
        assert_eq!(opened, text);
    }

    /// The query side: one index, picked by type, its term alone.
    #[tokio::test]
    async fn select_picks_each_index_and_its_operation_is_the_term_alone() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let age = 34u32;
        let indexes = (Equality, Ore, Ope);
        let stored = keyset
            .run(indexed::<u32, _, Borrowed, _>(indexes), &age, caller())
            .await
            .unwrap();
        let (eq, ore_t, ope_t) = stored.terms;

        let q: EqualityTerm = keyset
            .run(
                Index::<u32>::operation::<_, Borrowed>(Indexes::<u32>::select::<Equality, _>(
                    &indexes,
                )),
                &age,
                caller(),
            )
            .await
            .unwrap();
        assert_eq!(q, eq, "position 0");
        let q: OreTerm<u32> = keyset
            .run(
                Index::<u32>::operation::<_, Borrowed>(Indexes::<u32>::select::<Ore, _>(&indexes)),
                &age,
                caller(),
            )
            .await
            .unwrap();
        assert_eq!(q, ore_t, "position 1");
        let q: OpeTerm<u32> = keyset
            .run(
                Index::<u32>::operation::<_, Borrowed>(Indexes::<u32>::select::<Ope, _>(&indexes)),
                &age,
                caller(),
            )
            .await
            .unwrap();
        assert_eq!(q, ope_t, "position 2");

        let four = (Equality, Ore, Ope, Match::default());
        assert_eq!(
            Index::<String>::spec(Indexes::<String>::select::<Match, _>(&four)),
            IndexSpec::Match(MatchOptions::default()),
            "position 3"
        );
        assert_eq!(
            Index::<u32>::spec(<Ore as Indexes<u32>>::select::<Ore, _>(&Ore)),
            IndexSpec::Ore,
            "one index selects itself"
        );
        assert_eq!(
            Index::<u32>::spec(<(Ope, Ore) as Indexes<u32>>::select::<Ope, _>(&(Ope, Ore))),
            IndexSpec::Ope,
            "a pair's first"
        );
        assert_eq!(
            Index::<u32>::spec(<(Ope, Ore) as Indexes<u32>>::select::<Ore, _>(&(Ope, Ore))),
            IndexSpec::Ore,
            "a pair's second"
        );
    }

    /// The query side needs no copy: a term over an owned plaintext that is
    /// not `Clone` runs from the selected index alone.
    #[tokio::test]
    async fn a_selected_index_runs_over_an_owned_plaintext_without_clone() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let q: EqualityTerm = keyset
            .run(
                Index::<Protected<String>>::operation::<_, Owned>(&Equality),
                Protected::new("bob".to_string()),
                caller(),
            )
            .await
            .unwrap();
        let typed: EqualityTerm = keyset
            .run(
                equality::<String, _, Borrowed>(),
                &"bob".to_string(),
                caller(),
            )
            .await
            .unwrap();
        assert_eq!(q, typed);
    }
}

mod given_a_passthrough {
    use super::*;

    /// A value that is moved, never copied.
    struct Unclonable(Protected<String>);

    #[tokio::test]
    async fn borrowed_hands_back_a_copy_with_no_key_request_whatever_the_context() {
        let (cipher, generates, retrieves) = counting_cipher().await;
        let keyset = cipher.default_keyset();
        let id = "row-7".to_string();
        // `()` is a context no operation can run under, so a passthrough
        // that consulted its context could not run here at all.
        let out: String = keyset
            .run(passthrough::<String, _, Borrowed, ()>(), &id, ())
            .await
            .expect("passthrough");
        assert_eq!(out, id);
        assert_eq!(generates.load(Ordering::SeqCst), 0, "nothing is sealed");
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn owned_moves_the_value_through_without_clone() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let out = keyset
            .run(
                passthrough::<Unclonable, _, Owned, CallerContext>(),
                Unclonable(Protected::new("row-7".to_string())),
                caller(),
            )
            .await
            .expect("passthrough");
        assert_eq!(out.0.risky_ref(), "row-7");
    }

    /// Beside a sealed field it rides in the same run, which seals only the
    /// ciphertext: one key request, and the carried value is the source.
    #[tokio::test]
    async fn beside_a_sealed_field_it_is_carried_unsealed() {
        let (cipher, generates, _) = counting_cipher().await;
        let keyset = cipher.default_keyset();
        let value = "carried".to_string();
        let both: Encryption<'_, String, (StackCipherText, String), _, AeadContext> =
            ciphertext::<String, _, Borrowed>().zip(passthrough::<String, _, Borrowed, _>());
        let (sealed, carried) = keyset.run(both, &value, aead()).await.expect("run");
        assert_eq!(carried, value);
        assert_eq!(
            generates.load(Ordering::SeqCst),
            1,
            "one batch, for the ciphertext"
        );
        let opened: String = keyset.decrypt_as(sealed, aead()).await.expect("open");
        assert_eq!(opened, value);
    }
}

mod given_a_decryption_held_in_a_variable {
    use super::*;

    #[tokio::test]
    async fn run_decryption_opens_it_through_a_keyset_or_the_client() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed: StackCipherText = keyset
            .encrypt_as(&"secret".to_string(), aead())
            .await
            .unwrap();
        let again: StackCipherText = keyset
            .encrypt_as(&"secret".to_string(), aead())
            .await
            .unwrap();

        let opening: Decryption<String, FakeDataKeySource> =
            stack_encrypt::target::open(sealed, aead());
        assert_eq!(keyset.run_decryption(opening).await.unwrap(), "secret");
        let opening: Decryption<String, FakeDataKeySource> =
            stack_encrypt::target::open(again, aead());
        assert_eq!(cipher.run_decryption(opening).await.unwrap(), "secret");
    }

    #[tokio::test]
    async fn a_keyset_refuses_another_keysets_leaf_and_the_client_opens_it() {
        let cipher = stack_cipher().await;
        let acme = cipher
            .keyset(IdentifiedBy::Name("acme".to_string().into()))
            .await
            .unwrap();
        let globex = cipher
            .keyset(IdentifiedBy::Name("globex".to_string().into()))
            .await
            .unwrap();
        let sealed: StackCipherText = acme
            .encrypt_as(&"secret".to_string(), aead())
            .await
            .unwrap();
        let again: StackCipherText = acme
            .encrypt_as(&"secret".to_string(), aead())
            .await
            .unwrap();

        let result = globex
            .run_decryption(stack_encrypt::target::open::<String, _>(sealed, aead()))
            .await;
        assert!(
            matches!(result, Err(Error::ForeignKeyset { .. })),
            "{result:?}"
        );
        let opened = cipher
            .run_decryption(stack_encrypt::target::open::<String, _>(again, aead()))
            .await
            .unwrap();
        assert_eq!(opened, "secret");
    }
}

mod given_encrypted_terms_as_a_target {
    use super::*;
    use stack_encrypt::target::TermSet;

    /// A configuration other than the default, so a target that derived its
    /// match terms under the default one would show.
    struct Words;
    impl MatchConfig for Words {
        fn options() -> MatchOptions {
            MatchOptions {
                tokenizer: Tokenizer::Standard,
                downcase: false,
                k: 4,
                m: 512,
            }
        }
    }

    /// The typed spelling, `Encrypted<Terms>` as a target, beside the data
    /// spelling, `indexed(indexes)`: the same terms, and each ciphertext
    /// opens through the other's reader.
    async fn same_bytes<S, Terms, X>(value: S, indexes: X)
    where
        S: stack_encrypt::Encrypt
            + for<'a> stack_encrypt::Decrypt<'a>
            + Clone
            + PartialEq
            + std::fmt::Debug
            + 'static,
        Terms: TermSet<S> + PartialEq + std::fmt::Debug,
        X: Indexes<S, Terms = Terms>,
    {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();

        let typed: Encrypted<Terms> = keyset.encrypt_as(&value, caller()).await.expect("typed");
        let data = keyset
            .run(indexed::<S, _, Borrowed, _>(indexes), &value, caller())
            .await
            .expect("data");
        assert_eq!(
            typed.terms, data.terms,
            "the typed and data spellings agree"
        );

        let opened: S = Encrypted {
            ciphertext: typed.ciphertext,
            terms: (),
        }
        .decrypt_into(&cipher, aead())
        .await
        .expect("the typed ciphertext opens");
        assert_eq!(opened, value);
        let opened: S = data
            .decrypt_into(&cipher, aead())
            .await
            .expect("data opens");
        assert_eq!(opened, value);
    }

    #[tokio::test]
    async fn every_term_alone_lowers_to_its_index() {
        same_bytes::<u32, EqualityTerm, _>(7, Equality).await;
        same_bytes::<String, MatchTerms, _>("hello world".into(), Match::default()).await;
        same_bytes::<String, MatchTerms<Words>, _>("Hello World".into(), Match::<Words>::new())
            .await;
        same_bytes::<u32, OreTerm<u32>, _>(7, Ore).await;
        same_bytes::<u32, OpeTerm<u32>, _>(7, Ope).await;
    }

    #[tokio::test]
    async fn a_tuple_of_terms_lowers_to_the_tuple_of_their_indexes_in_order() {
        same_bytes::<u32, (EqualityTerm, OreTerm<u32>), _>(7, (Equality, Ore)).await;
        same_bytes::<u32, (OreTerm<u32>, EqualityTerm), _>(7, (Ore, Equality)).await;
        same_bytes::<u32, (OpeTerm<u32>, OreTerm<u32>, EqualityTerm), _>(7, (Ope, Ore, Equality))
            .await;
        same_bytes::<
            String,
            (
                MatchTerms<Words>,
                OpeTerm<String>,
                OreTerm<String>,
                EqualityTerm,
            ),
            _,
        >(
            "Hello World".into(),
            (Match::<Words>::new(), Ope, Ore, Equality),
        )
        .await;
        // Five: every index once, and a second match index under other options.
        same_bytes::<
            String,
            (
                EqualityTerm,
                MatchTerms,
                OreTerm<String>,
                OpeTerm<String>,
                MatchTerms<Words>,
            ),
            _,
        >(
            "Hello World".into(),
            (Equality, Match::default(), Ore, Ope, Match::<Words>::new()),
        )
        .await;
    }

    #[tokio::test]
    async fn the_typed_spelling_is_the_hand_composition() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let email = "bob@example.com".to_string();

        let typed: Encrypted<(EqualityTerm, MatchTerms)> =
            keyset.encrypt_as(&email, caller()).await.expect("typed");
        let hand = ciphertext::<String, _, Borrowed>()
            .accepting::<CallerContext>()
            .zip(equality::<String, _, Borrowed>())
            .zip(matching::<String, _, Borrowed, DefaultMatch>());
        let ((hand_c, hand_eq), hand_match) =
            keyset.run(hand, &email, caller()).await.expect("hand");
        assert_eq!(typed.terms, (hand_eq, hand_match));
        let opened: String = keyset.decrypt_as(hand_c, aead()).await.expect("hand opens");
        assert_eq!(opened, email);
        let opened: String = typed
            .decrypt_into(&cipher, aead())
            .await
            .expect("typed opens");
        assert_eq!(opened, email);
    }

    #[test]
    fn the_terms_name_their_indexes() {
        assert_eq!(
            Indexes::<String>::specs(
                &<(
                    MatchTerms<Words>,
                    OpeTerm<String>,
                    OreTerm<String>,
                    EqualityTerm
                ) as TermSet<String>>::INDEXES
            ),
            [
                IndexSpec::Match(Words::options()),
                IndexSpec::Ope,
                IndexSpec::Ore,
                IndexSpec::Equality
            ]
        );
    }
}

//! Block ORE (`OreBlock`): ore-rs's 6-bit schemes, the terms EQL v4's
//! `_ord_ore` domains store.
//!
//! Every kind the index takes orders as its ADR-0002 order key: integers by
//! value at their own width, floats as PostgreSQL's `float8` (`-0.0` ties
//! `0.0`, every NaN one value after `+Infinity`), text by its fold, bytes
//! as bytes, dates by day, timestamps by the microsecond and decimals by
//! value. A term carries a random nonce, so the pins hold the left half
//! only (the header, the permuted symbols and the per-block tags), which is
//! deterministic in the key, the context and the value.
//!
//! Keyed by `FakeDataKeySource`'s deterministic index key, so the pinned
//! bytes are stable without ZeroKMS.

use std::cmp::Ordering;

use stack_encrypt::sem::{Orderable, OreBlockTerm, TermBytesError, TermError};
use stack_encrypt::value::{Date, Decimal, Timestamp};
use stack_encrypt::{nonempty, Error, KeysetCipher, StackCipher};
use stack_kms::FakeDataKeySource;

async fn cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("build cipher")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn term<T: Orderable>(
    keyset: &KeysetCipher<'_, FakeDataKeySource>,
    value: T,
) -> OreBlockTerm<T> {
    keyset
        .ore_block_term(value, nonempty!("users/n"))
        .await
        .expect("a block ORE term")
}

/// The block count of a term, from its header.
fn blocks(term: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([term[2], term[3]]))
}

/// The deterministic left half: the header, then one permuted symbol and
/// one 16-byte tag per block.
fn left(term: &[u8]) -> &[u8] {
    let header = if term[1] == 0x02 { 4 } else { 7 };
    &term[..header + 17 * blocks(term)]
}

/// Every term in `values` (already in plaintext order) compared with every
/// other, both ways round, against the order of its index in the list.
fn assert_sorted<T: Orderable>(terms: &[OreBlockTerm<T>], what: &str) {
    for (i, a) in terms.iter().enumerate() {
        for (j, b) in terms.iter().enumerate() {
            assert_eq!(a.compare(b), Some(i.cmp(&j)), "{what}: {i} against {j}");
        }
    }
}

macro_rules! orders_integers {
    ($keyset:expr, $($ty:ty => $blocks:expr),+ $(,)?) => {$(
        let mut values: Vec<$ty> = vec![<$ty>::MIN, <$ty>::MIN + 1, 0 as $ty, 1 as $ty, 63 as $ty, 64 as $ty, <$ty>::MAX - 1, <$ty>::MAX];
        values.sort_unstable();
        values.dedup();
        let mut terms = Vec::new();
        for value in values {
            let term = term($keyset, value).await;
            assert_eq!(&term.as_bytes()[..2], &[0x02, 0x02], "{} is the 6-bit scheme", stringify!($ty));
            assert_eq!(blocks(term.as_bytes()), $blocks, "{} blocks", stringify!($ty));
            assert_eq!(term.as_bytes().len(), 4 + 25 * $blocks + 16, "{} length", stringify!($ty));
            terms.push(term);
        }
        assert_sorted(&terms, stringify!($ty));
    )+};
}

/// Every integer width from 16 to 64 bits is the 6-bit fixed-width scheme,
/// one block per six bits of the width, and orders by value, negatives
/// first. (An 8-bit integer has no order term.)
#[tokio::test]
async fn integers_order_by_value_at_their_width() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    orders_integers!(&keyset,
        i16 => 3, u16 => 3, i32 => 6, u32 => 6, i64 => 11, u64 => 11,
    );
    let negatives = [-1_000_000i32, -65, -64, -63, -1, 0, 1];
    let mut terms = Vec::new();
    for value in negatives {
        terms.push(term(&keyset, value).await);
    }
    assert_sorted(&terms, "negative i32");
}

/// The 128-bit integers are wider than the 6-bit scheme's ten bytes, so
/// they go through the chained scheme, unpadded: 22 blocks each.
#[tokio::test]
async fn wide_integers_are_the_chained_scheme_unpadded() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let mut signed = Vec::new();
    for value in [i128::MIN, -1, 0, 1, i128::MAX] {
        let term = term(&keyset, value).await;
        assert_eq!(&term.as_bytes()[..2], &[0x02, 0x03]);
        assert_eq!(&term.as_bytes()[4..7], &[0, 0, 0], "no padding");
        assert_eq!(blocks(term.as_bytes()), 22);
        signed.push(term);
    }
    assert_sorted(&signed, "i128");
    let mut unsigned = Vec::new();
    for value in [0u128, 1, u128::MAX] {
        unsigned.push(term(&keyset, value).await);
    }
    assert_sorted(&unsigned, "u128");
}

/// A date is four bytes, so the 6-bit fixed-width scheme's six blocks; a
/// timestamp (twelve bytes) and a decimal (fourteen) are the chained
/// scheme, unpadded. Each orders by value: a timestamp by the microsecond,
/// floored, so a nanosecond before the epoch is a microsecond before it,
/// and a decimal whatever its scale.
#[tokio::test]
async fn dates_timestamps_and_decimals_order_by_value() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let mut dates = Vec::new();
    for days in [-719_162, -1, 0, 1, 19_782] {
        let term = term(
            &keyset,
            Date::from_days_since_epoch(days).expect("in range"),
        )
        .await;
        assert_eq!(
            &term.as_bytes()[..2],
            &[0x02, 0x02],
            "a date is the 6-bit scheme"
        );
        assert_eq!(blocks(term.as_bytes()), 6);
        dates.push(term);
    }
    assert_sorted(&dates, "date");

    let instant = |seconds, nanos| Timestamp::new(seconds, nanos).expect("in range");
    let mut instants = Vec::new();
    for (seconds, nanos) in [(-1, 999_999_000), (0, 0), (0, 1_000), (1_700_000_000, 0)] {
        let term = term(&keyset, instant(seconds, nanos)).await;
        assert_eq!(
            &term.as_bytes()[..2],
            &[0x02, 0x03],
            "a timestamp is chained"
        );
        assert_eq!(&term.as_bytes()[4..7], &[0, 0, 0], "no padding");
        assert_eq!(blocks(term.as_bytes()), 16);
        instants.push(term);
    }
    assert_sorted(&instants, "timestamp");
    let tie = |a: &OreBlockTerm<Timestamp>, b: &OreBlockTerm<Timestamp>| a.compare(b);
    assert_eq!(
        tie(
            &term(&keyset, instant(0, 1_000)).await,
            &term(&keyset, instant(0, 1_999)).await
        ),
        Some(Ordering::Equal),
        "one microsecond"
    );
    assert_eq!(
        tie(&term(&keyset, instant(-1, 999_999_999)).await, &instants[0]),
        Some(Ordering::Equal),
        "a nanosecond before the epoch floors to the microsecond before it"
    );

    let decimal = |mantissa, scale| Decimal::new(mantissa, scale).expect("in range");
    let mut decimals = Vec::new();
    for (mantissa, scale) in [(-1, 0), (15, 1), (2, 0), (100, 0)] {
        let term = term(&keyset, decimal(mantissa, scale)).await;
        assert_eq!(&term.as_bytes()[..2], &[0x02, 0x03], "a decimal is chained");
        assert_eq!(&term.as_bytes()[4..7], &[0, 0, 0], "no padding");
        assert_eq!(blocks(term.as_bytes()), 19);
        decimals.push(term);
    }
    assert_sorted(&decimals, "decimal");
    assert_eq!(
        term(&keyset, decimal(150, 2)).await.compare(&decimals[1]),
        Some(Ordering::Equal),
        "1.50 ties 1.5"
    );
}

/// Floats order as PostgreSQL's `float8`: `-0.0` ties `0.0`, every NaN is
/// one value after `+Infinity`, and an `f32` is the `f64` it widens to.
#[tokio::test]
async fn floats_follow_the_semantic_baseline() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ordered = [
        f64::NEG_INFINITY,
        f64::MIN,
        -1.5,
        -f64::MIN_POSITIVE,
        0.0,
        f64::MIN_POSITIVE,
        1.5,
        f64::MAX,
        f64::INFINITY,
        f64::NAN,
    ];
    let mut terms = Vec::new();
    for value in ordered {
        let term = term(&keyset, value).await;
        assert_eq!(blocks(term.as_bytes()), 11, "an f64 is eight bytes");
        terms.push(term);
    }
    assert_sorted(&terms, "f64");
    assert_eq!(
        term(&keyset, -0.0f64)
            .await
            .compare(&term(&keyset, 0.0f64).await),
        Some(Ordering::Equal)
    );
    let negative_nan = f64::from_bits(f64::NAN.to_bits() | (1 << 63));
    assert_eq!(
        term(&keyset, negative_nan)
            .await
            .compare(&term(&keyset, f64::NAN).await),
        Some(Ordering::Equal)
    );
    for value in [-1.5f32, 0.1, f32::MAX, f32::NAN] {
        let narrow = term(&keyset, value).await;
        let wide = term(&keyset, f64::from(value)).await;
        assert_eq!(narrow.as_bytes()[..2], wide.as_bytes()[..2]);
        assert_eq!(left(narrow.as_bytes()), left(wide.as_bytes()), "{value:?}");
    }
}

/// Text is the chained scheme, padded to a power of two of at least 16
/// bytes (the marker byte counts): a term reveals the bucket, not the
/// length. Shared prefixes, different buckets and the empty string order
/// as their folds do, shorter first.
#[tokio::test]
async fn text_orders_by_its_fold_shortest_first() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let fifteen = "a".repeat(15);
    let sixteen = "a".repeat(16);
    let thirty_one = "a".repeat(31);
    let thirty_two = "a".repeat(32);
    let ordered: Vec<String> = vec![
        String::new(),
        "a".into(),
        "aa".into(),
        fifteen.clone(),
        sixteen.clone(),
        thirty_one.clone(),
        thirty_two.clone(),
        "ab".into(),
        "abc".into(),
        "abd".into(),
        "alice".into(),
        "b".into(),
        "Bob".into(),
        "zoe".into(),
    ];
    let mut terms = Vec::new();
    for value in &ordered {
        let term = term(&keyset, value.clone()).await;
        assert_eq!(&term.as_bytes()[..2], &[0x02, 0x03]);
        assert_eq!(&term.as_bytes()[4..7], &[1, 0, 16], "powers of two from 16");
        terms.push(term);
    }
    assert_sorted(&terms, "text");

    // The bucket is the length of the marker and the fold, rounded up.
    for (text, count) in [
        ("", 22),
        (fifteen.as_str(), 22),
        (sixteen.as_str(), 43),
        (thirty_one.as_str(), 43),
        (thirty_two.as_str(), 86),
    ] {
        let term = term(&keyset, text.to_string()).await;
        assert_eq!(blocks(term.as_bytes()), count, "{} bytes", text.len());
        assert_eq!(term.as_bytes().len(), 7 + 25 * count + 16);
    }

    // Case and accents fold: these tie.
    let cafe = term(&keyset, "cafe".to_string()).await;
    for spelling in ["Café", "CAFE", "cafe\u{301}"] {
        assert_eq!(
            term(&keyset, spelling.to_string()).await.compare(&cafe),
            Some(Ordering::Equal),
            "{spelling:?}"
        );
    }
}

/// Bytes are the chained scheme unpadded, ordered as bytes: a trailing zero
/// byte is kept, and the empty value still makes a keyed block.
#[tokio::test]
async fn bytes_order_as_bytes() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ordered: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0, 0], vec![1], vec![1, 0], vec![255]];
    let mut terms = Vec::new();
    for value in ordered {
        let term = term(&keyset, value).await;
        assert_eq!(&term.as_bytes()[4..7], &[0, 0, 0], "bytes are not padded");
        assert!(
            blocks(term.as_bytes()) >= 2,
            "the marker byte is two blocks"
        );
        terms.push(term);
    }
    assert_sorted(&terms, "bytes");
}

/// Bytes take a term up to 1023 bytes, as text's fold does: ore-rs's
/// 1024-byte ceiling counts the marker byte in front of them.
#[tokio::test]
async fn bytes_of_more_than_1023_bytes_have_no_term() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let longest = term(&keyset, vec![7u8; 1023]).await;
    assert!(blocks(longest.as_bytes()) > 1023, "every byte is ordered");
    let too_long = keyset
        .ore_block_term(vec![7u8; 1024], nonempty!("users/n"))
        .await
        .unwrap_err();
    assert!(
        matches!(too_long, Error::Term(TermError::OreBlockTooLong)),
        "{too_long:?}"
    );
}

/// One value encrypts to different bytes each time (the right half's
/// nonce), and those terms compare equal; the left half is deterministic.
#[tokio::test]
async fn one_value_is_new_bytes_that_compare_equal() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    for (a, b) in [
        (
            term(&keyset, 42i64).await.into_bytes(),
            term(&keyset, 42i64).await.into_bytes(),
        ),
        (
            term(&keyset, "alice".to_string()).await.into_bytes(),
            term(&keyset, "alice".to_string()).await.into_bytes(),
        ),
    ] {
        assert_ne!(a, b, "a fresh nonce each time");
        assert_eq!(left(&a), left(&b));
        let (a, b) = (
            OreBlockTerm::<i64>::from_bytes(a.clone()).unwrap(),
            OreBlockTerm::<i64>::from_bytes(b.clone()).unwrap(),
        );
        assert_eq!(a.compare(&b), Some(Ordering::Equal));
        assert!(a == b, "== is the scheme's equality");
    }
}

/// Every view of a term's bytes is the one serialised ciphertext, and its
/// `Debug` names the length only.
#[tokio::test]
async fn every_view_of_a_term_is_its_ciphertext() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let below = term(&keyset, 41i64).await;
    let term = term(&keyset, 42i64).await;
    // `PartialOrd` is the scheme's comparator.
    assert!(below < term);
    assert!(term >= below);
    assert_eq!(below.partial_cmp(&below.clone()), Some(Ordering::Equal));
    assert_eq!(term.partial_cmp(&below), Some(Ordering::Greater));
    let bytes = term.as_bytes().to_vec();
    assert_eq!(bytes[..2], [0x02, 0x02], "the fixed-width scheme's header");
    assert_eq!(term.to_bytes(), bytes);
    assert_eq!(AsRef::<[u8]>::as_ref(&term), bytes.as_slice());
    assert_eq!(
        format!("{term:?}"),
        format!("OreBlockTerm {{ len: {} }}", bytes.len())
    );
    assert_eq!(term.into_bytes(), bytes);
}

/// The deterministic left halves, pinned: a change to the key derivation,
/// the salt, the scheme selection or ore-rs's wire format changes every
/// stored term and must fail here.
#[tokio::test]
async fn left_halves_are_pinned() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let i32_term = keyset
        .ore_block_term(42i32, nonempty!("users/age"))
        .await
        .unwrap();
    let f64_term = keyset
        .ore_block_term(1.5f64, nonempty!("users/score"))
        .await
        .unwrap();
    let text_term = keyset
        .ore_block_term("Ab".to_string(), nonempty!("users/surname"))
        .await
        .unwrap();
    assert_eq!(
        [
            hex(left(i32_term.as_bytes())),
            hex(left(f64_term.as_bytes())),
            hex(left(text_term.as_bytes()))
        ],
        [PINNED_I32, PINNED_F64, PINNED_TEXT]
    );
}

const PINNED_I32: &str = "020200062422373e222f96362b6599fc5183c20804eeddd52d41890dc85341958dc7329d18a521c1d74f76fed42c7517b4e8cdfc74cbc6f9e521a72658dc177b73e9fa5a2d8a661bf3ef7117ecef8aeca900b3465c3640ebddfc8d5887729387bcdc64486801f99d2dda";
const PINNED_F64: &str = "0202000b0b033912381600140628353cede9c0b7d2aebfd0b81f922c34bb5faa5cd0f3723ab63db491c0f20f47873e7a28d2cde32d31b9ddc8ffb2708429b2432d25b6c806a06cd6efe7021e9c965388064ca5493283cc499209b81c212593869c9baca7cf007f21a318ba7c3932ea23448843d69cb7f79c952cf4bb986a42ddb795a01b558f97fcf9ef5eba7efe87bcb51c10fbe80a7997aa55963596e851c858f014c9408b15ad2762c2a02b32db5bd58e5d3f85651ee7d2d43869d3b09d";
const PINNED_TEXT: &str = "02030016010010172510373d14172510363017212d163e161a10341620b9ce74f6d4e48df255a31928333790bb04fffdcf1c73688b642c450bfd649429589029e048f81f6b746af7306d8c88833d5e3cd1dca9d109b48203a44e1be8cad4717a7072aeb2c694c4c7952bb117fc89635665a8c4023aed2b84e8652849986c7a4b6fd64d22012154868ba39ac5a7f55cfb26fee81c0b419ab238dc435cb5ac7475b496bb6fae32b60aa38855d425126a44fa59342dfb2d114e74d059399ab0b526d856e0f96f59a7740eef99a787001ebc2d1b6ca5d9bf600bc43f1452250ce58dd8f1e0590f1030c9bbacc31b9f2d984d19bbe6a35a0fd156871d39ff9d55e05f3b497efbfa358f17e32a7b96e3585f3d8a83308693ce3ed3d2dac7268c4570b10910fc73d0937f100ef31a7c7b70c1469984fad0be135ca4e00dcedc4242d1327c73746d3e90db658f48561f4f0572dc65dff246102e9875d98aa0dbdc5e079e76e3d3999f8a10766fcb034119794e333d82ba81db0692dbc93745204b";

/// The block ORE key is the index's own: its terms share no left half with
/// another context's, and none with CLLW ORE's key (a CLLW term is a
/// different shape altogether, so this checks the contexts).
#[tokio::test]
async fn terms_are_keyed_by_their_context() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let users = keyset
        .ore_block_term(7i32, nonempty!("users/age"))
        .await
        .unwrap();
    let orders = keyset
        .ore_block_term(7i32, nonempty!("orders/age"))
        .await
        .unwrap();
    assert_ne!(left(users.as_bytes()), left(orders.as_bytes()));
}

/// What block ORE refuses, each without naming the value: text whose fold
/// is longer than 1023 bytes, text that ends in NUL, text the fold cannot
/// take, and a boolean.
#[tokio::test]
async fn refusals_name_no_part_of_the_value() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let refused = |error: Error| match error {
        Error::Term(error) => error,
        other => panic!("not a term refusal: {other:?}"),
    };
    let long = "secret".repeat(200);
    assert!(keyset
        .ore_block_term("a".repeat(1023), nonempty!("users/n"))
        .await
        .is_ok());
    let too_long = refused(
        keyset
            .ore_block_term(long.clone(), nonempty!("users/n"))
            .await
            .unwrap_err(),
    );
    assert!(
        matches!(too_long, TermError::OreBlockTooLong),
        "{too_long:?}"
    );
    assert!(!too_long.to_string().contains("secret"));
    let nul = refused(
        keyset
            .ore_block_term("secret\0".to_string(), nonempty!("users/n"))
            .await
            .unwrap_err(),
    );
    assert!(matches!(nul, TermError::OreBlockTrailingNul), "{nul:?}");
    assert!(!nul.to_string().contains("secret"));
    let unassigned = refused(
        keyset
            .ore_block_term("a\u{378}b".to_string(), nonempty!("users/n"))
            .await
            .unwrap_err(),
    );
    assert!(
        matches!(unassigned, TermError::Normalize(_)),
        "{unassigned:?}"
    );
    // A boolean and an 8-bit integer have no block ORE term, as they have
    // no ORE or OPE term: `ore_block_term(true, ..)` and
    // `ore_block_term(7u8, ..)` do not compile (`sem::Orderable`).
}

/// Decoding is structural: a ciphertext of either scheme decodes, and
/// anything else, including a truncated one, is refused with its length.
#[tokio::test]
async fn decoding_checks_the_shape() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let bit6 = term(&keyset, 42i64).await.into_bytes();
    let chained = term(&keyset, "alice".to_string()).await.into_bytes();
    assert!(OreBlockTerm::<i64>::from_bytes(bit6.clone()).is_ok());
    assert!(OreBlockTerm::<String>::from_bytes(chained.clone()).is_ok());
    // The std conversions are the same decoder, by value and by copy.
    let by_value = OreBlockTerm::<i64>::try_from(bit6.clone()).unwrap();
    assert_eq!(by_value.as_bytes(), &bit6[..]);
    let by_copy = OreBlockTerm::<String>::try_from(&chained[..]).unwrap();
    assert_eq!(by_copy.as_bytes(), &chained[..]);
    for bad in [
        &bit6[..bit6.len() - 1],
        &chained[..10],
        &[][..],
        &[0x02, 0x04, 0, 1][..],
    ] {
        assert_eq!(
            OreBlockTerm::<i64>::from_bytes(bad.to_vec()).unwrap_err(),
            TermBytesError::MalformedOreBlockCiphertext(bad.len())
        );
        assert!(OreBlockTerm::<i64>::try_from(bad).is_err());
        assert!(OreBlockTerm::<i64>::try_from(bad.to_vec()).is_err());
    }
    // A 6-bit and a chained term have no order between them.
    let a = OreBlockTerm::<i64>::from_bytes(bit6).unwrap();
    let b = OreBlockTerm::<i64>::from_bytes(chained).unwrap();
    assert_eq!(a.compare(&b), None);
    assert!(a != b);
}

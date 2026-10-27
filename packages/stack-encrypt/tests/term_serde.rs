//! The order terms as serde types: lowercase hex in JSON, decoded through
//! the same structural check as `from_bytes`, with errors that carry no
//! byte of the term.

use serde_json::{json, Value};
use stack_encrypt::nonempty;
use stack_encrypt::sem::{OpeTerm, Orderable, OreBlockTerm, OreTerm, TermBytesError};
use stack_encrypt::target::EncryptInto;
use stack_encrypt::{KeysetCipher, StackCipher};
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

async fn block<T: Orderable>(
    keyset: &KeysetCipher<'_, FakeDataKeySource>,
    value: T,
) -> OreBlockTerm<T> {
    keyset
        .ore_block_term(value, nonempty!("users/n"))
        .await
        .expect("a block ORE term")
}

/// Each order term serializes as the lowercase hex of its bytes, and reads
/// back as the same bytes, in either case of hex.
#[tokio::test]
async fn an_order_term_is_its_bytes_in_lowercase_hex() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ore: OreTerm<u32> = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .expect("ore term");
    let ope: OpeTerm<String> = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .expect("ope term");
    let fixed = block(&keyset, 42i64).await;
    let chained = block(&keyset, "alice".to_string()).await;

    let cases: [(&[u8], Value); 4] = [
        (ore.as_bytes(), serde_json::to_value(&ore).unwrap()),
        (ope.as_bytes(), serde_json::to_value(&ope).unwrap()),
        (fixed.as_bytes(), serde_json::to_value(&fixed).unwrap()),
        (chained.as_bytes(), serde_json::to_value(&chained).unwrap()),
    ];
    for (bytes, value) in &cases {
        assert_eq!(value, &Value::String(hex(bytes)));
    }

    assert_eq!(
        serde_json::from_value::<OreTerm<u32>>(cases[0].1.clone()).unwrap(),
        ore
    );
    assert_eq!(
        serde_json::from_value::<OpeTerm<String>>(cases[1].1.clone()).unwrap(),
        ope
    );
    let back: OreBlockTerm<i64> = serde_json::from_value(cases[2].1.clone()).unwrap();
    assert_eq!(back.as_bytes(), fixed.as_bytes());
    let upper = json!(hex(chained.as_bytes()).to_uppercase());
    let back: OreBlockTerm<String> = serde_json::from_value(upper).unwrap();
    assert_eq!(back.as_bytes(), chained.as_bytes());
    assert_eq!(
        serde_json::to_value(&back).unwrap(),
        cases[3].1,
        "written back in lowercase"
    );
}

/// Deserializing refuses what `from_bytes` refuses: a term of the wrong
/// length or shape, an OPE carry other than 0 or 1, and anything that is
/// not hex. No error repeats the term.
#[tokio::test]
async fn deserializing_refuses_what_from_bytes_refuses_and_names_no_byte() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let fixed = hex(block(&keyset, 42i64).await.as_bytes());
    let truncated = &fixed[..fixed.len() - 2];

    let block_error = serde_json::from_value::<OreBlockTerm<i64>>(json!(truncated))
        .unwrap_err()
        .to_string();
    assert_eq!(
        block_error,
        TermBytesError::MalformedOreBlockCiphertext(truncated.len() / 2).to_string()
    );
    let ore_error = serde_json::from_value::<OreTerm<u32>>(json!("ab".repeat(31)))
        .unwrap_err()
        .to_string();
    assert_eq!(
        ore_error,
        TermBytesError::MalformedCllwCiphertext(31).to_string()
    );

    let carry_two = format!("02{}", "00".repeat(16));
    let ope_error = serde_json::from_value::<OpeTerm<u16>>(json!(carry_two))
        .unwrap_err()
        .to_string();
    assert_eq!(
        ope_error,
        TermBytesError::MalformedCllwCiphertext(17).to_string()
    );

    for not_a_term in [
        json!(format!("{fixed}0")),
        json!(format!("zz{}", &fixed[2..])),
        json!(42),
        json!([fixed]),
    ] {
        let error = serde_json::from_value::<OreBlockTerm<i64>>(not_a_term.clone())
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&fixed[4..]), "{not_a_term}: {error}");
    }
}

/// An OPE term leads with a carry of 0 or 1, through every decoder.
#[test]
fn an_ope_carry_other_than_zero_or_one_is_refused() {
    for carry in [0u8, 1] {
        let mut bytes = vec![0u8; 17];
        bytes[0] = carry;
        assert!(OpeTerm::<u16>::from_bytes(bytes.clone()).is_ok());
        assert!(OpeTerm::<u16>::try_from(&bytes[..]).is_ok());
        assert!(OpeTerm::<u16>::try_from(bytes).is_ok());
    }
    for carry in [2u8, 0xff] {
        let mut bytes = vec![0u8; 17];
        bytes[0] = carry;
        assert_eq!(
            OpeTerm::<u16>::from_bytes(bytes.clone()),
            Err(TermBytesError::MalformedCllwCiphertext(17))
        );
        assert!(OpeTerm::<u16>::try_from(bytes).is_err());
    }
    // An ORE term has no carry: any leading byte is a byte of the value.
    assert!(OreTerm::<u16>::from_bytes(vec![0xff; 16]).is_ok());
}

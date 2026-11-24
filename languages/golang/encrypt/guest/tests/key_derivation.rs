//! Known-answer tests for deriving keys from ZeroKMS key material, with the
//! stack-kms features this guest ships.
//!
//! The guest turns on stack-kms's `wasm-simd` feature, so on wasm32 it
//! re-encrypts key material on a SIMD path, while native builds and the other
//! SDKs take the scalar path. Both must derive the same keys: a key that
//! differed would make data the Go SDK encrypts unreadable to the others.
//!
//! Run natively (`cargo nextest run`), these check the scalar path. Run on
//! `wasm32-wasip1` under wazero (`mise run wasm:guest:test`), they check the
//! SIMD path against the same answers. The Go tests cannot do this: their
//! deterministic key source builds keys without re-encrypting anything.

use stack_kms::{ClientKey, DataKey, IndexKey};
use zerokms_protocol::testing::index_key_kat as kat;
use zerokms_protocol::ViturKeyMaterial;

fn client_key() -> ClientKey {
    ClientKey::from_hex_v1(uuid::Uuid::nil(), kat::KEYSET_HEX).expect("fixture client key")
}

fn key_material() -> ViturKeyMaterial {
    kat::key_material().into()
}

/// The index key matches the fixture shared with cipherstash-client.
#[test]
fn index_key_matches_the_shared_known_answer() {
    let index_key = IndexKey::from_key_material(&client_key(), &key_material())
        .expect("fixture material is valid");

    assert_eq!(
        base16ct::lower::encode_string(index_key.key()),
        kat::EXPECTED_INDEX_KEY_HEX,
    );
}

/// Data keys under three IVs. The index key uses an all-zero IV only, so
/// these also cover IVs that change every block of the re-encryption. The
/// answers were computed natively, on the scalar path.
#[test]
fn data_keys_match_the_known_answers() {
    let ascending: [u8; 16] = core::array::from_fn(|i| i as u8);
    let cases: [([u8; 16], &str); 3] = [
        (
            [0x00; 16],
            "04c0fdcd556654826b741f161cd05c978ab1fb31ace426c2b664c40ce2065150",
        ),
        (
            [0xff; 16],
            "c23564f65cf8bd26aa310fed2a09085d86403c3f0a2c6611ad6ce9c20ec1e941",
        ),
        (
            ascending,
            "3d43f70ecc4262db882410396e270cec0f47fb807841ba457c1f22e34e114999",
        ),
    ];

    let client_key = client_key();
    let material = key_material();
    for (iv, expected) in cases {
        let data_key = DataKey::from_key_material(&client_key, iv, &material)
            .expect("fixture material is valid");
        assert_eq!(
            base16ct::lower::encode_string(data_key.key()),
            expected,
            "data key for IV {iv:02x?}",
        );
    }
}

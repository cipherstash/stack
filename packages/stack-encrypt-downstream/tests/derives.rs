//! Each type of this crate goes through the cipher and comes back. The types
//! derive `Encrypt` and `Decrypt` from `stack_encrypt`, or implement them by
//! hand, in a crate whose only dependency is `stack-encrypt`.

use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{Ciphertext, KeysetCipher, StackCipher};
use stack_encrypt_downstream::{Email, Labelled, Price, Profile, Role, Wrapper};

/// Runs `test` with a keyset over the in-memory key source.
fn with_keyset<F>(test: F)
where
    F: AsyncFnOnce(&KeysetCipher<'_, FakeDataKeySource>),
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime builds")
        .block_on(async {
            let cipher = StackCipher::builder()
                .kms(FakeDataKeySource::new())
                .init()
                .await
                .expect("a cipher over the in-memory key source starts");
            let keyset = cipher.default_keyset();
            test(&keyset).await;
        });
}

#[test]
fn a_derived_newtype_encrypts_as_one_ciphertext() {
    with_keyset(async |keyset| {
        let stored: Ciphertext = keyset
            .encrypt(Email("ada@example.com".into()))
            .await
            .expect("a derived newtype over a String is one value");
        let as_string: String = keyset
            .decrypt(stored.clone())
            .await
            .expect("the newtype's ciphertext is its String's");
        assert_eq!(
            as_string, "ada@example.com",
            "a newtype encrypts exactly as its inner value"
        );
        let email: Email = keyset
            .decrypt(stored)
            .await
            .expect("the derived Decrypt builds the newtype");
        assert_eq!(
            email,
            Email("ada@example.com".into()),
            "the newtype comes back as it went in"
        );
    });
}

#[test]
fn a_derived_struct_and_enum_encrypt_as_a_tree() {
    with_keyset(async |keyset| {
        let profile = Profile {
            name: "Ada".into(),
            age: 37,
            role: Role::Admin,
            tenant: "acme".into(),
        };
        let stored = keyset
            .encrypt_tree(profile, ("users", "profile"))
            .await
            .expect("a derived struct encrypts as a tree");
        let back: Profile = keyset
            .decrypt_tree(stored, ("users", "profile"))
            .await
            .expect("the derived Decrypt builds the struct");
        assert_eq!(
            back,
            Profile {
                name: "Ada".into(),
                age: 37,
                role: Role::Admin,
                tenant: "acme".into(),
            },
            "every field, the enum, and the passthrough field come back"
        );
    });
}

#[test]
fn a_derived_enum_encrypts_as_one_ciphertext() {
    with_keyset(async |keyset| {
        let stored = keyset
            .encrypt(Role::Member)
            .await
            .expect("a fieldless enum is one value");
        let role: Role = keyset
            .decrypt(stored)
            .await
            .expect("the derived Decrypt reads the discriminant");
        assert_eq!(role, Role::Member, "the variant comes back");
    });
}

#[test]
fn derived_generic_types_encrypt_at_a_concrete_type() {
    with_keyset(async |keyset| {
        let stored = keyset
            .encrypt(Wrapper(42i64))
            .await
            .expect("a generic newtype over an i64 is one value");
        let wrapped: Wrapper<i64> = keyset
            .decrypt(stored)
            .await
            .expect("the generic newtype comes back");
        assert_eq!(wrapped, Wrapper(42), "the inner value comes back");

        let labelled = Labelled {
            label: "visits".into(),
            value: 7u32,
        };
        let stored = keyset
            .encrypt_tree(labelled, ("users", "visits"))
            .await
            .expect("a generic struct encrypts as a tree");
        let back: Labelled<u32> = keyset
            .decrypt_tree(stored, ("users", "visits"))
            .await
            .expect("the generic struct comes back");
        assert_eq!(
            back,
            Labelled {
                label: "visits".into(),
                value: 7,
            },
            "both fields of the generic struct come back"
        );
    });
}

#[test]
fn a_hand_written_impl_encrypts_as_one_ciphertext() {
    with_keyset(async |keyset| {
        let stored = keyset
            .encrypt(Price { cents: 1999 })
            .await
            .expect("a hand-written Scalar type is one value");
        let cents: i64 = keyset
            .decrypt(stored.clone())
            .await
            .expect("the hand-written impl stores one integer");
        assert_eq!(cents, 1999, "the integer is the price in cents");
        let price: Price = keyset
            .decrypt(stored)
            .await
            .expect("FromScalar builds the price");
        assert_eq!(price, Price { cents: 1999 }, "the price comes back");
    });
}

#[test]
fn the_paths_that_derive_errors_name_resolve() {
    // A refused derive or `Scalar` impl names these paths, so a user who
    // depends on stack-encrypt alone must be able to write them.
    assert_eq!(
        stack_encrypt::plaintext::depth::SCALAR,
        Some(0),
        "a scalar has nothing below it"
    );
    assert!(
        stack_encrypt::plaintext::depth::within_limit(Some(
            stack_encrypt::plaintext::depth::MAX_DEPTH
        )),
        "a value exactly `MAX_DEPTH` deep can be encrypted"
    );
}

//! Searchable Encrypted Metadata, leaf by leaf.
//!
//! Shows each index-term primitive on its own through the target-directed
//! `encrypt_into` API: equality terms (exact match), match terms (full-text
//! containment), and ORE/OPE terms (range queries) — all generated locally
//! from a deterministic per-keyset index key, then compared the way a server
//! would compare them: without ever seeing a plaintext.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p stack-encrypt --example search_terms
//! ```
//!
//! Talks to real ZeroKMS: needs `CS_CLIENT_ID` / `CS_CLIENT_KEY` and access-key
//! or device-session credentials in the environment (see the `zerokms_auth`
//! example for where they come from).

use stack_encrypt::sem::{EqualityTerm, MatchTerm, OreTerm};
use stack_encrypt::target::EncryptExt;
use stack_encrypt::StackCipher;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `StackCipher::new()` builds a ZeroKMS client from the environment and
    // loads the keyset's index key once, during construction.
    let terms = StackCipher::new().await?;
    println!("cipher ready on keyset {}", terms.keyset_id());

    // One cipher serves write time and query time; terms are deterministic
    // under the same index key + context, which is what makes them queryable.
    // Deriving a term touches no data keys, so a query builder never calls
    // ZeroKMS to build a probe.

    // --- Equality: exact-match lookups --------------------------------------
    //
    // The context ("users/email") domain-separates terms per field: the same
    // value indexed under another field can never produce a colliding term.

    let stored: EqualityTerm = "alice@example.com"
        .encrypt_into(&terms, "users/email")
        .await?;

    let hit: EqualityTerm = "alice@example.com"
        .encrypt_into(&terms, "users/email")
        .await?;
    let miss: EqualityTerm = "bob@example.com"
        .encrypt_into(&terms, "users/email")
        .await?;
    let wrong_field: EqualityTerm = "alice@example.com"
        .encrypt_into(&terms, "users/name")
        .await?;

    println!("\nequality:");
    println!("  same value, same field   => match: {}", stored == hit);
    println!("  different value          => match: {}", stored == miss);
    println!(
        "  same value, other field  => match: {}",
        stored == wrong_field
    );

    // --- Match: full-text containment ---------------------------------------
    //
    // Text is tokenized locally (3-grams by default), each token is PRF'd, and
    // the outputs fold into Bloom-filter bit positions. A query matches when
    // its positions are a subset of the stored term's (Bloom semantics: false
    // positives possible, false negatives not).

    let bio: MatchTerm = "alice, senior cryptography engineer"
        .to_string()
        .encrypt_into(&terms, "users/bio")
        .await?;

    for query in ["crypto", "engineer", "plumber"] {
        let probe: MatchTerm = query.to_string().encrypt_into(&terms, "users/bio").await?;
        println!("match: bio contains {query:?} => {}", bio.contains(&probe));
    }
    println!(
        "  (stored term is just bit positions: {:?} ...)",
        &bio.positions()[..bio.positions().len().min(8)]
    );

    // --- ORE: range queries --------------------------------------------------
    //
    // CLLW ORE ciphertexts compare like their plaintexts. The per-field ORE
    // key is derived *through the PRF* from the context alone — the plaintext
    // never enters the PRF, so under the coming 2-party ZeroKMS PRF backend
    // the key derivation becomes an auditable server event while values stay
    // local.

    let age_30: OreTerm<u32> = 30u32.encrypt_into(&terms, "users/age").await?;
    let age_45: OreTerm<u32> = 45u32.encrypt_into(&terms, "users/age").await?;
    let query_40: OreTerm<u32> = 40u32.encrypt_into(&terms, "users/age").await?;

    println!("\nore (WHERE age > 40):");
    println!("  age 30 > 40 => {}", age_30 > query_40);
    println!("  age 45 > 40 => {}", age_45 > query_40);

    // Strings order lexicographically.
    let apple: OreTerm<&str> = "apple".encrypt_into(&terms, "users/name").await?;
    let banana: OreTerm<&str> = "banana".encrypt_into(&terms, "users/name").await?;
    println!("  \"apple\" < \"banana\" => {}", apple < banana);

    Ok(())
}

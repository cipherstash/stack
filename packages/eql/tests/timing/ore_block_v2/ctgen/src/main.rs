//! ore-rs 6-bit block ORE ciphertexts for the EQL v4 comparator timing
//! harness (`../run.sh`). Tab-separated rows, one term per side, hex:
//!
//!   fixed   <first|last> <a> <b>  u64, 11 blocks; differ in block 0 / only block 10
//!   equal   <same|first> <a> <b>  u64; a second encryption of a / differ in block 0
//!   chained <first|last> <a> <b>  31-character text (32 bytes encoded), 43 blocks;
//!                                 differ in the first character / only the last
//!   prefix  <prefix|first> <a> <b> text in a 16-byte bucket against text in a
//!                                 32-byte bucket: every block a has equals b's
//!                                 (the block counts settle it) / the first differs
//!   check   <expected> <a> <b>    random pairs of either engine with shared
//!                                 prefixes; expected = sign(a cmp b)
//!
//! `BlockOre` sends a `u64` to the fixed-width engine and text to the chained
//! one. vitaminc-ore encodes text as a marker byte and then the text (lower
//! case ASCII folds to itself), so the byte offsets below count the marker.
//!
//! Every expected sign is the plaintext order, and ore-rs's own comparator
//! is asserted to agree before a row is written.
use std::cmp::Ordering;

use ore_rs::{BlockOre, Term};
use rand::Rng;
use vitaminc_ore::{OrderEncrypt, OrderKeyInit, OrderScheme, OrderTarget};
use vitaminc_protected::Protected;

fn sign(o: Ordering) -> i32 {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

fn lower(rng: &mut impl Rng, n: usize) -> String {
    (0..n).map(|_| rng.gen_range(b'a'..=b'z') as char).collect()
}

fn main() {
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();
    let scheme = BlockOre::new(Protected::new(key));
    let fixed = scheme.target(OrderTarget::U64);
    let text = scheme.target(OrderTarget::Text);
    let ct = |x: u64| fixed.encrypt_checked(&x).unwrap().into_raw().into_bytes();
    let st = |s: &str| {
        text.encrypt_checked(&s.to_owned())
            .unwrap()
            .into_raw()
            .into_bytes()
    };
    let compare = |a: &[u8], b: &[u8]| {
        BlockOre::compare(&Term::from_bytes(a.to_vec()), &Term::from_bytes(b.to_vec()))
    };
    let pairs: usize = std::env::args()
        .nth(1)
        .map(|s| s.parse().unwrap())
        .unwrap_or(256);
    let row = |kind: &str, label: &str, a: &[u8], b: &[u8]| {
        println!("{kind}\t{label}\t{}\t{}", hex::encode(a), hex::encode(b));
    };
    for _ in 0..pairs {
        let x: u64 = rng.gen();
        row("fixed", "first", &ct(x), &ct(x ^ (1 << 63)));
        row("fixed", "last", &ct(x), &ct(x ^ 1));
        row("equal", "same", &ct(x), &ct(x));
        row("equal", "first", &ct(x), &ct(x ^ (1 << 63)));

        let s = lower(&mut rng, 31);
        let mut first = s.clone().into_bytes();
        first[0] = b'a' + (first[0] - b'a' + 1) % 26;
        let mut last = s.clone().into_bytes();
        last[30] = b'a' + (last[30] - b'a' + 1) % 26;
        row(
            "chained",
            "first",
            &st(&s),
            &st(std::str::from_utf8(&first).unwrap()),
        );
        row(
            "chained",
            "last",
            &st(&s),
            &st(std::str::from_utf8(&last).unwrap()),
        );

        // 10 characters encode as 11 bytes, padded with NULs to a 16-byte
        // bucket: 22 blocks, the last holding two bits of byte 15 and four
        // of byte 16. The longer text repeats the padding and puts a byte
        // whose top four bits are clear at 16, so all 22 of the shorter
        // text's blocks match it, and its 26 bytes take a 32-byte bucket.
        let short = lower(&mut rng, 10);
        let long = format!("{short}\0\0\0\0\0\u{5}{}", lower(&mut rng, 9));
        let (a, b) = (st(&short), st(&long));
        assert_eq!(compare(&a, &b), Some(Ordering::Less));
        row("prefix", "prefix", &a, &b);
        let mut other = long.clone().into_bytes();
        other[0] = b'a' + (other[0] - b'a' + 1) % 26;
        row(
            "prefix",
            "first",
            &a,
            &st(std::str::from_utf8(&other).unwrap()),
        );
    }
    for i in 0..1500 {
        if i % 2 == 0 {
            let x: u64 = rng.gen();
            let keep = rng.gen_range(0..=64u32);
            let mask = if keep == 0 {
                0
            } else {
                u64::MAX << (64 - keep)
            };
            let y = if i % 6 == 0 {
                x
            } else {
                (x & mask) | (rng.gen::<u64>() & !mask)
            };
            let (a, b) = (ct(x), ct(y));
            let expected = x.cmp(&y);
            assert_eq!(compare(&a, &b), Some(expected));
            println!(
                "check\t{}\t{}\t{}",
                sign(expected),
                hex::encode(&a),
                hex::encode(&b)
            );
        } else {
            let len = rng.gen_range(0..=40);
            let s = lower(&mut rng, len);
            let shared = rng.gen_range(0..=s.len());
            let t = if i % 5 == 0 {
                s.clone()
            } else {
                let tail = rng.gen_range(0..=40 - shared);
                format!("{}{}", &s[..shared], lower(&mut rng, tail))
            };
            let (a, b) = (st(&s), st(&t));
            let expected = s.as_bytes().cmp(t.as_bytes());
            assert_eq!(compare(&a, &b), Some(expected));
            println!(
                "check\t{}\t{}\t{}",
                sign(expected),
                hex::encode(&a),
                hex::encode(&b)
            );
        }
    }
}

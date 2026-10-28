//! Legacy (bit2, 8-bit blocks) u64 ORE ciphertexts for the ORE comparator
//! timing harness (`../run.sh`). Tab-separated rows; arrays are
//! comma-separated hex terms (EQL stores text as up to six u64 terms).
//!   timing1 <first|last> <a> <b>   one term; differ in block 0 / only block 7
//!   timing6 <first|last> <a> <b>   six terms; differ in term 1 / only term 6
//!   check   <expected>   <a> <b>   arrays of 1..6 terms; expected = sign(a cmp b)
use ore_rs::scheme::bit2::OreAes128ChaCha20;
use ore_rs::{OreCipher, OreEncrypt, OreOutput};
use rand::Rng;

fn main() {
    let mut rng = rand::thread_rng();
    let (k1, k2): ([u8; 16], [u8; 16]) = (rng.gen(), rng.gen());
    let ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
    let ct = |x: u64| hex::encode(x.encrypt(&ore).unwrap().to_bytes());
    let arr = |xs: &[u64]| xs.iter().map(|&x| ct(x)).collect::<Vec<_>>().join(",");
    let pairs: usize = std::env::args()
        .nth(1)
        .map(|s| s.parse().unwrap())
        .unwrap_or(256);
    for _ in 0..pairs {
        let x: u64 = rng.gen();
        println!("timing1\tfirst\t{}\t{}", ct(x), ct(x ^ (1 << 63)));
        println!("timing1\tlast\t{}\t{}", ct(x), ct(x ^ 1));
        let xs: Vec<u64> = (0..6).map(|_| rng.gen()).collect();
        let mut first = xs.clone();
        first[0] ^= 1 << 63;
        let mut last = xs.clone();
        last[5] ^= 1;
        println!("timing6\tfirst\t{}\t{}", arr(&xs), arr(&first));
        println!("timing6\tlast\t{}\t{}", arr(&xs), arr(&last));
    }
    for i in 0..1500 {
        let la = rng.gen_range(1..=6);
        let xs: Vec<u64> = (0..la).map(|_| rng.gen()).collect();
        // Share a random-length prefix, then diverge (or not) in various ways.
        let shared = rng.gen_range(0..=la);
        let lb = if i % 3 == 0 {
            la
        } else {
            rng.gen_range(shared.max(1)..=6)
        };
        let mut ys: Vec<u64> = xs[..shared].to_vec();
        while ys.len() < lb {
            let k = ys.len();
            ys.push(match (i % 5, k < la) {
                (0, true) => xs[k] ^ (1u64 << rng.gen_range(0..64)),
                (1, true) => xs[k],
                _ => rng.gen(),
            });
        }
        let expected = match xs.cmp(&ys) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
        println!("check\t{expected}\t{}\t{}", arr(&xs), arr(&ys));
    }
}

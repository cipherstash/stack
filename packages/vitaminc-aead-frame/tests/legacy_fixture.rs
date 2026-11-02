//! Ciphertexts written before ADR 0001 open on the new path.
//!
//! Three fixtures, all sealed with native AES-256-GCM on the pre-ADR 0001
//! `Value` path and never regenerated:
//!
//! - `testdata/v0.5.1-cross-lang.bin`: the Go binding's cross-language
//!   fixture as published in `vitaminc-aead-value` 0.5.0 and 0.5.1, so the
//!   compatibility claim covers a release. Its value chunk uses the framing
//!   tags of the time (`0x10`, `0x11`, `0x12`), which #371 moved to
//!   `0xF0`, `0xF1`, `0xF2`; the sealed bytes are unchanged.
//! - `testdata/pre-adr-0001-cross-lang.bin`: the same fixture as generated
//!   just before #439, with the current framing tags.
//! - `testdata/pre-adr-0001-corpus.bin`: every vector of the shared
//!   conformance corpus and the edge documents the old interop test used
//!   (empty containers below the top, passthrough beside sealed values in
//!   an array, empty and non-ASCII keys, every numeric width, date,
//!   timestamp, decimal, undefined), each sealed on the `Value` path with
//!   the frame it must open to.
//!
//! Each ciphertext is decoded with this crate's codec, opened through
//! `decrypt_to_frame`, and must come out as its frame byte for byte. That
//! pins the leaf format, the AAD derivations and the container rules
//! against what shipped.
//!
//! Every leaf here is wire version 1. New leaves are version 2, and
//! `Aes256Cipher` on its own refuses version 1, because `vitaminc-encrypt`
//! 0.5's `Encrypt` path sealed raw, untagged bytes under that version. These
//! leaves are tagged, so they open through `Aes256Cipher::opening_version_1`.
//!
//! Cross-language layout (all lengths u32 LE):
//! `"VCGO1" ++ key[32] ++ len(aad) ++ aad ++ len(ct) ++ ct ++ len(val) ++ val`.
//! Corpus layout: `"VCLEG1" ++ key[32] ++ len(aad) ++ aad ++ u32 count ++
//! (len(name) ++ name ++ len(ct) ++ ct ++ len(frame) ++ frame)*`.

use vitaminc_aead::frame::{FrameWriteError, ARRAY, OBJECT, PASSTHROUGH};
use vitaminc_aead::{decrypt_to_frame, Context, DecryptError, Frame, Node, Unspecified};
use vitaminc_aead_frame::decode_ciphertext;
use vitaminc_encrypt::{Aes256Cipher, Key, LocalCipherText};
use vitaminc_protected::Controlled;

const RELEASED: &[u8] = include_bytes!("../testdata/v0.5.1-cross-lang.bin");
const PRE_ADR: &[u8] = include_bytes!("../testdata/pre-adr-0001-cross-lang.bin");
const CORPUS: &[u8] = include_bytes!("../testdata/pre-adr-0001-corpus.bin");

/// A cursor over the length-prefixed chunks of a fixture.
struct Chunks<'a>(&'a [u8]);

impl<'a> Chunks<'a> {
    fn magic(&mut self, magic: &[u8]) {
        let (found, rest) = self.0.split_at(magic.len());
        assert_eq!(found, magic);
        self.0 = rest;
    }

    fn key(&mut self) -> [u8; 32] {
        let (key, rest) = self.0.split_at(32);
        self.0 = rest;
        key.try_into().expect("32-byte key")
    }

    fn u32(&mut self) -> usize {
        let (len, rest) = self.0.split_at(4);
        self.0 = rest;
        u32::from_le_bytes(len.try_into().expect("u32")) as usize
    }

    fn chunk(&mut self) -> &'a [u8] {
        let len = self.u32();
        let (chunk, rest) = self.0.split_at(len);
        self.0 = rest;
        chunk
    }

    fn finished(&self) {
        assert!(self.0.is_empty(), "the fixture has trailing bytes");
    }
}

struct Vector {
    name: String,
    ciphertext: Vec<u8>,
    frame: Vec<u8>,
}

struct Fixture {
    key: [u8; 32],
    aad: Vec<u8>,
    vectors: Vec<Vector>,
}

fn cross_language(bytes: &[u8]) -> Fixture {
    let mut chunks = Chunks(bytes);
    chunks.magic(b"VCGO1");
    let key = chunks.key();
    let aad = chunks.chunk().to_vec();
    let ciphertext = chunks.chunk().to_vec();
    let frame = chunks.chunk().to_vec();
    chunks.finished();
    Fixture {
        key,
        aad,
        vectors: vec![Vector {
            name: "cross-lang".into(),
            ciphertext,
            frame,
        }],
    }
}

fn corpus() -> Fixture {
    let mut chunks = Chunks(CORPUS);
    chunks.magic(b"VCLEG1");
    let key = chunks.key();
    let aad = chunks.chunk().to_vec();
    let count = chunks.u32();
    let vectors = (0..count)
        .map(|_| Vector {
            name: String::from_utf8(chunks.chunk().to_vec()).expect("name"),
            ciphertext: chunks.chunk().to_vec(),
            frame: chunks.chunk().to_vec(),
        })
        .collect();
    chunks.finished();
    Fixture { key, aad, vectors }
}

/// The released fixture's value chunk, with the framing tags of its time
/// moved to today's. Those three bytes were the only change to the frame
/// between the release and now, and the mapping is applied to every byte,
/// so the equality below holds only if no payload byte collides with a
/// tag; for this fixture none does, and the mapped frame parses as one.
fn released() -> Fixture {
    let mut fixture = cross_language(RELEASED);
    for vector in &mut fixture.vectors {
        for byte in &mut vector.frame {
            *byte = match *byte {
                0x10 => ARRAY,
                0x11 => OBJECT,
                0x12 => PASSTHROUGH,
                other => other,
            };
        }
        assert_eq!(
            Frame::parse(&vector.frame)
                .expect("one frame")
                .as_bytes()
                .len(),
            vector.frame.len()
        );
    }
    fixture
}

type Opened = Result<Vec<u8>, DecryptError<FrameWriteError, Unspecified>>;

fn node(vector: &Vector) -> Node<LocalCipherText> {
    decode_ciphertext(&vector.ciphertext).unwrap_or_else(|_| panic!("{} decodes", vector.name))
}

fn open(fixture: &Fixture, vector: &Vector, aad: &[u8]) -> Opened {
    let cipher = Aes256Cipher::new(&Key::from(fixture.key)).expect("cipher");
    decrypt_to_frame(
        &cipher.opening_version_1(),
        node(vector),
        Context::from_encoded(aad),
    )
    .map(|frame| frame.risky_ref().to_vec())
}

fn opens_into_its_frame(fixture: &Fixture) {
    for vector in &fixture.vectors {
        let opened = open(fixture, vector, &fixture.aad)
            .unwrap_or_else(|e| panic!("{} opens: {e:?}", vector.name));
        assert_eq!(opened, vector.frame, "{}", vector.name);
        let frame = Frame::parse(&vector.frame).expect("one frame");
        assert_eq!(
            frame.as_bytes().len(),
            vector.frame.len(),
            "{}",
            vector.name
        );
    }
}

#[test]
fn the_released_fixture_opens_into_the_frame_it_was_sealed_from() {
    opens_into_its_frame(&released());
}

#[test]
fn the_pre_adr_0001_fixture_opens_into_the_frame_it_was_sealed_from() {
    opens_into_its_frame(&cross_language(PRE_ADR));
}

#[test]
fn every_corpus_vector_sealed_on_the_value_path_opens_into_its_frame() {
    let fixture = corpus();
    assert!(
        fixture.vectors.len() > 30,
        "the corpus and the edge documents"
    );
    let names: Vec<&str> = fixture.vectors.iter().map(|v| v.name.as_str()).collect();
    for expected in ["nested-sample", "nested-edges", "top-level-passthrough"] {
        assert!(names.contains(&expected), "{expected} is in the fixture");
    }
    opens_into_its_frame(&fixture);
}

#[test]
fn the_fixtures_still_authenticate_their_aad() {
    for fixture in [released(), cross_language(PRE_ADR), corpus()] {
        for vector in &fixture.vectors {
            let wrong = open(&fixture, vector, b"other");
            // A passthrough-only value authenticates nothing, by design.
            if vector.frame.first() == Some(&PASSTHROUGH) {
                assert!(wrong.is_ok(), "{}", vector.name);
            } else {
                assert!(
                    matches!(wrong, Err(DecryptError::Cipher(_))),
                    "{}: {wrong:?}",
                    vector.name
                );
            }
        }
    }
}

#[test]
fn the_fixtures_do_not_open_under_another_key() {
    for fixture in [released(), cross_language(PRE_ADR), corpus()] {
        // Flip one bit, so the key always differs.
        let mut key = fixture.key;
        key[0] ^= 1;
        let wrong = Fixture {
            key,
            aad: fixture.aad.clone(),
            vectors: Vec::new(),
        };
        for vector in &fixture.vectors {
            let opened = open(&wrong, vector, &fixture.aad);
            // A passthrough-only value is not encrypted, by design.
            if vector.frame.first() == Some(&PASSTHROUGH) {
                assert!(opened.is_ok(), "{}", vector.name);
            } else {
                assert!(
                    matches!(opened, Err(DecryptError::Cipher(_))),
                    "{}: {opened:?}",
                    vector.name
                );
            }
        }
    }
}

#[test]
fn the_cipher_on_its_own_refuses_the_version_1_leaves() {
    for fixture in [released(), cross_language(PRE_ADR), corpus()] {
        let cipher = Aes256Cipher::new(&Key::from(fixture.key)).expect("cipher");
        for vector in &fixture.vectors {
            // A passthrough-only value has no leaf to refuse.
            if vector.frame.first() == Some(&PASSTHROUGH) {
                continue;
            }
            let opened =
                decrypt_to_frame(&cipher, node(vector), Context::from_encoded(&fixture.aad));
            assert!(
                matches!(opened, Err(DecryptError::Cipher(_))),
                "{}: {opened:?}",
                vector.name
            );
        }
    }
}

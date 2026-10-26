//! How fast the storage profile writes and reads, next to the transport
//! serde format and JSON.
//!
//! Each workload is written and read by five formats: `storage`
//! (`storage::to_vec` and `storage::from_slice`), `transport`
//! (`serde::to_vec` and `serde::from_slice`), `json` (`serde_json`),
//! `msgpack` (`rmp_serde`, with field names, as the others carry them) and
//! `borsh`. Borsh writes no field names and no kinds, so it shows what a
//! format costs that carries nothing but the values. Throughput is the size
//! of the bytes each format writes, so the rates compare work per byte and
//! the times compare work per value.
//!
//! A storage write reads the blob back before it returns it, to find a
//! repeated key as a reader would. A write and both `to_vec`s wipe their
//! buffers as they grow and when they are dropped. Both costs are part of
//! what is measured. MessagePack, Borsh and JSON wipe nothing.
//!
//! Run with `cargo bench -p vitaminc-aead-frame --features serde`.

use std::collections::BTreeMap;
use std::hint::black_box;

use borsh::{BorshDeserialize, BorshSerialize};
use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, Throughput};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use vitaminc_aead_frame::{serde as transport, storage};
use vitaminc_protected::Controlled;

/// A row of the kind an application keeps: integers, text, a flag, a
/// float, a list and an option.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
struct Record {
    id: u64,
    name: String,
    email: String,
    active: bool,
    score: f64,
    tags: Vec<String>,
    manager: Option<u64>,
}

fn record(i: u64) -> Record {
    Record {
        id: i,
        name: format!("Person {i}"),
        email: format!("person{i}@example.com"),
        active: !i.is_multiple_of(3),
        score: i as f64 * 1.25,
        tags: vec!["staff".into(), format!("team-{}", i % 7)],
        manager: (!i.is_multiple_of(4)).then_some(i / 4),
    }
}

/// Bytes, written as bytes rather than as a list of numbers.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Debug)]
struct Blob(#[serde(with = "serde_bytes")] Vec<u8>);

/// Writes and reads `value` in all five formats, in one group.
fn formats<T>(c: &mut Criterion, name: &str, value: &T)
where
    T: Serialize
        + DeserializeOwned
        + BorshSerialize
        + BorshDeserialize
        + PartialEq
        + std::fmt::Debug,
{
    let stored = storage::to_vec(value).expect("storage writes");
    let carried = transport::to_vec(value).expect("transport writes");
    let json = serde_json::to_vec(value).expect("json writes");
    let msgpack = rmp_serde::to_vec_named(value).expect("msgpack writes");
    let borsh = borsh::to_vec(value).expect("borsh writes");

    // A bench is only worth reading if the format gives the value back.
    assert_eq!(
        &storage::from_slice::<T>(stored.risky_ref()).expect("storage reads"),
        value
    );
    assert_eq!(
        &transport::from_slice::<T>(carried.risky_ref()).expect("transport reads"),
        value
    );
    assert_eq!(
        &serde_json::from_slice::<T>(&json).expect("json reads"),
        value
    );
    assert_eq!(
        &rmp_serde::from_slice::<T>(&msgpack).expect("msgpack reads"),
        value
    );
    assert_eq!(&borsh::from_slice::<T>(&borsh).expect("borsh reads"), value);

    let mut group = c.benchmark_group(name);
    pair(
        &mut group,
        "storage",
        stored.risky_ref(),
        || storage::to_vec(black_box(value)).expect("storage writes"),
        |bytes| storage::from_slice::<T>(black_box(bytes)).expect("storage reads"),
    );
    pair(
        &mut group,
        "transport",
        carried.risky_ref(),
        || transport::to_vec(black_box(value)).expect("transport writes"),
        |bytes| transport::from_slice::<T>(black_box(bytes)).expect("transport reads"),
    );
    pair(
        &mut group,
        "json",
        &json,
        || serde_json::to_vec(black_box(value)).expect("json writes"),
        |bytes| serde_json::from_slice::<T>(black_box(bytes)).expect("json reads"),
    );
    pair(
        &mut group,
        "msgpack",
        &msgpack,
        || rmp_serde::to_vec_named(black_box(value)).expect("msgpack writes"),
        |bytes| rmp_serde::from_slice::<T>(black_box(bytes)).expect("msgpack reads"),
    );
    pair(
        &mut group,
        "borsh",
        &borsh,
        || borsh::to_vec(black_box(value)).expect("borsh writes"),
        |bytes| borsh::from_slice::<T>(black_box(bytes)).expect("borsh reads"),
    );
    group.finish();
}

/// Benches one format's write and read, at the rate of the bytes it writes.
fn pair<W, R>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    format: &str,
    bytes: &[u8],
    write: impl Fn() -> W,
    read: impl Fn(&[u8]) -> R,
) {
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function(format!("{format}/write"), |b| b.iter(&write));
    group.bench_function(format!("{format}/read"), |b| b.iter(|| read(bytes)));
}

fn benches(c: &mut Criterion) {
    formats(c, "record", &record(42));
    formats(
        c,
        "records_1000",
        &(0..1000).map(record).collect::<Vec<_>>(),
    );
    formats(
        c,
        "map_1000",
        &(0..1000u64)
            .map(|i| (format!("key-{i:04}"), i))
            .collect::<BTreeMap<_, _>>(),
    );
    formats(c, "text_64k", &"a".repeat(64 * 1024));
    formats(
        c,
        "bytes_64k",
        &Blob((0..64 * 1024).map(|i| i as u8).collect()),
    );
}

criterion_group!(storage_benches, benches);
criterion_main!(storage_benches);

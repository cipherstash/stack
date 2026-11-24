//! Oracle tests for [`Client::send_chunked`]: every spec gets the key derived
//! from its own response, for any batch size, request size, concurrency and
//! response order, for all three operations, and every failure fails the
//! whole call cleanly.
//!
//! The fake connection answers each key with material computed from that
//! key's IV, so the right key for every spec can be computed directly:
//! `DataKey::from_key_material(&client_key, iv, &material_for(iv))`. A key
//! paired with the wrong spec, or a response paired with the wrong request,
//! is a different key.

use super::*;
use crate::connection::ZeroKMSConnectionInit;
use crate::key::V1KeySet;
use proptest::prelude::*;
use recipher::keyset::{EncryptionKeySet, ProxyKeySet};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
use zerokms_protocol::{
    GenerateKeyResponse, GeneratedKey, KeyId, RetrieveKeyResponse, RetrieveKeyResponseFallible,
    RetrievedKey, ViturKeyMaterial, ViturRequestErrorKind,
};

// ---------------------------------------------------------------- the oracle

fn h(label: &[u8], iv: &[u8; 16], j: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(iv);
    h.update([j]);
    h.finalize().into()
}

/// The key material ZeroKMS "returns" for the key with this IV.
fn material_for(iv: &[u8; 16]) -> ViturKeyMaterial {
    let mut out = Vec::with_capacity(17 * 32);
    for j in 0..17 {
        out.extend_from_slice(&h(b"material", iv, j));
    }
    out.truncate(528);
    ViturKeyMaterial::from(out)
}

/// The tag a generated key with this IV comes back with.
fn tag_for(iv: &[u8; 16]) -> Vec<u8> {
    h(b"tag", iv, 0).to_vec()
}

/// Whether a fallible retrieval of this IV fails (about 1 in 6).
fn fails_for(iv: &[u8; 16]) -> bool {
    h(b"fail", iv, 0)[0] < 43
}

fn failure_for(iv: &[u8; 16]) -> String {
    format!("no key for {}", base16ct::lower::encode_string(iv))
}

fn oracle_key(client_key: &ClientKey, iv: &[u8; 16]) -> DataKey {
    DataKey::from_key_material(client_key, *iv, &material_for(iv)).unwrap()
}

/// The IV of the `k`th spec of a retrieve: `k`, then a salt, so IVs differ
/// from case to case.
fn retrieve_iv(k: usize, salt: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&(k as u64).to_le_bytes());
    iv[8..].copy_from_slice(&salt.to_le_bytes());
    iv
}

// ------------------------------------------------------------ the connection

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// The request fails.
    Fail,
    /// The response has one key too few.
    Short,
    /// The response has one key too many.
    Long,
}

struct ReqState {
    released: bool,
    waker: Option<Waker>,
}

struct Shared {
    keys_per_req: usize,
    /// A fault on the request for this chunk index.
    fault: Option<(usize, Fault)>,
    /// Natively: how long each chunk's request takes. Otherwise the test
    /// releases each request by hand.
    delays: Option<Vec<Duration>>,
    reqs: Mutex<Vec<ReqState>>,
    /// Every IV sent, with the index of the spec it was sent for.
    ivs: Mutex<HashMap<[u8; 16], usize>>,
    /// Request futures that have started and not been dropped.
    live: AtomicUsize,
    max_live: AtomicUsize,
}

#[derive(Clone)]
struct Oracle(Arc<Shared>);

struct Live(Arc<Shared>);

impl Live {
    fn new(shared: &Arc<Shared>) -> Self {
        let now = shared.live.fetch_add(1, Ordering::SeqCst) + 1;
        shared.max_live.fetch_max(now, Ordering::SeqCst);
        Live(shared.clone())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Oracle {
    fn new(
        keys_per_req: usize,
        fault: Option<(usize, Fault)>,
        delays: Option<Vec<Duration>>,
    ) -> Self {
        Oracle(Arc::new(Shared {
            keys_per_req,
            fault,
            delays,
            reqs: Mutex::default(),
            ivs: Mutex::default(),
            live: AtomicUsize::new(0),
            max_live: AtomicUsize::new(0),
        }))
    }

    fn sent(&self) -> usize {
        self.0.reqs.lock().unwrap().len()
    }

    fn in_flight(&self) -> Vec<usize> {
        let reqs = self.0.reqs.lock().unwrap();
        (0..reqs.len()).filter(|&i| !reqs[i].released).collect()
    }

    fn release(&self, i: usize) {
        let mut reqs = self.0.reqs.lock().unwrap();
        reqs[i].released = true;
        if let Some(w) = reqs[i].waker.take() {
            w.wake();
        }
    }

    fn live(&self) -> usize {
        self.0.live.load(Ordering::SeqCst)
    }
}

impl ZeroKMSConnectionInit for Oracle {
    type ConnectionOpts = Oracle;
    type Error = std::convert::Infallible;

    fn init(o: Self) -> Result<Self, Self::Error> {
        Ok(o)
    }
}

impl ZeroKMSConnection for Oracle {
    async fn send<Request: ViturRequest>(
        &self,
        request: Request,
        _access_token: &str,
    ) -> Result<Request::Response, ViturRequestError> {
        let shared = &self.0;
        let _live = Live::new(shared);
        let value = serde_json::to_value(&request).unwrap();
        // Each spec's IV, and its index in the batch (from its descriptor).
        let specs: Vec<([u8; 16], usize)> = value["keys"]
            .as_array()
            .expect("a request for keys")
            .iter()
            .map(|s| {
                let iv: KeyId = serde_json::from_value(s["iv"].clone()).unwrap();
                let k: usize = s["descriptor"].as_str().unwrap()[1..].parse().unwrap();
                (*iv.as_ref(), k)
            })
            .collect();
        assert!(!specs.is_empty(), "a request for no keys");
        let chunk = specs[0].1 / shared.keys_per_req;
        assert_eq!(
            specs[0].1 % shared.keys_per_req,
            0,
            "a request starts mid-chunk"
        );
        assert!(
            specs.len() <= shared.keys_per_req,
            "a request over the limit"
        );
        for (j, (_, k)) in specs.iter().enumerate() {
            assert_eq!(
                *k,
                specs[0].1 + j,
                "a request's specs are not one chunk, in order"
            );
        }
        {
            let mut ivs = shared.ivs.lock().unwrap();
            for (iv, k) in &specs {
                assert!(ivs.insert(*iv, *k).is_none(), "an IV sent twice");
            }
        }

        if let Some(delays) = &shared.delays {
            tokio::time::sleep(delays[chunk]).await;
        } else {
            let i = {
                let mut reqs = shared.reqs.lock().unwrap();
                reqs.push(ReqState {
                    released: false,
                    waker: None,
                });
                reqs.len() - 1
            };
            std::future::poll_fn(|cx| {
                let mut reqs = shared.reqs.lock().unwrap();
                if reqs[i].released {
                    Poll::Ready(())
                } else {
                    reqs[i].waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
        }

        let fault = match shared.fault {
            Some((c, f)) if c == chunk => Some(f),
            _ => None,
        };
        if fault == Some(Fault::Fail) {
            return Err(ViturRequestError::new(
                ViturRequestErrorKind::FailureResponse,
                "injected",
                std::io::Error::other(format!("injected failure of chunk {chunk}")),
            ));
        }
        let mut ivs: Vec<[u8; 16]> = specs.iter().map(|s| s.0).collect();
        match fault {
            Some(Fault::Short) => {
                ivs.pop();
            }
            Some(Fault::Long) => ivs.push([0xee; 16]),
            _ => {}
        }
        let response = match Request::ENDPOINT {
            "retrieve-data-key" => serde_json::to_value(RetrieveKeyResponse {
                keys: ivs
                    .iter()
                    .map(|iv| RetrievedKey {
                        key_material: material_for(iv),
                    })
                    .collect(),
            }),
            "retrieve-data-key-fallible" => serde_json::to_value(RetrieveKeyResponseFallible {
                keys: ivs
                    .iter()
                    .map(|iv| {
                        if fails_for(iv) {
                            Err(failure_for(iv))
                        } else {
                            Ok(RetrievedKey {
                                key_material: material_for(iv),
                            })
                        }
                    })
                    .collect(),
            }),
            "generate-data-key" => serde_json::to_value(GenerateKeyResponse {
                keys: ivs
                    .iter()
                    .map(|iv| GeneratedKey {
                        key_material: material_for(iv),
                        tag: tag_for(iv),
                        decryption_policy: None,
                    })
                    .collect(),
            }),
            other => panic!("unexpected endpoint {other}"),
        }
        .unwrap();
        Ok(serde_json::from_value(response).unwrap())
    }
}

// ------------------------------------------------------------ the operations

#[derive(Clone, Copy, Debug)]
enum Op {
    Retrieve,
    Fallible,
    Generate,
}

/// What a call returned for one spec.
enum Got {
    Key {
        iv: [u8; 16],
        key: DataKey,
        tag: Option<Vec<u8>>,
    },
    KeyErr(String),
}

#[derive(Debug, PartialEq)]
enum CallErr {
    Count { expected: usize, received: usize },
    Other(String),
}

type Call<'a> = Pin<Box<dyn Future<Output = Result<Vec<Got>, CallErr>> + Send + 'a>>;

const TAG: &[u8] = b"t";

fn call<'a>(
    client: &'a Client<Oracle>,
    client_key: &'a ClientKey,
    op: Op,
    descriptors: &'a [String],
    salt: u64,
) -> Call<'a> {
    match op {
        Op::Retrieve => {
            let payloads = descriptors
                .iter()
                .enumerate()
                .map(move |(k, d)| RetrieveKeyPayload::new(retrieve_iv(k, salt), d, TAG));
            Box::pin(async move {
                match client
                    .retrieve_keys(payloads, client_key, None, "token", None)
                    .await
                {
                    Ok(keys) => Ok(keys
                        .into_iter()
                        .map(|key| Got::Key {
                            iv: key.iv,
                            key,
                            tag: None,
                        })
                        .collect()),
                    Err(RetrieveKeyError::InvalidNumberOfKeys { expected, received }) => {
                        Err(CallErr::Count { expected, received })
                    }
                    Err(e) => Err(CallErr::Other(format!("{e:?}"))),
                }
            })
        }
        Op::Fallible => {
            let payloads = descriptors
                .iter()
                .enumerate()
                .map(move |(k, d)| RetrieveKeyPayload::new(retrieve_iv(k, salt), d, TAG));
            Box::pin(async move {
                match client
                    .retrieve_keys_fallible(payloads, client_key, None, "token", None)
                    .await
                {
                    Ok(keys) => Ok(keys
                        .into_iter()
                        .map(|r| match r {
                            Ok(key) => Got::Key {
                                iv: key.iv,
                                key,
                                tag: None,
                            },
                            Err(RetrieveKeyError::FailedRetrieval(m)) => Got::KeyErr(m),
                            Err(e) => Got::KeyErr(format!("UNEXPECTED {e:?}")),
                        })
                        .collect()),
                    Err(RetrieveKeyError::InvalidNumberOfKeys { expected, received }) => {
                        Err(CallErr::Count { expected, received })
                    }
                    Err(e) => Err(CallErr::Other(format!("{e:?}"))),
                }
            })
        }
        Op::Generate => {
            let payloads = descriptors
                .iter()
                .map(|d| GenerateKeyPayload::new(d, Cow::Borrowed(&[])));
            Box::pin(async move {
                match client
                    .generate_keys(payloads, client_key, None, "token", None)
                    .await
                {
                    Ok(keys) => Ok(keys
                        .into_iter()
                        .map(|k| Got::Key {
                            iv: k.key.iv,
                            tag: Some(k.tag.clone()),
                            key: k.key.clone(),
                        })
                        .collect()),
                    Err(GenerateKeyError::InvalidNumberOfKeys { expected, received }) => {
                        Err(CallErr::Count { expected, received })
                    }
                    Err(e) => Err(CallErr::Other(format!("{e:?}"))),
                }
            })
        }
    }
}

// ---------------------------------------------------------------- the drivers

/// A small deterministic RNG for the drivers' choices, seeded per case.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, self.below(i + 1));
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Drive {
    /// As a wasm guest's host: every request a step sent is answered, in a
    /// random order, before the next poll.
    GuestAtOnce,
    /// A step's requests are answered in a random order, sometimes with a
    /// poll between answers.
    GuestPollBetween,
    /// Whenever the batch waits, a random non-empty subset of the requests
    /// in flight is answered; sometimes some are answered on a yield too.
    Network,
    /// On tokio (current-thread, paused clock), each request taking a
    /// random time.
    Tokio,
}

#[derive(Debug, Default)]
struct Trace {
    /// How many requests each step that sent any sent.
    request_steps: Vec<usize>,
    /// Steps that sent nothing and woke themselves.
    yields: usize,
    /// Steps that sent requests and woke themselves.
    both: usize,
    /// Steps that left the batch pending, not woken, with nothing in flight.
    hung: bool,
}

struct Woken(AtomicBool);

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

enum Polled<T> {
    Ready(T),
    Pending {
        sent: std::ops::Range<usize>,
        woke: bool,
    },
}

/// Drive `fut` by hand. Returns its output, or `None` if it was dropped
/// after `drop_after` polls (or hung).
fn drive_by_hand(
    mut fut: Call<'_>,
    conn: &Oracle,
    drive: Drive,
    rng: &mut SplitMix,
    drop_after: Option<usize>,
) -> (Option<Result<Vec<Got>, CallErr>>, Trace) {
    let woken = Arc::new(Woken(AtomicBool::new(false)));
    let waker = Waker::from(woken.clone());
    let mut cx = Context::from_waker(&waker);
    let mut trace = Trace::default();
    let mut seen = 0;
    let mut polls = 0;

    let mut poll = |fut: &mut Call<'_>, trace: &mut Trace, seen: &mut usize| {
        woken.0.store(false, Ordering::SeqCst);
        polls += 1;
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => (Polled::Ready(r), polls),
            Poll::Pending => {
                let sent = *seen..conn.sent();
                *seen = sent.end;
                let woke = woken.0.load(Ordering::SeqCst);
                if !sent.is_empty() {
                    trace.request_steps.push(sent.len());
                    if woke {
                        trace.both += 1;
                    }
                } else if woke {
                    trace.yields += 1;
                }
                (Polled::Pending { sent, woke }, polls)
            }
        }
    };

    loop {
        let (polled, polls) = poll(&mut fut, &mut trace, &mut seen);
        if drop_after.is_some_and(|d| polls >= d) {
            drop(fut);
            return (None, trace);
        }
        let (sent, woke) = match polled {
            Polled::Ready(r) => return (Some(r), trace),
            Polled::Pending { sent, woke } => (sent, woke),
        };
        let in_flight = conn.in_flight();
        if sent.is_empty() && !woke && in_flight.is_empty() {
            trace.hung = true;
            return (None, trace);
        }
        match drive {
            Drive::GuestAtOnce | Drive::GuestPollBetween => {
                // The host answers what the guest has asked for: this
                // step's requests, and (polling between answers) any sent
                // by a poll between answers.
                if in_flight.is_empty() {
                    if woke {
                        continue;
                    }
                    trace.hung = true;
                    return (None, trace);
                }
                if matches!(drive, Drive::GuestAtOnce)
                    && in_flight != sent.clone().collect::<Vec<_>>()
                {
                    // In a guest, a step that waits sent everything it
                    // waits on.
                    trace.hung = true;
                    return (None, trace);
                }
                let mut order = in_flight;
                rng.shuffle(&mut order);
                let last = order.len() - 1;
                for (j, i) in order.into_iter().enumerate() {
                    conn.release(i);
                    if matches!(drive, Drive::GuestPollBetween) && j < last && rng.coin() {
                        match poll(&mut fut, &mut trace, &mut seen).0 {
                            Polled::Ready(r) => return (Some(r), trace),
                            Polled::Pending { .. } => {}
                        }
                    }
                }
            }
            Drive::Network => {
                if woke && rng.below(3) != 0 {
                    continue;
                }
                if in_flight.is_empty() {
                    continue;
                }
                let mut released = false;
                for &i in &in_flight {
                    if rng.coin() {
                        conn.release(i);
                        released = true;
                    }
                }
                if !released && !woke {
                    conn.release(in_flight[rng.below(in_flight.len())]);
                }
            }
            Drive::Tokio => unreachable!(),
        }
    }
}

fn drive_tokio(fut: Call<'_>, timeout: Option<Duration>) -> Option<Result<Vec<Got>, CallErr>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    rt.block_on(async move {
        match timeout {
            Some(d) => tokio::time::timeout(d, fut).await.ok(),
            None => Some(fut.await),
        }
    })
}

// ------------------------------------------------------------------ the cases

#[derive(Debug, Clone)]
struct Case {
    op: Op,
    drive: Drive,
    keys: usize,
    keys_per_req: usize,
    concurrent_reqs: usize,
    /// A fault on the request for chunk `index % chunks`.
    fault: Option<(usize, Fault)>,
    /// Drop the call: after this many polls by hand, or after this many
    /// milliseconds on tokio.
    drop_after: Option<usize>,
    seed: u64,
}

fn chunks(keys: usize, per: usize) -> usize {
    keys.div_ceil(per)
}

fn case() -> impl Strategy<Value = Case> {
    let op = prop_oneof![Just(Op::Retrieve), Just(Op::Fallible), Just(Op::Generate)];
    let drive = prop_oneof![
        Just(Drive::GuestAtOnce),
        Just(Drive::GuestPollBetween),
        Just(Drive::Network),
        Just(Drive::Tokio)
    ];
    let fault = prop_oneof![
        6 => Just(None),
        1 => (any::<usize>(), prop_oneof![Just(Fault::Fail), Just(Fault::Short), Just(Fault::Long)])
            .prop_map(Some),
    ];
    let drop_after = prop_oneof![8 => Just(None), 1 => (1usize..40).prop_map(Some)];
    (
        op,
        drive,
        1usize..=600,
        1usize..=8,
        fault,
        drop_after,
        any::<u64>(),
    )
        .prop_flat_map(
            |(op, drive, keys_per_req, concurrent_reqs, fault, drop_after, seed)| {
                let keys = prop_oneof![
                    3 => prop::sample::select(vec![
                        0usize, 1, 499, 500, 501, 999, 1000, 1001, 1499, 1500, 1501, 2501
                    ]),
                    2 => (1usize..=6, 0usize..=2)
                        .prop_map(move |(m, d)| (m * keys_per_req + d).saturating_sub(1)),
                    2 => 0usize..3000,
                ];
                keys.prop_map(move |keys| Case {
                    op,
                    drive,
                    keys,
                    keys_per_req,
                    concurrent_reqs,
                    fault: fault
                        .filter(|_| keys > 0)
                        .map(|(i, f)| (i % chunks(keys, keys_per_req), f)),
                    drop_after,
                    seed,
                })
            },
        )
}

/// Yields beyond one per YIELD_EVERY keys, outside the guest's own driving
/// (reported, not failed).
static EXTRA_YIELDS: AtomicUsize = AtomicUsize::new(0);
static CASES: AtomicUsize = AtomicUsize::new(0);

fn run(case: &Case) -> Result<(), TestCaseError> {
    // ORACLE_OP=Retrieve|Fallible|Generate runs only that operation.
    if let Ok(only) = std::env::var("ORACLE_OP") {
        if format!("{:?}", case.op) != only {
            return Ok(());
        }
    }
    CASES.fetch_add(1, Ordering::Relaxed);
    let mut rng = SplitMix(case.seed);
    let delays = matches!(case.drive, Drive::Tokio).then(|| {
        (0..chunks(case.keys, case.keys_per_req))
            .map(|_| Duration::from_millis(rng.below(500) as u64))
            .collect()
    });
    let conn = Oracle::new(case.keys_per_req, case.fault, delays);
    let opts = ClientOpts::new(conn.clone())
        .with_max_keys_per_req(case.keys_per_req)
        .unwrap()
        .with_max_concurrent_reqs(case.concurrent_reqs)
        .unwrap();
    let client = Client::<Oracle>::init_opts(opts).unwrap();
    let client_key = ClientKey {
        key_id: Uuid::nil(),
        keyset: V1KeySet(ProxyKeySet::generate(
            &EncryptionKeySet::generate().unwrap(),
            &EncryptionKeySet::generate().unwrap(),
        )),
    };
    let descriptors: Vec<String> = (0..case.keys).map(|k| format!("d{k}")).collect();
    let salt = rng.next();
    let fut = call(&client, &client_key, case.op, &descriptors, salt);

    let (result, trace) = match case.drive {
        Drive::Tokio => (
            drive_tokio(
                fut,
                case.drop_after
                    .map(|ms| Duration::from_millis(ms as u64 * 25)),
            ),
            None,
        ),
        drive => {
            let (r, t) = drive_by_hand(fut, &conn, drive, &mut rng, case.drop_after);
            (r, Some(t))
        }
    };

    // Whatever happened, no request future outlives the call.
    prop_assert_eq!(conn.live(), 0, "request futures outlived the call");
    prop_assert!(
        conn.0.max_live.load(Ordering::SeqCst) <= case.concurrent_reqs,
        "more than {} requests in flight",
        case.concurrent_reqs
    );
    if let Some(t) = &trace {
        prop_assert!(!t.hung, "the call hung: {t:?}");
    }

    let Some(result) = result else {
        prop_assert!(case.drop_after.is_some(), "no result, and not dropped");
        return Ok(());
    };

    let chunk_len = |c: usize| case.keys_per_req.min(case.keys - c * case.keys_per_req);
    match case.fault {
        Some((c, Fault::Fail)) => match &result {
            Err(CallErr::Other(s)) => prop_assert!(
                s.contains(&format!("injected failure of chunk {c}")),
                "the wrong error: {s}"
            ),
            Err(e) => prop_assert!(false, "the wrong error: {e:?}"),
            Ok(_) => prop_assert!(false, "a failed request did not fail the call"),
        },
        Some((c, Fault::Short)) => prop_assert_eq!(
            result.err(),
            Some(CallErr::Count {
                expected: chunk_len(c),
                received: chunk_len(c) - 1
            })
        ),
        Some((c, Fault::Long)) => prop_assert_eq!(
            result.err(),
            Some(CallErr::Count {
                expected: chunk_len(c),
                received: chunk_len(c) + 1
            })
        ),
        None => {
            let got = match result {
                Ok(got) => got,
                Err(e) => return Err(TestCaseError::fail(format!("the call failed: {e:?}"))),
            };
            prop_assert_eq!(got.len(), case.keys);
            let ivs = conn.0.ivs.lock().unwrap();
            prop_assert_eq!(ivs.len(), case.keys, "every spec sent once");
            for (k, g) in got.iter().enumerate() {
                let expected_iv = match case.op {
                    Op::Retrieve | Op::Fallible => retrieve_iv(k, salt),
                    Op::Generate => match g {
                        Got::Key { iv, .. } => {
                            prop_assert_eq!(
                                ivs.get(iv),
                                Some(&k),
                                "key {} has spec {:?}'s IV",
                                k,
                                ivs.get(iv)
                            );
                            *iv
                        }
                        Got::KeyErr(e) => {
                            return Err(TestCaseError::fail(format!("key {k} failed: {e}")))
                        }
                    },
                };
                let want_err = matches!(case.op, Op::Fallible) && fails_for(&expected_iv);
                match g {
                    Got::KeyErr(m) => {
                        prop_assert!(want_err, "key {} failed: {}", k, m);
                        prop_assert_eq!(
                            m,
                            &failure_for(&expected_iv),
                            "key {}'s error is another's",
                            k
                        );
                    }
                    Got::Key { iv, key, tag } => {
                        prop_assert!(!want_err, "key {} should have failed", k);
                        prop_assert_eq!(iv, &expected_iv, "key {} has the wrong IV", k);
                        prop_assert!(
                            *key == oracle_key(&client_key, &expected_iv),
                            "key {} is not the key derived from its own response",
                            k
                        );
                        if let Op::Generate = case.op {
                            prop_assert_eq!(tag.as_deref(), Some(&tag_for(&expected_iv)[..]));
                        }
                    }
                }
            }

            // How the batch went out, as a guest polls it.
            // How the batch went out, as a guest polls it. (A step that
            // sends requests can also wake itself: `FuturesUnordered` does
            // when it has polled every future it holds. The guest's step
            // loop looks at the requests first, so that is no yield.)
            if let Some(t) = &trace {
                let derive_yields = case.keys.saturating_sub(1) / YIELD_EVERY;
                if let Drive::GuestAtOnce = case.drive {
                    // Exactly one yield per YIELD_EVERY keys, and every step
                    // but the last sends as many requests as the
                    // concurrency allows.
                    prop_assert_eq!(t.yields, derive_yields, "yields: {:?}", t);
                    let n = chunks(case.keys, case.keys_per_req);
                    let c = case.concurrent_reqs;
                    let mut want = vec![c; n / c];
                    if n % c != 0 {
                        want.push(n % c);
                    }
                    prop_assert_eq!(&t.request_steps, &want, "windows: {:?}", t);
                } else {
                    // Here a poll can send a request and then derive up to
                    // a yield, so a yield can come in a step that sent.
                    prop_assert!(
                        t.yields + t.both >= derive_yields,
                        "too few yields: {:?}",
                        t
                    );
                    if t.yields > derive_yields {
                        EXTRA_YIELDS.fetch_add(t.yields - derive_yields, Ordering::Relaxed);
                    }
                }
            }
        }
    }
    Ok(())
}

proptest! {
    // PROPTEST_CASES sets the number of cases (default 256 here, so the
    // ordinary test run stays quick); PROPTEST_RNG_SEED fixes the seed.
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn every_spec_gets_the_key_derived_from_its_own_response(case in case()) {
        run(&case)?;
    }
}

#[test]
fn zz_report() {
    eprintln!(
        "oracle cases run so far in this process: {}, extra yields outside the guest driver: {}",
        CASES.load(Ordering::Relaxed),
        EXTRA_YIELDS.load(Ordering::Relaxed)
    );
}

/// Dropping the call while every request of a window is in flight drops
/// every request future, on each operation.
#[test]
fn dropping_the_call_drops_every_request_in_flight() {
    for op in [Op::Retrieve, Op::Fallible, Op::Generate] {
        for concurrent in [1, 3, 8] {
            let conn = Oracle::new(10, None, None);
            let opts = ClientOpts::new(conn.clone())
                .with_max_keys_per_req(10)
                .unwrap()
                .with_max_concurrent_reqs(concurrent)
                .unwrap();
            let client = Client::<Oracle>::init_opts(opts).unwrap();
            let client_key = ClientKey {
                key_id: Uuid::nil(),
                keyset: V1KeySet(ProxyKeySet::generate(
                    &EncryptionKeySet::generate().unwrap(),
                    &EncryptionKeySet::generate().unwrap(),
                )),
            };
            let descriptors: Vec<String> = (0..100).map(|k| format!("d{k}")).collect();
            let mut fut = call(&client, &client_key, op, &descriptors, 7);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(fut.as_mut().poll(&mut cx).is_pending());
            assert_eq!(conn.live(), concurrent);
            // Answer the oldest, derive its keys, so a new one goes out.
            conn.release(0);
            for _ in 0..5 {
                let _ = fut.as_mut().poll(&mut cx);
            }
            assert_eq!(conn.live(), concurrent, "{op:?} {concurrent}");
            drop(fut);
            assert_eq!(
                conn.live(),
                0,
                "{op:?} {concurrent}: request futures outlived the call"
            );
        }
    }
}

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
//!
//! Where a key is derived is seen through a probe: a key whose material is a
//! byte short. Deriving it fails, and on `retrieve_keys` and `generate_keys`
//! that ends the call on the poll that derived it, so the yields before that
//! poll say which run of [`YIELD_EVERY`] keys it was derived in.
//!
//! Environment variables:
//!
//! - `PROPTEST_CASES` sets the number of cases (default 256) and
//!   `PROPTEST_RNG_SEED` fixes the seed.
//! - `ORACLE_MAX_KEYS` caps the random batch sizes (default 1,100, so the
//!   default run stays quick in the debug profile). The fixed boundary sizes,
//!   up to 2,501, are always drawn. `ORACLE_MAX_KEYS=4000` draws every size
//!   up to the largest a case can name.
//! - `ORACLE_OP=Retrieve|Fallible|Generate` runs only that operation. Any
//!   other value fails the test.

use super::*;
use crate::connection::ZeroKMSConnectionInit;
use crate::key::V1KeySet;
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
use zerokms_keyset::keyset::{EncryptionKeySet, ProxyKeySet};
use zerokms_protocol::{
    GenerateKeyResponse, GeneratedKey, KeyId, RetrieveKeyResponse, RetrieveKeyResponseFallible,
    RetrievedKey, ViturKeyMaterial, ViturRequestErrorKind,
};

// ---------------------------------------------------------------- the oracle

/// SHA-256 of `label` and `iv`: a hash of the IV, kept apart from the other
/// hashes of it by its label.
fn labelled_hash(label: &[u8], iv: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(iv);
    hasher.finalize().into()
}

/// The key material ZeroKMS "returns" for the key with this IV: 528 bytes
/// spread from one hash of it, so different for every IV. One hash per key,
/// not one per 32 bytes, keeps the debug-profile run quick.
fn material_bytes(iv: &[u8; 16]) -> Vec<u8> {
    let seed = labelled_hash(b"material", iv);
    (0..528).map(|i| seed[i % 32] ^ (i / 32) as u8).collect()
}

fn material_for(iv: &[u8; 16]) -> ViturKeyMaterial {
    ViturKeyMaterial::from(material_bytes(iv))
}

/// The material a [`Fault::BadMaterial`] key gets: a byte short, so deriving
/// a key from it fails.
fn bad_material_for(iv: &[u8; 16]) -> ViturKeyMaterial {
    let mut bytes = material_bytes(iv);
    bytes.pop();
    ViturKeyMaterial::from(bytes)
}

/// The tag a generated key with this IV comes back with.
fn tag_for(iv: &[u8; 16]) -> Vec<u8> {
    labelled_hash(b"tag", iv).to_vec()
}

/// Whether a fallible retrieval of this IV fails (about 1 in 6).
fn fails_for(iv: &[u8; 16]) -> bool {
    labelled_hash(b"fail", iv)[0] < 43
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

/// The descriptor of the `k`th spec of a batch. The connection reads `k`
/// back from it with [`spec_index`].
fn descriptor(k: usize) -> String {
    format!("d{k}")
}

/// The index of the spec a [`descriptor`] was made for.
fn spec_index(descriptor: &str) -> usize {
    descriptor
        .strip_prefix('d')
        .and_then(|k| k.parse().ok())
        .unwrap_or_else(|| panic!("{descriptor:?} is not a descriptor of a spec"))
}

/// The descriptors of a batch of `keys` specs.
fn descriptors(keys: usize) -> Vec<String> {
    (0..keys).map(descriptor).collect()
}

// ------------------------------------------------------------ the connection

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// The request for this chunk fails.
    Fail { chunk: usize },
    /// The response to this chunk has one key too few.
    Short { chunk: usize },
    /// The response to this chunk has one key too many.
    Long { chunk: usize },
    /// The material for this key, the index of its spec, is a byte short.
    BadMaterial { key: usize },
}

impl Fault {
    /// This fault, its chunk or key drawn as any number, moved into a batch
    /// of `keys` specs (at least one) sent `per` to a request.
    fn placed(self, keys: usize, per: usize) -> Self {
        let n = chunks(keys, per);
        match self {
            Fault::Fail { chunk } => Fault::Fail { chunk: chunk % n },
            Fault::Short { chunk } => Fault::Short { chunk: chunk % n },
            Fault::Long { chunk } => Fault::Long { chunk: chunk % n },
            Fault::BadMaterial { key } => Fault::BadMaterial { key: key % keys },
        }
    }

    /// Whether this fault fails the whole call. A fallible retrieval keeps a
    /// bad key's failure to that key.
    fn fails_the_call(self, op: Op) -> bool {
        !matches!((self, op), (Fault::BadMaterial { .. }, Op::Fallible))
    }
}

struct ReqState {
    released: bool,
    waker: Option<Waker>,
}

struct Shared {
    keys_per_req: usize,
    fault: Option<Fault>,
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
    fn new(keys_per_req: usize, fault: Option<Fault>, delays: Option<Vec<Duration>>) -> Self {
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
                (*iv.as_ref(), spec_index(s["descriptor"].as_str().unwrap()))
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

        if shared.fault == Some(Fault::Fail { chunk }) {
            return Err(ViturRequestError::new(
                ViturRequestErrorKind::FailureResponse,
                "injected",
                std::io::Error::other(format!("injected failure of chunk {chunk}")),
            ));
        }
        let mut ivs: Vec<[u8; 16]> = specs.iter().map(|s| s.0).collect();
        // The IV of the bad key, if it is in this request.
        let mut bad = None;
        match shared.fault {
            Some(Fault::Short { chunk: c }) if c == chunk => {
                ivs.pop();
            }
            Some(Fault::Long { chunk: c }) if c == chunk => ivs.push([0xee; 16]),
            Some(Fault::BadMaterial { key }) => {
                bad = specs.iter().find(|s| s.1 == key).map(|s| s.0);
            }
            _ => {}
        }
        let material = |iv: &[u8; 16]| {
            if bad == Some(*iv) {
                bad_material_for(iv)
            } else {
                material_for(iv)
            }
        };
        let response = match Request::ENDPOINT {
            "retrieve-data-key" => serde_json::to_value(RetrieveKeyResponse {
                keys: ivs
                    .iter()
                    .map(|iv| RetrievedKey {
                        key_material: material(iv),
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
                                key_material: material(iv),
                            })
                        }
                    })
                    .collect(),
            }),
            "generate-data-key" => serde_json::to_value(GenerateKeyResponse {
                keys: ivs
                    .iter()
                    .map(|iv| GeneratedKey {
                        key_material: material(iv),
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

fn client(conn: &Oracle, keys_per_req: usize, concurrent_reqs: usize) -> Client<Oracle> {
    let opts = ClientOpts::new(conn.clone())
        .with_max_keys_per_req(keys_per_req)
        .unwrap()
        .with_max_concurrent_reqs(concurrent_reqs)
        .unwrap();
    Client::<Oracle>::init_opts(opts).unwrap()
}

fn client_key() -> ClientKey {
    ClientKey {
        key_id: Uuid::nil(),
        keyset: V1KeySet(ProxyKeySet::generate(
            &EncryptionKeySet::generate().unwrap(),
            &EncryptionKeySet::generate().unwrap(),
        )),
    }
}

// ------------------------------------------------------------ the operations

#[derive(Clone, Copy, Debug)]
enum Op {
    Retrieve,
    Fallible,
    Generate,
}

impl Op {
    const ALL: [Op; 3] = [Op::Retrieve, Op::Fallible, Op::Generate];
}

/// What a call returned for one spec.
enum Got {
    Key {
        iv: [u8; 16],
        key: DataKey,
        tag: Option<Vec<u8>>,
    },
    /// ZeroKMS's failure for this key.
    KeyErr(String),
    /// The key's material was not valid key material.
    BadMaterial,
}

#[derive(Debug, PartialEq)]
enum CallErr {
    Count { expected: usize, received: usize },
    BadMaterial,
    Other(String),
}

impl From<RetrieveKeyError> for CallErr {
    fn from(e: RetrieveKeyError) -> Self {
        match e {
            RetrieveKeyError::InvalidNumberOfKeys { expected, received } => {
                CallErr::Count { expected, received }
            }
            RetrieveKeyError::InvalidKeyMaterial(_) => CallErr::BadMaterial,
            e => CallErr::Other(format!("{e:?}")),
        }
    }
}

impl From<GenerateKeyError> for CallErr {
    fn from(e: GenerateKeyError) -> Self {
        match e {
            GenerateKeyError::InvalidNumberOfKeys { expected, received } => {
                CallErr::Count { expected, received }
            }
            GenerateKeyError::InvalidKeyMaterial(_) => CallErr::BadMaterial,
            e => CallErr::Other(format!("{e:?}")),
        }
    }
}

type Call<'a> = Pin<Box<dyn Future<Output = Result<Vec<Got>, CallErr>> + Send + 'a>>;

const TAG: &[u8] = b"t";

fn retrieve_payloads(
    descriptors: &[String],
    salt: u64,
) -> impl Iterator<Item = RetrieveKeyPayload<'_>> {
    descriptors
        .iter()
        .enumerate()
        .map(move |(k, d)| RetrieveKeyPayload::new(retrieve_iv(k, salt), d, TAG))
}

fn call<'a>(
    client: &'a Client<Oracle>,
    client_key: &'a ClientKey,
    op: Op,
    descriptors: &'a [String],
    salt: u64,
) -> Call<'a> {
    match op {
        Op::Retrieve => Box::pin(async move {
            let keys = client
                .retrieve_keys(
                    retrieve_payloads(descriptors, salt),
                    client_key,
                    None,
                    "token",
                    None,
                )
                .await?;
            Ok(keys
                .into_iter()
                .map(|key| Got::Key {
                    iv: key.iv,
                    key,
                    tag: None,
                })
                .collect())
        }),
        Op::Fallible => Box::pin(async move {
            let keys = client
                .retrieve_keys_fallible(
                    retrieve_payloads(descriptors, salt),
                    client_key,
                    None,
                    "token",
                    None,
                )
                .await?;
            Ok(keys
                .into_iter()
                .map(|r| match r {
                    Ok(key) => Got::Key {
                        iv: key.iv,
                        key,
                        tag: None,
                    },
                    Err(RetrieveKeyError::FailedRetrieval(m)) => Got::KeyErr(m),
                    Err(RetrieveKeyError::InvalidKeyMaterial(_)) => Got::BadMaterial,
                    Err(e) => Got::KeyErr(format!("UNEXPECTED {e:?}")),
                })
                .collect())
        }),
        Op::Generate => {
            let payloads = descriptors
                .iter()
                .map(|d| GenerateKeyPayload::new(d, Cow::Borrowed(&[])));
            Box::pin(async move {
                let keys = client
                    .generate_keys(payloads, client_key, None, "token", None)
                    .await?;
                Ok(keys
                    .into_iter()
                    .map(|k| Got::Key {
                        iv: k.key.iv,
                        tag: Some(k.tag.clone()),
                        key: k.key.clone(),
                    })
                    .collect())
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Drive {
    /// Polled by hand, one poll at a time.
    Hand(HandDrive),
    /// On tokio (current-thread, paused clock), each request taking a
    /// random time.
    Tokio,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandDrive {
    /// As a wasm guest's host: every request a step sent is answered, in a
    /// random order, before the next poll.
    GuestAtOnce,
    /// A step's requests are answered in a random order, sometimes with a
    /// poll between answers.
    GuestPollBetween,
    /// Whenever the batch waits, a random non-empty subset of the requests
    /// in flight is answered; sometimes some are answered on a yield too.
    Network,
}

#[derive(Debug, Default)]
struct Trace {
    /// How many requests each step that sent any sent.
    request_steps: Vec<usize>,
    /// Steps that sent nothing and woke themselves.
    yields: usize,
    /// Steps that sent requests and woke themselves.
    sent_and_woke: usize,
}

/// How a driven call ended.
enum Outcome {
    /// The call returned this.
    Done(Result<Vec<Got>, CallErr>),
    /// The call was pending when the case's `drop_after` came, and could
    /// still make progress, so it was dropped.
    Dropped,
    /// The call was pending and nothing would wake it: why.
    Hung(&'static str),
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

/// Drive `fut` by hand, dropping it if it is still pending after
/// `drop_after` polls.
fn drive_by_hand(
    mut fut: Call<'_>,
    conn: &Oracle,
    drive: HandDrive,
    rng: &mut SplitMix,
    drop_after: Option<usize>,
) -> (Outcome, Trace) {
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
                        trace.sent_and_woke += 1;
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
        let (sent, woke) = match polled {
            Polled::Ready(r) => return (Outcome::Done(r), trace),
            Polled::Pending { sent, woke } => (sent, woke),
        };
        // A hang is checked before the drop, so a call that hangs on the
        // poll it is dropped after is a hang, not a clean drop.
        let in_flight = conn.in_flight();
        if !woke && in_flight.is_empty() {
            return (Outcome::Hung("not woken, nothing in flight"), trace);
        }
        if drive == HandDrive::GuestAtOnce
            && !in_flight.is_empty()
            && in_flight != sent.collect::<Vec<_>>()
        {
            // In a guest, a step that waits sent everything it waits on.
            return (Outcome::Hung("waits on a request it did not send"), trace);
        }
        if drop_after.is_some_and(|d| polls >= d) {
            drop(fut);
            return (Outcome::Dropped, trace);
        }
        match drive {
            HandDrive::GuestAtOnce | HandDrive::GuestPollBetween => {
                // The host answers what the guest has asked for: this
                // step's requests, and (polling between answers) any sent
                // by a poll between answers. With none, the step woke
                // itself.
                if in_flight.is_empty() {
                    continue;
                }
                let poll_between = drive == HandDrive::GuestPollBetween;
                let mut order = in_flight;
                rng.shuffle(&mut order);
                let last = order.len() - 1;
                for (j, i) in order.into_iter().enumerate() {
                    conn.release(i);
                    if poll_between && j < last && rng.coin() {
                        match poll(&mut fut, &mut trace, &mut seen).0 {
                            Polled::Ready(r) => return (Outcome::Done(r), trace),
                            Polled::Pending { .. } => {}
                        }
                    }
                }
            }
            HandDrive::Network => {
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
        }
    }
}

/// On tokio, how long a call with no `drop_after` may take. Each request
/// takes under 500 ms, so even one at a time 7,200 of them fit. The clock is
/// paused, so once the runtime has nothing to run it jumps straight here: a
/// call that is never woken again fails at once instead of hanging the test.
const TOKIO_DEADLINE: Duration = Duration::from_secs(60 * 60);

/// Records a wake, and passes it on to the task.
struct Forward {
    woken: Arc<Woken>,
    task: Waker,
}

impl Wake for Forward {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.0.store(true, Ordering::SeqCst);
        self.task.wake_by_ref();
    }
}

/// Drive `fut` on tokio, dropping it if it is still pending at `drop_at`.
///
/// On tokio a call waits only on its requests and on its own yields. So a
/// call that is pending at the drop, has not been woken since its last poll
/// began, and has no request in flight is parked: nothing will wake it, and
/// it is a hang, not a drop. A call that loses the wake of a request still
/// in flight is not told apart from one waiting on it, and a call that only
/// parks after the drop is not seen. Without a drop, both fail at the
/// deadline.
fn drive_tokio(mut fut: Call<'_>, conn: &Oracle, drop_at: Option<Duration>) -> Outcome {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    rt.block_on(async move {
        // Whether the call has been woken since its last poll began.
        let woken = Arc::new(Woken(AtomicBool::new(false)));
        let mut deadline = std::pin::pin!(tokio::time::sleep(drop_at.unwrap_or(TOKIO_DEADLINE)));
        let result = std::future::poll_fn(|cx| {
            // The deadline comes first, so the call is judged as its last
            // poll left it: one more poll could wake a parked call.
            if deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            woken.0.store(false, Ordering::SeqCst);
            let waker = Waker::from(Arc::new(Forward {
                woken: woken.clone(),
                task: cx.waker().clone(),
            }));
            fut.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .map(Some)
        })
        .await;
        match result {
            Some(r) => Outcome::Done(r),
            None if !woken.0.load(Ordering::SeqCst) && conn.live() == 0 => {
                Outcome::Hung("not woken, nothing in flight")
            }
            None if drop_at.is_some() => Outcome::Dropped,
            None => Outcome::Hung("still pending at the deadline"),
        }
    })
}

// ------------------------------------------------------------------ the cases

/// On tokio, a case's `drop_after` counts in these.
const TOKIO_DROP_UNIT: Duration = Duration::from_millis(25);

#[derive(Debug, Clone)]
struct Case {
    op: Op,
    drive: Drive,
    keys: usize,
    keys_per_req: usize,
    concurrent_reqs: usize,
    fault: Option<Fault>,
    /// Drop the call: after this many polls by hand, or after this many
    /// [`TOKIO_DROP_UNIT`]s on tokio.
    drop_after: Option<usize>,
    seed: u64,
}

fn chunks(keys: usize, per: usize) -> usize {
    keys.div_ceil(per)
}

/// `ORACLE_OP` picks one operation; unset, every operation is drawn.
fn op() -> BoxedStrategy<Op> {
    match std::env::var("ORACLE_OP") {
        Err(std::env::VarError::NotPresent) => {
            prop_oneof![Just(Op::Retrieve), Just(Op::Fallible), Just(Op::Generate)].boxed()
        }
        Ok(only) => Just(match only.as_str() {
            "Retrieve" => Op::Retrieve,
            "Fallible" => Op::Fallible,
            "Generate" => Op::Generate,
            other => panic!("ORACLE_OP={other:?}: expected Retrieve, Fallible or Generate"),
        })
        .boxed(),
        Err(e) => panic!("ORACLE_OP: {e}"),
    }
}

/// The largest random batch size: `ORACLE_MAX_KEYS`, or 1,100.
fn max_keys() -> usize {
    std::env::var("ORACLE_MAX_KEYS").map_or(1100, |v| {
        v.parse()
            .unwrap_or_else(|_| panic!("ORACLE_MAX_KEYS={v:?}: expected a number"))
    })
}

fn case() -> impl Strategy<Value = Case> {
    let max_keys = max_keys();
    let drive = prop_oneof![
        Just(Drive::Hand(HandDrive::GuestAtOnce)),
        Just(Drive::Hand(HandDrive::GuestPollBetween)),
        Just(Drive::Hand(HandDrive::Network)),
        Just(Drive::Tokio)
    ];
    // Drawn with any chunk or key, and placed once the batch size is known.
    let fault = prop_oneof![
        4 => Just(None),
        1 => prop_oneof![
            any::<usize>().prop_map(|chunk| Fault::Fail { chunk }),
            any::<usize>().prop_map(|chunk| Fault::Short { chunk }),
            any::<usize>().prop_map(|chunk| Fault::Long { chunk }),
        ]
        .prop_map(Some),
        2 => any::<usize>().prop_map(|key| Some(Fault::BadMaterial { key })),
    ];
    let drop_after = prop_oneof![8 => Just(None), 1 => (1usize..40).prop_map(Some)];
    (
        op(),
        drive,
        1usize..=600,
        1usize..=8,
        fault,
        drop_after,
        any::<u64>(),
    )
        .prop_flat_map(
            move |(op, drive, keys_per_req, concurrent_reqs, fault, drop_after, seed)| {
                // Whole chunks, give or take a key, up to the cap.
                let max_chunks = (max_keys / keys_per_req).clamp(1, 6);
                let keys = prop_oneof![
                    3 => prop::sample::select(vec![
                        0usize, 1, 499, 500, 501, 999, 1000, 1001, 1499, 1500, 1501, 2501
                    ]),
                    2 => (1usize..=max_chunks, 0usize..=2).prop_map(move |(m, d)| {
                        (m * keys_per_req + d).saturating_sub(1).min(max_keys)
                    }),
                    2 => 0usize..=max_keys,
                ];
                keys.prop_map(move |keys| Case {
                    op,
                    drive,
                    keys,
                    keys_per_req,
                    concurrent_reqs,
                    fault: fault
                        .filter(|_| keys > 0)
                        .map(|f| f.placed(keys, keys_per_req)),
                    drop_after,
                    seed,
                })
            },
        )
}

fn run(case: &Case) -> Result<(), TestCaseError> {
    let mut rng = SplitMix(case.seed);
    let delays = (case.drive == Drive::Tokio).then(|| {
        (0..chunks(case.keys, case.keys_per_req))
            .map(|_| Duration::from_millis(rng.below(500) as u64))
            .collect()
    });
    let conn = Oracle::new(case.keys_per_req, case.fault, delays);
    let client = client(&conn, case.keys_per_req, case.concurrent_reqs);
    let client_key = client_key();
    let descriptors = descriptors(case.keys);
    let salt = rng.next();
    let fut = call(&client, &client_key, case.op, &descriptors, salt);

    let (outcome, trace) = match case.drive {
        Drive::Tokio => {
            let drop_at = case.drop_after.map(|units| TOKIO_DROP_UNIT * units as u32);
            (drive_tokio(fut, &conn, drop_at), None)
        }
        Drive::Hand(drive) => {
            let (outcome, trace) = drive_by_hand(fut, &conn, drive, &mut rng, case.drop_after);
            (outcome, Some(trace))
        }
    };

    // Whatever happened, no request future outlives the call, and no more
    // than the limit are in flight at once.
    prop_assert_eq!(conn.live(), 0, "request futures outlived the call");
    prop_assert!(
        conn.0.max_live.load(Ordering::SeqCst) <= case.concurrent_reqs,
        "more than {} requests in flight",
        case.concurrent_reqs
    );
    let result = match outcome {
        Outcome::Done(result) => result,
        Outcome::Dropped => return Ok(()),
        Outcome::Hung(why) => {
            return Err(TestCaseError::fail(format!(
                "the call hung ({why}): {trace:?}"
            )))
        }
    };

    match case.fault {
        Some(fault) if fault.fails_the_call(case.op) => {
            check_failure(case, fault, result)?;
            if let (Fault::BadMaterial { key }, Some(t)) = (fault, &trace) {
                // The call failed on the poll that derived `key`, so the
                // yields before it are those of keys `0..=key`.
                check_trace(case, t, key + 1)?;
            }
        }
        _ => {
            let got = result.map_err(|e| TestCaseError::fail(format!("the call failed: {e:?}")))?;
            check_keys(case, &conn, &client_key, salt, &got)?;
            if let Some(t) = &trace {
                check_trace(case, t, case.keys)?;
            }
        }
    }
    Ok(())
}

/// Check that a fault that fails the whole call failed it with that fault's
/// error.
fn check_failure(
    case: &Case,
    fault: Fault,
    result: Result<Vec<Got>, CallErr>,
) -> Result<(), TestCaseError> {
    let chunk_len = |c: usize| case.keys_per_req.min(case.keys - c * case.keys_per_req);
    let count = |c: usize, received: usize| CallErr::Count {
        expected: chunk_len(c),
        received,
    };
    let want = match fault {
        Fault::Fail { chunk } => {
            return match &result {
                Err(CallErr::Other(s)) => {
                    prop_assert!(
                        s.contains(&format!("injected failure of chunk {chunk}")),
                        "the wrong error: {}",
                        s
                    );
                    Ok(())
                }
                Err(e) => Err(TestCaseError::fail(format!("the wrong error: {e:?}"))),
                Ok(_) => Err(TestCaseError::fail(
                    "a failed request did not fail the call",
                )),
            }
        }
        Fault::Short { chunk } => count(chunk, chunk_len(chunk) - 1),
        Fault::Long { chunk } => count(chunk, chunk_len(chunk) + 1),
        Fault::BadMaterial { .. } => CallErr::BadMaterial,
    };
    prop_assert_eq!(result.err(), Some(want));
    Ok(())
}

/// Check the keys of a call that returned: one for every spec, each the key
/// derived from that spec's own response, and each failure the one ZeroKMS
/// gave for that spec.
fn check_keys(
    case: &Case,
    conn: &Oracle,
    client_key: &ClientKey,
    salt: u64,
    got: &[Got],
) -> Result<(), TestCaseError> {
    // Only a fallible retrieval returns with a bad key.
    let bad_key = match case.fault {
        Some(Fault::BadMaterial { key }) => Some(key),
        _ => None,
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
                Got::KeyErr(_) | Got::BadMaterial => {
                    return Err(TestCaseError::fail(format!("key {k} failed")))
                }
            },
        };
        // ZeroKMS's own failure comes first: that key has no material.
        let want_err = matches!(case.op, Op::Fallible) && fails_for(&expected_iv);
        let want_bad = !want_err && bad_key == Some(k);
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
            Got::BadMaterial => {
                prop_assert!(want_bad, "key {}'s material was not valid", k);
            }
            Got::Key { iv, key, tag } => {
                prop_assert!(!want_err, "key {} should have failed", k);
                prop_assert!(!want_bad, "key {}'s bad material made a key", k);
                prop_assert_eq!(iv, &expected_iv, "key {} has the wrong IV", k);
                prop_assert!(
                    *key == oracle_key(client_key, &expected_iv),
                    "key {} is not the key derived from its own response",
                    k
                );
                if let Op::Generate = case.op {
                    prop_assert_eq!(tag.as_deref(), Some(&tag_for(&expected_iv)[..]));
                }
            }
        }
    }
    Ok(())
}

/// Check where a call driven by hand yielded, given that it derived (or, the
/// last failing, tried to derive) its first `derived` keys.
///
/// Keys are derived in order, with a yield before every `YIELD_EVERY`th, so
/// exactly `(derived - 1) / YIELD_EVERY` yields came first: no step derives
/// keys from two runs of `YIELD_EVERY`. Each yield is a poll that woke
/// itself. Such a poll that also sent requests counts as `sent_and_woke`,
/// not as a yield: `FuturesUnordered` wakes itself when it has polled every
/// future it holds, so a step that sends can wake itself without a yield,
/// and the trace cannot tell the two apart. A poll that sends nothing
/// polls only requests that were answered, and returns at the first, so
/// only a yield wakes it.
fn check_trace(case: &Case, t: &Trace, derived: usize) -> Result<(), TestCaseError> {
    let yields = derived.saturating_sub(1) / YIELD_EVERY;
    if case.drive != Drive::Hand(HandDrive::GuestAtOnce) {
        // Here a poll can send a request and then derive up to a yield, so
        // a yield can come in a step that sent.
        prop_assert!(
            t.yields + t.sent_and_woke >= yields,
            "{} keys derived after too few yields: {:?}",
            derived,
            t
        );
        prop_assert!(
            t.yields <= yields,
            "{} keys derived after too many yields: {:?}",
            derived,
            t
        );
        return Ok(());
    }
    // As a guest's host polls it, the step loop looks at the requests
    // first, so a step that sent and woke is no yield: the yields are
    // exact.
    prop_assert_eq!(
        t.yields,
        yields,
        "{} keys derived after {} yields, not {}: {:?}",
        derived,
        t.yields,
        yields,
        t
    );
    if derived == case.keys {
        // Every step but the last sends as many requests as the
        // concurrency allows.
        let n = chunks(case.keys, case.keys_per_req);
        let c = case.concurrent_reqs;
        let mut want = vec![c; n / c];
        if !n.is_multiple_of(c) {
            want.push(n % c);
        }
        prop_assert_eq!(&t.request_steps, &want, "windows: {:?}", t);
    }
    Ok(())
}

proptest! {
    // See the module documentation for the environment variables that size
    // the run.
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn every_spec_gets_the_key_derived_from_its_own_response(case in case()) {
        run(&case)?;
    }
}

/// A call that completes on the poll it would be dropped after is returned,
/// so its result is checked.
#[test]
fn a_call_that_completes_on_its_last_poll_before_the_drop_is_returned() {
    let conn = Oracle::new(10, None, None);
    let client = client(&conn, 10, 1);
    let client_key = client_key();
    let fut = call(&client, &client_key, Op::Retrieve, &[], 7);
    let (outcome, _) = drive_by_hand(
        fut,
        &conn,
        HandDrive::GuestAtOnce,
        &mut SplitMix(0),
        Some(1),
    );
    assert!(matches!(outcome, Outcome::Done(Ok(ref keys)) if keys.is_empty()));
}

/// A call that is never woken again is a hang under every driver, even on
/// the poll (or at the time) it would be dropped after, and on tokio with
/// no drop it fails rather than waiting forever.
#[test]
fn a_call_that_is_never_woken_hangs_under_every_driver() {
    let never = || -> Call<'static> { Box::pin(std::future::pending()) };
    let conn = Oracle::new(10, None, None);
    for drive in [
        HandDrive::GuestAtOnce,
        HandDrive::GuestPollBetween,
        HandDrive::Network,
    ] {
        for drop_after in [None, Some(1)] {
            let (outcome, _) = drive_by_hand(never(), &conn, drive, &mut SplitMix(0), drop_after);
            assert!(
                matches!(outcome, Outcome::Hung(_)),
                "{drive:?}, drop_after {drop_after:?}: not a hang"
            );
        }
    }
    for drop_at in [None, Some(TOKIO_DROP_UNIT)] {
        assert!(
            matches!(drive_tokio(never(), &conn, drop_at), Outcome::Hung(_)),
            "tokio, drop at {drop_at:?}: not a hang"
        );
    }
}

/// On tokio, a call waiting on its requests when it is dropped is a drop,
/// not a hang.
#[test]
fn a_call_waiting_on_its_requests_on_tokio_is_dropped() {
    let conn = Oracle::new(10, None, Some(vec![Duration::from_millis(400); 10]));
    let client = client(&conn, 10, 3);
    let client_key = client_key();
    let descriptors = descriptors(100);
    let fut = call(&client, &client_key, Op::Retrieve, &descriptors, 7);
    assert!(matches!(
        drive_tokio(fut, &conn, Some(TOKIO_DROP_UNIT)),
        Outcome::Dropped
    ));
    assert_eq!(conn.live(), 0, "request futures outlived the call");
}

/// Every fault, at the first, a middle and the last chunk or key, on every
/// operation and driver. The proptest gives each of `Fail`, `Short` and
/// `Long` about one case in 21, so a given operation, driver and fault can
/// go a whole run without one. 70 keys at 25 a request is three requests,
/// the last one short, and one yield.
#[test]
fn every_fault_on_every_operation_and_driver() {
    let (keys, keys_per_req) = (70, 25);
    let mut faults = vec![None];
    for chunk in 0..3 {
        faults.push(Some(Fault::Fail { chunk }));
        faults.push(Some(Fault::Short { chunk }));
        faults.push(Some(Fault::Long { chunk }));
    }
    for key in [0, 40, keys - 1] {
        faults.push(Some(Fault::BadMaterial { key }));
    }
    let mut failures = Vec::new();
    for op in Op::ALL {
        for drive in [
            Drive::Hand(HandDrive::GuestAtOnce),
            Drive::Hand(HandDrive::GuestPollBetween),
            Drive::Hand(HandDrive::Network),
            Drive::Tokio,
        ] {
            for (seed, &fault) in faults.iter().enumerate() {
                let case = Case {
                    op,
                    drive,
                    keys,
                    keys_per_req,
                    concurrent_reqs: 2,
                    fault,
                    drop_after: None,
                    seed: seed as u64,
                };
                if let Err(e) = run(&case) {
                    failures.push(format!("{case:?}: {e}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Dropping the call while every request of a window is in flight drops
/// every request future, on each operation.
#[test]
fn dropping_the_call_drops_every_request_in_flight() {
    for op in Op::ALL {
        for concurrent in [1, 3, 8] {
            let conn = Oracle::new(10, None, None);
            let client = client(&conn, 10, concurrent);
            let client_key = client_key();
            let descriptors = descriptors(100);
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

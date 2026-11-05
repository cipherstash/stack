//! Capture a [`PrfValue`] now, derive it later.
//!
//! A keyset whose index key lasts one settle (ADR-0009, wrapped data keys)
//! gives the cipher no PRF when the term is built: the key is loaded inside
//! the settle. The source value of a term may borrow (`&str`), so it cannot
//! wait for the settle itself. [`Program::capture`] therefore runs the value
//! against a recording backend during the synchronous build. The recording
//! holds the exact calls the value made — every leaf's bytes, encoding and
//! fully derived context, and the shape of every sequence and map — and
//! owns all of it. Inside the settle, [`Program`] is itself a [`PrfValue`]
//! that replays those calls into the real PRF.
//!
//! The replay gives the same blocks as running the value against the PRF
//! directly, because it makes the same backend calls with the same
//! arguments: a leaf is `prf_bytes_vec(bytes, encoding, context)`, and a
//! sequence or a map is the backend's own driver over the replayed
//! children. The one assumption is that a value passes the visitor it is
//! given through unchanged, as every `vitaminc-prf` implementation does: the
//! recording does not keep a visitor of the value's own. The tests compare
//! the two paths for every shape.

use std::any::Any;
use std::borrow::Cow;
use std::marker::PhantomData;

use vitaminc_prf::{
    Context, IntoPrfContext, MapPrf, Prf, PrfBuildError, PrfEncoding, PrfError, PrfValue,
    PrfVisitor, PrfVisitorError, SeqPrf,
};
use vitaminc_protected::Protected;

type PassthroughValue = Box<dyn Any + Send + 'static>;

/// The calls a [`PrfValue`] made, owned, ready to replay into a PRF.
pub(crate) enum Program {
    /// `prf_bytes_vec(data, encoding, context)`.
    Leaf {
        data: Protected<Vec<u8>>,
        encoding: PrfEncoding,
        context: Context<'static>,
    },
    /// A sequence of children, in order.
    Seq(Vec<Item>),
    /// A map of children, in order.
    Map(Vec<Entry>),
    /// `prf_none(context)`.
    Absent(Context<'static>),
    /// A passthrough value.
    Passthrough(PassthroughValue),
    /// The value failed to build (for example a duplicate map key).
    Failed(Failure),
}

/// One element of a captured sequence.
pub(crate) enum Item {
    Value(Program),
    Passthrough(PassthroughValue),
}

/// One entry of a captured map.
pub(crate) enum Entry {
    Value(String, Program),
    Passthrough(String, PassthroughValue),
}

/// A failure the recording keeps, to replay as the PRF's own.
pub(crate) enum Failure {
    Build(PrfBuildError),
    Visitor(PrfVisitorError),
}

impl Program {
    /// Record `value` under `context`.
    pub(crate) fn capture<'a, T: PrfValue>(value: T, context: impl IntoPrfContext<'a>) -> Self {
        value
            .prf_visit_with_context(&Capture, context, Recorded)
            .program
    }
}

/// Replay the recorded calls into `prf`. The context given here is not
/// used: every leaf carries the context it was recorded under.
impl PrfValue for Program {
    fn prf_visit_with_context<'a, P, V, C>(
        self,
        prf: &P,
        _context: C,
        visitor: V,
    ) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        match self {
            Program::Leaf {
                data,
                encoding,
                context,
            } => prf.prf_bytes_vec(data, encoding, context, visitor),
            Program::Seq(items) => {
                let seq = items
                    .into_iter()
                    .fold(prf.prf_seq(None), |seq, item| match item {
                        Item::Value(program) => seq.prf_next(program, Context::empty()),
                        Item::Passthrough(value) => seq.passthrough_next_boxed(value),
                    });
                seq.end(visitor)
            }
            Program::Map(entries) => {
                let map = entries
                    .into_iter()
                    .fold(prf.prf_map(None), |map, entry| match entry {
                        Entry::Value(key, program) => map.prf_entry(key, program, Context::empty()),
                        Entry::Passthrough(key, value) => map.passthrough_entry_boxed(key, value),
                    });
                map.end(visitor)
            }
            Program::Absent(context) => prf.prf_none(context, visitor),
            Program::Passthrough(value) => prf.passthrough_boxed(value, visitor),
            Program::Failed(Failure::Build(error)) => prf.failure(PrfError::Build(error)),
            Program::Failed(Failure::Visitor(error)) => prf.failure(PrfError::Visitor(error)),
        }
    }
}

/// The recording backend. Its blocks are never produced.
pub(crate) struct Capture;

/// The visitor the recording passes in. Never called: the recording
/// produces no blocks.
struct Recorded;

impl PrfVisitor<[u8; 32], PassthroughValue> for Recorded {
    type Value = ();
}

/// The recording returned for any call: the program, and no value.
pub(crate) struct Captured<T> {
    program: Program,
    _value: PhantomData<fn() -> T>,
}

impl<T> Captured<T> {
    fn of(program: Program) -> Self {
        Self {
            program,
            _value: PhantomData,
        }
    }
}

/// A recording is not a derivation: awaiting one is an error, and nothing
/// in this crate awaits one.
impl<T> std::future::IntoFuture for Captured<T> {
    type Output = Result<T, PrfError<NotDerived>>;
    type IntoFuture = std::future::Ready<Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(Err(PrfError::Backend(NotDerived)))
    }
}

/// A recording was awaited as if it were a derivation.
#[derive(Debug, thiserror::Error)]
#[error("a captured PRF value was awaited before it was derived")]
pub(crate) struct NotDerived;

impl Prf for Capture {
    type Block = [u8; 32];
    type BackendError = NotDerived;
    type Passthrough = PassthroughValue;
    type SeqPrf<'a> = CaptureSeq;
    type MapPrf<'a> = CaptureMap;
    type Ok<T>
        = Captured<T>
    where
        T: Send + 'static;

    fn prf_bytes_vec<V>(
        &self,
        data: Protected<Vec<u8>>,
        encoding: PrfEncoding,
        context: Context<'static>,
        _visitor: V,
    ) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        Captured::of(Program::Leaf {
            data,
            encoding,
            context,
        })
    }

    fn prf_seq(&self, size_hint: Option<usize>) -> Self::SeqPrf<'_> {
        CaptureSeq {
            items: Vec::with_capacity(size_hint.unwrap_or(0)),
        }
    }

    fn prf_map(&self, size_hint: Option<usize>) -> Self::MapPrf<'_> {
        CaptureMap {
            entries: Vec::with_capacity(size_hint.unwrap_or(0)),
            pending_key: None,
            error: None,
        }
    }

    fn prf_none<V>(&self, context: Context<'static>, _visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        Captured::of(Program::Absent(context))
    }

    fn passthrough<V>(&self, value: Self::Passthrough, _visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        Captured::of(Program::Passthrough(value))
    }

    fn passthrough_boxed<V>(&self, value: PassthroughValue, visitor: V) -> Self::Ok<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        self.passthrough(value, visitor)
    }

    fn failure<T>(&self, error: PrfError<Self::BackendError>) -> Self::Ok<T>
    where
        T: Send + 'static,
    {
        Captured::of(Program::Failed(match error {
            PrfError::Build(error) => Failure::Build(error),
            PrfError::Visitor(error) => Failure::Visitor(error),
            PrfError::Backend(NotDerived) => Failure::Visitor(PrfVisitorError::InvalidValue),
        }))
    }
}

/// The recording sequence driver.
pub(crate) struct CaptureSeq {
    items: Vec<Item>,
}

impl SeqPrf for CaptureSeq {
    type Prf = Capture;
    type Block = [u8; 32];
    type BackendError = NotDerived;
    type Passthrough = PassthroughValue;

    fn prf_next<T>(mut self, value: T, context: Context<'static>) -> Self
    where
        T: PrfValue,
    {
        self.items
            .push(Item::Value(Program::capture(value, context)));
        self
    }

    fn passthrough_next(mut self, value: Self::Passthrough) -> Self {
        self.items.push(Item::Passthrough(value));
        self
    }

    fn passthrough_next_boxed(self, value: PassthroughValue) -> Self {
        self.passthrough_next(value)
    }

    fn end<V>(self, _visitor: V) -> Captured<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        Captured::of(Program::Seq(self.items))
    }
}

/// The recording map driver. It records each value under the context the
/// PRF's own driver derives for its entry, and the build errors the PRF's
/// own driver reports, so the replay meets the same map.
pub(crate) struct CaptureMap {
    entries: Vec<Entry>,
    pending_key: Option<String>,
    error: Option<PrfBuildError>,
}

impl CaptureMap {
    fn fail(&mut self, error: PrfBuildError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn has_key(&self, key: &str) -> bool {
        self.entries.iter().any(|entry| match entry {
            Entry::Value(existing, _) | Entry::Passthrough(existing, _) => existing == key,
        })
    }
}

impl MapPrf for CaptureMap {
    type Prf = Capture;
    type Block = [u8; 32];
    type BackendError = NotDerived;
    type Passthrough = PassthroughValue;

    fn prf_key<K>(mut self, key: K) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        if self.pending_key.is_some() {
            self.fail(PrfBuildError::KeyWithoutValue);
        } else if self.error.is_none() {
            self.pending_key = Some(key.into().into_owned());
        }
        self
    }

    fn prf_value<T>(mut self, value: T, context: Context<'static>) -> Self
    where
        T: PrfValue,
    {
        let Some(key) = self.pending_key.take() else {
            self.fail(PrfBuildError::ValueWithoutKey);
            return self;
        };
        if self.error.is_some() {
            return self;
        }
        if self.has_key(&key) {
            self.fail(PrfBuildError::DuplicateKey);
            return self;
        }
        let context = context.for_map_entry(&key);
        let program = Program::capture(value, context);
        self.entries.push(Entry::Value(key, program));
        self
    }

    fn passthrough_entry<K>(mut self, key: K, value: Self::Passthrough) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        if self.pending_key.is_some() {
            self.fail(PrfBuildError::KeyWithoutValue);
        } else if self.error.is_none() {
            let key = key.into().into_owned();
            if self.has_key(&key) {
                self.fail(PrfBuildError::DuplicateKey);
            } else {
                self.entries.push(Entry::Passthrough(key, value));
            }
        }
        self
    }

    fn passthrough_entry_boxed<K>(self, key: K, value: PassthroughValue) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        self.passthrough_entry(key, value)
    }

    fn end<V>(mut self, _visitor: V) -> Captured<V::Value>
    where
        V: PrfVisitor<Self::Block, Self::Passthrough>,
    {
        if self.pending_key.is_some() {
            self.fail(PrfBuildError::DanglingKey);
        }
        match self.error {
            Some(error) => Captured::of(Program::Failed(Failure::Build(error))),
            None => Captured::of(Program::Map(self.entries)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use vitaminc_hmac::HmacSha256Prf;
    use vitaminc_prf::{PrfKeyInit, ResolvedPrf, ResolvedVisitor};

    use super::*;

    fn prf() -> HmacSha256Prf {
        HmacSha256Prf::new(Protected::new([42u8; 32]))
    }

    /// The blocks of a resolved tree, depth first, with the structure
    /// marked, so two trees compare by value.
    fn flatten(node: ResolvedPrf<[u8; 32], PassthroughValue>, out: &mut Vec<String>) {
        match node {
            ResolvedPrf::Block(block) => out.push(format!("{block:?}")),
            ResolvedPrf::Sequence(items) => {
                out.push("[".into());
                for item in items {
                    flatten(item, out);
                }
                out.push("]".into());
            }
            ResolvedPrf::Map(entries) => {
                out.push("{".into());
                for (key, value) in entries {
                    out.push(key);
                    flatten(value, out);
                }
                out.push("}".into());
            }
            ResolvedPrf::Absent => out.push("absent".into()),
            ResolvedPrf::Passthrough(value) => {
                out.push(format!("pass:{:?}", value.downcast::<u32>().ok()))
            }
        }
    }

    fn direct<T: PrfValue>(value: T) -> Vec<String> {
        let mut out = Vec::new();
        let tree = value
            .prf_visit_with_context(&prf(), Context::pae(&[b"ctx"]), ResolvedVisitor)
            .into_result()
            .unwrap();
        flatten(tree, &mut out);
        out
    }

    fn replayed<T: PrfValue>(value: T) -> Vec<String> {
        let program = Program::capture(value, Context::pae(&[b"ctx"]));
        let mut out = Vec::new();
        let tree = program
            .prf_visit_with_context(&prf(), Context::empty(), ResolvedVisitor)
            .into_result()
            .unwrap();
        flatten(tree, &mut out);
        out
    }

    macro_rules! same {
        ($($value:expr),+ $(,)?) => {$(
            assert_eq!(direct($value), replayed($value), "{}", stringify!($value));
        )+};
    }

    #[test]
    fn a_replay_derives_what_the_value_derives() {
        same!(
            "text",
            String::from("text"),
            &b"bytes"[..],
            vec![1u8, 2, 3],
            [7u8; 4],
            17u32,
            -3i64,
            u128::MAX,
            Some(5u16),
            None::<u16>,
            vec![String::from("a"), String::from("b")],
            vec![vec![1u32, 2], vec![]],
            vec![Some(1u8), None],
            BTreeMap::from([("b", 2u8), ("a", 1u8)]),
            HashMap::from([("y", vec![1u32]), ("x", vec![2u32, 3])]),
            Protected::new(String::from("secret")),
            vitaminc_prf::Passthrough::new(9u32),
        );
    }

    /// A map error the PRF's own driver reports is reported by the replay.
    #[test]
    fn a_map_build_error_replays_as_the_same_error() {
        struct Duplicate;
        impl PrfValue for Duplicate {
            fn prf_visit_with_context<'a, P, V, C>(
                self,
                prf: &P,
                context: C,
                visitor: V,
            ) -> P::Ok<V::Value>
            where
                P: Prf,
                V: PrfVisitor<P::Block, P::Passthrough>,
                C: IntoPrfContext<'a>,
            {
                let context = context.into_prf_context().into_owned();
                prf.prf_map(None)
                    .prf_entry("k", 1u8, context.clone())
                    .prf_entry("k", 2u8, context)
                    .end(visitor)
            }
        }
        let direct = Duplicate
            .prf_visit_with_context(&prf(), Context::empty(), ResolvedVisitor)
            .into_result();
        let replayed = Program::capture(Duplicate, Context::empty())
            .prf_visit_with_context(&prf(), Context::empty(), ResolvedVisitor)
            .into_result();
        assert!(matches!(
            direct,
            Err(PrfError::Build(PrfBuildError::DuplicateKey))
        ));
        assert!(matches!(
            replayed,
            Err(PrfError::Build(PrfBuildError::DuplicateKey))
        ));
    }

    #[test]
    fn a_recording_is_not_a_derivation() {
        let captured: Captured<u8> = Captured::of(Program::Absent(Context::empty()));
        let result = futures_lite_block_on(std::future::IntoFuture::into_future(captured));
        assert!(matches!(result, Err(PrfError::Backend(NotDerived))));
    }

    /// Poll a ready future once.
    fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => panic!("a ready future was pending"),
        }
    }
}

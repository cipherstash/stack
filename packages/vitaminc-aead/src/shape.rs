//! The rules a value's shape must keep to be encrypted, for every sink that
//! has to agree with encryption on which values it accepts.
//!
//! [`EncryptSink`](crate::EncryptSink) keeps these rules as it plans a
//! value. A sink that walks a value without encrypting it, such as the
//! terms sink in vitaminc-normalize, keeps the same ones through this
//! module, so it refuses exactly the values encryption refuses, for the
//! same [`Unencryptable`] reason and at the same [`Path`]:
//!
//! - nothing may sit deeper than [`MAX_DEPTH`] ([`scalar`], [`container`],
//!   [`frame_passthrough`]);
//! - a scalar must be a valid value of its logical type ([`scalar`]);
//! - a passthrough subtree must frame ([`frame_passthrough`]);
//! - a map may not give a key twice ([`MapRules::entry`]);
//! - a source may not drop a child sink without writing a value into it
//!   ([`SeqRules`], [`MapRules`]);
//! - a container with children must seal at least one of them, because a
//!   passthrough authenticates nothing and an all-passthrough container
//!   would decrypt under any AAD ([`SeqRules::end`], [`MapRules::end`]).
//!
//! A node's place is a chain of [`Locate`] links to its parents, so a walk
//! carries no path. A [`Refusal`]'s path is built from the chain only when
//! a value is refused.

use std::collections::HashMap;

use vitaminc_protected::{OpaqueDebug, Protected};

use crate::frame::{to_frame_at, FrameWriteError, MAX_DEPTH};
use crate::plaintext::{Error, Logical, Path, Physical, Plaintext, Step};

/// Why a value cannot be encrypted as given.
///
/// `#[non_exhaustive]`, so a rule can be added without breaking a caller.
/// No reason carries any part of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unencryptable {
    /// A map gave the same key twice.
    #[error("duplicate key")]
    DuplicateKey,
    /// A sequence has elements but seals none of them: every element is a
    /// passthrough, which authenticates nothing.
    #[error("sequence has nothing sealed")]
    SequenceHasNothingSealed,
    /// A map has entries but seals none of them.
    #[error("map has nothing sealed")]
    MapHasNothingSealed,
    /// A scalar is not a valid value of its logical type.
    #[error("value is not valid for its logical type")]
    InvalidValue,
    /// A scalar cannot be written as a leaf.
    #[error("value cannot be written as a leaf")]
    Unwritable,
    /// A passthrough subtree cannot be framed.
    #[error("passthrough subtree cannot be framed")]
    UnframablePassthrough,
    /// The source took an element or entry sink and dropped it without
    /// writing a value into it.
    #[error("a child sink was dropped without a value")]
    DroppedChild,
    /// The value nests deeper than [`MAX_DEPTH`].
    #[error("value nests deeper than {MAX_DEPTH} levels")]
    TooDeep,
}

/// A value refused for its shape: the rule it broke, and where.
///
/// `Display` shows only the reason, because the path can hold map keys and
/// map keys can be user data. `Debug` shows the reason and the path's
/// shape, with every key masked. Read the path with
/// [`path`](Refusal::path).
#[derive(Clone, OpaqueDebug, thiserror::Error)]
#[error("{reason}")]
pub struct Refusal {
    #[non_sensitive]
    reason: Unencryptable,
    #[non_sensitive]
    path: Path,
}

impl Refusal {
    /// The rule the value broke.
    pub fn reason(&self) -> Unencryptable {
        self.reason
    }

    /// Where the value was refused, from the root: the scalar or container
    /// that broke the rule, or for [`Unencryptable::DuplicateKey`] the
    /// entry under the repeated key. For a passthrough subtree that cannot
    /// be framed, the passthrough itself.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A node's place in the value, as a chain of links to its parents.
///
/// Each child sink holds a borrow of its parent container's place and its
/// own step, so the walk carries no path. One is built only when it is
/// needed, by following the links up to the root.
pub trait Locate {
    /// Append the steps from the root to this node.
    fn locate(&self, steps: &mut Vec<Step>);
}

/// The place of the value's root, which has no steps.
pub struct Root;

impl Locate for Root {
    fn locate(&self, _: &mut Vec<Step>) {}
}

/// Refuse the node at `at` for `reason`.
pub(crate) fn refuse(at: &dyn Locate, reason: Unencryptable) -> Refusal {
    refuse_under(at, None, reason)
}

/// Refuse the node at `at`, or its child at `step`, for `reason`.
fn refuse_under(at: &dyn Locate, step: Option<Step>, reason: Unencryptable) -> Refusal {
    let mut steps = Vec::new();
    at.locate(&mut steps);
    steps.extend(step);
    Refusal {
        reason,
        path: Path::new(steps),
    }
}

/// Refuse a node more than [`MAX_DEPTH`] below the root, as the transport
/// decoder refuses it.
fn depth(depth: usize, at: &dyn Locate) -> Result<(), Refusal> {
    if depth > MAX_DEPTH {
        return Err(refuse(at, Unencryptable::TooDeep));
    }
    Ok(())
}

/// The rules for a scalar `depth` levels below the root: not too deep, and
/// a valid value of its logical type, if it has one.
///
/// # Errors
///
/// [`Unencryptable::TooDeep`], then [`Unencryptable::InvalidValue`], at
/// `at`.
pub fn scalar(
    depth: usize,
    ty: Option<Logical>,
    value: &Physical<'_>,
    at: &dyn Locate,
) -> Result<(), Refusal> {
    self::depth(depth, at)?;
    if ty.is_some_and(|ty| !ty.admits(value)) {
        return Err(refuse(at, Unencryptable::InvalidValue));
    }
    Ok(())
}

/// The rule for opening a sequence or map `depth` levels below the root:
/// not too deep. What it holds is [`SeqRules`] or [`MapRules`].
///
/// # Errors
///
/// [`Unencryptable::TooDeep`] at `at`.
pub fn container(depth: usize, at: &dyn Locate) -> Result<(), Refusal> {
    self::depth(depth, at)
}

/// Frame a passthrough subtree `depth` levels below the root, as
/// encryption frames it. The frame's root sits one level below the
/// passthrough, as the transport decoder counts it.
///
/// # Errors
///
/// A source's own failure inside the subtree as `E::source`. Otherwise
/// `refused` of a [`Refusal`] at `at`: [`Unencryptable::TooDeep`] if the
/// passthrough or anything in it is too deep, or
/// [`Unencryptable::UnframablePassthrough`] if the subtree breaks a rule
/// of the frame.
pub fn frame_passthrough<P, E>(
    value: P,
    depth: usize,
    at: &dyn Locate,
    refused: impl FnOnce(Refusal) -> E,
) -> Result<Protected<Vec<u8>>, E>
where
    P: Plaintext,
    E: Error,
{
    if let Err(refusal) = self::depth(depth, at) {
        return Err(refused(refusal));
    }
    to_frame_at(value, depth + 1).map_err(|e| match e {
        FrameWriteError::Source(e) => E::source(e),
        FrameWriteError::TooDeep => refused(refuse(at, Unencryptable::TooDeep)),
        _ => refused(refuse(at, Unencryptable::UnframablePassthrough)),
    })
}

/// How a container's children have gone: how many were handed a sink, how
/// many have put a node, and whether any of those sealed something.
#[derive(Default)]
struct Children {
    handed: usize,
    settled: usize,
    sealed: bool,
}

impl Children {
    /// Refuse the container at `at` if a child sink was dropped without a
    /// value: each one handed out must have settled by the next child or
    /// the end.
    fn settled(&self, at: &dyn Locate) -> Result<(), Refusal> {
        if self.settled != self.handed {
            return Err(refuse(at, Unencryptable::DroppedChild));
        }
        Ok(())
    }

    /// Hand out the next child, and return its position.
    fn hand(&mut self) -> usize {
        let position = self.handed;
        self.handed += 1;
        position
    }

    fn end(&self, at: &dyn Locate, nothing_sealed: Unencryptable) -> Result<(), Refusal> {
        self.settled(at)?;
        if self.handed > 0 && !self.sealed {
            return Err(refuse(at, nothing_sealed));
        }
        Ok(())
    }
}

/// The rules a sequence keeps for its elements: no element sink dropped
/// without a value, and, if it has any elements, at least one sealed.
#[derive(Default)]
pub struct SeqRules(Children);

impl SeqRules {
    /// A sequence with no elements yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Before handing out the next element's sink. The returned [`Settle`]
    /// says how the element ended.
    ///
    /// # Errors
    ///
    /// [`Unencryptable::DroppedChild`] at the sequence, `at`, if the last
    /// element's sink was dropped without a value.
    pub fn element(&mut self, at: &dyn Locate) -> Result<Settle<'_>, Refusal> {
        self.0.settled(at)?;
        Ok(Settle {
            step: Under::Element(self.0.hand()),
            children: &mut self.0,
        })
    }

    /// At the sequence's end.
    ///
    /// # Errors
    ///
    /// [`Unencryptable::DroppedChild`], then
    /// [`Unencryptable::SequenceHasNothingSealed`], at the sequence, `at`.
    pub fn end(&self, at: &dyn Locate) -> Result<(), Refusal> {
        self.0.end(at, Unencryptable::SequenceHasNothingSealed)
    }
}

/// The rules a map keeps for its entries: [`SeqRules`]' rules, and no key
/// given twice.
///
/// It keeps one copy of each key, which is what checking for a repeat
/// exactly costs.
#[derive(Default)]
pub struct MapRules {
    /// Every key handed an entry sink, and its entry's position.
    keys: HashMap<String, usize>,
    children: Children,
}

impl MapRules {
    /// A map with no entries yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Before handing out the sink for the entry under `key`. The returned
    /// [`Settle`] says how the entry ended.
    ///
    /// # Errors
    ///
    /// [`Unencryptable::DroppedChild`] at the map, `at`, if the last
    /// entry's sink was dropped without a value, then
    /// [`Unencryptable::DuplicateKey`] at the entry under `key`.
    pub fn entry(&mut self, key: &str, at: &dyn Locate) -> Result<Settle<'_>, Refusal> {
        let Self { keys, children } = self;
        children.settled(at)?;
        if keys.contains_key(key) {
            let step = Step::Key(key.to_owned());
            return Err(refuse_under(at, Some(step), Unencryptable::DuplicateKey));
        }
        keys.insert(key.to_owned(), children.hand());
        Ok(Settle {
            step: Under::Entry(keys.get_key_value(key).map(|(key, _)| key.as_str())),
            children,
        })
    }

    /// At the map's end.
    ///
    /// # Errors
    ///
    /// [`Unencryptable::DroppedChild`], then
    /// [`Unencryptable::MapHasNothingSealed`], at the map, `at`.
    pub fn end(&self, at: &dyn Locate) -> Result<(), Refusal> {
        self.children.end(at, Unencryptable::MapHasNothingSealed)
    }

    /// Each key, moved out, with its entry's position.
    pub(crate) fn into_keys(self) -> impl Iterator<Item = (String, usize)> {
        self.keys.into_iter()
    }
}

/// The step from a container to the child a [`Settle`] belongs to.
enum Under<'r> {
    Element(usize),
    /// Borrowed from the map's keys, so always there: [`MapRules::entry`]
    /// inserts the key before it lends it.
    Entry(Option<&'r str>),
}

/// One child's hold on its container's rules: the child says how it ended
/// by consuming it. A child dropped without either is refused at the next
/// child or the end.
pub struct Settle<'r> {
    step: Under<'r>,
    children: &'r mut Children,
}

impl Settle<'_> {
    /// The child put a sealed node: a scalar, a container, or an empty
    /// container's marker.
    pub fn sealed(self) {
        self.children.settled += 1;
        self.children.sealed = true;
    }

    /// The child put a passthrough, which seals nothing.
    pub fn passthrough(self) {
        self.children.settled += 1;
    }

    /// Append the steps to this child from the root, given its container's
    /// place.
    pub(crate) fn locate_under(&self, parent: &dyn Locate, steps: &mut Vec<Step>) {
        parent.locate(steps);
        match self.step {
            Under::Element(index) => steps.push(Step::Index(index)),
            Under::Entry(key) => steps.extend(key.map(|key| Step::Key(key.to_owned()))),
        }
    }
}

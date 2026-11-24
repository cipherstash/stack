//! Projection of the generic [`CipherText`] container onto JS structures.
//!
//! The container has **no canonical byte representation** — only the sealed
//! `Leaf` type does (see the container docs). Crossing the FFI boundary, the
//! tree is projected onto plain JS values that the application can hold,
//! store (e.g. as JSONB with its own Buffer encoding policy), and pass back
//! for decryption:
//!
//! ```text
//! Single(leaf)        ↦ { t: "ct",   v: Buffer }
//! Sequence(...)       ↦ { t: "seq",  v: [node, ...] }
//! EmptySequence(leaf) ↦ { t: "eseq", v: Buffer }
//! Map(entries)        ↦ { t: "map",  v: { key: node, ... } }
//! EmptyMap(leaf)      ↦ { t: "emap", v: Buffer }
//! Passthrough(p)      ↦ { t: "pt",   v: <P's own JS projection> }
//! ```
//!
//! The passthrough payload of the sink-based tree ([`Node`]) is a
//! [`PassthroughFrame`], which projects onto the plain JavaScript value the
//! frame describes, and reads back by walking the JavaScript value into a
//! frame.
//!
//! The `t`/`v` node shape is an **in-memory/application-side convenience**:
//! it is what a JS application holds between `encrypt` and `decrypt` calls,
//! and what an application that manages its own storage may choose to
//! persist. Database interop across languages is *not* this projection's
//! job — that is the role of the EQL layer, which owns the durable
//! database format and treats the sealed leaves opaquely. Within that
//! scope the node shape should still change only deliberately (apps may
//! have persisted it), but it is not a cross-language wire commitment;
//! only the leaf byte format (the leaf codec in `vitaminc-aead`) is frozen.
//!
//! [`Node`]: vitaminc_aead::Node

use napi::bindgen_prelude::{
    Array, Buffer, BufferSlice, FromNapiValue, JsObjectValue, JsValue, Object, ToNapiValue,
    TypeName, Unknown,
};
use napi::{sys, Env, Error, Result, Status, ValueType};
use vitaminc_aead::{CipherText, Frame, PassthroughFrame};
use vitaminc_protected::Controlled;

use crate::js::{
    define_own_properties, depth_error, eager_capacity, forbidden_key, get_own,
    get_property_unknown, new_array, own_enumerable_keys, own_property, MAX_DEPTH,
};
use crate::js_builder::JsBuilder;
use crate::js_ref::{frame_error, JsRef};

const T_CIPHERTEXT: &str = "ct";
const T_SEQ: &str = "seq";
const T_EMPTY_SEQ: &str = "eseq";
const T_MAP: &str = "map";
const T_EMPTY_MAP: &str = "emap";
const T_PASSTHROUGH: &str = "pt";

/// Newtype carrying a [`CipherText`] across the NAPI boundary using the
/// node projection documented at the module level.
///
/// `Leaf` needs only byte-level accessors (`AsRef<[u8]>` out,
/// `From<Vec<u8>>` in); the passthrough payload `P` converts through
/// [`NapiPassthrough`], implemented for [`PassthroughFrame`] (the
/// sink-based tree's payload) and `()`. A cipher whose passthrough
/// payload type is something else needs its own `NapiPassthrough` impl.
pub struct JsCipherText<Leaf, P>(pub CipherText<Leaf, P>);

/// A ciphertext passthrough payload's conversion to and from JS.
///
/// A payload shares the tree's 128-level nesting limit, as it does in the
/// transport encoding, rather than starting a fresh count: it sits one level
/// below its passthrough node.
pub trait NapiPassthrough: Sized {
    /// Build the payload's JS value. [`JsCipherText`] calls this only once
    /// [`exceeds_depth`](Self::exceeds_depth) has passed for the payload's
    /// position, which bounds any recursion here.
    fn to_js(self, env: &Env) -> Result<Unknown<'_>>;
    /// Read the payload from its JS value at `depth`, refusing anything that
    /// nests past the limit.
    fn from_js(value: Unknown<'_>, depth: usize) -> Result<Self>;
    /// Whether the payload, placed at `depth`, nests past the limit.
    fn exceeds_depth(&self, depth: usize) -> bool;
    /// Drop the payload without recursing once per nesting level, for a tree
    /// refused as too deep.
    fn drop_flat(self);
}

/// No payload: projects to `undefined`, which is all it accepts back. It is
/// a single node, so it is too deep only past the limit itself.
impl NapiPassthrough for () {
    fn to_js(self, env: &Env) -> Result<Unknown<'_>> {
        ().into_unknown(env)
    }

    fn from_js(value: Unknown<'_>, depth: usize) -> Result<Self> {
        if depth > MAX_DEPTH {
            return Err(depth_error());
        }
        // napi-rs's own `()` conversion accepts any value; check instead.
        if value.get_type()? == ValueType::Undefined {
            Ok(())
        } else {
            Err(shape_error())
        }
    }

    fn exceeds_depth(&self, depth: usize) -> bool {
        depth > MAX_DEPTH
    }

    fn drop_flat(self) {}
}

/// A frame payload projects onto the JavaScript value it describes, and
/// reads back as the frame of the JavaScript value, walked at the
/// payload's depth so the tree's limit counts the whole structure.
impl NapiPassthrough for PassthroughFrame {
    fn to_js(self, env: &Env) -> Result<Unknown<'_>> {
        // `exceeds_depth` has passed for this payload, which validated it.
        let frame = Frame::parse(&self.0).map_err(|_| shape_error())?;
        JsBuilder::build(env, frame)
    }

    fn from_js(value: Unknown<'_>, depth: usize) -> Result<Self> {
        let frame = vitaminc_aead::to_frame(JsRef::at_depth(value, depth)).map_err(frame_error)?;
        Ok(PassthroughFrame(frame.risky_ref().to_vec()))
    }

    /// A frame parsed `depth` levels down is bounded there; a payload that
    /// is not a well-formed frame cannot be built either, so it counts as
    /// exceeding too.
    fn exceeds_depth(&self, depth: usize) -> bool {
        Frame::parse_nested(&self.0, depth).is_err()
    }

    /// A frame is one flat buffer.
    fn drop_flat(self) {}
}

/// Whether a ciphertext tree nests past [`MAX_DEPTH`], payloads included.
/// Iterative, so a tree of any depth is measured without recursion.
fn exceeds_depth<Leaf, P: NapiPassthrough>(node: &CipherText<Leaf, P>) -> bool {
    let mut stack = vec![(node, 0)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return true;
        }
        match node {
            CipherText::Sequence(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            CipherText::Map(entries) => {
                stack.extend(entries.iter().map(|(_, value)| (value, depth + 1)))
            }
            CipherText::Passthrough(p) if p.exceeds_depth(depth + 1) => return true,
            _ => {}
        }
    }
    false
}

/// Drop a ciphertext tree without recursing once per level (see
/// [`NapiPassthrough::drop_flat`]).
fn drop_flat<Leaf, P: NapiPassthrough>(node: CipherText<Leaf, P>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node {
            CipherText::Sequence(items) => stack.extend(items),
            CipherText::Map(entries) => stack.extend(entries.into_iter().map(|(_, value)| value)),
            CipherText::Passthrough(p) => p.drop_flat(),
            _ => {}
        }
    }
}

fn ciphertext_depth_error() -> Error {
    Error::new(Status::InvalidArg, "ciphertext is nested too deeply")
}

fn shape_error() -> Error {
    Error::new(Status::InvalidArg, "malformed ciphertext value")
}

/// Build `node` in JS. Callers check [`exceeds_depth`] first, which bounds
/// this recursion.
fn node_to_js<Leaf, P>(env: &Env, node: CipherText<Leaf, P>) -> Result<Object<'_>>
where
    Leaf: AsRef<[u8]>,
    P: NapiPassthrough,
{
    let leaf = |tag: &'static str, leaf: Leaf| -> Result<(&'static str, Unknown<'_>)> {
        Ok((tag, Buffer::from(leaf.as_ref().to_vec()).into_unknown(env)?))
    };
    let (tag, value) = match node {
        CipherText::Single(l) => leaf(T_CIPHERTEXT, l)?,
        CipherText::EmptySequence(l) => leaf(T_EMPTY_SEQ, l)?,
        CipherText::EmptyMap(l) => leaf(T_EMPTY_MAP, l)?,
        CipherText::Sequence(items) => {
            let mut arr = new_array(env, items.len())?;
            let mut elements = Vec::with_capacity(items.len());
            for (i, item) in items.into_iter().enumerate() {
                let node = node_to_js(env, item)?;
                elements.push(own_property(env, &i.to_string(), &node)?);
            }
            define_own_properties(&mut arr, &elements)?;
            (T_SEQ, arr.into_unknown(env)?)
        }
        CipherText::Map(entries) => {
            let mut map = Object::new(env)?;
            let mut properties = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                // Map keys travel in the clear inside the stored ciphertext
                // and are therefore attacker-writable; never assign
                // prototype-polluting names onto a JS object.
                if forbidden_key(&key) {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("ciphertext map key is not allowed: {key}"),
                    ));
                }
                let node = node_to_js(env, value)?;
                properties.push(own_property(env, &key, &node)?);
            }
            define_own_properties(&mut map, &properties)?;
            (T_MAP, map.into_unknown(env)?)
        }
        CipherText::Passthrough(p) => (T_PASSTHROUGH, p.to_js(env)?),
    };
    // Own properties throughout, so a polluted inherited `t`, `v` or index
    // setter never sees the ciphertext (see `define_own_properties`).
    let mut obj = Object::new(env)?;
    let tag = tag.into_unknown(env)?;
    define_own_properties(
        &mut obj,
        &[
            own_property(env, T_KEY, &tag)?,
            own_property(env, V_KEY, &value)?,
        ],
    )?;
    Ok(obj)
}

const T_KEY: &str = "t";
const V_KEY: &str = "v";

/// A node is a JavaScript object, for the places napi-rs asks what a value
/// is, such as the result of an async task.
impl<Leaf, P> TypeName for JsCipherText<Leaf, P> {
    fn type_name() -> &'static str {
        "CipherText"
    }

    fn value_type() -> ValueType {
        ValueType::Object
    }
}

impl<Leaf, P> ToNapiValue for JsCipherText<Leaf, P>
where
    Leaf: AsRef<[u8]>,
    P: NapiPassthrough,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        if exceeds_depth(&val.0) {
            drop_flat(val.0);
            return Err(ciphertext_depth_error());
        }
        Ok(node_to_js(&Env::from_raw(env), val.0)?.raw())
    }
}

/// A node must be a JS object. napi-rs's `Object` conversion does not check
/// the type, and N-API reads properties of a primitive through its wrapper
/// object, so a bare string would otherwise read `t` and `v` from a
/// (possibly polluted) `String.prototype`.
fn node_object(value: Unknown<'_>) -> Result<Object<'_>> {
    if value.get_type()? != ValueType::Object {
        return Err(shape_error());
    }
    Object::from_unknown(value)
}

/// A node's own `t` or `v`. A node missing either would otherwise take it
/// from a (possibly polluted) prototype. Ownership is checked immediately
/// before the read, where no JS can run in between, so a getter on the
/// other field cannot delete this one after the check.
fn own_field<'e>(obj: &Object<'e>, key: &str) -> Result<Unknown<'e>> {
    if !obj.has_own_property(key)? {
        return Err(shape_error());
    }
    get_property_unknown(obj, key)
}

fn node_from_js<Leaf, P>(obj: &Object<'_>, depth: usize) -> Result<CipherText<Leaf, P>>
where
    Leaf: From<Vec<u8>>,
    P: NapiPassthrough,
{
    if depth > MAX_DEPTH {
        return Err(ciphertext_depth_error());
    }
    let t = String::from_unknown(own_field(obj, T_KEY)?)?;
    match t.as_str() {
        T_CIPHERTEXT | T_EMPTY_SEQ | T_EMPTY_MAP => {
            // Borrowed as a slice, which holds no reference: napi-rs's
            // `Buffer` takes one before it checks the value and never
            // releases it when the check fails.
            let buf = BufferSlice::from_unknown(own_field(obj, V_KEY)?)?;
            let leaf = Leaf::from(buf.to_vec());
            Ok(match t.as_str() {
                T_CIPHERTEXT => CipherText::Single(leaf),
                T_EMPTY_SEQ => CipherText::EmptySequence(leaf),
                _ => CipherText::EmptyMap(leaf),
            })
        }
        T_SEQ => {
            let arr = Array::from_unknown(own_field(obj, V_KEY)?)?;
            // The same array seen as an object, for per-index own checks.
            let elements = Object::from_unknown(arr.to_unknown())?;
            let len = arr.len();
            // Capacity is granted lazily: the reported length is
            // attacker-cheap (`{t:"seq", v:new Array(2**32-1)}` materialises
            // nothing), so reserving it up front would abort the process on
            // allocation failure before any element is validated.
            let mut items = Vec::with_capacity(eager_capacity(len));
            for i in 0..len {
                // Own elements only: a hole would otherwise read an element
                // from a (possibly polluted) `Array.prototype`, and as
                // `undefined` it is not a node anyway.
                if !elements.has_own_property(&i.to_string())? {
                    return Err(shape_error());
                }
                let element = arr.get::<Unknown>(i)?.ok_or_else(shape_error)?;
                items.push(node_from_js(&node_object(element)?, depth + 1)?);
            }
            Ok(CipherText::Sequence(items))
        }
        T_MAP => {
            let map = node_object(own_field(obj, V_KEY)?)?;
            // Own keys only — `Object::keys` walks the prototype chain, so
            // a hostile node object with enumerable prototype members would
            // otherwise have its inherited keys become ciphertext map
            // entries (see `own_enumerable_keys`).
            let keys = own_enumerable_keys(&map)?;
            let mut entries = Vec::with_capacity(keys.len());
            for key in keys {
                if forbidden_key(&key.name) {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("ciphertext map key is not allowed: {}", *key.name),
                    ));
                }
                let value = node_object(get_own(&map, &key)?)?;
                entries.push((key.name.to_string(), node_from_js(&value, depth + 1)?));
            }
            Ok(CipherText::Map(entries))
        }
        T_PASSTHROUGH => {
            // `undefined` is a *faithful* projection here (`P = ()` and
            // `NapiValue::Undefined` both project to it), and
            // `JSON.stringify` drops a `v: undefined` key outright, so a
            // missing `v` reads as `undefined` rather than as malformed —
            // never from the prototype. Whether `undefined` converts is
            // `P`'s decision.
            let env = Env::from_raw(obj.value().env);
            let value = if obj.has_own_property(V_KEY)? {
                own_field(obj, V_KEY)?
            } else {
                ().into_unknown(&env)?
            };
            Ok(CipherText::Passthrough(P::from_js(value, depth + 1)?))
        }
        _ => Err(shape_error()),
    }
}

impl<Leaf, P> FromNapiValue for JsCipherText<Leaf, P>
where
    Leaf: From<Vec<u8>>,
    P: NapiPassthrough,
{
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        // SAFETY: napi-rs calls this with the `env` and `napi_val` of the
        // current call, which is all `Unknown::from_napi_value` needs: an
        // `Unknown` may hold any value type, and `node_object` checks it is
        // an object before anything reads it as one. The handle does not
        // outlive this call.
        let value = unsafe { Unknown::from_napi_value(env, napi_val) }?;
        let obj = node_object(value)?;
        Ok(JsCipherText(node_from_js(&obj, 0)?))
    }
}

#[cfg(test)]
mod tests {
    use super::{drop_flat, exceeds_depth, CipherText, NapiPassthrough, MAX_DEPTH};
    use vitaminc_aead::{to_frame, PassthroughFrame};
    use vitaminc_protected::Controlled;

    type Node<P> = CipherText<Vec<u8>, P>;

    #[test]
    fn a_node_is_a_javascript_object_named_ciphertext() {
        use napi::bindgen_prelude::{TypeName, ValueType};
        type Js = super::JsCipherText<Vec<u8>, PassthroughFrame>;
        assert_eq!(Js::type_name(), "CipherText");
        assert_eq!(Js::value_type(), ValueType::Object);
    }

    fn nested<P>(levels: usize, wrap: fn(Node<P>) -> Node<P>, leaf: Node<P>) -> Node<P> {
        (0..levels).fold(leaf, |node, _| wrap(node))
    }

    fn seq<P>(node: Node<P>) -> Node<P> {
        CipherText::Sequence(vec![CipherText::Single(vec![1]), node])
    }

    fn map<P>(node: Node<P>) -> Node<P> {
        CipherText::Map(vec![
            ("a".into(), CipherText::EmptySequence(vec![1])),
            ("k".into(), node),
        ])
    }

    /// `levels` arrays around `true`, as a frame payload.
    fn payload(levels: usize) -> Node<PassthroughFrame> {
        struct Arrays(usize);
        impl vitaminc_aead::Encrypt for Arrays {
            fn visit<S: vitaminc_aead::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                use vitaminc_aead::SeqSink;
                if self.0 == 0 {
                    return sink.scalar(None, vitaminc_aead::Physical::Bool(true));
                }
                let mut seq = sink.seq(Some(1))?;
                Arrays(self.0 - 1).visit(seq.element()?)?;
                seq.end()
            }
        }
        let frame = to_frame(Arrays(levels)).expect("within the frame's own bound");
        CipherText::Passthrough(PassthroughFrame(frame.risky_ref().to_vec()))
    }

    #[test]
    fn depth_is_measured_to_the_limit_for_every_container() {
        for wrap in [seq::<()>, map::<()>] {
            let leaf = || CipherText::EmptySequence(vec![1]);
            assert!(!exceeds_depth(&nested(MAX_DEPTH, wrap, leaf())));
            assert!(exceeds_depth(&nested(MAX_DEPTH + 1, wrap, leaf())));
        }
    }

    #[test]
    fn a_payload_continues_the_count() {
        // A `()` payload sits one level below its passthrough node.
        assert!(!exceeds_depth(&nested(
            MAX_DEPTH - 1,
            seq,
            CipherText::Passthrough(())
        )));
        assert!(exceeds_depth(&nested(
            MAX_DEPTH,
            seq,
            CipherText::Passthrough(())
        )));
        assert!(!().exceeds_depth(MAX_DEPTH));
        assert!(().exceeds_depth(MAX_DEPTH + 1));
        // So does every level inside a frame payload.
        assert!(!exceeds_depth(&nested(60, seq, payload(67))));
        assert!(exceeds_depth(&nested(60, seq, payload(68))));
        // A frame that is not well formed cannot be built, so it exceeds.
        assert!(PassthroughFrame(vec![0xF0, 1, 0, 0, 0]).exceeds_depth(0));
    }

    #[test]
    fn trees_too_deep_for_the_stack_are_measured_and_dropped_flat() {
        for wrap in [seq::<PassthroughFrame>, map::<PassthroughFrame>] {
            let deep = nested(1_000_000, wrap, CipherText::Single(vec![1]));
            assert!(exceeds_depth(&deep));
            drop_flat(deep);
        }
        drop_flat(nested(1_000_000, seq, CipherText::Passthrough(())));
    }
}

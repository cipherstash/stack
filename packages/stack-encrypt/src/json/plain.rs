//! JSON plaintext under vitaminc's controls.
//!
//! A JSON document's plaintext lives in `Protected` here as it does on the
//! scalar paths: a node's plaintext is built into a `Protected<Vec<u8>>`
//! before it is sealed, and an opened entry's bytes stay in the
//! `Protected<Vec<u8>>` the cipher returns, read in place while they are
//! parsed. A parsed value is a [`PlainJson`] inside a `Protected`, which
//! wipes it on drop. It leaves the wrapper only where the caller receives
//! it: the value of the document, the node or the subtree it asked for.
use serde_json::{Map, Number, Value};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

/// A JSON value's plaintext, for holding in a `Protected`.
///
/// `serde_json::Value` has no `Zeroize`, so this newtype gives it one:
/// [`zeroize`](Zeroize::zeroize) wipes every string in the tree, values
/// and object keys alike (a key is taken out of its map by ownership to
/// reach it), sets every number to zero and every boolean to `false`, and
/// leaves `null`. Strings are wiped through `zeroize`, which writes
/// volatilely over the whole buffer. Numbers and booleans sit inline in
/// their parent's array or map node and are overwritten in place; with
/// unsafe code denied in this crate there is no volatile write for them,
/// so that overwrite is best-effort against the optimiser.
///
/// It has no `Debug`, `Clone`, `PartialEq`, `Default` or `Deref`, so
/// nothing reads it but through its `Protected`.
pub(crate) struct PlainJson(Value);

impl PlainJson {
    /// Wrap `value`, which the caller has just built or parsed.
    pub(crate) fn protect(value: Value) -> Protected<Self> {
        Protected::new(Self(value))
    }

    /// A value just built, to be wrapped by the caller.
    pub(crate) fn from_value(value: Value) -> Self {
        Self(value)
    }

    /// Parse JSON text into a value to be wrapped by the caller.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok().map(Self)
    }

    /// The value, for the caller that asked for it. Only at that
    /// boundary, after `risky_unwrap` on the `Protected` that held it.
    pub(crate) fn into_value(self) -> Value {
        self.0
    }

    /// The value, read in place.
    pub(crate) fn value(&self) -> &Value {
        &self.0
    }

    /// The value, changed in place, inside its `Protected`.
    pub(crate) fn value_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}

impl Zeroize for PlainJson {
    fn zeroize(&mut self) {
        wipe(&mut self.0);
        self.0 = Value::Null;
    }
}

/// Overwrite every scalar and key in `value` in place, then empty its
/// containers.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Number(number) => *number = Number::from(0u8),
        Value::Bool(flag) => *flag = false,
        Value::Null => {}
        Value::Array(items) => {
            items.iter_mut().for_each(wipe);
            items.clear();
        }
        Value::Object(members) => {
            members.values_mut().for_each(wipe);
            for (mut key, _) in std::mem::take(members) {
                key.zeroize();
            }
        }
    }
    // Keep the in-place overwrites above from being dropped as dead stores
    // before the memory is freed.
    let _ = std::hint::black_box(&*value);
}

/// Read a `T` out of `source` without `source` leaving its `Protected`:
/// `read` borrows the inner value through vitaminc (`zip_ref`), and what it
/// returns is wrapped as it is made. `None` when `read` refuses.
pub(crate) fn read_protected<S, T>(
    source: &Protected<S>,
    read: impl FnOnce(&S) -> Option<T>,
) -> Option<Protected<T>>
where
    S: Zeroize,
    T: Zeroize,
{
    Protected::new(None::<T>)
        .zip_ref(source, |_, inner: &S| read(inner))
        .transpose()
}

/// Move a `T` out of `source` without `source` leaving its `Protected`:
/// `take` borrows the inner value mutably through vitaminc (`update`) and
/// moves out what it returns, which is wrapped as it leaves. What stays
/// behind is wiped with `source`. `None` when `take` refuses. The moving
/// counterpart of [`read_protected`]: one copy of the plaintext, not two.
pub(crate) fn take_protected<S, T>(
    source: &mut Protected<S>,
    take: impl FnOnce(&mut S) -> Option<T>,
) -> Option<Protected<T>>
where
    S: Zeroize,
    T: Zeroize,
{
    let mut take = Some(take);
    let mut taken = Protected::new(None::<T>);
    source.update(|inner| {
        if let Some(take) = take.take() {
            let mut moved = take(inner);
            taken.update(|slot| *slot = moved.take());
        }
    });
    taken.transpose()
}

/// An object under construction inside a `Protected`, so a member already
/// moved in is wiped if the build fails before the object is handed over.
pub(crate) fn protected_object() -> Protected<PlainJson> {
    PlainJson::protect(Value::Object(Map::new()))
}

/// An array under construction inside a `Protected`; see
/// [`protected_object`].
pub(crate) fn protected_array(capacity: usize) -> Protected<PlainJson> {
    PlainJson::protect(Value::Array(Vec::with_capacity(capacity)))
}

/// Move `member` into the object `into` under `key`. Both arrive wrapped
/// and are unwrapped only to be moved into `into`'s own `Protected`.
pub(crate) fn insert_member(
    into: &mut Protected<PlainJson>,
    key: Protected<String>,
    member: Protected<PlainJson>,
) {
    let mut entry = Some((key.risky_unwrap(), member.risky_unwrap().into_value()));
    into.update(|object| {
        if let (Value::Object(members), Some((key, member))) = (object.value_mut(), entry.take()) {
            let _ = members.insert(key, member);
        }
    });
}

/// Move `element` onto the end of the array `into`; see [`insert_member`].
pub(crate) fn push_element(into: &mut Protected<PlainJson>, element: Protected<PlainJson>) {
    let mut element = Some(element.risky_unwrap().into_value());
    into.update(|array| {
        if let (Value::Array(items), Some(element)) = (array.value_mut(), element.take()) {
            items.push(element);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn zeroize_leaves_null_whatever_the_tree_held() {
        let mut plain = PlainJson(json!({
            "secret": "hunter2",
            "nested": {"pin": 1234, "ok": true, "list": ["a", 2.5, null]},
        }));
        plain.zeroize();
        assert_eq!(plain.value(), &Value::Null);
        // And through `Protected`, whose drop runs the same `zeroize`.
        let mut protected = PlainJson::protect(json!(["x"]));
        protected.zeroize();
        assert_eq!(protected.risky_ref().value(), &Value::Null);
    }

    #[test]
    fn a_wiped_string_is_zero_before_it_is_freed() {
        // `wipe` zeroizes strings in place; observe it on a value the test
        // still owns.
        let mut value = json!(["hunter2", {"k": "v", "n": 7, "b": true}]);
        if let Value::Array(items) = &mut value {
            wipe(&mut items[0]);
            assert_eq!(items[0], json!(""), "a zeroized String is emptied");
            if let Value::Object(members) = &mut items[1] {
                let mut number = members.get("n").cloned().unwrap();
                wipe(&mut number);
                assert_eq!(number, json!(0));
                let mut flag = members.get("b").cloned().unwrap();
                wipe(&mut flag);
                assert_eq!(flag, json!(false));
            }
        }
        wipe(&mut value);
        assert_eq!(value, json!([]), "containers are emptied");
        let mut object = json!({"key": "value"});
        wipe(&mut object);
        assert_eq!(object, json!({}), "keys are taken out and wiped");
    }

    #[test]
    fn read_protected_wraps_what_it_reads_and_refuses_with_none() {
        let bytes = Protected::new(b"\"hello\"".to_vec());
        let parsed = read_protected(&bytes, |b: &Vec<u8>| {
            serde_json::from_slice(b).ok().map(PlainJson)
        })
        .unwrap();
        assert_eq!(parsed.risky_ref().value(), &json!("hello"));
        assert!(read_protected(&bytes, |_: &Vec<u8>| None::<PlainJson>).is_none());
        // The source is only borrowed: it is still whole.
        assert_eq!(bytes.risky_ref(), b"\"hello\"");
    }

    #[test]
    fn take_protected_moves_the_node_out_and_leaves_null() {
        let mut doc = PlainJson::protect(json!({"a": {"secret": "s3cret"}, "b": 1}));
        let taken = take_protected(&mut doc, |d: &mut PlainJson| {
            d.value_mut()
                .get_mut("a")
                .map(|a| PlainJson::from_value(std::mem::take(a)))
        })
        .unwrap();
        assert_eq!(
            taken.risky_unwrap().into_value(),
            json!({"secret": "s3cret"})
        );
        assert_eq!(
            doc.risky_unwrap().into_value(),
            json!({"a": null, "b": 1}),
            "the document keeps no copy of what was taken"
        );
        let mut doc = PlainJson::protect(json!([]));
        assert!(take_protected(&mut doc, |_: &mut PlainJson| None::<PlainJson>).is_none());
    }

    #[test]
    fn members_and_elements_move_in_under_protection() {
        let mut object = protected_object();
        insert_member(
            &mut object,
            Protected::new("k".to_owned()),
            PlainJson::protect(json!(1)),
        );
        let mut array = protected_array(1);
        push_element(&mut array, object);
        assert_eq!(array.risky_unwrap().into_value(), json!([{"k": 1}]));
    }
}

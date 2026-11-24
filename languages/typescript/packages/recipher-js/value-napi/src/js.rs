//! What the walk and the build share about JavaScript objects: which keys
//! are read, how properties are written, and the limits both directions
//! apply. Everything here needs a live `Env`, so it runs on the
//! JavaScript thread.

use napi::bindgen_prelude::{
    FromNapiValue, JsObjectValue, JsValue, KeyCollectionMode, KeyConversion, KeyFilter, Object,
    ToNapiValue, Unknown,
};
use napi::{check_status, sys, Env, Error, Property, Result, Status, ValueType};
use zeroize::Zeroizing;

/// Maximum nesting depth, in both directions: walking a JavaScript value
/// and building one. Bounds recursion so a deeply nested input cannot
/// overflow the stack. The same limit, counted the same way, as the
/// frame's, so any frame builds and any value that walks frames.
pub const MAX_DEPTH: usize = vitaminc_aead::frame::MAX_DEPTH;

/// Property names that must never be read from or written onto a plain JS
/// object: assigning them via `napi_set_property` triggers prototype-chain
/// semantics (prototype pollution), and accepting them on input would let a
/// value round-trip into that hazard.
pub(crate) fn forbidden_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

pub(crate) fn depth_error() -> Error {
    Error::new(Status::InvalidArg, "value is nested too deeply")
}

pub(crate) fn forbidden_key_error(key: &str) -> Error {
    Error::new(
        Status::InvalidArg,
        format!("property name is not allowed: {key}"),
    )
}

/// Initial `Vec` capacity granted to a JS-reported length before any element
/// has been validated. An array's reported length is attacker-cheap —
/// `new Array(2**32 - 1)` materialises no elements — so reserving the full
/// reported length up front would let a one-line input demand hundreds of
/// gigabytes and abort the whole Node process on allocation failure
/// (`handle_alloc_error` is not a catchable JS throw). Real elements grow
/// the `Vec` amortised past this cap.
const MAX_EAGER_CAPACITY: usize = 1024;

pub(crate) fn eager_capacity(reported_len: u32) -> usize {
    (reported_len as usize).min(MAX_EAGER_CAPACITY)
}

/// An own property key: the JS key itself, for reading the property back
/// exactly, and its text.
pub(crate) struct OwnKey<'e> {
    handle: Unknown<'e>,
    pub(crate) name: Zeroizing<String>,
}

/// Own, enumerable, string-keyed properties of `obj`.
///
/// `Object::keys` (`napi_get_property_names`) walks the prototype chain —
/// per the Node-API spec it equals `napi_get_all_property_names` with
/// `include_prototypes | enumerable` — so a polluted `Object.prototype`
/// (or an instance with enumerable prototype members) would inject its
/// keys into the result, and inherited getters would run when the values
/// are read. Own-only enumeration forecloses both.
///
/// A key holding an unpaired surrogate is refused, as string values are: it
/// has no UTF-8 spelling, so it could not be sealed as written.
pub(crate) fn own_enumerable_keys<'e>(obj: &Object<'e>) -> Result<Vec<OwnKey<'e>>> {
    // napi-rs takes a single key filter, so symbol keys are skipped below
    // rather than by an `enumerable | skip_symbols` filter.
    let names = obj.get_all_property_names(
        KeyCollectionMode::OwnOnly,
        KeyFilter::Enumerable,
        KeyConversion::NumbersToStrings,
    )?;
    let len = names.get_array_length()?;
    let mut keys = Vec::with_capacity(eager_capacity(len));
    for i in 0..len {
        let handle = names.get_element::<Unknown>(i)?;
        if handle.get_type()? == ValueType::Symbol {
            continue;
        }
        let name = lossless_string(handle, "property name")?;
        keys.push(OwnKey { handle, name });
    }
    Ok(keys)
}

/// Read the own property `key` names, by the key's own JS handle.
///
/// The key list is a snapshot, and a getter that ran since may have deleted
/// this property; `[[Get]]` would then read it from a (possibly polluted)
/// prototype. So ownership is checked again immediately before the read,
/// where no JS can run in between for an ordinary object.
pub(crate) fn get_own<'e>(obj: &Object<'e>, key: &OwnKey<'e>) -> Result<Unknown<'e>> {
    if !obj.has_own_property_js(key.handle)? {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "property was removed while it was being read: {}",
                *key.name
            ),
        ));
    }
    obj.get_property_unchecked(key.handle)
}

/// A JS string as Rust text. Fetched as UTF-16 (JS's native representation)
/// and decoded with `char::decode_utf16`, which errors on unpaired
/// surrogates. The UTF-8 fetch (`napi_get_value_string_utf8`) would silently
/// replace them with U+FFFD, so a value would seal *mutated* and a key would
/// stop naming its property; refuse loudly instead.
///
/// The text may be plaintext, so both Rust copies, the code units and the
/// UTF-8, are wiped on drop. The V8 original cannot be wiped from here. The
/// code units are read straight from Node-API rather than through
/// napi-rs's `Utf16String`, whose buffer cannot be reached to wipe.
pub(crate) fn lossless_string(value: Unknown<'_>, what: &str) -> Result<Zeroizing<String>> {
    let env = value.value().env;
    let raw = value.raw();
    let mut len = 0usize;
    // SAFETY: `value` is a live string handle of `env` (the caller checked
    // its type), and a null buffer with size 0 asks for the length only.
    let status =
        unsafe { sys::napi_get_value_string_utf16(env, raw, std::ptr::null_mut(), 0, &mut len) };
    check_status!(status, "failed to measure a {what}")?;
    // Room for the terminating NUL Node-API writes.
    let mut units = Zeroizing::new(vec![0u16; len + 1]);
    let mut written = 0usize;
    // SAFETY: as above, and `units` holds `len + 1` code units, which is the
    // size passed, so the write stays inside the buffer.
    let status = unsafe {
        sys::napi_get_value_string_utf16(env, raw, units.as_mut_ptr(), len + 1, &mut written)
    };
    check_status!(status, "failed to read a {what}")?;
    from_utf16(&units[..written.min(len)]).ok_or_else(|| {
        Error::new(
            Status::InvalidArg,
            format!("{what} contains an unpaired surrogate and cannot be encrypted losslessly"),
        )
    })
}

/// UTF-16 code units as UTF-8 text, or `None` if any surrogate is unpaired.
///
/// The UTF-8 length is measured first, so the text is built in a wiped
/// buffer of its final size: a `String` that grows leaves its old buffer
/// unwiped, as `String::from_utf16` does for any text outside ASCII.
fn from_utf16(units: &[u16]) -> Option<Zeroizing<String>> {
    let mut utf8_len = 0usize;
    for c in char::decode_utf16(units.iter().copied()) {
        utf8_len += c.ok()?.len_utf8();
    }
    let mut text = Zeroizing::new(String::with_capacity(utf8_len));
    // Every unit was checked above, so `flatten` drops nothing.
    for c in char::decode_utf16(units.iter().copied()).flatten() {
        text.push(c);
    }
    Some(text)
}

/// Fetch a property as the raw JS value, without [`Object::get`]'s
/// `undefined`-to-`None` mapping — `{ x: undefined }` has an own property
/// `x` (`Object.hasOwn` says so) and must round-trip, but `Object::get`
/// cannot distinguish its value from a missing property. A genuinely
/// missing property also comes back as `undefined`, which is exactly JS
/// property semantics.
pub(crate) fn get_property_unknown<'e>(obj: &Object<'e>, key: &str) -> Result<Unknown<'e>> {
    // The key goes over as a JS string with an explicit length, so a key
    // holding NUL survives (`get_named_property` would refuse it).
    let env = Env::from_raw(obj.value().env);
    let js_key = key.into_unknown(&env)?;
    obj.get_property_unchecked(js_key)
}

/// The refusal of anything but a plain object or a wrapper instance; the
/// check itself is [`Wrappers::is_plain`](crate::Wrappers::is_plain).
pub(crate) fn not_plain_error() -> Error {
    Error::new(
        Status::InvalidArg,
        "only plain objects and the wrapper classes can be encrypted; Map, Set, class instances \
         and other exotic objects lose their contents under key enumeration — convert the value \
         to a plain object, array, string, number, Buffer, or Uint8Array first",
    )
}

/// One own data property, for [`define_own_properties`]. `Property::new()`
/// defaults to writable, enumerable and configurable, the attributes
/// `obj.key = value` would give.
pub(crate) fn own_property<'e, V: JsValue<'e>>(
    env: &Env,
    key: &str,
    value: &V,
) -> Result<Property> {
    // A JS string name, not a UTF-8 C string, so a key holding NUL works.
    Ok(Property::new().with_name(env, key)?.with_value(value))
}

/// Write `properties` onto `obj` as **own data properties**
/// (`defineProperty` semantics) rather than through [`Object::set`] or
/// `Array::set` (`napi_set_property` / `napi_set_element`, `[[Set]]`
/// semantics), which walk the prototype chain: a polluted inherited setter on
/// a key or array index would receive the decrypted plaintext (leak) and
/// leave the result without the own property (drop). The intake side already
/// treats prototype pollution as in-threat-model (`own_enumerable_keys`,
/// `is_plain_object`); this closes the output side. One call per object.
pub(crate) fn define_own_properties(obj: &mut Object<'_>, properties: &[Property]) -> Result<()> {
    obj.define_properties(properties)
}

/// A new JS array of `len` holes, seen as an object so its elements can be
/// defined with [`define_own_properties`].
pub(crate) fn new_array<'e>(env: &'e Env, len: usize) -> Result<Object<'e>> {
    let len = u32::try_from(len)
        .map_err(|_| Error::new(Status::InvalidArg, "array is too long for JS"))?;
    Object::from_unknown(env.create_array(len)?.to_unknown())
}

#[cfg(test)]
mod tests {
    use super::{eager_capacity, forbidden_key, from_utf16, MAX_EAGER_CAPACITY};

    #[test]
    fn forbidden_keys_are_rejected() {
        assert!(forbidden_key("__proto__"));
        assert!(forbidden_key("constructor"));
        assert!(forbidden_key("prototype"));
        assert!(!forbidden_key("proto"));
        assert!(!forbidden_key("name"));
        assert!(!forbidden_key(""));
    }

    #[test]
    fn eager_capacity_passes_small_lengths_through() {
        assert_eq!(eager_capacity(0), 0);
        assert_eq!(eager_capacity(1), 1);
        assert_eq!(eager_capacity(37), 37);
        assert_eq!(
            eager_capacity(MAX_EAGER_CAPACITY as u32),
            MAX_EAGER_CAPACITY
        );
    }

    #[test]
    fn eager_capacity_caps_attacker_reported_lengths() {
        assert_eq!(
            eager_capacity(MAX_EAGER_CAPACITY as u32 + 1),
            MAX_EAGER_CAPACITY
        );
        assert_eq!(eager_capacity(u32::MAX), MAX_EAGER_CAPACITY);
    }

    #[test]
    fn utf16_text_is_built_at_its_final_size() {
        for text in ["", "a", "José", "😀b", "\u{10FFFF}"] {
            let units: Vec<u16> = text.encode_utf16().collect();
            let built = from_utf16(&units).expect("well formed");
            assert_eq!(built.as_str(), text);
            // A buffer that grew would have left a smaller one unwiped.
            assert_eq!(built.capacity(), text.len(), "{text}");
        }
    }

    #[test]
    fn an_unpaired_surrogate_is_refused() {
        for units in [&[0xD800][..], &[0x61, 0xDC00, 0x62], &[0xD83D, 0x61]] {
            assert!(from_utf16(units).is_none(), "{units:x?}");
        }
    }
}

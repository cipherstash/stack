//! The per-call options object, and the keyset selector it carries.
//!
//! Every export that touches a keyset takes one more codec-encoded
//! argument: a frame object with one required key, `keyset`, whose
//! value is a tagged object naming the keyset the call binds to, and two
//! optional keys: `context` on `se_decrypt_record`, and `audit` on the
//! exports that request data keys (both below):
//!
//! | selector          | meaning |
//! |-------------------|---------|
//! | `{"default": {}}` | the cipher's default keyset (the one named at `se_cipher_init`, else the client's) |
//! | `{"name": <string>}` | the keyset with that name, loaded on first use |
//! | `{"id": <16 bytes>}` | the keyset with that id (raw UUID bytes), loaded on first use |
//! | `{"any": {}}`     | **decrypt only**: open leaves from whichever keyset each was sealed under, one batched retrieval per keyset (chunked at the client's request limit, 500 keys) |
//!
//! Every variant is spelled; there is no zero-length or omitted-field
//! sentinel, so a host that means the default says so. A name is validated
//! at parse (ZeroKMS's own rules for keyset names), so a malformed
//! selector is refused before the cipher is consulted. On the sealing and
//! term exports the selector picks the keyset that mints; on the opening
//! exports it is a *constraint*: `{"name"}`, `{"id"}` and `{"default"}`
//! refuse a leaf sealed under any other keyset before any key is retrieved
//! ([`STATUS_FOREIGN_KEYSET`](crate::status::STATUS_FOREIGN_KEYSET)), and `{"any"}` lifts the constraint. `{"any"}`
//! on a sealing or term export is [`STATUS_ENCODING`]: there is no keyset
//! to mint under. Anything else — another key, a second key, a wrong value
//! type, an id that is not 16 bytes — is [`STATUS_ENCODING`].
//!
//! `context` is the context the host expects a record's context field to
//! hold, for a plan that takes its context from a field (the plan-level
//! `"context_field"` key of `dynamic::record::plan`): a string that parses
//! as a plain label, `"tenants/acme"`, which the engine checks against each
//! record's stored context field before any key is retrieved and refuses
//! with [`STATUS_CONTEXT_MISMATCH`](crate::status::STATUS_CONTEXT_MISMATCH).
//! Omitted, each record opens under the context it stores. It is the data
//! form of the Rust chain's `open(record).context(expected)`. On
//! `se_encrypt_record` and `se_term` it is [`STATUS_ENCODING`]: a plan that
//! names a context field reads the context from each value when it seals,
//! and a term's context arrives as its own argument. A `context` that is
//! not a string, or not a plain label, is [`STATUS_ENCODING`] too.
//!
//! `audit` is audit metadata: facts about the call, which the engine sends
//! with every data-key request the call makes, for the ZeroKMS audit log.
//! It is the data form of the Rust call's `.audit(metadata)`, and
//! [`AuditMetadata`] reads it. The value is an object with text keys. A
//! value in it is a bool, an integer that fits a signed 64-bit integer, a
//! float, text, null, a list of these, or another such object. Bytes, a
//! wider integer and a value with a logical type (a date, a timestamp, a
//! decimal) are [`STATUS_ENCODING`], and so is an `audit` that is not an
//! object. A float that is not finite is sent as null. An empty object
//! sends nothing, as an absent key does. ZeroKMS does not verify the facts,
//! and no key depends on them.
//!
//! ZeroKMS has no type for a time, so a time crosses as text. A binding
//! that takes its language's time type in audit metadata sends this text,
//! so that every language SDK logs one form:
//!
//! - RFC 3339, in UTC, with the suffix `Z`;
//! - a fraction of a second only when it is not zero, with no trailing
//!   zeros and at most nine digits;
//! - a year from 0000 to 9999. The binding refuses a time outside those
//!   years.
//!
//! For example, `2026-11-20T10:00:00Z` and `2026-11-20T10:00:00.5Z`. The
//! guest cannot hold a binding to this rule, because the text arrives as
//! any other text does.
//!
//! `audit` is accepted where the call requests data keys:
//! `se_encrypt_record`, `se_decrypt_record` and `se_json_open`. On `se_term`
//! and `se_query_term` it is [`STATUS_ENCODING`]: a term is derived from the
//! keyset's index key, so the call makes no data-key request to send the
//! facts with, and a host that sent them there would log nothing.
//! [`Export::accepts`] states which export takes which key.
//!
//! This object is a cross-language contract: every binding builds it, so
//! it is objects, strings, bytes and, inside `audit`, the plain values
//! listed above, and this module is its one home. The Go bindings plan
//! points here.

use stack_encrypt::CipherRef;
use stack_encrypt::{AuditMetadata, KeysetCipher, Label, StackCipher};
use stack_kms::{IdentifiedBy, IndexKeySource};
use uuid::Uuid;
use zerokms_protocol::Name;

use stack_encrypt::dynamic::frame::serde::from_slice;
use stack_guest_abi::last_error::malformed;

use crate::status::fail_error;
#[cfg(any(doc, test))]
use crate::status::STATUS_ENCODING;

/// Which keyset a call binds to. See the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetSelector {
    /// The cipher's default keyset.
    Default,
    /// A keyset by name, already validated against ZeroKMS's naming rules.
    Name(Name),
    /// A keyset by id.
    Id(Uuid),
    /// Whichever keyset each leaf was sealed under; opening only.
    Any,
}

/// The export an options object is parsed for. The export decides which
/// keys the object may carry: see [`Export::accepts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Export {
    /// `se_encrypt_record`.
    EncryptRecord,
    /// `se_decrypt_record`.
    DecryptRecord,
    /// `se_json_open`.
    JsonOpen,
    /// `se_term`.
    Term,
    /// `se_query_term`.
    QueryTerm,
}

/// What an export takes in its options object, beyond one keyset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepts {
    /// The `{"any"}` selector: the call opens leaves from any keyset.
    pub any_keyset: bool,
    /// The `context` key.
    pub context: bool,
    /// The `audit` key: the call requests data keys.
    pub audit: bool,
}

impl Export {
    /// Every export this module parses options for.
    pub const ALL: [Export; 5] = [
        Export::EncryptRecord,
        Export::DecryptRecord,
        Export::JsonOpen,
        Export::Term,
        Export::QueryTerm,
    ];

    /// What this export takes. This function is the one statement of the
    /// rules, and [`parse_options`] refuses whatever it does not list.
    ///
    /// - Decrypting a record opens leaves from any keyset, checks a stored
    ///   context, and retrieves data keys.
    /// - Encrypting a record and reading a JSON document work under one
    ///   keyset, and request data keys.
    /// - A term and a query term derive under one keyset, from its index
    ///   key. They request no data key.
    pub const fn accepts(self) -> Accepts {
        match self {
            Export::DecryptRecord => Accepts {
                any_keyset: true,
                context: true,
                audit: true,
            },
            Export::EncryptRecord | Export::JsonOpen => Accepts {
                any_keyset: false,
                context: false,
                audit: true,
            },
            Export::Term | Export::QueryTerm => Accepts {
                any_keyset: false,
                context: false,
                audit: false,
            },
        }
    }
}

/// The parsed options object.
#[derive(Debug, Clone, PartialEq)]
pub struct Options {
    pub keyset: KeysetSelector,
    /// The context the host expects a record's context field to hold;
    /// opening only. See the [module docs](self).
    pub context: Option<Label>,
    /// The audit metadata to send with the call's data-key requests. Empty
    /// when the host sent none: empty metadata sends nothing. See the
    /// [module docs](self).
    pub audit: AuditMetadata,
}

/// Parse the options frame a host sent for `export`. Anything outside the
/// shape in the [module docs](self) is [`STATUS_ENCODING`], with a message
/// that names what was wrong and never a value. So is a key or a selector
/// that the export does not take ([`Export::accepts`]).
pub fn parse_options(bytes: &[u8], export: Export) -> Result<Options, u32> {
    let wire: wire::Options =
        from_slice(bytes).map_err(|e| malformed(format!("the options: {e}")))?;
    let keyset = KeysetSelector::from(wire.keyset);
    let accepts = export.accepts();
    if wire.context.is_some() && !accepts.context {
        return Err(malformed(
            r#"the "context" option is for decrypting a record only"#,
        ));
    }
    if keyset == KeysetSelector::Any && !accepts.any_keyset {
        return Err(malformed(
            r#"{"any"} names no keyset, and this call works under one"#,
        ));
    }
    if wire.audit.is_some() && !accepts.audit {
        return Err(malformed(
            r#"the "audit" option is for a call that requests data keys; a term requests none"#,
        ));
    }
    Ok(Options {
        keyset,
        context: wire.context.map(|context| context.0),
        audit: wire.audit.unwrap_or_default(),
    })
}

/// Parse a bare keyset selector frame, as `se_keyset` takes it. One
/// definition, `wire::Selector`, serves this and [`parse_options`].
pub fn parse_selector(bytes: &[u8]) -> Result<KeysetSelector, u32> {
    from_slice::<wire::Selector>(bytes)
        .map(KeysetSelector::from)
        .map_err(|e| malformed(format!("a keyset selector: {e}")))
}

/// The options and the selector as a host writes them, read straight from
/// the frame by serde (`vitaminc_aead_frame::serde`). Each field type
/// validates as it reads, through `TryFrom`, so a parsed value is already
/// the guest's. The frame's serde never repeats a `TryFrom` error's text,
/// so a refusal names the key and says only that its value was not
/// accepted; each error here is still a fixed string, for the reader.
mod wire {
    use serde::{Deserialize, Deserializer};
    use stack_encrypt::{AuditMetadata, Label};
    use uuid::Uuid;
    use zerokms_protocol::Name;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Options {
        pub(super) keyset: Selector,
        /// Absent is `None`. Present, it must be a label: a null is refused
        /// like any other non-string, as it always has been.
        #[serde(default, deserialize_with = "present")]
        pub(super) context: Option<ContextLabel>,
        /// Absent is `None`. Present, it must be an object: a null is
        /// refused, as it is for `context`. [`AuditMetadata`] reads the
        /// object and refuses a value ZeroKMS has no form for.
        #[serde(default, deserialize_with = "present")]
        pub(super) audit: Option<AuditMetadata>,
    }

    fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        d: D,
    ) -> Result<Option<T>, D::Error> {
        T::deserialize(d).map(Some)
    }

    /// Every variant is spelled; the payload of `default` and `any` is an
    /// empty object.
    #[derive(Deserialize)]
    #[serde(rename_all = "lowercase", deny_unknown_fields)]
    pub(super) enum Selector {
        Default {},
        Any {},
        Name(KeysetName),
        Id(KeysetId),
    }

    impl From<Selector> for super::KeysetSelector {
        fn from(selector: Selector) -> Self {
            match selector {
                Selector::Default {} => Self::Default,
                Selector::Any {} => Self::Any,
                Selector::Name(KeysetName(name)) => Self::Name(name),
                Selector::Id(KeysetId(id)) => Self::Id(id),
            }
        }
    }

    /// A keyset name, checked against ZeroKMS's naming rules here at the
    /// boundary, not at resolution.
    #[derive(Deserialize)]
    #[serde(try_from = "&str")]
    pub(super) struct KeysetName(Name);

    impl TryFrom<&str> for KeysetName {
        type Error = &'static str;

        fn try_from(name: &str) -> Result<Self, Self::Error> {
            Name::try_from(name)
                .map(KeysetName)
                .map_err(|_| "a keyset name that breaks ZeroKMS's naming rules")
        }
    }

    /// A keyset id: exactly 16 bytes, a UUID's raw form.
    #[derive(Deserialize)]
    #[serde(try_from = "&[u8]")]
    pub(super) struct KeysetId(Uuid);

    impl TryFrom<&[u8]> for KeysetId {
        type Error = &'static str;

        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            Uuid::from_slice(bytes)
                .map(KeysetId)
                .map_err(|_| "a keyset id that is not 16 bytes")
        }
    }

    /// The context a host expects a record's context field to hold: a
    /// string that parses as a plain label.
    #[derive(Deserialize)]
    #[serde(try_from = "&str")]
    pub(super) struct ContextLabel(pub(super) Label);

    impl TryFrom<&str> for ContextLabel {
        type Error = &'static str;

        fn try_from(text: &str) -> Result<Self, Self::Error> {
            Label::parse(text)
                .map(ContextLabel)
                .map_err(|_| "a context that is not a plain label")
        }
    }
}

impl KeysetSelector {
    /// The keyset this selector names, as the cipher resolves it: the
    /// default without a round trip, a name or id through the cipher's
    /// cache (a first use is one `load-keyset` call). `Any` is not a keyset
    /// and is [`STATUS_ENCODING`] here; opening exports resolve it through
    /// [`scope_for`] instead.
    pub async fn resolve<'c, K>(
        &self,
        cipher: &'c StackCipher<K>,
    ) -> Result<KeysetCipher<'c, K>, u32>
    where
        K: IndexKeySource,
    {
        let by: IdentifiedBy = match self {
            KeysetSelector::Default => return Ok(cipher.default_keyset()),
            KeysetSelector::Any => return Err(malformed(r#"{"any"} is not a keyset"#)),
            KeysetSelector::Name(name) => IdentifiedBy::Name(name.clone()),
            KeysetSelector::Id(id) => IdentifiedBy::Uuid(*id),
        };
        cipher.keyset(by).await.map_err(|e| fail_error(&e))
    }
}

/// Returns the [`CipherRef`] for the keyset selector of a decrypt call.
///
/// - For `{"any"}`, the result is the client. The client opens a leaf
///   sealed under any of its keysets.
/// - For one keyset, the result is that keyset's cipher. That cipher only
///   opens leaves from its own keyset. The cipher refuses any other leaf
///   before it retrieves any key.
pub async fn scope_for<'c, K>(
    cipher: &'c StackCipher<K>,
    selector: &KeysetSelector,
) -> Result<CipherRef<'c, K>, u32>
where
    K: IndexKeySource,
{
    match selector {
        KeysetSelector::Any => Ok(CipherRef::from(cipher)),
        other => other.resolve(cipher).await.map(CipherRef::from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_frame::{empty, frame, obj, V};

    fn options(selector: V) -> V {
        obj(vec![("keyset", selector)])
    }

    fn selector(v: V) -> Result<KeysetSelector, u32> {
        parse_selector(&frame(&v))
    }

    fn opts(v: V, export: Export) -> Result<Options, u32> {
        parse_options(&frame(&v), export)
    }

    #[test]
    fn every_selector_variant_is_spelled() {
        let id = Uuid::from_u128(7);
        assert_eq!(
            selector(obj(vec![("default", empty())])),
            Ok(KeysetSelector::Default)
        );
        assert_eq!(
            selector(obj(vec![("any", empty())])),
            Ok(KeysetSelector::Any)
        );
        assert_eq!(
            selector(obj(vec![("name", V::Str("acme".into()))])),
            Ok(KeysetSelector::Name(
                Name::try_from("acme").ok().expect("valid name")
            ))
        );
        assert_eq!(
            selector(obj(vec![("id", V::Bytes(id.as_bytes().to_vec()))])),
            Ok(KeysetSelector::Id(id))
        );
    }

    #[test]
    fn a_selector_is_exactly_one_known_tag_with_the_right_payload() {
        for (label, bad) in [
            ("an empty object", empty()),
            ("a string", V::Str("default".into())),
            ("null", V::Null),
            ("an unknown tag", obj(vec![("primary", empty())])),
            (
                "two tags",
                obj(vec![("default", empty()), ("any", empty())]),
            ),
            (
                "default with a payload",
                obj(vec![("default", V::Bool(true))]),
            ),
            (
                "default with fields",
                obj(vec![("default", obj(vec![("x", empty())]))]),
            ),
            (
                "a name that is not a string",
                obj(vec![("name", V::U64(1))]),
            ),
            ("an empty name", obj(vec![("name", V::Str("".into()))])),
            (
                "a name past ZeroKMS's 64-byte limit",
                obj(vec![("name", V::Str("x".repeat(65)))]),
            ),
            (
                "an id that is not 16 bytes",
                obj(vec![("id", V::Bytes(vec![1, 2, 3]))]),
            ),
            (
                "a 16-byte id sent as text",
                obj(vec![("id", V::Str("0123456789abcdef".into()))]),
            ),
            (
                "a name sent as bytes",
                obj(vec![("name", V::Bytes(b"acme".to_vec()))]),
            ),
            (
                "a selector sent as an array",
                V::Arr(vec![obj(vec![("name", V::Str("acme".into()))])]),
            ),
            (
                "an id as text",
                obj(vec![(
                    "id",
                    V::Str("00000000-0000-0000-0000-000000000007".into()),
                )]),
            ),
        ] {
            assert_eq!(
                selector(bad).err(),
                Some(STATUS_ENCODING),
                "{label} is not a selector and must be refused"
            );
        }
    }

    /// Options sent as an array are refused: the frame reads them only from
    /// an object, never by position.
    #[test]
    fn options_sent_as_an_array_are_refused() {
        let positional = V::Arr(vec![obj(vec![("name", V::Str("acme".into()))])]);
        assert_eq!(
            opts(positional, Export::DecryptRecord),
            Err(STATUS_ENCODING)
        );
    }

    #[test]
    fn options_are_one_keyset_key() {
        assert_eq!(
            opts(
                options(obj(vec![("default", empty())])),
                Export::EncryptRecord
            ),
            Ok(Options {
                keyset: KeysetSelector::Default,
                context: None,
                audit: AuditMetadata::new(),
            })
        );
        for (label, bad) in [
            ("no keyset", empty()),
            ("not an object", V::Null),
            (
                "an unknown key beside it",
                obj(vec![
                    ("keyset", obj(vec![("default", empty())])),
                    ("mode", V::Bool(true)),
                ]),
            ),
            (
                "keyset twice",
                obj(vec![
                    ("keyset", obj(vec![("default", empty())])),
                    ("keyset", obj(vec![("default", empty())])),
                ]),
            ),
        ] {
            assert_eq!(
                opts(bad, Export::DecryptRecord).err(),
                Some(STATUS_ENCODING),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn an_expected_context_is_an_opening_option_only() {
        let with = |context: V| {
            obj(vec![
                ("keyset", obj(vec![("default", empty())])),
                ("context", context),
            ])
        };
        assert_eq!(
            opts(with(V::Str("tenants/acme".into())), Export::DecryptRecord),
            Ok(Options {
                keyset: KeysetSelector::Default,
                context: Some(Label::parse("tenants/acme").expect("a label")),
                audit: AuditMetadata::new(),
            })
        );
        for (label, bad, export) in [
            (
                "on the sealing side",
                with(V::Str("tenants/acme".into())),
                Export::EncryptRecord,
            ),
            ("not a string", with(V::U64(7)), Export::DecryptRecord),
            (
                "not a plain label",
                with(V::Str("tenants/(acme)".into())),
                Export::DecryptRecord,
            ),
            ("empty", with(V::Str("".into())), Export::DecryptRecord),
            (
                "given twice",
                obj(vec![
                    ("keyset", obj(vec![("default", empty())])),
                    ("context", V::Str("a".into())),
                    ("context", V::Str("a".into())),
                ]),
                Export::DecryptRecord,
            ),
        ] {
            assert_eq!(
                opts(bad, export).err(),
                Some(STATUS_ENCODING),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn any_is_an_opening_selector_only() {
        let any = || options(obj(vec![("any", empty())]));
        assert_eq!(
            opts(any(), Export::DecryptRecord),
            Ok(Options {
                keyset: KeysetSelector::Any,
                context: None,
                audit: AuditMetadata::new(),
            })
        );
        assert_eq!(
            opts(any(), Export::EncryptRecord).err(),
            Some(STATUS_ENCODING)
        );
        assert_eq!(opts(any(), Export::Term).err(), Some(STATUS_ENCODING));
    }

    /// The rules, as a table a reader can check against the docs. A change
    /// to [`Export::accepts`] has to change this table too.
    #[test]
    fn the_exports_accept_these_keys() {
        let table = Export::ALL.map(|export| {
            let Accepts {
                any_keyset,
                context,
                audit,
            } = export.accepts();
            (export, any_keyset, context, audit)
        });
        assert_eq!(
            table,
            [
                (Export::EncryptRecord, false, false, true),
                (Export::DecryptRecord, true, true, true),
                (Export::JsonOpen, false, false, true),
                (Export::Term, false, false, false),
                (Export::QueryTerm, false, false, false),
            ]
        );
    }

    /// The parser holds every export to what it accepts: a key or selector
    /// it accepts is read, and one it does not is `STATUS_ENCODING`.
    #[test]
    fn each_export_takes_what_it_accepts_and_refuses_the_rest() {
        let held = |result: Result<Options, u32>, accepted: bool, what: &str| {
            if accepted {
                assert!(result.is_ok(), "{what} must be read");
            } else {
                assert_eq!(
                    result.err(),
                    Some(STATUS_ENCODING),
                    "{what} must be refused"
                );
            }
        };
        for export in Export::ALL {
            let accepts = export.accepts();
            // Every export takes one keyset and nothing else.
            assert_eq!(
                opts(options(obj(vec![("default", empty())])), export),
                Ok(Options {
                    keyset: KeysetSelector::Default,
                    context: None,
                    audit: AuditMetadata::new(),
                }),
                "{export:?}"
            );
            held(
                opts(options(obj(vec![("any", empty())])), export),
                accepts.any_keyset,
                &format!("{export:?}: the any selector"),
            );
            let with_context = obj(vec![
                ("keyset", obj(vec![("default", empty())])),
                ("context", V::Str("tenants/acme".into())),
            ]);
            held(
                opts(with_context, export),
                accepts.context,
                &format!("{export:?}: a context"),
            );
            // Audit metadata is refused where it would log nothing, even
            // when it holds no facts.
            for audit in [facts(), empty()] {
                held(
                    opts(audited(audit), export),
                    accepts.audit,
                    &format!("{export:?}: audit metadata"),
                );
            }
        }
    }

    /// The options with an `audit` key holding `audit`.
    fn audited(audit: V) -> V {
        obj(vec![
            ("keyset", obj(vec![("default", empty())])),
            ("audit", audit),
        ])
    }

    fn facts() -> V {
        obj(vec![
            ("purpose", V::Str("list issues".into())),
            ("rows", V::U32(250)),
            ("dry_run", V::Bool(false)),
            ("actor", V::Null),
            ("tables", V::Arr(vec![V::Str("users".into()), V::I32(-1)])),
            ("request", obj(vec![("id", V::Str("req_01J9Z3".into()))])),
        ])
    }

    fn facts_built() -> AuditMetadata {
        AuditMetadata::new()
            .with("purpose", "list issues")
            .with("rows", 250)
            .with("dry_run", false)
            .with("actor", None::<bool>)
            .with(
                "tables",
                vec![
                    stack_encrypt::AuditValue::from("users"),
                    stack_encrypt::AuditValue::from(-1),
                ],
            )
            .with("request", AuditMetadata::new().with("id", "req_01J9Z3"))
    }

    #[test]
    fn audit_is_read_as_the_facts_the_host_sent() {
        for export in Export::ALL {
            if !export.accepts().audit {
                continue;
            }
            assert_eq!(
                opts(audited(facts()), export).map(|options| options.audit),
                Ok(facts_built()),
                "{export:?}"
            );
            // An empty object is metadata with no facts, which sends nothing.
            let none = opts(audited(empty()), export).expect("an empty object");
            assert!(none.audit.is_empty(), "{export:?}");
        }
    }

    #[test]
    fn audit_is_an_object_of_values_zerokms_has_a_form_for() {
        let fact = |value: V| audited(obj(vec![("fact", value)]));
        for (label, bad) in [
            ("null", audited(V::Null)),
            ("a string", audited(V::Str("purpose".into()))),
            ("a list", audited(V::Arr(vec![]))),
            ("bytes", fact(V::Bytes(vec![1, 2, 3]))),
            ("bytes in a list", fact(V::Arr(vec![V::Bytes(vec![1])]))),
            (
                "an integer above a signed 64-bit integer",
                fact(V::U64(u64::MAX)),
            ),
            (
                "given twice",
                obj(vec![
                    ("keyset", obj(vec![("default", empty())])),
                    ("audit", empty()),
                    ("audit", empty()),
                ]),
            ),
            (
                "a fact given twice",
                audited(obj(vec![("fact", V::Bool(true)), ("fact", V::Bool(true))])),
            ),
        ] {
            assert_eq!(
                opts(bad, Export::DecryptRecord).err(),
                Some(STATUS_ENCODING),
                "{label} must be refused"
            );
        }
        // The largest integer that fits is read.
        let max = fact(V::U64(i64::MAX.unsigned_abs()));
        assert_eq!(
            opts(max, Export::DecryptRecord).map(|options| options.audit),
            Ok(AuditMetadata::new().with("fact", i64::MAX))
        );
    }
}

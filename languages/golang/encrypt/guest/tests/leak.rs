//! The leak test: no error this guest records carries a secret.
//!
//! Every error path a native test can reach is driven with marker values —
//! a marker plaintext, context, ciphertext, client key, access token and
//! ZeroKMS response body — exactly where a caller's data would be, through
//! the same functions the wasm exports run (`ops`, `options`, `config`, the
//! `status` mappers that record). Each failure's encoded error, the bytes
//! `se_last_error` would hand the host, is decoded and searched at every
//! depth, keys included: no marker may appear. The rule it enforces is
//! written on `ErrorPayload` in `stack-profile`.
//!
//! Each step runs through the real export lifecycle and its error is read
//! back through `se_last_error`'s packing. Each scenario also pins the codes
//! it reaches, so a path that stops being driven fails here, by name,
//! instead of quietly dropping out of the check.
//! Unreachable natively, and so not here: the host imports (`token_get`,
//! `transport_send`), whose failures arrive as stack-auth and ZeroKMS
//! errors the key-source and token scenarios below already encode.

use std::borrow::Cow;
use std::future::IntoFuture;

use stack_auth::{SecretToken, ServiceToken};
use stack_encrypt::dynamic::Scope;
use stack_encrypt::{CipherText, Descriptor, StackCipher};
use stack_encrypt_guest::options::{parse_options, Side};
use stack_encrypt_guest::status::fail_error;
use stack_encrypt_guest::{config, ops};
use stack_guest_abi::{call, last_error};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyError,
    GenerateKeyPayload, IndexKeySource, LoadKeysetError, RetrieveKeyError, RetrieveKeyPayload,
};
use uuid::Uuid;
use vitaminc_aead_value::{transport as codec, FfiValue};
use zerokms_protocol::{IdentifiedBy, UnverifiedContext, ViturRequestError};

const PLAINTEXT: &str = "leak-marker-plaintext";
const CONTEXT: &str = "leak-marker-context";
const CIPHERTEXT: &[u8] = b"leak-marker-ciphertext";
const CLIENT_KEY: &str = "leak-marker-client-key";
const ACCESS_TOKEN: &str = "leak-marker-access-token";
const ZEROKMS_BODY: &str = "leak-marker-zerokms-body";

const MARKERS: &[&[u8]] = &[
    PLAINTEXT.as_bytes(),
    CONTEXT.as_bytes(),
    CIPHERTEXT,
    CLIENT_KEY.as_bytes(),
    ACCESS_TOKEN.as_bytes(),
    ZEROKMS_BODY.as_bytes(),
];

fn block_on<F: IntoFuture>(f: F) -> F::Output {
    futures::executor::block_on(f.into_future())
}

// =============================================================================
// Key sources: a working one, and one whose every ZeroKMS answer is a failure
// carrying the marker body
// =============================================================================

/// A ZeroKMS failure response as the guest's connection classifies one,
/// with the marker as its body: nothing may copy it.
fn vitur(status: u16) -> ViturRequestError {
    stack_kms::classify_response::<String>(
        status,
        Some("application/json"),
        Some(ZEROKMS_BODY.as_bytes()),
        std::collections::HashMap::new(),
    )
    .expect_err("a failure status")
}

/// Index keys load for the default keyset and fail for a named one; every
/// data-key request fails. Each failure carries the marker body.
#[derive(Default)]
struct Failing(FakeDataKeySource);

impl DataKeySource for Failing {
    async fn generate_keys(
        &self,
        _payloads: Vec<GenerateKeyPayload<'_>>,
        _keyset_id: Option<Uuid>,
        _unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        Err(GenerateKeyError::RequestFailed(vitur(500)).into())
    }

    async fn retrieve_keys(
        &self,
        _payloads: Vec<RetrieveKeyPayload<'_>>,
        _keyset_id: Option<Uuid>,
        _unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        Err(RetrieveKeyError::FailedRetrieval(ZEROKMS_BODY.to_owned()).into())
    }
}

impl IndexKeySource for Failing {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, stack_kms::IndexKey), stack_kms::Error> {
        match keyset_id {
            None => self.0.load_index_key(None).await,
            Some(_) => Err(LoadKeysetError::KeysetNotFound(vitur(404)).into()),
        }
    }
}

fn cipher() -> StackCipher<FakeDataKeySource> {
    block_on(
        StackCipher::builder()
            .kms(FakeDataKeySource::default())
            .init(),
    )
    .expect("cipher")
}

fn failing() -> StackCipher<Failing> {
    block_on(StackCipher::builder().kms(Failing::default()).init()).expect("failing cipher")
}

// =============================================================================
// Values
// =============================================================================

fn encode(value: FfiValue) -> Vec<u8> {
    let mut out = Vec::new();
    codec::encode_value(value, &mut out).expect("encode");
    out
}

fn s(value: &str) -> FfiValue {
    FfiValue::String(value.into())
}

fn obj(entries: Vec<(&str, FfiValue)>) -> FfiValue {
    FfiValue::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

fn label(field: &str) -> FfiValue {
    FfiValue::Array(vec![s("users"), s(field)])
}

/// A field's label extended by a marker part: a context built from the
/// caller's data, as a tenant id is.
fn extended(field: &str, part: &str) -> FfiValue {
    FfiValue::Array(vec![label(field), s(part)])
}

fn field(context: FfiValue, outputs: &[&str], ty: Option<&str>) -> FfiValue {
    let mut spec = vec![
        ("context", context),
        (
            "outputs",
            FfiValue::Array(outputs.iter().map(|o| s(o)).collect()),
        ),
    ];
    if let Some(ty) = ty {
        spec.push(("type", s(ty)));
    }
    obj(spec)
}

/// `email` sealed and equality-indexed under `context`, typed string.
fn plan_under(context: FfiValue) -> Vec<u8> {
    encode(obj(vec![(
        "email",
        field(context, &["c", "eq"], Some("string")),
    )]))
}

fn row(email: &str) -> FfiValue {
    obj(vec![("email", s(email))])
}

fn sealed(cipher: &StackCipher<FakeDataKeySource>, plan: &[u8]) -> Vec<u8> {
    block_on(ops::encrypt_record(
        &cipher.default_keyset(),
        &encode(row(PLAINTEXT)),
        plan,
    ))
    .expect("seal")
}

/// A one-leaf ciphertext tree whose leaf is `leaf`, under `email`/`c`.
fn tree_with_leaf(leaf: CipherText<Vec<u8>, Box<dyn std::any::Any + Send>>) -> Vec<u8> {
    let tree: CipherText<Vec<u8>, Box<dyn std::any::Any + Send>> = CipherText::Map(vec![(
        "email".to_owned(),
        CipherText::Map(vec![("c".to_owned(), leaf)]),
    )]);
    let mut out = Vec::new();
    codec::encode_ciphertext_boxed(tree, &mut out).expect("encode tree");
    out
}

// =============================================================================
// Reading an encoded error
// =============================================================================

/// Run one failing step through the real export lifecycle
/// ([`call::run`]), read its error the way the host does, through
/// `se_last_error`'s packing ([`call::take_last_error`]), and check it has
/// the codes this scenario is there to reach: its own code, then its
/// causes'. Each scenario pins its own, so one that stops reaching the code
/// that could leak its marker fails by name.
fn failure<T: std::fmt::Debug>(
    what: &str,
    expect: &[&str],
    step: impl FnOnce() -> Result<T, u32>,
) -> FfiValue {
    let _ = call::run(step).expect_err(what);
    let bytes = call::take_last_error().unwrap_or_else(|| panic!("{what}: no error recorded"));
    let error = codec::decode_value(&mut codec::Reader::new(&bytes)).expect("an error decodes");
    assert_eq!(codes(&error), expect, "{what}: the codes it reaches");
    error
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Record every marker in `bytes` against the path `at`.
fn check(bytes: &[u8], at: &str, found: &mut Vec<String>) {
    for marker in MARKERS {
        if contains(bytes, marker) {
            found.push(format!("{at}: {}", String::from_utf8_lossy(marker)));
        }
    }
}

/// Every place in `value` a marker appears, as a path.
fn leaks(value: &FfiValue, path: &str, found: &mut Vec<String>) {
    match value {
        FfiValue::String(text) => check(text.risky_ref(), path, found),
        FfiValue::Bytes(bytes) => {
            use vitaminc_protected::Controlled;
            check(bytes.risky_ref(), path, found);
        }
        FfiValue::Array(items) => {
            for (at, item) in items.iter().enumerate() {
                leaks(item, &format!("{path}[{at}]"), found);
            }
        }
        FfiValue::Object(entries) => {
            for (key, item) in entries {
                check(key.as_bytes(), &format!("{path} key"), found);
                leaks(item, &format!("{path}.{key}"), found);
            }
        }
        FfiValue::Passthrough(inner) => leaks(inner, &format!("{path}(passthrough)"), found),
        _ => {}
    }
}

fn get<'a>(value: &'a FfiValue, key: &str) -> Option<&'a FfiValue> {
    match value {
        FfiValue::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn text(value: Option<&FfiValue>) -> Option<String> {
    match value? {
        FfiValue::String(s) => String::from_utf8(s.risky_ref().to_vec()).ok(),
        _ => None,
    }
}

/// The error's code and every cause's code.
fn codes(value: &FfiValue) -> Vec<String> {
    let mut out: Vec<String> = text(get(value, "code")).into_iter().collect();
    if let Some(FfiValue::Array(causes)) = get(value, "causes") {
        out.extend(causes.iter().filter_map(|cause| text(get(cause, "code"))));
    }
    out
}

// =============================================================================
// The scenarios
// =============================================================================

/// Every failing step, by what it drives.
fn scenarios() -> Vec<(&'static str, FfiValue)> {
    let cipher = cipher();
    let keyset = cipher.default_keyset();
    let failing = failing();
    let long_context = CONTEXT.repeat(30);
    let mut out = vec![
        // -- terms --------------------------------------------------------
        (
            "a context that is not codec bytes",
            failure("context", &["stack_guest_abi::malformed_input"], || {
                let context = [&[0xff][..], CONTEXT.as_bytes()].concat();
                block_on(ops::term(
                    &keyset,
                    &encode(s(PLAINTEXT)),
                    &context,
                    ops::TERM_EQUALITY,
                ))
            }),
        ),
        (
            "a context of a kind no context has",
            failure("context kind", &["stack_encrypt::dynamic_context"], || {
                block_on(ops::term(
                    &keyset,
                    &encode(s(PLAINTEXT)),
                    &encode(FfiValue::Bool(true)),
                    ops::TERM_EQUALITY,
                ))
            }),
        ),
        (
            "an equality term over a boolean",
            failure(
                "equality over a boolean",
                &["stack_encrypt::dynamic_term"],
                || {
                    block_on(ops::term(
                        &keyset,
                        &encode(FfiValue::Bool(true)),
                        &encode(s(CONTEXT)),
                        ops::TERM_EQUALITY,
                    ))
                },
            ),
        ),
        (
            "a term kind that is not one",
            failure("kind", &["stack_guest_abi::malformed_input"], || {
                block_on(ops::term(
                    &keyset,
                    &encode(s(PLAINTEXT)),
                    &encode(s(CONTEXT)),
                    99,
                ))
            }),
        ),
        (
            "match text with no tokens",
            failure("empty match", &["stack_encrypt::empty_term_text"], || {
                block_on(ops::term(
                    &keyset,
                    &encode(s("  ")),
                    &encode(s(CONTEXT)),
                    ops::TERM_MATCH,
                ))
            }),
        ),
        // -- plans --------------------------------------------------------
        (
            "a plan that is not codec bytes",
            failure("plan bytes", &["stack_guest_abi::malformed_input"], || {
                ops::plan_check(CONTEXT.as_bytes())
            }),
        ),
        (
            "a plan field context of a kind no context has",
            failure("plan context", &["stack_encrypt::dynamic_context"], || {
                ops::plan_check(&encode(obj(vec![(
                    "email",
                    field(FfiValue::Bool(true), &["c"], None),
                )])))
            }),
        ),
        (
            "an indexed field with no type",
            failure("untyped", &["stack_encrypt::dynamic_untyped_index"], || {
                ops::plan_check(&encode(obj(vec![(
                    "email",
                    field(label("email"), &["eq"], None),
                )])))
            }),
        ),
        (
            "an output that is not one",
            failure("output", &["stack_encrypt::dynamic_plan"], || {
                ops::plan_check(&encode(obj(vec![(
                    "email",
                    field(extended("email", CONTEXT), &["zz"], None),
                )])))
            }),
        ),
        (
            "a target this build cannot run",
            failure(
                "target",
                if cfg!(feature = "eql") {
                    &["stack_encrypt::target_unknown"]
                } else {
                    &["stack_encrypt::target_none"]
                },
                || {
                    ops::plan_check(&encode(obj(vec![(
                        "email",
                        obj(vec![("context", label("email")), ("target", s("Nope"))]),
                    )])))
                },
            ),
        ),
        // -- records ------------------------------------------------------
        (
            "a source value of another type",
            failure("source type", &["stack_encrypt::dynamic_source"], || {
                let plan = encode(obj(vec![(
                    "age",
                    field(label("age"), &["c", "ore"], Some("uint32")),
                )]));
                block_on(ops::encrypt_record(
                    &keyset,
                    &encode(obj(vec![("age", s(PLAINTEXT))])),
                    &plan,
                ))
            }),
        ),
        (
            "a passthrough under a sealed field",
            failure(
                "source passthrough",
                &["stack_encrypt::dynamic_source"],
                || {
                    let source = obj(vec![(
                        "email",
                        FfiValue::Passthrough(Box::new(s(PLAINTEXT))),
                    )]);
                    block_on(ops::encrypt_record(
                        &keyset,
                        &encode(source),
                        &plan_under(label("email")),
                    ))
                },
            ),
        ),
        (
            "a context too long for ZeroKMS",
            failure(
                "descriptor",
                &["stack_encrypt::descriptor_too_long"],
                || {
                    block_on(ops::encrypt_record(
                        &keyset,
                        &encode(row(PLAINTEXT)),
                        &plan_under(extended("email", &long_context)),
                    ))
                },
            ),
        ),
        (
            "a record that is not codec bytes",
            failure(
                "record bytes",
                &["stack_guest_abi::malformed_input"],
                || {
                    block_on(ops::decrypt_record(
                        Scope::Client(&cipher),
                        CIPHERTEXT,
                        &plan_under(label("email")),
                        None,
                    ))
                },
            ),
        ),
        (
            "a leaf that is not a sealed value",
            failure("leaf", &["stack_encrypt::leaf_version"], || {
                let record = tree_with_leaf(CipherText::Single(CIPHERTEXT.to_vec()));
                block_on(ops::decrypt_record(
                    Scope::Client(&cipher),
                    &record,
                    &plan_under(label("email")),
                    None,
                ))
            }),
        ),
        (
            "a passthrough under c",
            failure(
                "record passthrough",
                &["stack_encrypt::dynamic_record"],
                || {
                    let record = tree_with_leaf(CipherText::Passthrough(Box::new(
                        FfiValue::Bytes(vitaminc_protected::Protected::new(CIPHERTEXT.to_vec())),
                    )));
                    block_on(ops::decrypt_record(
                        Scope::Client(&cipher),
                        &record,
                        &plan_under(label("email")),
                        None,
                    ))
                },
            ),
        ),
        (
            "a record missing a field",
            failure("record field", &["stack_encrypt::dynamic_record"], || {
                let plan = encode(obj(vec![
                    ("email", field(label("email"), &["c"], None)),
                    ("nick", field(label("nick"), &["c"], None)),
                ]));
                let record = sealed(&cipher, &plan_under(label("email")));
                block_on(ops::decrypt_record(
                    Scope::Client(&cipher),
                    &record,
                    &plan,
                    None,
                ))
            }),
        ),
        (
            "a record opened under another context",
            failure("aead", &["stack_encrypt::aead"], || {
                let record = sealed(&cipher, &plan_under(label("email")));
                block_on(ops::decrypt_record(
                    Scope::Client(&cipher),
                    &record,
                    &plan_under(extended("email", CONTEXT)),
                    None,
                ))
            }),
        ),
        (
            "a record opened through another keyset",
            failure("foreign keyset", &["stack_encrypt::foreign_keyset"], || {
                let globex =
                    block_on(cipher.keyset(IdentifiedBy::Name("globex".to_owned().into())))
                        .expect("keyset");
                let record = sealed(&cipher, &plan_under(label("email")));
                block_on(ops::decrypt_record(
                    Scope::Keyset(globex),
                    &record,
                    &plan_under(label("email")),
                    None,
                ))
            }),
        ),
        // -- options ------------------------------------------------------
        (
            "options that are not an object",
            failure("options", &["stack_guest_abi::malformed_input"], || {
                parse_options(s(CONTEXT), Side::Open)
            }),
        ),
        // -- ZeroKMS, through a key source whose answers carry the body ---
        (
            "a data-key generation ZeroKMS refused",
            failure("generate", &["stack_kms::generate_key_failed"], || {
                block_on(ops::encrypt_record(
                    &failing.default_keyset(),
                    &encode(row(PLAINTEXT)),
                    &plan_under(label("email")),
                ))
            }),
        ),
        (
            "a data key ZeroKMS could not retrieve",
            failure("retrieve", &["stack_kms::key_not_retrieved"], || {
                let record = sealed(&cipher, &plan_under(label("email")));
                block_on(ops::decrypt_record(
                    Scope::Client(&failing),
                    &record,
                    &plan_under(label("email")),
                    None,
                ))
            }),
        ),
        (
            "a keyset ZeroKMS does not know",
            failure("keyset", &["stack_kms::keyset_not_found"], || {
                let options = parse_options(
                    obj(vec![("keyset", obj(vec![("name", s("tenant"))]))]),
                    Side::Mint,
                )?;
                block_on(options.keyset.resolve(&failing)).map(drop)
            }),
        ),
        // -- the access token ----------------------------------------------
        (
            "a token that is not a JWT",
            failure("token", &["stack_auth::invalid_token"], || {
                ServiceToken::new(SecretToken::new(ACCESS_TOKEN))
                    .zerokms_url()
                    .map_err(|e| fail_error(&stack_encrypt::Error::Kms(stack_kms::Error::Auth(e))))
            }),
        ),
        (
            "a token whose claims are not the claims",
            failure("claims", &["stack_auth::invalid_token"], || {
                use base64ct::{Base64UrlUnpadded, Encoding};
                let claims = format!(r#"{{"sub": "x", "iss": "x", "services": "{ACCESS_TOKEN}"}}"#);
                let jwt = format!(
                    "e30.{}.c2ln",
                    Base64UrlUnpadded::encode_string(claims.as_bytes())
                );
                ServiceToken::new(SecretToken::new(jwt))
                    .zerokms_url()
                    .map_err(|e| fail_error(&stack_encrypt::Error::Kms(stack_kms::Error::Auth(e))))
            }),
        ),
        // -- the config, which carries the client key ----------------------
        (
            "a client key that is not one",
            failure("config", &["stack_guest_abi::malformed_input"], || {
                let config = obj(vec![
                    ("client_id", s("6a1b8c6e-6f3a-4e43-9a3b-2f0f6f8b1c2d")),
                    ("client_key", s(CLIENT_KEY)),
                ]);
                config::parse_config(config)
                    .map(drop)
                    .map_err(|e| last_error::malformed(e.describe()))
            }),
        ),
        (
            "a config key this version does not know",
            failure("config key", &["stack_guest_abi::malformed_input"], || {
                config::parse_config(obj(vec![(CLIENT_KEY, s(CLIENT_KEY))]))
                    .map(drop)
                    .map_err(|e| last_error::malformed(e.describe()))
            }),
        ),
        // -- an error no native path raises, recorded the same way ---------
        (
            "a stored context that does not match",
            failure(
                "context mismatch",
                &["stack_encrypt::context_mismatch"],
                || {
                    Err::<(), _>(fail_error(&stack_encrypt::Error::ContextMismatch {
                        stored: Descriptor::of(("tenant", CONTEXT)),
                    }))
                },
            ),
        ),
    ];
    // An EQL value whose stored bytes are a JSON string where an object
    // belongs: serde_json's message would quote the string.
    #[cfg(feature = "eql")]
    out.push((
        "stored EQL bytes that do not parse",
        failure("eql stored", &["stack_encrypt::target_stored"], || {
            let plan = encode(obj(vec![(
                "email",
                obj(vec![("context", label("email")), ("target", s("TextEq"))]),
            )]));
            let tree: CipherText<Vec<u8>, Box<dyn std::any::Any + Send>> = CipherText::Map(vec![(
                "email".to_owned(),
                CipherText::Map(vec![(
                    "eql".to_owned(),
                    CipherText::Passthrough(Box::new(FfiValue::Bytes(
                        vitaminc_protected::Protected::new(
                            [&b"\""[..], CIPHERTEXT, &b"\""[..]].concat(),
                        ),
                    ))),
                )]),
            )]);
            let mut record = Vec::new();
            codec::encode_ciphertext_boxed(tree, &mut record).expect("encode tree");
            block_on(ops::decrypt_record(
                Scope::Client(&cipher),
                &record,
                &plan,
                None,
            ))
        }),
    ));
    // A cause from another library this guest does not vouch for: the PRF
    // backend's error is reported by its type, never its message.
    out.push((
        "a cause no one vouches for",
        failure("prf", &["stack_encrypt::prf_failed"], || {
            Err::<(), _>(fail_error(&stack_encrypt::Error::Term(
                stack_encrypt::sem::TermError::Prf(Box::new(std::io::Error::other(ZEROKMS_BODY))),
            )))
        }),
    ));
    out
}

#[test]
fn no_encoded_error_carries_a_marker() {
    let mut found = Vec::new();
    for (what, error) in scenarios() {
        leaks(&error, what, &mut found);
        assert!(
            text(get(&error, "message")).is_some_and(|m| !m.is_empty()),
            "{what}: every error has a message"
        );
        assert!(
            text(get(&error, "code")).is_some(),
            "{what}: every error has a code"
        );
    }
    assert!(
        found.is_empty(),
        "markers in encoded errors:\n{}",
        found.join("\n")
    );
}

/// The marker check itself: a value carrying one is caught, in a string, in
/// bytes, in a key and in a cause.
#[test]
fn the_marker_check_finds_a_marker_at_any_depth() {
    let carrying = obj(vec![
        ("message", s(&format!("x {PLAINTEXT} y"))),
        (
            "causes",
            FfiValue::Array(vec![obj(vec![(
                CONTEXT,
                FfiValue::Bytes(vitaminc_protected::Protected::new(CIPHERTEXT.to_vec())),
            )])]),
        ),
    ]);
    let mut found = Vec::new();
    leaks(&carrying, "error", &mut found);
    assert_eq!(found.len(), 3, "{found:?}");
}

/// A ZeroKMS failure's cause names the request and the status, and the
/// keyset-not-found help reaches the host.
#[test]
fn a_keyset_not_found_carries_its_help_and_request_kind() {
    let failing = failing();
    let error = failure("keyset", &["stack_kms::keyset_not_found"], || {
        let options = parse_options(
            obj(vec![("keyset", obj(vec![("name", s("tenant"))]))]),
            Side::Mint,
        )?;
        block_on(options.keyset.resolve(&failing)).map(drop)
    });
    assert_eq!(
        text(get(&error, "code")).as_deref(),
        Some("stack_kms::keyset_not_found")
    );
    assert!(text(get(&error, "help")).is_some_and(|help| help.contains("client is unknown")));
    let fields = get(&error, "fields").expect("fields");
    assert_eq!(
        text(get(fields, "request_kind")).as_deref(),
        Some("NotFound")
    );
    let Some(FfiValue::Array(causes)) = get(&error, "causes") else {
        panic!("causes");
    };
    let messages: Vec<String> = causes
        .iter()
        .filter_map(|c| text(get(c, "message")))
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("ZeroKMS request failed")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m == "ZeroKMS responded with status 404"),
        "{messages:?}"
    );
}

/// The foreign-keyset error carries both keyset ids as fields, which the Go
/// side exposes as typed accessors.
#[test]
fn a_foreign_keyset_carries_both_keyset_ids() {
    let cipher = cipher();
    let globex =
        block_on(cipher.keyset(IdentifiedBy::Name("globex".to_owned().into()))).expect("keyset");
    let globex_id = globex.keyset_id();
    let record = sealed(&cipher, &plan_under(label("email")));
    let error = failure("foreign", &["stack_encrypt::foreign_keyset"], || {
        block_on(ops::decrypt_record(
            Scope::Keyset(globex),
            &record,
            &plan_under(label("email")),
            None,
        ))
    });
    let fields = get(&error, "fields").expect("fields");
    assert_eq!(text(get(fields, "expected")), Some(globex_id.to_string()));
    assert_eq!(
        text(get(fields, "found")),
        Some(cipher.default_keyset().keyset_id().to_string())
    );
}

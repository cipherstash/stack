//! [`Cipher`] and [`Keyset`]: the engine, and the calls that run on it.
//!
//! Each call reads its arguments on the JavaScript thread, then runs the
//! engine's future on napi's runtime, holding only what it owns: the
//! engine (shared by every handle of one cipher) and the values read. The
//! future is `Send` and `'static`, which `spawn_future_with_callback`
//! requires, so this compiles only because the engine's pending calls are.

use std::sync::Arc;

use napi::bindgen_prelude::{JavaScriptClassExt, JsValue, Object, PromiseRaw, Unknown};
use napi::Env;
use napi_derive::napi;
use stack_encrypt::dynamic::{ValueFrame, ValueKind};
use stack_encrypt::kms::{DataKeySource, IndexKeySource, StackKms};
use stack_encrypt::{CipherRef, DecryptFrom, EncryptInto, KeysetCipher, StackCipher};
use vitaminc_protected::OpaqueDebug;

use crate::ciphertext::Ciphertext;
use crate::error::{ErrorKind, RecipherErrorFields};
use crate::js;
use crate::json::Json;
use crate::outcome::{not_made, refused, spawn, Outcome};
use crate::record::{field_value, one_field_row, open_rows, seal_rows, RecordPlan};
use crate::value::OneValue;
use napi::bindgen_prelude::ToNapiValue;

/// The engine cipher, over the key source it was built with. A napi class
/// cannot be generic, so the two key sources are the two variants.
#[derive(OpaqueDebug)]
enum Engine {
    /// Over ZeroKMS, with the credentials the engine detected.
    Detected(Box<StackCipher<StackKms<stack_auth::AutoStrategy>>>),
    /// Over the engine's deterministic test key source.
    #[cfg(feature = "testing")]
    Testing(Box<StackCipher<stack_encrypt::kms::DeterministicSource>>),
}

/// Run `$body` with `$cipher` bound to the engine cipher, whatever its key
/// source.
macro_rules! with_engine {
    ($engine:expr, |$cipher:ident| $body:expr) => {
        match $engine {
            Engine::Detected($cipher) => $body,
            #[cfg(feature = "testing")]
            Engine::Testing($cipher) => $body,
        }
    };
}

/// A cipher: the engine, and the keysets it reaches.
///
/// Build one with `Cipher.create()`, or, in a test, with `testCipher()`
/// from `@cipherstash/recipher/testing`. It has no constructor.
#[napi]
#[derive(OpaqueDebug)]
pub struct Cipher {
    engine: Arc<Engine>,
}

/// One keyset of a cipher. Every data key is made under one keyset, and a
/// ciphertext names the keyset it was made under.
///
/// Get one from `cipher.defaultKeyset()`. It has no constructor.
#[napi]
#[derive(OpaqueDebug)]
pub struct Keyset {
    engine: Arc<Engine>,
}

#[napi]
impl Cipher {
    /// A cipher over ZeroKMS, with the credentials the engine finds: the
    /// `CS_*` variables, then the profile `stash auth login` writes.
    ///
    /// Resolves to a failure of kind `credential` when there are none or
    /// they are refused, and of kind `zerokms` when ZeroKMS refuses to load
    /// the default keyset.
    ///
    /// `options.records` are declarations to check now, before any
    /// credential is looked for: a declaration the engine refuses is a
    /// failure of kind `declaration`, naming the record.
    // Configurable, as an instance method is, so the package's TypeScript
    // can wrap it (`adapt`).
    #[napi(configurable = true, ts_return_type = "Promise<Outcome<Cipher>>")]
    pub fn create<'e>(
        env: &'e Env,
        options: Option<Unknown<'_>>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        if let Err(error) = records_of_options(env, options)
            .and_then(|records| records.map(|records| check(env, records)).unwrap_or(Ok(())))
        {
            return refused(env, error);
        }
        spawn(
            env,
            async {
                StackCipher::with_detected_credentials()
                    .await
                    .map(|cipher| Engine::Detected(Box::new(cipher)))
                    .map_err(|error| RecipherErrorFields::engine(&error))
            },
            cipher_value,
        )
    }

    /// The client's default keyset: the one a ZeroKMS administrator set for
    /// it. Encrypting needs a keyset.
    #[napi]
    pub fn default_keyset(&self) -> Keyset {
        Keyset {
            engine: Arc::clone(&self.engine),
        }
    }

    /// Open a ciphertext from any of this cipher's keysets, as the value it
    /// was sealed as, or an array of them. With a record first, open its
    /// stored row, or an array of them, in one key request for each keyset
    /// they were sealed under.
    #[napi(ts_return_type = "Promise<Outcome<unknown>>")]
    pub fn decrypt<'e>(
        &self,
        env: &'e Env,
        first: Unknown<'_>,
        second: Option<Unknown<'_>>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        if js::is_record(env, &first) {
            return open_rows_of(env, &self.engine, first, second, Confined::No);
        }
        if let Some(error) = js::second_without_record(env, &first, second.as_ref()) {
            return refused(env, error);
        }
        open(env, &self.engine, first, Confined::No)
    }

    /// Open one field of a record's stored row, as `encryptField` or
    /// `encrypt` stored it, or an array of them in one key request.
    #[napi(ts_return_type = "Promise<Outcome<unknown>>")]
    pub fn decrypt_field<'e>(
        &self,
        env: &'e Env,
        record: Unknown<'_>,
        field: Unknown<'_>,
        stored: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        open_field(env, &self.engine, record, field, stored, Confined::No)
    }

    /// Names the type.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Cipher"
    }
}

#[napi]
impl Keyset {
    /// Encrypt a value, with no context, as one ciphertext with its own data
    /// key. An array of values is an array of ciphertexts, in the same
    /// order, made with one key request however long it is. All or nothing:
    /// one value refused is a failure for the whole array, before any
    /// request.
    ///
    /// A value's type picks how it is encrypted, by vitaminc's mapping for
    /// JavaScript. A `Json` from `json(..)` is encrypted as a JSON document.
    ///
    /// With a record first, encrypt its row, or an array of them in one key
    /// request: each field under its field path.
    #[napi(ts_return_type = "Promise<Outcome<unknown>>")]
    pub fn encrypt<'e>(
        &self,
        env: &'e Env,
        first: Unknown<'_>,
        second: Option<Unknown<'_>>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        if js::is_record(env, &first) {
            return seal_rows_of(env, &self.engine, first, second);
        }
        if let Some(error) = js::second_without_record(env, &first, second.as_ref()) {
            return refused(env, error);
        }
        let value = first;
        let (many, values) = match js::elements(env, value) {
            Some(Ok(elements)) => (true, elements),
            Some(Err(error)) => return refused(env, error),
            None => (false, vec![value]),
        };
        let mut sealable = Vec::with_capacity(values.len());
        let mut opens_as = Vec::with_capacity(values.len());
        for value in values {
            match one_value(env, value) {
                Ok((value, kind)) => {
                    sealable.push(value);
                    opens_as.push(kind);
                }
                Err(error) => return refused(env, error),
            }
        }
        let engine = Arc::clone(&self.engine);
        spawn(
            env,
            async move {
                with_engine!(&*engine, |cipher| {
                    seal(&cipher.default_keyset(), sealable).await
                })
            },
            move |env, sealed| {
                let mut instances = sealed
                    .into_iter()
                    .zip(opens_as)
                    .map(|(sealed, opens_as)| {
                        Ok(Ciphertext::new(sealed, opens_as)
                            .into_instance(env)
                            .map_err(not_made)?
                            .to_unknown())
                    })
                    .collect::<Outcome<Vec<_>>>()?;
                if many {
                    return instances.into_unknown(env).map_err(not_made);
                }
                instances.pop().ok_or_else(|| {
                    RecipherErrorFields::internal("recipher::outcome", "the engine sealed no value")
                })
            },
        )
    }

    /// Open a ciphertext sealed under this keyset, or an array of them. A
    /// ciphertext of another keyset is a failure of kind `foreign_keyset`,
    /// before any key is requested. With a record first, open its stored
    /// row, or an array of them.
    #[napi(ts_return_type = "Promise<Outcome<unknown>>")]
    pub fn decrypt<'e>(
        &self,
        env: &'e Env,
        first: Unknown<'_>,
        second: Option<Unknown<'_>>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        if js::is_record(env, &first) {
            return open_rows_of(env, &self.engine, first, second, Confined::ToDefault);
        }
        if let Some(error) = js::second_without_record(env, &first, second.as_ref()) {
            return refused(env, error);
        }
        open(env, &self.engine, first, Confined::ToDefault)
    }

    /// Encrypt one field of a record, for an update of that field: its
    /// stored form, as the field has it in a whole stored row. An array of
    /// values is an array of stored fields, in one key request.
    #[napi(ts_return_type = "Promise<Outcome<unknown>>")]
    pub fn encrypt_field<'e>(
        &self,
        env: &'e Env,
        record: Unknown<'_>,
        field: Unknown<'_>,
        value: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        seal_field(env, &self.engine, record, field, value)
    }

    /// Open one field of a record's stored row sealed under this keyset, or
    /// an array of them in one key request.
    #[napi(ts_return_type = "Promise<Outcome<unknown>>")]
    pub fn decrypt_field<'e>(
        &self,
        env: &'e Env,
        record: Unknown<'_>,
        field: Unknown<'_>,
        stored: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        open_field(
            env,
            &self.engine,
            record,
            field,
            stored,
            Confined::ToDefault,
        )
    }

    /// Names the type.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Keyset"
    }
}

/// A cipher over the engine's deterministic test keys, from a 32-byte seed:
/// every key is a function of the seed and the value's context, so a value
/// sealed by one test cipher opens in another with the same seed. It needs
/// no credentials and makes no request. Its keys are no secret from anyone
/// who knows the seed.
///
/// Only a build with the `testing` feature has one; any other resolves to
/// a failure of kind `internal`, code `recipher::no_testing`.
#[napi(ts_return_type = "Promise<Outcome<Cipher>>")]
pub fn create_testing<'e>(
    env: &'e Env,
    seed: Unknown<'_>,
) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
    let seed = crate::ciphertext::bytes_of(seed).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    let Some(seed) = seed else {
        return refused(
            env,
            RecipherErrorFields::new(
                ErrorKind::Value,
                "recipher::testing_seed",
                "a test cipher's seed is a Uint8Array of 32 bytes",
            ),
        );
    };
    testing(env, seed)
}

#[cfg(feature = "testing")]
fn testing(env: &Env, seed: [u8; 32]) -> napi::Result<PromiseRaw<'_, Object<'_>>> {
    spawn(
        env,
        async move {
            StackCipher::builder()
                .kms(stack_encrypt::kms::DeterministicSource::new(seed))
                .init()
                .await
                .map(|cipher| Engine::Testing(Box::new(cipher)))
                .map_err(|error| RecipherErrorFields::engine(&error))
        },
        cipher_value,
    )
}

#[cfg(not(feature = "testing"))]
fn testing(env: &Env, _seed: [u8; 32]) -> napi::Result<PromiseRaw<'_, Object<'_>>> {
    refused(env, no_testing())
}

/// The failure of `createTesting` in a build without the test cipher.
#[cfg_attr(feature = "testing", allow(dead_code))]
fn no_testing() -> RecipherErrorFields {
    RecipherErrorFields::internal(
        "recipher::no_testing",
        "this native build has no test cipher. Build it with \
         `pnpm --filter @cipherstash/recipher build:debug`.",
    )
}

/// A new cipher's JavaScript value.
fn cipher_value(env: &Env, engine: Engine) -> Outcome<Unknown<'_>> {
    Ok(Cipher {
        engine: Arc::new(engine),
    }
    .into_instance(env)
    .map_err(not_made)?
    .to_unknown())
}

/// Which keysets a decrypt opens a value of.
#[derive(Clone, Copy)]
enum Confined {
    /// Any of the cipher's.
    No,
    /// The default keyset's alone.
    ToDefault,
}

/// Open a ciphertext, or an array of them, as `cipher.decrypt` and
/// `keyset.decrypt` do.
fn open<'e>(
    env: &'e Env,
    engine: &Arc<Engine>,
    value: Unknown<'_>,
    confined: Confined,
) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
    let (many, values) = match js::elements(env, value) {
        Some(Ok(elements)) => (true, elements),
        Some(Err(error)) => return refused(env, error),
        None => (false, vec![value]),
    };
    let mut ciphertexts = Vec::with_capacity(values.len());
    for value in values {
        match Ciphertext::of(env, value) {
            Some(ciphertext) => ciphertexts.push(ciphertext),
            None => {
                return refused(
                    env,
                    RecipherErrorFields::new(
                        ErrorKind::Value,
                        "recipher::not_a_ciphertext",
                        "decrypt takes a Ciphertext, or an array of them; read stored bytes \
                         with Ciphertext.fromBytes",
                    ),
                )
            }
        }
    }
    let sealed = ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.sealed().clone())
        .collect();
    let engine = Arc::clone(engine);
    spawn(
        env,
        async move {
            let opened = with_engine!(&*engine, |cipher| match confined {
                Confined::No => unseal(&**cipher, sealed).await,
                Confined::ToDefault => unseal(&cipher.default_keyset(), sealed).await,
            })?;
            opened
                .into_iter()
                .zip(&ciphertexts)
                .map(|(value, ciphertext)| ciphertext.opened(value))
                .collect::<Outcome<Vec<_>>>()
        },
        move |env, opened| {
            let mut values = opened
                .into_iter()
                .map(|value| js::build(env, value))
                .collect::<Outcome<Vec<_>>>()?;
            if many {
                return values.into_unknown(env).map_err(not_made);
            }
            values.pop().ok_or_else(|| {
                RecipherErrorFields::internal("recipher::outcome", "the engine opened no value")
            })
        },
    )
}

/// One value to seal, and the kind its ciphertext opens as: a `Json`'s
/// document, which opens as JSON, or any other value, which opens as what
/// it was sealed as.
fn one_value(env: &Env, value: Unknown<'_>) -> Outcome<(OneValue, Option<ValueKind>)> {
    if let Some(document) = Json::of(env, value) {
        return Ok((OneValue::json(document?), Some(ValueKind::Json)));
    }
    Ok((OneValue::scalar(js::read(env, value)?)?, None))
}

/// Check declarations with the engine, with no credentials and no
/// request: for a test or a CI step. The first refusal is the failure, of
/// kind `declaration`, naming the record and, where there is one, the
/// field.
#[napi(ts_return_type = "Outcome<undefined>")]
pub fn check_declarations<'e>(env: &'e Env, records: Unknown<'_>) -> napi::Result<Object<'e>> {
    let checked = check(env, records);
    crate::outcome::settle(env, checked, |env, ()| {
        ().into_unknown(env).map_err(not_made)
    })
}

/// Build the plan of each declaration in `records`, an array of them.
fn check(env: &Env, records: Unknown<'_>) -> Outcome<()> {
    let records = match js::elements(env, records) {
        Some(records) => records?,
        None => vec![records],
    };
    for record in records {
        let _ = plan_of(env, record)?;
    }
    Ok(())
}

/// The `records` of `Cipher.create`'s options, if it names any.
fn records_of_options<'e>(env: &Env, options: Option<Unknown<'e>>) -> Outcome<Option<Unknown<'e>>> {
    match options {
        None => Ok(None),
        Some(options) => js::property(env, options, "records"),
    }
}

/// The plan of the declaration `record`.
fn plan_of(env: &Env, record: Unknown<'_>) -> Outcome<Arc<RecordPlan>> {
    if !js::is_record(env, &record) {
        return Err(RecipherErrorFields::new(
            ErrorKind::Declaration,
            "recipher::not_a_record",
            "a record is declared with record(..)",
        ));
    }
    RecordPlan::of(&js::read(env, record)?)
}

/// The values of `value`: its elements when it is an array, and whether it
/// was one.
fn one_or_many<'e>(env: &Env, value: Unknown<'e>) -> Outcome<(bool, Vec<Unknown<'e>>)> {
    match js::elements(env, value) {
        Some(elements) => Ok((true, elements?)),
        None => Ok((false, vec![value])),
    }
}

/// One JavaScript value for each result, or the one result alone.
fn one_or_array<'e>(
    env: &'e Env,
    many: bool,
    mut values: Vec<Unknown<'e>>,
) -> Outcome<Unknown<'e>> {
    if many {
        return values.into_unknown(env).map_err(not_made);
    }
    values.pop().ok_or_else(|| {
        RecipherErrorFields::internal("recipher::outcome", "the engine returned no result")
    })
}

/// A row of `plan`'s record, read and each field read as its kind. A value
/// vitaminc refuses is named by the field it was read from.
fn read_row(env: &Env, plan: &RecordPlan, row: Unknown<'_>) -> Outcome<ValueFrame> {
    let not_a_row = || {
        let mut error = RecipherErrorFields::new(
            ErrorKind::Value,
            "recipher::not_a_row",
            "a row is an object of the record's fields",
        );
        error.record = Some(plan.name().to_owned());
        error
    };
    if row.get_type().ok() != Some(napi::ValueType::Object) || row.is_array().unwrap_or(false) {
        return Err(not_a_row());
    }
    let frame = js::read(env, row).map_err(|mut error| {
        error.record = Some(plan.name().to_owned());
        error.field = plan
            .field_names()
            .find(|name| {
                js::property(env, row, name)
                    .map(|value| value.is_some_and(|value| js::read(env, value).is_err()))
                    .unwrap_or(true)
            })
            .map(str::to_owned);
        error
    })?;
    crate::record::conform_row(plan, &frame)
}

/// `keyset.encrypt(record, row | rows)`.
fn seal_rows_of<'e>(
    env: &'e Env,
    engine: &Arc<Engine>,
    record: Unknown<'_>,
    rows: Option<Unknown<'_>>,
) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
    let read = || -> Outcome<(Arc<RecordPlan>, bool, Vec<ValueFrame>)> {
        let plan = plan_of(env, record)?;
        let rows = rows.unwrap_or(().into_unknown(env).map_err(not_made)?);
        let (many, rows) = one_or_many(env, rows)?;
        let rows = rows
            .into_iter()
            .map(|row| read_row(env, &plan, row))
            .collect::<Outcome<Vec<_>>>()?;
        Ok((plan, many, rows))
    };
    let (plan, many, rows) = match read() {
        Ok(read) => read,
        Err(error) => return refused(env, error),
    };
    let engine = Arc::clone(engine);
    spawn(
        env,
        async move {
            with_engine!(&*engine, |cipher| {
                seal_rows(&cipher.default_keyset(), plan, rows).await
            })
        },
        move |env, stored| {
            let values = stored
                .into_iter()
                .map(|row| js::build(env, row))
                .collect::<Outcome<Vec<_>>>()?;
            one_or_array(env, many, values)
        },
    )
}

/// `cipher.decrypt(record, stored | stored[])` and `keyset.decrypt`.
fn open_rows_of<'e>(
    env: &'e Env,
    engine: &Arc<Engine>,
    record: Unknown<'_>,
    stored: Option<Unknown<'_>>,
    confined: Confined,
) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
    let read = || -> Outcome<(Arc<RecordPlan>, bool, Vec<ValueFrame>)> {
        let plan = plan_of(env, record)?;
        let stored = stored.unwrap_or(().into_unknown(env).map_err(not_made)?);
        let (many, rows) = one_or_many(env, stored)?;
        let rows = rows
            .into_iter()
            .map(|row| {
                js::read(env, row).map_err(|mut error| {
                    error.record = Some(plan.name().to_owned());
                    error
                })
            })
            .collect::<Outcome<Vec<_>>>()?;
        Ok((plan, many, rows))
    };
    let (plan, many, rows) = match read() {
        Ok(read) => read,
        Err(error) => return refused(env, error),
    };
    let engine = Arc::clone(engine);
    let names: Vec<String> = plan.field_names().map(str::to_owned).collect();
    let record_name = plan.name().to_owned();
    spawn(
        env,
        async move {
            with_engine!(&*engine, |cipher| match confined {
                Confined::No => open_rows(&**cipher, plan, rows).await,
                Confined::ToDefault => open_rows(&cipher.default_keyset(), plan, rows).await,
            })
        },
        move |env, opened| {
            let values = opened
                .into_iter()
                .map(|row| js::hidden(env, js::build(env, row)?, &record_name, &names))
                .collect::<Outcome<Vec<_>>>()?;
            one_or_array(env, many, values)
        },
    )
}

/// The plan of `field` of `record` alone, and the field's name.
fn field_plan_of(
    env: &Env,
    record: Unknown<'_>,
    field: Unknown<'_>,
) -> Outcome<(Arc<RecordPlan>, String)> {
    let plan = plan_of(env, record)?;
    let name = js::string(field).ok_or_else(|| {
        let mut error = RecipherErrorFields::new(
            ErrorKind::Declaration,
            "recipher::no_field",
            "a field is named by a string",
        );
        error.record = Some(plan.name().to_owned());
        error
    })?;
    Ok((plan.field(&name)?, name))
}

/// `keyset.encryptField(record, field, value | values)`.
fn seal_field<'e>(
    env: &'e Env,
    engine: &Arc<Engine>,
    record: Unknown<'_>,
    field: Unknown<'_>,
    value: Unknown<'_>,
) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
    let read = || -> Outcome<(Arc<RecordPlan>, String, bool, Vec<ValueFrame>)> {
        let (plan, name) = field_plan_of(env, record, field)?;
        let (many, values) = one_or_many(env, value)?;
        let rows = values
            .into_iter()
            .map(|value| {
                let value = js::read(env, value).map_err(|mut error| {
                    error.record = Some(plan.name().to_owned());
                    error.field = Some(name.clone());
                    error
                })?;
                crate::record::conform_row(&plan, &one_field_row(&name, &value)?)
            })
            .collect::<Outcome<Vec<_>>>()?;
        Ok((plan, name, many, rows))
    };
    let (plan, name, many, rows) = match read() {
        Ok(read) => read,
        Err(error) => return refused(env, error),
    };
    let engine = Arc::clone(engine);
    spawn(
        env,
        async move {
            with_engine!(&*engine, |cipher| {
                seal_rows(&cipher.default_keyset(), plan, rows).await
            })
        },
        move |env, stored| {
            let values = stored
                .iter()
                .map(|row| js::build(env, field_value(row, &name)?))
                .collect::<Outcome<Vec<_>>>()?;
            one_or_array(env, many, values)
        },
    )
}

/// `cipher.decryptField(record, field, stored | stored[])` and
/// `keyset.decryptField`.
fn open_field<'e>(
    env: &'e Env,
    engine: &Arc<Engine>,
    record: Unknown<'_>,
    field: Unknown<'_>,
    stored: Unknown<'_>,
    confined: Confined,
) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
    let read = || -> Outcome<(Arc<RecordPlan>, String, bool, Vec<ValueFrame>)> {
        let (plan, name) = field_plan_of(env, record, field)?;
        let (many, values) = one_or_many(env, stored)?;
        let rows = values
            .into_iter()
            .map(|value| {
                let value = js::read(env, value).map_err(|mut error| {
                    error.record = Some(plan.name().to_owned());
                    error.field = Some(name.clone());
                    error
                })?;
                one_field_row(&name, &value)
            })
            .collect::<Outcome<Vec<_>>>()?;
        Ok((plan, name, many, rows))
    };
    let (plan, name, many, rows) = match read() {
        Ok(read) => read,
        Err(error) => return refused(env, error),
    };
    let engine = Arc::clone(engine);
    spawn(
        env,
        async move {
            let opened = with_engine!(&*engine, |cipher| match confined {
                Confined::No => open_rows(&**cipher, plan, rows).await,
                Confined::ToDefault => open_rows(&cipher.default_keyset(), plan, rows).await,
            })?;
            opened
                .iter()
                .map(|row| field_value(row, &name))
                .collect::<Outcome<Vec<_>>>()
        },
        move |env, values| {
            let values = values
                .into_iter()
                .map(|value| js::build(env, value))
                .collect::<Outcome<Vec<_>>>()?;
            one_or_array(env, many, values)
        },
    )
}

/// Seal values under `keyset`, each as one ciphertext with its own data
/// key, in one key request however many there are.
pub(crate) async fn seal<K>(
    keyset: &KeysetCipher<'_, K>,
    values: Vec<OneValue>,
) -> Outcome<Vec<stack_encrypt::Ciphertext>>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    values
        .encrypt_into::<Vec<stack_encrypt::Ciphertext>, K>(keyset)
        .await
        .map_err(|error| match error {
            // No ciphertext exists yet, so this is the value, not damage.
            stack_encrypt::Error::Aead => RecipherErrorFields::new(
                ErrorKind::Value,
                "recipher::not_sealed",
                "the engine could not seal the value as given",
            ),
            error => RecipherErrorFields::engine(&error),
        })
}

/// Open ciphertexts through `cipher` (a cipher, or one keyset of it), in
/// one key request for each keyset they were sealed under.
pub(crate) async fn unseal<'c, K>(
    cipher: impl Into<CipherRef<'c, K>>,
    sealed: Vec<stack_encrypt::Ciphertext>,
) -> Outcome<Vec<ValueFrame>>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    Vec::<ValueFrame>::decrypt_from(sealed, cipher)
        .await
        .map_err(|error| RecipherErrorFields::engine(&error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_build_without_the_test_cipher_says_how_to_get_one() {
        let error = no_testing();
        assert_eq!(error.kind, ErrorKind::Internal);
        assert_eq!(error.code, "recipher::no_testing");
        assert!(error.message.contains("build:debug"));
    }
}

//! The [`Cipher`] and [`Keyset`] classes, and the calls that run on the
//! engine. The engine is the Stack Encrypt engine, the `stack-encrypt`
//! crate.
//!
//! Each call reads its arguments on the JavaScript thread. The call then
//! runs the engine's future on napi's runtime. The future owns everything
//! it uses: the engine and the values read. Every `Cipher` and `Keyset`
//! object of one cipher shares the same engine.
//!
//! `spawn_future_with_callback` requires the future to be `Send` and
//! `'static`. So this module compiles only because the engine's pending
//! calls are `Send` and `'static` too.

use std::sync::Arc;

use napi::bindgen_prelude::{JavaScriptClassExt, JsValue, Object, PromiseRaw, Unknown};
use napi::Env;
use napi_derive::napi;
use stack_encrypt::dynamic::{ValueFrame, ValueKind};
use stack_encrypt::kms::{DataKeySource, IndexKeySource, StackKms};
use stack_encrypt::{CipherRef, DecryptFrom, EncryptInto, KeysetCipher, StackCipher};
use vitaminc_protected::OpaqueDebug;

use crate::ciphertext::Ciphertext;
use crate::error::{Error, RecipherErrorFields};
use crate::js;
use crate::json::Json;
use crate::outcome::{not_made, refused, spawn, Outcome};
use crate::record::{field_value, one_field_row, open_rows, seal_rows, RecordPlan};
use crate::value::OneValue;
use napi::bindgen_prelude::ToNapiValue;

/// The engine's cipher, with the key source it was built with. A napi class
/// cannot be generic, so each key source is one variant.
#[derive(OpaqueDebug)]
enum Engine {
    /// Keys from ZeroKMS, with the credentials the engine found.
    Detected(Box<StackCipher<StackKms<stack_auth::AutoStrategy>>>),
    /// Keys from the engine's deterministic test key source.
    #[cfg(feature = "testing")]
    Testing(Box<StackCipher<stack_encrypt::kms::DeterministicSource>>),
}

/// Runs `$body` with `$cipher` bound to the engine's cipher, for either key
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

/// A cipher: the engine, and the keysets it can use. A keyset is a group
/// of keys in ZeroKMS, CipherStash's key service.
///
/// Make a cipher with `Cipher.create()`. In a test, make one with
/// `testCipher()` from `@cipherstash/recipher/testing`. The class has no
/// constructor.
#[napi]
#[derive(OpaqueDebug)]
pub struct Cipher {
    engine: Arc<Engine>,
}

/// One keyset of a cipher. A data key is the key that encrypts one value.
/// Each data key is made under one keyset. A ciphertext names the keyset it
/// was made under.
///
/// Get a keyset from `cipher.defaultKeyset()`. The class has no
/// constructor.
#[napi]
#[derive(OpaqueDebug)]
pub struct Keyset {
    engine: Arc<Engine>,
}

#[napi]
impl Cipher {
    /// Makes a cipher that gets its keys from ZeroKMS. The engine looks for
    /// credentials in the `CS_*` environment variables first, then in the
    /// profile that `stash auth login` writes.
    ///
    /// The promise resolves to the engine's error in these cases:
    ///
    /// - there are no credentials;
    /// - the credentials are refused;
    /// - ZeroKMS refuses to load the default keyset.
    ///
    /// `options.records` lists record declarations to check now, before the
    /// engine looks for credentials. If the engine refuses a declaration,
    /// the result is a failure that names the record.
    // An instance method is configurable. This static method is made
    // configurable too, so the package's TypeScript can wrap it (`adapt`).
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

    /// Returns the client's default keyset: the keyset that a ZeroKMS
    /// administrator set for this client. Encrypting needs a keyset.
    #[napi]
    pub fn default_keyset(&self) -> Keyset {
        Keyset {
            engine: Arc::clone(&self.engine),
        }
    }

    /// Decrypts a ciphertext, or an array of ciphertexts, made under any of
    /// this cipher's keysets. Each value decrypts as the type it was
    /// encrypted as.
    ///
    /// With a record declaration as the first argument, decrypts a stored
    /// row of that record, or an array of stored rows. A stored row is what
    /// `keyset.encrypt` returns for a row. The cipher makes one key request
    /// for each keyset the rows were encrypted under. A key request is one
    /// request to ZeroKMS for data keys.
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

    /// Decrypts one field of a record's stored row, as `encryptField` or
    /// `encrypt` stored it. An array of stored fields decrypts in one key
    /// request.
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

    /// Returns the type's name.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Cipher"
    }
}

#[napi]
impl Keyset {
    /// Encrypts a value as one ciphertext with its own data key, with no
    /// context. A context is a value that a ciphertext is bound to, and
    /// decrypting needs the same context.
    ///
    /// An array of values returns an array of ciphertexts, in the same
    /// order. The keyset makes one key request for the whole array, however
    /// long it is. A key request is one request to ZeroKMS for data keys. If
    /// any value is refused, the whole array fails, before any request.
    ///
    /// A value's type sets how it is encrypted. The mapping of JavaScript
    /// types comes from vitaminc, CipherStash's cryptography library. A
    /// `Json` from `json(..)` is encrypted as a JSON document.
    ///
    /// With a record declaration as the first argument, encrypts a row of
    /// that record, or an array of rows in one key request. Each field is
    /// encrypted under its field path: the record's name, then the field's
    /// name.
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
                instances.pop().ok_or_else(|| Error::NoResult.into())
            },
        )
    }

    /// Decrypts a ciphertext made under this keyset, or an array of them. A
    /// ciphertext of another keyset fails with the code
    /// `stack_encrypt::foreign_keyset`, before any key is requested.
    ///
    /// With a record declaration as the first argument, decrypts a stored
    /// row of that record, or an array of stored rows.
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

    /// Encrypts one field of a record, to update that field alone. The
    /// result is the field's stored form, the same form as in a whole stored
    /// row. An array of values returns an array of stored fields, in one key
    /// request.
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

    /// Decrypts one field of a record's stored row made under this keyset.
    /// An array of stored fields decrypts in one key request.
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

    /// Returns the type's name.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Keyset"
    }
}

/// Makes a cipher over the engine's deterministic test keys, from a 32-byte
/// seed. Every key is derived from the seed and the value's context. So a
/// value encrypted by one test cipher decrypts in another with the same
/// seed.
///
/// The test cipher needs no credentials and makes no request. Anyone who
/// knows the seed can derive its keys.
///
/// Only a build with the `testing` feature has the test cipher. In any
/// other build, the promise resolves to a failure with the code
/// `recipher::no_testing`.
#[napi(ts_return_type = "Promise<Outcome<Cipher>>")]
pub fn create_testing<'e>(
    env: &'e Env,
    seed: Unknown<'_>,
) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
    let seed = crate::ciphertext::bytes_of(seed).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    let Some(seed) = seed else {
        return refused(env, Error::TestingSeed.into());
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
    refused(env, Error::NoTesting.into())
}

/// Returns the JavaScript value of a new cipher.
fn cipher_value(env: &Env, engine: Engine) -> Outcome<Unknown<'_>> {
    Ok(Cipher {
        engine: Arc::new(engine),
    }
    .into_instance(env)
    .map_err(not_made)?
    .to_unknown())
}

/// The keysets whose values a decrypt call accepts.
#[derive(Clone, Copy)]
enum Confined {
    /// Any of the cipher's keysets.
    No,
    /// Only the default keyset.
    ToDefault,
}

/// Decrypts a ciphertext, or an array of them, for `cipher.decrypt` and
/// `keyset.decrypt`.
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
            None => return refused(env, Error::NotACiphertext.into()),
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
            values.pop().ok_or_else(|| Error::NoResult.into())
        },
    )
}

/// Returns one value to encrypt, and the kind its ciphertext decrypts as. A
/// `Json`'s document decrypts as JSON. Any other value decrypts as the type
/// it was encrypted as.
fn one_value(env: &Env, value: Unknown<'_>) -> Outcome<(OneValue, Option<ValueKind>)> {
    if let Some(document) = Json::of(env, value) {
        return Ok((OneValue::json(document?), Some(ValueKind::Json)));
    }
    Ok((OneValue::scalar(js::read(env, value)?)?, None))
}

/// Checks record declarations with the engine, without credentials and
/// without any request. Use it in a test or a CI step. The failure is the
/// engine's first refusal. The failure names the record and, where there is
/// one, the field.
#[napi(ts_return_type = "Outcome<undefined>")]
pub fn check_declarations<'e>(env: &'e Env, records: Unknown<'_>) -> napi::Result<Object<'e>> {
    let checked = check(env, records);
    crate::outcome::settle(env, checked, |env, ()| {
        ().into_unknown(env).map_err(not_made)
    })
}

/// Builds the plan of each declaration in `records`. The argument is one
/// declaration or an array of them.
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

/// Returns the `records` property of `Cipher.create`'s options, if the
/// options have one.
fn records_of_options<'e>(env: &Env, options: Option<Unknown<'e>>) -> Outcome<Option<Unknown<'e>>> {
    match options {
        None => Ok(None),
        Some(options) => js::property(env, options, "records"),
    }
}

/// Returns the plan of the declaration `record`. A plan is the engine's
/// description of how to encrypt each field of a record.
fn plan_of(env: &Env, record: Unknown<'_>) -> Outcome<Arc<RecordPlan>> {
    if !js::is_record(env, &record) {
        return Err(Error::NotARecord.into());
    }
    RecordPlan::of(&js::read(env, record)?)
}

/// Returns the values in `value`, and whether `value` was an array. The
/// values are the array's elements, or `value` alone.
fn one_or_many<'e>(env: &Env, value: Unknown<'e>) -> Outcome<(bool, Vec<Unknown<'e>>)> {
    match js::elements(env, value) {
        Some(elements) => Ok((true, elements?)),
        None => Ok((false, vec![value])),
    }
}

/// Returns a JavaScript array with one value for each result when `many`
/// is true, or the one result alone when it is false.
fn one_or_array<'e>(
    env: &'e Env,
    many: bool,
    mut values: Vec<Unknown<'e>>,
) -> Outcome<Unknown<'e>> {
    if many {
        return values.into_unknown(env).map_err(not_made);
    }
    values.pop().ok_or_else(|| Error::NoResult.into())
}

/// Reads a row of `plan`'s record, with each value read as its field's
/// kind. When vitaminc refuses a value, the failure names the field the
/// value was read from.
fn read_row(env: &Env, plan: &RecordPlan, row: Unknown<'_>) -> Outcome<ValueFrame> {
    let not_a_row = || RecipherErrorFields::from(Error::NotARow).in_record(plan.name());
    if row.get_type().ok() != Some(napi::ValueType::Object) || row.is_array().unwrap_or(false) {
        return Err(not_a_row());
    }
    let frame = js::read(env, row).map_err(|error| {
        let field = plan.field_names().find(|name| {
            js::property(env, row, name)
                .map(|value| value.is_some_and(|value| js::read(env, value).is_err()))
                .unwrap_or(true)
        });
        error.in_record(plan.name()).at_field(field)
    })?;
    crate::record::conform_row(plan, &frame)
}

/// Runs `keyset.encrypt(record, row | rows)`.
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

/// Runs `cipher.decrypt(record, stored | stored[])` and `keyset.decrypt`.
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
            .map(|row| js::read(env, row).map_err(|error| error.in_record(plan.name())))
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

/// Returns the plan of the field `field` of `record` on its own, and the
/// field's name.
fn field_plan_of(
    env: &Env,
    record: Unknown<'_>,
    field: Unknown<'_>,
) -> Outcome<(Arc<RecordPlan>, String)> {
    let plan = plan_of(env, record)?;
    let name = js::string(field)
        .ok_or_else(|| RecipherErrorFields::from(Error::NoField).in_record(plan.name()))?;
    Ok((plan.field(&name)?, name))
}

/// Runs `keyset.encryptField(record, field, value | values)`.
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
                let value = js::read(env, value)
                    .map_err(|error| error.in_record(plan.name()).at_field(Some(&name)))?;
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

/// Runs `cipher.decryptField(record, field, stored | stored[])` and
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
                let value = js::read(env, value)
                    .map_err(|error| error.in_record(plan.name()).at_field(Some(&name)))?;
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

/// Encrypts values under `keyset`. Each value becomes one ciphertext with
/// its own data key. All the values use one key request, however many
/// there are.
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
            // No ciphertext exists yet, so the value caused this failure,
            // not a damaged ciphertext.
            stack_encrypt::Error::Aead => Error::NotSealed.into(),
            error => RecipherErrorFields::engine(&error),
        })
}

/// Decrypts ciphertexts through `cipher`: a cipher, or one keyset of it.
/// The function makes one key request for each keyset the ciphertexts
/// were made under.
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
        let error = RecipherErrorFields::from(Error::NoTesting);
        assert_eq!(error.code, "recipher::no_testing");
        assert!(error.help.is_some_and(|help| help.contains("build:debug")));
    }
}

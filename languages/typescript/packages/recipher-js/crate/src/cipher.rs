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
    // Configurable, as an instance method is, so the package's TypeScript
    // can wrap it (`adapt`).
    #[napi(configurable = true, ts_return_type = "Promise<Outcome<Cipher>>")]
    pub fn create(env: &Env) -> napi::Result<PromiseRaw<'_, Object<'_>>> {
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
    /// was sealed as.
    #[napi(ts_return_type = "Promise<Outcome<unknown>>")]
    pub fn decrypt<'e>(
        &self,
        env: &'e Env,
        ciphertext: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        open(env, &self.engine, ciphertext, Confined::No)
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
    #[napi(ts_return_type = "Promise<Outcome<Ciphertext | Ciphertext[]>>")]
    pub fn encrypt<'e>(
        &self,
        env: &'e Env,
        value: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
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

    /// Open a ciphertext sealed under this keyset. A ciphertext of another
    /// keyset is a failure of kind `foreign_keyset`, before any key is
    /// requested.
    #[napi(ts_return_type = "Promise<Outcome<unknown>>")]
    pub fn decrypt<'e>(
        &self,
        env: &'e Env,
        ciphertext: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        open(env, &self.engine, ciphertext, Confined::ToDefault)
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

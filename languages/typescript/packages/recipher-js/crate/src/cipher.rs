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
use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::kms::{DataKeySource, IndexKeySource, StackKms};
use stack_encrypt::{CipherRef, DecryptFrom, EncryptInto, KeysetCipher, StackCipher};
use vitaminc_protected::OpaqueDebug;

use crate::ciphertext::Ciphertext;
use crate::error::{Error, RecipherErrorFields};
use crate::js;
use crate::outcome::{not_made, refused, spawn, Outcome};
use crate::value::OneValue;

/// The engine's cipher, with the key source it was built with. A napi class
/// cannot be generic, so each key source is one variant.
#[derive(OpaqueDebug)]
pub(crate) enum Engine {
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
///
/// Call each method on its cipher. A method taken off its cipher, as in
/// `stored.map(cipher.decrypt)`, throws a `TypeError` when it is called.
/// Write `stored.map((ciphertext) => cipher.decrypt(ciphertext))` instead.
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
///
/// Call each method on its keyset. A method taken off its keyset, as in
/// `values.map(keyset.encrypt)`, throws a `TypeError` when it is called.
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
    /// The promise does not reject.
    #[napi(ts_return_type = "Promise<Result<Cipher, RecipherError>>")]
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

    /// Returns the client's default keyset: the keyset that a ZeroKMS
    /// administrator set for this client. Encrypting needs a keyset.
    #[napi]
    pub fn default_keyset(&self) -> Keyset {
        Keyset {
            engine: Arc::clone(&self.engine),
        }
    }

    /// Decrypts a ciphertext made under any of this cipher's keysets. The
    /// value decrypts as the type it was encrypted as.
    ///
    /// Resolves to an `Err` with the code `recipher_js::not_a_ciphertext`
    /// when the argument is not a `Ciphertext`. The promise does not reject.
    #[napi(ts_type = "<T>(ciphertext: Ciphertext<T>): Promise<Result<T, RecipherError>>")]
    pub fn decrypt<'e>(
        &self,
        env: &'e Env,
        ciphertext: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        open(env, &self.engine, ciphertext, Confined::No)
    }

    /// Returns the type's name.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Cipher"
    }
}

#[napi]
impl Keyset {
    /// Encrypts a string as one ciphertext with its own data key, with no
    /// context. A context is a value that a ciphertext is bound to, and
    /// decrypting needs the same context.
    ///
    /// Resolves to an `Err` with the code `recipher_js::not_a_string` when
    /// the value is not a string. The promise does not reject.
    #[napi(
        ts_args_type = "value: string",
        ts_return_type = "Promise<Result<Ciphertext<string>, RecipherError>>"
    )]
    pub fn encrypt<'e>(
        &self,
        env: &'e Env,
        value: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        let value = match js::read(env, value).and_then(OneValue::new) {
            Ok(value) => value,
            Err(error) => return refused(env, error),
        };
        let engine = Arc::clone(&self.engine);
        spawn(
            env,
            async move {
                with_engine!(&*engine, |cipher| {
                    seal(&cipher.default_keyset(), vec![value]).await
                })
            },
            |env, mut sealed| match sealed.pop() {
                Some(sealed) => Ok(Ciphertext::new(sealed)
                    .into_instance(env)
                    .map_err(not_made)?
                    .to_unknown()),
                None => Err(Error::NoResult.into()),
            },
        )
    }

    /// Decrypts a ciphertext made under this keyset. A ciphertext of another
    /// keyset fails with the code `stack_encrypt::foreign_keyset`, before
    /// any key is requested. The promise does not reject.
    #[napi(ts_type = "<T>(ciphertext: Ciphertext<T>): Promise<Result<T, RecipherError>>")]
    pub fn decrypt<'e>(
        &self,
        env: &'e Env,
        ciphertext: Unknown<'_>,
    ) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
        open(env, &self.engine, ciphertext, Confined::ToDefault)
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
/// Only the debug build of the addon has the test cipher. In any other
/// build, the promise resolves to an `Err` with the code
/// `recipher_js::no_testing`. A seed that is not 32 bytes is an `Err` with
/// the code `recipher_js::testing_seed`. The promise does not reject.
///
/// Call `testCipher()` from `@cipherstash/recipher/testing` rather than
/// this function.
#[napi(
    ts_args_type = "seed: unknown",
    ts_return_type = "Promise<Result<Cipher, RecipherError>>"
)]
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
pub(crate) enum Confined {
    /// Any of the cipher's keysets.
    No,
    /// Only the default keyset.
    ToDefault,
}

/// Decrypts a ciphertext, for `cipher.decrypt` and `keyset.decrypt`.
fn open<'e>(
    env: &'e Env,
    engine: &Arc<Engine>,
    ciphertext: Unknown<'_>,
    confined: Confined,
) -> napi::Result<PromiseRaw<'e, Object<'e>>> {
    let Some(ciphertext) = Ciphertext::of(env, ciphertext) else {
        return refused(env, Error::NotACiphertext.into());
    };
    let sealed = vec![ciphertext.sealed().clone()];
    let engine = Arc::clone(engine);
    spawn(
        env,
        async move { open_in(&engine, sealed, confined).await },
        |env, mut opened| match opened.pop() {
            Some(value) => js::build(env, value),
            None => Err(Error::NoResult.into()),
        },
    )
}

/// Decrypts ciphertexts through `engine`: through the whole cipher, or
/// through its default keyset only, as `confined` says.
pub(crate) async fn open_in(
    engine: &Engine,
    sealed: Vec<stack_encrypt::Ciphertext>,
    confined: Confined,
) -> Outcome<Vec<OwnedFrame>> {
    with_engine!(engine, |cipher| match confined {
        Confined::No => unseal(&**cipher, sealed).await,
        Confined::ToDefault => unseal(&cipher.default_keyset(), sealed).await,
    })
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
        .map_err(|error| RecipherErrorFields::engine(&error))
}

/// Decrypts ciphertexts through `cipher`: a cipher, or one keyset of it.
/// The function makes one key request for each keyset the ciphertexts
/// were made under.
pub(crate) async fn unseal<'c, K>(
    cipher: impl Into<CipherRef<'c, K>>,
    sealed: Vec<stack_encrypt::Ciphertext>,
) -> Outcome<Vec<OwnedFrame>>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    Vec::<OwnedFrame>::decrypt_from(sealed, cipher)
        .await
        .map_err(|error| RecipherErrorFields::engine(&error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_build_without_the_test_cipher_says_how_to_get_one() {
        let error = RecipherErrorFields::from(Error::NoTesting);
        assert_eq!(error.code, "recipher_js::no_testing");
        assert!(error.help.is_some_and(|help| help.contains("build:debug")));
    }
}

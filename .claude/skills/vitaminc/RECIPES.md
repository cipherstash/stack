# vitaminc recipes

One recipe per task. Each is complete, compiles, and is the production path: copy it as written. Imports use the individual crates; with the facade crate, `vitaminc_protected::X` is `vitaminc::protected::X`, and so on.

## Hold a secret

Wrap the secret the moment it exists, and keep it wrapped until the last call that needs it.

```rust
use std::env::VarError;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

/// Says that the token could not be read, and nothing about its value.
#[derive(Debug)]
pub struct TokenUnavailable;

/// Read a token from the environment straight into a `Protected`. `VarError`
/// holds the raw value when it is not Unicode, so it is wiped here and never returned.
fn api_token() -> Result<Protected<String>, TokenUnavailable> {
    Protected::generate_ok(|| match std::env::var("API_TOKEN") {
        Ok(token) => Ok(token),
        Err(VarError::NotPresent) => Err(TokenUnavailable),
        Err(VarError::NotUnicode(raw)) => {
            raw.into_encoded_bytes().zeroize();
            Err(TokenUnavailable)
        }
    })
}

/// Transform without unwrapping. The closure owns the bare value, so it returns
/// it (here as bytes, in the same allocation) rather than dropping it unwiped.
fn token_bytes(token: Protected<String>) -> Protected<Vec<u8>> {
    token.map(String::into_bytes)
}

/// To read a value without taking it, borrow it. The wrapper keeps ownership
/// and still wipes the token when it is dropped.
fn token_len(token: &Protected<String>) -> usize {
    token.risky_ref().len()
}

/// At the boundary to an API that takes a plain `&str`, borrow with `risky_ref`.
/// Keep the borrow inside one call, never store it.
fn send(token: &Protected<String>, client: impl Fn(&str)) {
    client(token.risky_ref());
}
```

## Compare secrets

`Protected` has no `PartialEq`. Compare through `Equatable`, which is constant-time.

```rust
use vitaminc_protected::{Equatable, Protected};

fn tag_matches(
    presented: &Equatable<Protected<[u8; 32]>>,
    expected: &Equatable<Protected<[u8; 32]>>,
) -> bool {
    presented == expected
}

let a: Equatable<Protected<[u8; 32]>> = Equatable::new([7; 32]);
let b: Equatable<Protected<[u8; 32]>> = Equatable::new([7; 32]);
assert!(tag_matches(&a, &b));
```

## Generate random values

```rust
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, RandomError, SafeRand};

fn random_secret() -> Result<Protected<[u8; 32]>, RandomError> {
    let mut rng = SafeRand::from_entropy()?;
    Protected::random(&mut rng)
}

/// A uniform index in `0..len`, for choosing from a list. `next_below` panics on a
/// zero bound, since `0..0` has nothing to draw, so an empty list is refused here.
fn random_index(rng: &mut SafeRand, len: u32) -> Option<u32> {
    (len > 0).then(|| rng.next_below(len))
}
```

Derive `Generatable` to generate a whole struct of random fields:

```rust
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, RandomError, SafeRand};

#[derive(Generatable)]
struct SessionSecrets {
    signing: Protected<[u8; 32]>,
    encryption: Protected<[u8; 32]>,
}

fn new_session() -> Result<SessionSecrets, RandomError> {
    SessionSecrets::random(&mut SafeRand::from_entropy()?)
}
```

## Generate a password

Use the `vitaminc-password` types. Each draws its characters uniformly and holds them wrapped. The length is a const generic, and a length below the type's minimum fails compilation. `generate` gives the minimum length; `random` with a `SafeRand` gives any longer one.

```rust
use vitaminc_password::{AlphaNumericPassword, RandomError};
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, SafeRand};

/// 22 letters and digits, about 131 bits.
fn new_password() -> Result<Protected<String>, RandomError> {
    Ok(AlphaNumericPassword::generate()?.into_protected_string())
}

/// A longer password, for a service account.
fn new_service_password(rng: &mut SafeRand) -> Result<Protected<String>, RandomError> {
    Ok(AlphaNumericPassword::<32>::random(rng)?.into_protected_string())
}
```

## Encrypt a value or a struct

Build the cipher at startup from a key that outlives the process (see "Wrap a data key" below), and pass it to every call. `Aes256Cipher` is not `Sync`, so build one per thread or task from the same key rather than sharing one across threads. A key generated inside the function that encrypts is lost when it returns, and so is everything sealed under it. Encrypt under associated data (AAD) naming the record the ciphertext belongs to. Decryption must present the same AAD, so a ciphertext copied onto another record fails to open. Nonces are generated for you.

Describe the AAD with a type of your own that implements `IntoContext`, as `UserRecord` does below, and pass it at both sites. The write and the read then cannot disagree, and the parts are encoded unambiguously. `encrypt` also accepts a bare `&str`, so `""`, a typo or a value copied from another record compiles; the type is what stops that.

Each sealed leaf (each encrypted field, each sequence element) draws a random 96-bit nonce, and nothing counts them. Keep the leaves sealed under one key, across every cipher instance and restart, well below 2³², and rotate to a new data key before that (see "Wrap a data key" below).

```rust
use vitaminc_aead::{ContextPiece, IntoContext};
use vitaminc_encrypt::{
    decrypt, encrypt, Aes256Cipher, AesCipherText, DecodeError, Decrypt, DecryptError, Encrypt,
    EncryptError, Unspecified,
};

/// The record a user ciphertext belongs to. The one place its AAD is spelled.
struct UserRecord(u64);

impl<'a> IntoContext<'a> for UserRecord {
    fn into_context(self) -> ContextPiece<'a> {
        ("users", self.0).into_context()
    }
}

#[derive(Encrypt, Decrypt)]
struct User {
    #[aead(passthrough)] // stored in the clear: only for non-sensitive fields
    id: u64,
    email: String,
    date_of_birth: String,
}

/// Seal a user for storage. `cipher` is built at startup, one per thread or task.
fn seal_user(cipher: &Aes256Cipher, user: &User) -> Result<AesCipherText, EncryptError<Unspecified>> {
    encrypt(user, cipher, UserRecord(user.id))
}

/// Open the record stored under `id`. Take `id` from the lookup, not from the stored
/// value: the passthrough copy is unauthenticated. Under another record's id this fails.
fn open_user(
    cipher: &Aes256Cipher,
    id: u64,
    stored: AesCipherText,
) -> Result<User, DecryptError<DecodeError, Unspecified>> {
    decrypt(cipher, stored, UserRecord(id))
}
```

To encrypt a single secret, pass the `Protected` itself. It is walked inside the wrapper and decrypts back into one. The AAD has no id, so a unit type names the one place the value lives:

```rust
use vitaminc_aead::{ContextPiece, IntoContext};
use vitaminc_encrypt::{
    decrypt, encrypt, Aes256Cipher, AesCipherText, DecodeError, DecryptError, EncryptError,
    Unspecified,
};
use vitaminc_protected::Protected;

/// The one stored GitHub integration token. The one place its AAD is spelled.
struct GithubToken;

impl<'a> IntoContext<'a> for GithubToken {
    fn into_context(self) -> ContextPiece<'a> {
        ("integrations", "github/token").into_context()
    }
}

fn seal_token(cipher: &Aes256Cipher, token: Protected<String>) -> Result<AesCipherText, EncryptError<Unspecified>> {
    encrypt(token, cipher, GithubToken)
}

fn open_token(
    cipher: &Aes256Cipher,
    stored: AesCipherText,
) -> Result<Protected<String>, DecryptError<DecodeError, Unspecified>> {
    decrypt(cipher, stored, GithubToken)
}
```

## Wrap a data key under a key-encryption key

Generate the data key once, when its owner (a tenant, a table) is created, and store only the wrapped form. At every startup, unwrap it and build the cipher the encrypt recipes take. `kek` is the key-encryption key the service holds for its whole lifetime; it is never generated per call. It is built from 32 bytes held in the secret store, passed straight to `Key::from`.

Wrap each data key under AAD naming its owner and its version. Under one KEK, a wrapped key copied onto another tenant's record then fails to unwrap rather than opening as that tenant's key. The version is how a tenant rotates: before the leaves sealed under one data key near the nonce budget (see the encrypt recipe), generate version 2, encrypt new values under it, and keep version 1 only to open what it sealed.

```rust
use vitaminc_aead::{ContextPiece, IntoContext};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};
use vitaminc_random::{Generatable, SafeRand};

/// The tenant and version a wrapped data key belongs to.
struct DataKeyOwner<'t> {
    tenant_id: &'t str,
    version: u32,
}

impl<'a> IntoContext<'a> for DataKeyOwner<'a> {
    fn into_context(self) -> ContextPiece<'a> {
        (("tenants/dek", self.tenant_id), self.version).into_context()
    }
}

/// Run at startup, on the root key's bytes fetched from the secret store. `Key` takes a
/// plain array (it has no constructor from `Protected` yet) and wraps it at once: fetch
/// straight into this call, and keep no other copy of the bytes.
fn key_encryption_cipher(root_key: [u8; 32]) -> Result<Aes256Cipher, Box<dyn std::error::Error>> {
    Ok(Aes256Cipher::new(&Key::from(root_key))?)
}

/// Run once, when the tenant is created. Store the result with the tenant.
fn new_data_key(
    kek: &Aes256Cipher,
    rng: &mut SafeRand,
    owner: DataKeyOwner<'_>,
) -> Result<AesCipherText, Box<dyn std::error::Error>> {
    let dek = Key::random(rng)?;
    Ok(dek.wrap(kek, owner)?)
}

/// Run at every startup, on the stored result of `new_data_key` for the same owner.
fn data_cipher(
    kek: &Aes256Cipher,
    owner: DataKeyOwner<'_>,
    wrapped: AesCipherText,
) -> Result<Aes256Cipher, Box<dyn std::error::Error>> {
    let dek = Key::from_wrapped(kek, wrapped, owner)?;
    Ok(Aes256Cipher::new(&dek)?)
}
```

## Keyed hash, blind index, or equality term

An unkeyed hash of a low-entropy value (an email, a phone number) is reversible by guessing. Derive a keyed term instead, under a context naming the index and its version; `nonempty!` refuses an empty context at compile time. Writes and queries must use the same input type and context. The key is what makes the terms unguessable, so it is generated once, kept in the secret store, and never written into the source.

```rust
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{PrfKeyInit, PrfValue};
use vitaminc_protected::{nonempty, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};

/// Run once, when the index is created. Put the result in the secret store.
fn new_index_key(rng: &mut SafeRand) -> Result<Protected<[u8; 32]>, RandomError> {
    Protected::random(rng)
}

/// Run at startup, on the key bytes as the secret store's read returns them, already wrapped.
fn index_key_from_secret_store(
    bytes: Protected<Vec<u8>>,
) -> Result<HmacSha256Prf, Box<dyn std::error::Error>> {
    // Rejects keys shorter than the minimum length instead of deriving weak terms.
    Ok(HmacSha256Prf::try_from_bytes(bytes)?)
}

async fn email_term(prf: &HmacSha256Prf, email: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(email.prf_with_context(prf, nonempty!("users/email/exact/v1")).await?)
}

// The index's first run: a fresh key, keyed directly. Later runs load it instead.
let mut rng = SafeRand::from_entropy().unwrap();
let prf = HmacSha256Prf::new(new_index_key(&mut rng).unwrap());
let a = futures::executor::block_on(email_term(&prf, "ada@example.com")).unwrap();
let b = futures::executor::block_on(email_term(&prf, "ada@example.com")).unwrap();
assert_eq!(a, b);
```

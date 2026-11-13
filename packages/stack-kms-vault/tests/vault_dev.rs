//! The Vault Transit backend against a real `vault server -dev`, over the
//! native transport.
//!
//! Runs only when `STACK_KMS_VAULT_ADDR` is set (for example
//! `http://127.0.0.1:8200`); otherwise each test passes at once and says it
//! was skipped. The token is `STACK_KMS_VAULT_TOKEN` (default `root`). CI
//! runs Vault as a service and sets both.
//!
//! ```sh
//! docker run -d --rm -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:1.20
//! STACK_KMS_VAULT_ADDR=http://127.0.0.1:8200 \
//!   cargo nextest run -p stack-kms-vault --all-features --test vault_dev
//! ```
//!
//! `records_the_fixtures` writes `tests/fixtures/*.json` again. It runs
//! only when `STACK_KMS_VAULT_RECORD_FIXTURES=1` is also set, against a dev
//! server at `common::ADDRESS` whose root token is `common::TOKEN`:
//!
//! ```sh
//! docker run -d --rm -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=fixture-root-token hashicorp/vault:1.20
//! STACK_KMS_VAULT_ADDR=http://127.0.0.1:8200 STACK_KMS_VAULT_TOKEN=fixture-root-token \
//!   STACK_KMS_VAULT_RECORD_FIXTURES=1 \
//!   cargo nextest run -p stack-kms-vault --all-features --test vault_dev records_the_fixtures
//! ```

#![cfg(not(target_arch = "wasm32"))]

mod common;

use common::{Fixture, Recording, DERIVED_KEY, KEY};
use serde_json::{json, Value};
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_vault::{
    AppRoleLogin, CachedToken, KeyDerivation, TokenProvider, VaultConfig, VaultToken, VaultTransit,
};
use stack_kms_vendor::derive::record_key_aad;
use stack_kms_vendor::{contract, HttpVendorTransport, KeyVendorBackend};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};
use zeroize::Zeroizing;

const ADDR_VAR: &str = "STACK_KMS_VAULT_ADDR";
const TOKEN_VAR: &str = "STACK_KMS_VAULT_TOKEN";
const RECORD_VAR: &str = "STACK_KMS_VAULT_RECORD_FIXTURES";

type Client = VaultTransit<HttpVendorTransport, VaultToken>;

struct Server {
    address: String,
    token: String,
}

fn server() -> Option<Server> {
    let address = std::env::var(ADDR_VAR).ok().filter(|e| !e.is_empty());
    let Some(address) = address else {
        eprintln!("skipped: set {ADDR_VAR} to run against vault server -dev");
        return None;
    };
    let token = std::env::var(TOKEN_VAR)
        .ok()
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| "root".to_owned());
    Some(Server { address, token })
}

fn config(server: &Server) -> VaultConfig {
    VaultConfig::new(&server.address).unwrap()
}

fn client(server: &Server) -> Client {
    VaultTransit::new(
        config(server),
        HttpVendorTransport::new().unwrap(),
        VaultToken::new(&server.token),
    )
}

fn body(value: Value) -> Option<Zeroizing<Vec<u8>>> {
    Some(Zeroizing::new(serde_json::to_vec(&value).unwrap()))
}

/// Send an admin request, ignoring a failure (the mount or key may exist).
async fn admin(vault: &Client, method: &str, path: &str, value: Option<Value>) -> Option<Value> {
    vault
        .send_json::<Value>(method, path, value.and_then(body))
        .await
        .ok()
}

/// Enable the Transit engine (if needed) and create a key.
async fn create_key(vault: &Client, name: &str, derived: bool) {
    let _ = admin(
        vault,
        "POST",
        "sys/mounts/transit",
        Some(json!({"type": "transit"})),
    )
    .await;
    let _ = admin(
        vault,
        "POST",
        &format!("transit/keys/{name}"),
        Some(json!({"derived": derived})),
    )
    .await;
}

fn kind(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { kind, .. } => kind,
        other => panic!("{other:?}"),
    }
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

#[tokio::test]
async fn vault_transit_meets_the_contract_on_vault_dev() {
    let Some(server) = server() else { return };
    let admin_client = client(&server);
    for derived in [false, true] {
        let key = unique(if derived {
            "contract-derived"
        } else {
            "contract"
        });
        create_key(&admin_client, &key, derived).await;
        let make = || {
            VaultTransit::new(
                config(&server),
                HttpVendorTransport::new().unwrap(),
                VaultToken::new(&server.token),
            )
        };
        contract::run(make, &key).await;
    }
}

#[tokio::test]
async fn vault_dev_errors_map_to_kinds() {
    let Some(server) = server() else { return };
    let vault = client(&server);
    let key = unique("errors");
    let derived = unique("errors-derived");
    create_key(&vault, &key, false).await;
    create_key(&vault, &derived, true).await;
    let aad = record_key_aad(Uuid::new_v4(), KeyVendor::Vault, KeyMode::Derived);
    let wrapped = vault
        .wrap(&derived, &Protected::new([8u8; 32]), &aad)
        .await
        .unwrap();
    assert_eq!(
        vault
            .unwrap(&derived, &wrapped, &aad)
            .await
            .unwrap()
            .risky_ref(),
        &[8u8; 32]
    );

    // Another context: Vault itself refuses it for a derived key.
    let other = record_key_aad(Uuid::new_v4(), KeyVendor::Vault, KeyMode::Derived);
    let error = vault.unwrap(&derived, &wrapped, &other).await.unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::InvalidCiphertext);

    // A damaged ciphertext.
    let mut damaged = wrapped.clone();
    if let Some(last) = damaged.last_mut() {
        *last ^= 1;
    }
    let error = vault.unwrap(&derived, &damaged, &aad).await.unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::InvalidCiphertext);

    // A key version that does not exist yet.
    let mut future = wrapped.clone();
    future[1..5].copy_from_slice(&9u32.to_be_bytes());
    let error = vault.unwrap(&derived, &future, &aad).await.unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::InvalidCiphertext);

    // Another key's ciphertext.
    let error = vault.unwrap(&key, &wrapped, &aad).await.unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::InvalidCiphertext);

    // A key that does not exist.
    let error = vault
        .wrap(&unique("missing"), &Protected::new([1u8; 32]), &aad)
        .await
        .unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::NotFound);

    // A derived key told it is not derived.
    let not_derived = VaultTransit::new(
        config(&server).with_key_derivation(KeyDerivation::NotDerived),
        HttpVendorTransport::new().unwrap(),
        VaultToken::new(&server.token),
    );
    let error = not_derived
        .wrap(&derived, &Protected::new([1u8; 32]), &aad)
        .await
        .unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::AccessDenied);

    // A bad token.
    let bad = VaultTransit::new(
        config(&server),
        HttpVendorTransport::new().unwrap(),
        VaultToken::new("not-a-token"),
    );
    let error = bad
        .wrap(&key, &Protected::new([1u8; 32]), &aad)
        .await
        .unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::AccessDenied);

    // A mount that does not exist.
    let no_mount = VaultTransit::new(
        config(&server).with_mount("no-such-mount").unwrap(),
        HttpVendorTransport::new().unwrap(),
        VaultToken::new(&server.token),
    );
    let error = no_mount
        .wrap(&key, &Protected::new([1u8; 32]), &aad)
        .await
        .unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::NotFound);
}

#[tokio::test]
async fn rotation_and_rewrap_on_vault_dev() {
    let Some(server) = server() else { return };
    let vault = client(&server);
    let key = unique("rotate");
    create_key(&vault, &key, true).await;
    let wrapped = vault
        .wrap(&key, &Protected::new([6u8; 32]), b"aad")
        .await
        .unwrap();
    let _ = admin(&vault, "POST", &format!("transit/keys/{key}/rotate"), None).await;
    // The old version still opens; rewrap moves it to the new one.
    assert_eq!(
        vault
            .unwrap(&key, &wrapped, b"aad")
            .await
            .unwrap()
            .risky_ref(),
        &[6u8; 32]
    );
    let rewrapped = vault.rewrap(&key, &wrapped, b"aad").await.unwrap();
    assert_eq!(&rewrapped[1..5], &2u32.to_be_bytes());
    assert_eq!(
        vault
            .unwrap(&key, &rewrapped, b"aad")
            .await
            .unwrap()
            .risky_ref(),
        &[6u8; 32]
    );
}

/// Enable AppRole auth and make a role that may use `key`; its role id and
/// a secret id. With `fixed`, the ids are the fixtures' own.
async fn approle(vault: &Client, role: &str, key: &str, fixed: bool) -> (String, String) {
    let _ = admin(
        vault,
        "POST",
        "sys/auth/approle",
        Some(json!({"type": "approle"})),
    )
    .await;
    let policy = format!(
        "path \"transit/encrypt/{key}\" {{ capabilities = [\"update\"] }}\n\
         path \"transit/decrypt/{key}\" {{ capabilities = [\"update\"] }}\n\
         path \"transit/keys/{key}\" {{ capabilities = [\"read\"] }}\n"
    );
    let _ = admin(
        vault,
        "PUT",
        &format!("sys/policies/acl/{role}"),
        Some(json!({ "policy": policy })),
    )
    .await;
    let _ = admin(
        vault,
        "POST",
        &format!("auth/approle/role/{role}"),
        Some(json!({ "token_policies": [role], "token_ttl": "20m" })),
    )
    .await;
    if fixed {
        let _ = admin(
            vault,
            "POST",
            &format!("auth/approle/role/{role}/role-id"),
            Some(json!({ "role_id": "fixture-role-id" })),
        )
        .await;
        let _ = admin(
            vault,
            "POST",
            &format!("auth/approle/role/{role}/custom-secret-id"),
            Some(json!({ "secret_id": "fixture-secret-id" })),
        )
        .await;
        return ("fixture-role-id".into(), "fixture-secret-id".into());
    }
    let role_id = admin(
        vault,
        "GET",
        &format!("auth/approle/role/{role}/role-id"),
        None,
    )
    .await
    .unwrap();
    let secret = admin(
        vault,
        "POST",
        &format!("auth/approle/role/{role}/secret-id"),
        Some(json!({})),
    )
    .await
    .unwrap();
    (
        role_id["data"]["role_id"].as_str().unwrap().to_owned(),
        secret["data"]["secret_id"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn approle_login_on_vault_dev() {
    let Some(server) = server() else { return };
    let admin_client = client(&server);
    let key = unique("approle");
    create_key(&admin_client, &key, false).await;
    let role = unique("role");
    let (role_id, secret_id) = approle(&admin_client, &role, &key, false).await;

    let auth = CachedToken::new(AppRoleLogin::new(
        &config(&server),
        HttpVendorTransport::new().unwrap(),
        role_id,
        secret_id,
    ));
    let token = auth.token().await.unwrap();
    assert_eq!(token.lease(), Some(std::time::Duration::from_secs(20 * 60)));
    let vault = VaultTransit::new(config(&server), HttpVendorTransport::new().unwrap(), auth);
    let aad = record_key_aad(Uuid::new_v4(), KeyVendor::Vault, KeyMode::Derived);
    let wrapped = vault
        .wrap(&key, &Protected::new([5u8; 32]), &aad)
        .await
        .unwrap();
    assert_eq!(
        vault
            .unwrap(&key, &wrapped, &aad)
            .await
            .unwrap()
            .risky_ref(),
        &[5u8; 32]
    );

    // A wrong secret id is refused.
    let wrong = AppRoleLogin::new(
        &config(&server),
        HttpVendorTransport::new().unwrap(),
        "fixture-role-id-that-does-not-exist",
        "nope",
    );
    assert_eq!(
        wrong.token().await.unwrap_err().kind(),
        BackendErrorKind::AccessDenied
    );
}

/// Write `tests/fixtures/<name>` (an exchange sequence).
fn write(name: &str, exchanges: Vec<Fixture>) {
    let text = serde_json::to_string_pretty(&exchanges).unwrap() + "\n";
    std::fs::write(common::fixture_path(name), text).unwrap();
}

fn recorded_client(
    derivation: KeyDerivation,
) -> VaultTransit<Recording<HttpVendorTransport>, VaultToken> {
    VaultTransit::new(
        VaultConfig::new(common::ADDRESS)
            .unwrap()
            .with_key_derivation(derivation),
        Recording::new(HttpVendorTransport::new().unwrap()),
        VaultToken::new(common::TOKEN),
    )
}

/// The record key fixtures wrap: a fixed keyset id.
pub const FIXTURE_KEYSET: Uuid = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);

#[tokio::test]
async fn records_the_fixtures() {
    let Some(server) = server() else { return };
    if std::env::var(RECORD_VAR).as_deref() != Ok("1") {
        eprintln!("skipped: set {RECORD_VAR}=1 to record the fixtures");
        return;
    }
    assert_eq!(server.address.trim_end_matches('/'), common::ADDRESS);
    assert_eq!(server.token, common::TOKEN);
    let admin_client = client(&server);
    create_key(&admin_client, KEY, false).await;
    create_key(&admin_client, DERIVED_KEY, true).await;

    let record_aad = record_key_aad(FIXTURE_KEYSET, KeyVendor::Vault, KeyMode::Derived);

    for (key, prefix) in [(KEY, ""), (DERIVED_KEY, "derived_")] {
        // One key: a key read, then encrypt.
        let vault = recorded_client(KeyDerivation::Detect);
        let wrapped = vault
            .wrap(key, &Protected::new([0x42u8; 32]), &record_aad)
            .await
            .unwrap();
        write(&format!("{prefix}encrypt.json"), vault.transport_take());
        let vault = recorded_client(KeyDerivation::Detect);
        let opened = vault.unwrap(key, &wrapped, &record_aad).await.unwrap();
        assert_eq!(opened.risky_ref(), &[0x42u8; 32]);
        write(&format!("{prefix}decrypt.json"), vault.transport_take());
    }

    // Rewrap after a rotation.
    let vault = recorded_client(KeyDerivation::NotDerived);
    let wrapped = vault
        .wrap(KEY, &Protected::new([0x42u8; 32]), &record_aad)
        .await
        .unwrap();
    let _ = vault.transport_take();
    let _ = admin(
        &admin_client,
        "POST",
        &format!("transit/keys/{KEY}/rotate"),
        None,
    )
    .await;
    let rewrapped = vault.rewrap(KEY, &wrapped, &record_aad).await.unwrap();
    write("rewrap.json", vec![vault.transport_take().pop().unwrap()]);
    let _ = rewrapped;

    // An AppRole login, then a key read and an encrypt with its token.
    let _ = approle(&admin_client, "cipherstash-fixture", KEY, true).await;
    let login = AppRoleLogin::new(
        &VaultConfig::new(common::ADDRESS).unwrap(),
        Recording::new(HttpVendorTransport::new().unwrap()),
        "fixture-role-id",
        "fixture-secret-id",
    );
    let _ = login.token().await.unwrap();
    write("approle_login.json", login.transport().take());

    // Errors, each one exchange.
    let mut errors = Vec::new();
    let mut case = |name: &str, kind: &str, exchanges: Vec<Fixture>| {
        let exchange = exchanges.into_iter().last().unwrap();
        errors.push(json!({
            "name": name,
            "kind": kind,
            "response": exchange.response,
        }));
    };
    let vault = recorded_client(KeyDerivation::NotDerived);
    let derived_wrapped = recorded_client(KeyDerivation::Derived)
        .wrap(DERIVED_KEY, &Protected::new([1u8; 32]), &record_aad)
        .await
        .unwrap();
    let other_aad = record_key_aad(Uuid::from_u128(2), KeyVendor::Vault, KeyMode::Derived);
    let derived = recorded_client(KeyDerivation::Derived);
    assert_eq!(
        kind(
            derived
                .unwrap(DERIVED_KEY, &derived_wrapped, &other_aad)
                .await
                .unwrap_err()
        ),
        BackendErrorKind::InvalidCiphertext
    );
    case(
        "decrypt under another context",
        "InvalidCiphertext",
        derived.transport_take(),
    );
    let mut future = derived_wrapped.clone();
    future[1..5].copy_from_slice(&9u32.to_be_bytes());
    let derived = recorded_client(KeyDerivation::Derived);
    assert_eq!(
        kind(
            derived
                .unwrap(DERIVED_KEY, &future, &record_aad)
                .await
                .unwrap_err()
        ),
        BackendErrorKind::InvalidCiphertext
    );
    case(
        "a key version that is too new",
        "InvalidCiphertext",
        derived.transport_take(),
    );
    let short = stack_kms_vault::compact_ciphertext("vault:v1:AAAA").unwrap();
    assert_eq!(
        kind(vault.unwrap(KEY, &short, &record_aad).await.unwrap_err()),
        BackendErrorKind::InvalidCiphertext
    );
    case(
        "a ciphertext that is too short",
        "InvalidCiphertext",
        vault.transport_take(),
    );
    assert_eq!(
        kind(
            vault
                .unwrap("no-such-key", &short, &record_aad)
                .await
                .unwrap_err()
        ),
        BackendErrorKind::NotFound
    );
    case(
        "decrypt with a key that does not exist",
        "NotFound",
        vault.transport_take(),
    );
    let detect = recorded_client(KeyDerivation::Detect);
    assert_eq!(
        kind(
            detect
                .wrap("no-such-key", &Protected::new([1u8; 32]), &record_aad)
                .await
                .unwrap_err()
        ),
        BackendErrorKind::NotFound
    );
    case(
        "read a key that does not exist",
        "NotFound",
        detect.transport_take(),
    );
    assert_eq!(
        kind(
            vault
                .wrap(DERIVED_KEY, &Protected::new([1u8; 32]), &record_aad)
                .await
                .unwrap_err()
        ),
        BackendErrorKind::AccessDenied
    );
    case(
        "a derived key with no context",
        "AccessDenied",
        vault.transport_take(),
    );
    let bad = VaultTransit::new(
        VaultConfig::new(common::ADDRESS)
            .unwrap()
            .with_key_derivation(KeyDerivation::NotDerived),
        Recording::new(HttpVendorTransport::new().unwrap()),
        VaultToken::new("not-a-token"),
    );
    assert_eq!(
        kind(bad.unwrap(KEY, &short, &record_aad).await.unwrap_err()),
        BackendErrorKind::AccessDenied
    );
    case("a bad token", "AccessDenied", bad.transport_take());
    let no_mount = VaultTransit::new(
        VaultConfig::new(common::ADDRESS)
            .unwrap()
            .with_mount("no-such-mount")
            .unwrap()
            .with_key_derivation(KeyDerivation::NotDerived),
        Recording::new(HttpVendorTransport::new().unwrap()),
        VaultToken::new(common::TOKEN),
    );
    assert_eq!(
        kind(no_mount.unwrap(KEY, &short, &record_aad).await.unwrap_err()),
        BackendErrorKind::NotFound
    );
    case(
        "a mount that does not exist",
        "NotFound",
        no_mount.transport_take(),
    );
    // Responses a dev server does not give, in Vault's shapes.
    for (name, status, message, kind) in [
        (
            "a rate limit quota",
            429,
            "request path \"transit/decrypt/cipherstash-fixture\": rate limit quota exceeded",
            "Throttled",
        ),
        ("a sealed Vault", 503, "Vault is sealed", "Unavailable"),
        ("an internal error", 500, "internal error", "Unavailable"),
        (
            "a policy that denies",
            403,
            "1 error occurred:\n\t* permission denied\n\n",
            "AccessDenied",
        ),
        (
            "a retired key version",
            400,
            "ciphertext version is disallowed by policy (too old)",
            "InvalidCiphertext",
        ),
    ] {
        errors.push(json!({
            "name": format!("{name} (written by hand)"),
            "kind": kind,
            "response": {
                "status": status,
                "headers": [["content-type", "application/json"]],
                "body": { "errors": [message] }
            },
        }));
    }
    std::fs::write(
        common::fixture_path("errors.json"),
        serde_json::to_string_pretty(&errors).unwrap() + "\n",
    )
    .unwrap();
}

trait TakeExchanges {
    fn transport_take(&self) -> Vec<Fixture>;
}

impl<A: TokenProvider> TakeExchanges for VaultTransit<Recording<HttpVendorTransport>, A> {
    fn transport_take(&self) -> Vec<Fixture> {
        self.transport().take()
    }
}

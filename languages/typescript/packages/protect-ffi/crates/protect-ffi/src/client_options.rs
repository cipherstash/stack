//! The options `newClient` and `ensureKeyset` accept, and the serde contract
//! that defines them.
//!
//! Both bindings deserialize these same types — the Neon entry through neon's
//! `Json` extractor (`serde_json`), the wasm entry through
//! `serde_wasm_bindgen`. That is the whole point of #142: the accepted shape is
//! identical by construction rather than by convention. It also means the
//! deserialization behaviour IS the public API, which is why it lives in one
//! file with the tests that pin it.
//!
//! # The parts worth knowing about
//!
//! **`clientKey` is decoded during deserialization, not after.** The field's
//! type is [`ViturKeyMaterial`] — cipherstash-client's own key material type,
//! `Zeroize + ZeroizeOnDrop` — and [`deserialize_hex_key`] decodes hex straight
//! into it. So there is no hex `String` on any struct to wipe later, and no
//! window between "options parsed" and "key consumed" for one to sit in.
//!
//! One caveat, and it is not fixable here: `#[serde(flatten)]` below makes
//! serde buffer the map through `serde::__private::de::Content` before the
//! field impls run, so the hex does pass through a `String` that nothing wipes.
//! Neon's `Json` extractor already stringifies the entire options payload for
//! the same reason. Narrowing that is the extractor's business; what this
//! module guarantees is that nothing it *holds* outlives its use.
//!
//! **`clientId` names itself on failure.** See [`deserialize_client_id`].
//!
//! **Unknown keys are dropped, not rejected.** No `deny_unknown_fields`, so a
//! `keyset` left at the top level of `newClient` — where the wasm entry used to
//! take it — is silently ignored and the client binds to the default keyset.
//! Tracked in #147; the CHANGELOG calls it out under Breaking.

#[cfg(not(target_arch = "wasm32"))]
use cipherstash_client::zerokms::FallbackKeyProvider;
use cipherstash_client::zerokms::{SecretKey, ViturKeyMaterial};
use cipherstash_client::{AutoStrategy, IdentifiedBy};
use cts_common::Crn;
#[cfg(not(target_arch = "wasm32"))]
use serde::Serialize;
use serde::{Deserialize, Deserializer};
use uuid::Uuid;

use crate::encrypt_config::EncryptConfigInput;
use crate::DenyUnknown;
use crate::Error;

/// Parse `clientId`, naming the field on failure.
///
/// [`Uuid`]'s own `Deserialize` reports a bare `UUID parsing failed: ...`, and
/// [`CredentialOpts`] is reached through `#[serde(flatten)]`, which buffers the
/// map and reports at its closing brace — so serde supplies no field context
/// either. Without this the caller gets a parse error with nothing tying it to
/// a key they wrote.
fn deserialize_client_id<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    Uuid::parse_str(&raw)
        .map(Some)
        .map_err(|e| serde::de::Error::custom(format!("invalid clientId: {e}")))
}

/// Decode a hex `clientKey` into cipherstash-client's [`ViturKeyMaterial`].
///
/// Decoding at the boundary rather than holding the hex and converting later is
/// what keeps the key material inside a zeroizing type for its whole life here.
/// `ViturKeyMaterial`'s own `Deserialize` is base64 (it is what
/// `secretkey.json` stores on the wire), so the hex spelling this option uses
/// needs its own impl.
///
/// **Hex only.** `SecretKey::from_hex` also accepts standard padded base64, so
/// a value copied out of `secretkey.json` works in `CS_CLIENT_KEY`. That
/// tolerance belongs to the CLI's key handling; an explicit
/// `clientOpts.clientKey` is hex. It is a breaking narrowing — see the
/// CHANGELOG.
///
/// **The decode error is discarded.** `hex`'s `Display` is `Invalid character
/// {c:?} at position {index}`, which would put a character of the caller's
/// actual key, and its offset, into a message bound for logs and error
/// trackers.
fn deserialize_hex_key<'de, D>(deserializer: D) -> Result<Option<ViturKeyMaterial>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    hex::decode(raw.as_bytes())
        .map(|bytes| Some(ViturKeyMaterial::from(bytes)))
        .map_err(|_| serde::de::Error::custom("invalid clientKey: expected a hex-encoded key"))
}

/// Credential fields shared by [`ClientOpts`] and [`EnsureKeysetOpts`].
///
/// Every field is optional on both targets, because "which of these are
/// required" is a target question, not a shape question: the Neon entry falls
/// back to `~/.cipherstash/secretkey.json`, and wasm — which has no filesystem
/// and no readable environment — reports what is missing from
/// [`CredentialOpts::build_key_provider`].
///
/// No `deny_unknown_fields` of its own: this is a `#[serde(flatten)]` target,
/// and a flattened struct is fed the outer struct's leftovers through
/// `FlatMapDeserializer`, which ignores what it doesn't recognise no matter
/// what the inner struct asks for. The rejection has to happen on the outer
/// struct — [`ClientOpts`] and [`EnsureKeysetOpts`] both carry it, and both are
/// already on the map path this needs (see [`DenyUnknown`]) by virtue of
/// flattening this.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialOpts {
    workspace_crn: Option<Crn>,
    access_key: Option<String>,
    /// UUID identifying the client key. Parsed at the boundary rather than
    /// carried as a `String` and validated later inside the key provider, so a
    /// malformed value fails before any network I/O.
    #[serde(default, deserialize_with = "deserialize_client_id")]
    client_id: Option<Uuid>,
    /// Hex-encoded client key, decoded into cipherstash-client's own zeroizing
    /// key material type as it is read. See [`deserialize_hex_key`].
    #[serde(default, deserialize_with = "deserialize_hex_key")]
    client_key: Option<ViturKeyMaterial>,
}

impl CredentialOpts {
    /// Build an [`AutoStrategy`] from optional workspace CRN and access key,
    /// falling back to env vars and profile store for unset fields.
    ///
    /// On wasm, `AutoStrategy`'s own arm is access-key-only — `stack-auth`
    /// compiles out the profile-store fallback, and `std::env::var` always
    /// returns `Err` on `wasm32-unknown-unknown` — so this resolves exactly
    /// "an `AccessKeyStrategy` from the supplied CRN and access key".
    pub(crate) fn build_strategy(&self) -> Result<AutoStrategy, Error> {
        let mut builder = AutoStrategy::builder();
        if let Some(key) = self.access_key.as_ref() {
            builder = builder.with_access_key(key);
        }
        if let Some(crn) = self.workspace_crn.as_ref() {
            builder = builder.with_workspace_crn(crn.clone());
        }
        Ok(builder.detect()?)
    }

    /// Build a [`SecretKey`] from the `clientId` + `clientKey` pair.
    ///
    /// `None` if either half is missing — on the Neon target that triggers
    /// `FallbackKeyProvider` to try the profile store; on wasm it is an error,
    /// since there is no store to fall back to. Both halves are already
    /// validated by this point: the only work left is pairing them.
    fn secret_key(&self) -> Option<SecretKey> {
        let (Some(client_id), Some(client_key)) = (self.client_id, self.client_key.as_ref()) else {
            return None;
        };
        // `ViturKeyMaterial` derefs to `[u8]`; `SecretKey` owns its copy, and
        // both wipe on drop.
        Some(SecretKey::new(
            client_id,
            ViturKeyMaterial::from(client_key.to_vec()),
        ))
    }

    /// Build a key provider that resolves the client key from explicit fields,
    /// falling back to the profile store (`~/.cipherstash/secretkey.json`).
    ///
    /// Note: env vars (`CS_CLIENT_ID`/`CS_CLIENT_KEY`) are read on the JS side
    /// and passed through as explicit fields to support Bun.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn build_key_provider(
        &self,
    ) -> Result<FallbackKeyProvider<Option<SecretKey>, stack_profile::ProfileStore>, Error> {
        Ok(FallbackKeyProvider::new(
            self.secret_key(),
            stack_profile::ProfileStore::default(),
        ))
    }

    /// Build a key provider for wasm: the explicit client key, and nothing
    /// else.
    ///
    /// Same name and same call shape as the Neon version above, so
    /// `new_client` reads identically on both targets and the divergence stays
    /// confined to this one function. What differs is only what wasm cannot
    /// have: there is no filesystem, so no `~/.cipherstash/secretkey.json` to
    /// fall back to, which makes the credentials required rather than
    /// optional. Erroring here names the missing fields; letting `None` through
    /// would fail later inside ZeroKMS with something far less useful.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn build_key_provider(&self) -> Result<SecretKey, Error> {
        self.secret_key().ok_or_else(|| {
            Error::Credentials(
                "clientOpts.clientId and clientOpts.clientKey are required — this build has no \
                 profile store to fall back to"
                    .to_string(),
            )
        })
    }
}

/// `newClient`'s `clientOpts`: credentials, plus which keyset to scope to.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ClientOpts {
    #[serde(flatten)]
    pub(crate) creds: CredentialOpts,
    /// Keyset to scope the cipher to, by id or name. `None` uses the default
    /// keyset granted to the client.
    ///
    /// The wasm entry took this at the TOP level before #142. It is dropped
    /// silently if left there — see the module header.
    pub(crate) keyset: Option<IdentifiedBy>,
}

/// `ensureKeyset` is a Neon-only export, so on wasm these are dead code. Gated
/// to keep the lint honest, NOT because the split is right: the missing wasm
/// export is an oversight rather than a boundary (#149). Taking these two gates
/// off is what marks that issue done. See the `wasm` module docs.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EnsureKeysetOpts {
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) creds: CredentialOpts,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize)]
pub(crate) struct EnsureKeysetResult {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NewClientOptions {
    pub(crate) encrypt_config: EncryptConfigInput,
    pub(crate) client_opts: Option<ClientOpts>,
    /// EQL wire version to emit: 2 or 3. When omitted, SteVec configurations
    /// use v3 and scalar-only configurations retain the v2 default. Sits
    /// alongside `encrypt_config` (not in `client_opts`, which carries
    /// credentials + keyset) because it configures the encryption output
    /// format.
    pub(crate) eql_version: Option<u8>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "8f1a4d2e-0000-4000-8000-000000000001";

    fn client_opts(value: serde_json::Value) -> Result<ClientOpts, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// `ClientOpts` is deliberately not `Debug` — it holds key material — so
    /// the error-path cases go through this rather than `expect_err`.
    fn client_opts_err(value: serde_json::Value) -> String {
        match client_opts(value) {
            Ok(_) => panic!("expected a deserialization error"),
            Err(e) => e.to_string(),
        }
    }

    fn new_client_options(value: serde_json::Value) -> Result<NewClientOptions, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// `NewClientOptions` reaches `ClientOpts`, so it is not `Debug` either.
    fn new_client_options_err(value: serde_json::Value) -> String {
        match new_client_options(value) {
            Ok(_) => panic!("expected a deserialization error"),
            Err(e) => e.to_string(),
        }
    }

    fn minimal_config() -> serde_json::Value {
        json!({"v": 1, "tables": {"users": {"email": {"cast_as": "text", "indexes": {}}}}})
    }

    // --- the shape both bindings accept -----------------------------------

    #[test]
    fn credentials_and_keyset_live_under_client_opts() {
        let opts = new_client_options(json!({
            "encryptConfig": minimal_config(),
            "clientOpts": {
                "clientId": ID,
                "clientKey": "aabbccdd",
                "workspaceCrn": "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY",
                "accessKey": "CSAK.test",
                "keyset": {"Name": "prod"},
            },
            "eqlVersion": 3,
        }))
        .expect("should deserialize");

        let client_opts = opts.client_opts.expect("clientOpts present");
        assert!(client_opts.keyset.is_some());
        assert!(client_opts.creds.secret_key().is_some());
        assert_eq!(opts.eql_version, Some(3));
    }

    #[test]
    fn every_option_but_encrypt_config_is_optional() {
        // `newClient({ encryptConfig })` is legal on both bindings: whether
        // credentials resolve is a runtime question, answered by
        // `build_strategy` / `build_key_provider`, not by the shape.
        let opts = new_client_options(json!({"encryptConfig": minimal_config()}))
            .expect("should deserialize");
        assert!(opts.client_opts.is_none());
        assert!(opts.eql_version.is_none());
    }

    #[test]
    fn omitted_credentials_yield_no_secret_key() {
        // The Neon path reads this as "try the profile store"; the wasm path
        // turns it into the "clientId and clientKey are required" error.
        for value in [
            json!({}),
            json!({"clientId": ID}),
            json!({"clientKey": "aabbccdd"}),
        ] {
            let opts = client_opts(value.clone()).expect("should deserialize");
            assert!(
                opts.creds.secret_key().is_none(),
                "half a credential pair is not a key: {value}"
            );
        }
    }

    #[test]
    fn a_malformed_workspace_crn_is_rejected_at_the_boundary() {
        // `Crn` parses in its own `Deserialize`, so this fails here rather than
        // inside `AutoStrategy::detect()`. Named separately from `clientId`
        // because `cts_common`'s message already says "Invalid CRN".
        let err = client_opts_err(json!({"workspaceCrn": "not-a-crn"}));
        assert!(err.contains("CRN"), "got: {err}");
    }

    // --- unknown keys ------------------------------------------------------

    #[test]
    fn an_unknown_key_is_rejected_by_name() {
        // #144. These used to deserialize and be dropped: a top-level `keyset`
        // or `clientId` did not become a `clientOpts`, it became nothing, and
        // the caller found out later — or not at all.
        let err = new_client_options_err(json!({
            "encryptConfig": minimal_config(),
            "totallyMadeUp": 42,
        }));
        assert!(err.contains("unknown field `totallyMadeUp`"), "got: {err}");
    }

    #[test]
    fn a_misplaced_keyset_is_rejected_rather_than_dropped() {
        // The wasm entry took `keyset` at the top level before #142. Moving it
        // under `clientOpts` is now a failure a caller can see, not a silent
        // downgrade to the default keyset.
        let err = new_client_options_err(json!({
            "encryptConfig": minimal_config(),
            "keyset": {"Name": "prod"},
        }));
        assert!(err.contains("unknown field `keyset`"), "got: {err}");
    }

    // --- clientId ----------------------------------------------------------

    #[test]
    fn a_malformed_client_id_names_the_field() {
        // `#[serde(flatten)]` buffers the map and reports at its closing brace
        // with no field context, so the name has to come from the message.
        // Without `deserialize_client_id` this reads "UUID parsing failed: ..."
        // and the caller has to guess which key it means.
        let err = client_opts_err(json!({"clientId": "not-a-uuid", "clientKey": "aabb"}));
        assert!(err.contains("clientId"), "got: {err}");
    }

    #[test]
    fn a_malformed_client_id_fails_even_with_no_client_key() {
        // Before #142 `client_id` was a `String`, validated only as half of the
        // pair — so this call fell through to the profile store and succeeded
        // on the Neon entry. Fail-closed now; it is in the CHANGELOG.
        assert!(client_opts(json!({"clientId": "not-a-uuid"})).is_err());
    }

    #[test]
    fn an_absent_client_id_is_not_an_error() {
        let opts = client_opts(json!({"workspaceCrn": null})).expect("should deserialize");
        assert!(opts.creds.client_id.is_none());
    }

    // --- clientKey ---------------------------------------------------------

    #[test]
    fn a_hex_client_key_decodes_to_the_bytes_it_names() {
        let opts = client_opts(json!({"clientId": ID, "clientKey": "00ff10"}))
            .expect("should deserialize");
        assert_eq!(
            opts.creds.client_key.as_deref(),
            Some(&[0x00, 0xff, 0x10][..])
        );
    }

    #[test]
    fn a_bad_client_key_does_not_echo_the_key_material() {
        // `hex`'s Display is `Invalid character {c:?} at position {index}` —
        // interpolating it would put a character of the caller's real key, and
        // its offset, into logs and error trackers.
        let err = client_opts_err(json!({"clientId": ID, "clientKey": "aabbZZdd"}));
        assert!(!err.contains('Z'), "leaked key material: {err}");
        assert!(!err.contains("position"), "leaked an offset: {err}");
        assert!(err.contains("clientKey"), "should name the field: {err}");
    }

    #[test]
    fn a_base64_client_key_is_rejected() {
        // `SecretKey::from_hex` accepts it (that is what `secretkey.json`
        // stores), and this option deliberately does not. Breaking, and in the
        // CHANGELOG — a caller who pasted a base64 key into `CS_CLIENT_KEY`
        // needs to know it stopped working rather than find out at runtime.
        let err = client_opts_err(json!({"clientId": ID, "clientKey": "3q2+7wA="}));
        assert!(err.contains("clientKey"), "got: {err}");
    }

    #[test]
    fn an_odd_length_client_key_is_rejected() {
        assert!(client_opts(json!({"clientId": ID, "clientKey": "abc"})).is_err());
    }

    // --- undefined-valued keys --------------------------------------------
    // `{ clientKey: opts.clientKey }` with an undefined `clientKey` is ordinary
    // JavaScript. Neon never sees these — its extractor is JSON.stringify-based
    // — but on wasm they arrive as `Value::Null`, so every field here has to
    // treat an explicit null as absent or one config stops working on the other
    // binding. `#[serde(default)]` alone does NOT cover this.

    #[test]
    fn explicit_nulls_read_as_absent_fields() {
        let opts = client_opts(json!({
            "clientId": null,
            "clientKey": null,
            "workspaceCrn": null,
            "accessKey": null,
            "keyset": null,
        }))
        .expect("nulls are absent fields, not type errors");
        assert!(opts.creds.secret_key().is_none());
        assert!(opts.keyset.is_none());
    }

    #[test]
    fn an_explicitly_null_client_opts_reads_as_absent() {
        let opts = new_client_options(json!({
            "encryptConfig": minimal_config(),
            "clientOpts": null,
            "eqlVersion": null,
        }))
        .expect("should deserialize");
        assert!(opts.client_opts.is_none());
        assert!(opts.eql_version.is_none());
    }

    // --- ensureKeyset ------------------------------------------------------

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn ensure_keyset_takes_the_same_credential_fields() {
        // Shared via `#[serde(flatten)]`, so `newClient`'s credentials and
        // `ensureKeyset`'s cannot drift apart.
        let opts: EnsureKeysetOpts = serde_json::from_value(json!({
            "name": "prod",
            "clientId": ID,
            "clientKey": "aabbccdd",
        }))
        .expect("should deserialize");
        assert_eq!(opts.name, "prod");
        assert!(opts.creds.secret_key().is_some());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn ensure_keyset_requires_a_name() {
        assert!(serde_json::from_value::<EnsureKeysetOpts>(json!({"clientId": ID})).is_err());
    }
}

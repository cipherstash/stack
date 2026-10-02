//! The guest's operations, written against [`stack_profile::ProfileStore`]
//! over a directory the caller names, so they compile — and their tests run
//! — on the native host target against a temporary directory. The
//! wasm32-only [`crate::abi`] module wires them to the packed ABI; nothing
//! in here knows about linear memory.
//!
//! Every operation takes the store's directory as bytes: on wasm32 that is
//! a guest path under the mount, and the Go side names it on every call
//! rather than the guest keeping a handle. A workspace-scoped store is the
//! same thing with a longer directory, which [`workspace_dir`] produces
//! through the crate's own validation.
//!
//! # Errors
//!
//! Every function reports a [`crate::status`] code, never a message. A
//! directory, id or filename that is not UTF-8, or an empty directory, is
//! [`STATUS_ENCODING`]; everything else is `stack-profile`'s verdict
//! ([`status_for_profile`]).
//!
//! # Copies
//!
//! `stack-profile` reads a file into a `String` and deserializes from it,
//! and this module builds the result out of what it deserialized. The
//! file's contents and the intermediate values are freed when they drop,
//! not wiped; the codec buffer that crosses to the host *is* wiped, by the
//! registry, once the host has taken it. What this leaves in freed guest
//! memory lives in linear memory the host locks, excludes from dumps and
//! wipes on release, and nowhere else.

use serde::Deserialize;
use stack_auth::Token;
use stack_profile::{DeviceIdentity, ProfileStore};
use vitaminc_aead_value::{transport as codec, FfiValue};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::status::{status_for_profile, STATUS_ENCODING, STATUS_INTERNAL};

/// The file `secretkey.json`, as `stack-auth`'s device client writes it
/// and `stack-kms`'s `SecretKey` reads it: the ZeroKMS client id and the
/// client key material, standard padded base64. The key crosses to the
/// host in the form the file holds, which is one of the two forms
/// `stackencrypt`'s config takes — as bytes, so the host gets a slice it
/// can wipe rather than a string it cannot. What is deserialized here is
/// wiped when it drops; what is moved out of it into the codec value is
/// wiped by the codec's own protected types.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct SecretKeyFile {
    client_id: String,
    client_key: String,
}

/// The filename `stack-kms`'s `SecretKey` declares. Spelled here rather
/// than taken from that crate, which this guest does not build: its
/// `ProfileData` impl is where the name lives, and this constant is pinned
/// to it by the Go tests that write the file where `stash auth login` does.
const SECRET_KEY_FILENAME: &str = "secretkey.json";

/// The filename `stack-auth`'s `Token` declares. Kept here for the profile
/// read export, with a native test checking the crate's own name.
const AUTH_FILENAME: &str = "auth.json";

/// The store at `dir`. The directory is the caller's to name; an empty or
/// non-UTF-8 one is refused before any path is built.
pub fn store(dir: &[u8]) -> Result<ProfileStore, u32> {
    let dir = text(dir)?;
    if dir.is_empty() {
        return Err(STATUS_ENCODING);
    }
    Ok(ProfileStore::new(dir))
}

fn text(bytes: &[u8]) -> Result<&str, u32> {
    std::str::from_utf8(bytes).map_err(|_| STATUS_ENCODING)
}

fn string(value: impl Into<String>) -> FfiValue {
    FfiValue::String(value.into().into())
}

fn optional(value: Option<&str>) -> FfiValue {
    value.map_or(FfiValue::Null, string)
}

fn encode(value: FfiValue) -> Result<Vec<u8>, u32> {
    let mut out = Vec::new();
    codec::encode_value(value, &mut out).map_err(|_| STATUS_INTERNAL)?;
    Ok(out)
}

/// The current workspace id, as text.
pub fn current_workspace(dir: &[u8]) -> Result<Vec<u8>, u32> {
    store(dir)?
        .current_workspace()
        .map(String::into_bytes)
        .map_err(|e| status_for_profile(&e))
}

/// Set the current workspace. The workspace must already have a directory;
/// a login creates one, this guest never does. Empty output.
pub fn set_current_workspace(dir: &[u8], id: &[u8]) -> Result<Vec<u8>, u32> {
    store(dir)?
        .set_current_workspace(text(id)?)
        .map(|()| Vec::new())
        .map_err(|e| status_for_profile(&e))
}

/// Remove the current workspace selection. Empty output; nothing to remove
/// is not an error.
pub fn clear_current_workspace(dir: &[u8]) -> Result<Vec<u8>, u32> {
    store(dir)?
        .clear_current_workspace()
        .map(|()| Vec::new())
        .map_err(|e| status_for_profile(&e))
}

/// The workspace ids with profile data on disk, sorted, as a codec array
/// of strings.
pub fn list_workspaces(dir: &[u8]) -> Result<Vec<u8>, u32> {
    let ids = store(dir)?
        .list_workspaces()
        .map_err(|e| status_for_profile(&e))?;
    encode(FfiValue::Array(ids.into_iter().map(string).collect()))
}

/// The directory of the store scoped to workspace `id`, as text: what
/// [`ProfileStore::workspace_store`] would root a store at, after the
/// crate has validated the id. The host names this directory on the calls
/// it scopes to that workspace.
pub fn workspace_dir(dir: &[u8], id: &[u8]) -> Result<Vec<u8>, u32> {
    let scoped = store(dir)?
        .workspace_store(text(id)?)
        .map_err(|e| status_for_profile(&e))?;
    path_bytes(scoped.dir())
}

/// The path of the lock file [`ProfileStore::lock_exclusive`] would take
/// for `filename`, as text. Nothing is created or locked: the host holds
/// the lock, on this path, because this guest cannot.
pub fn lock_path(dir: &[u8], filename: &[u8]) -> Result<Vec<u8>, u32> {
    let path = store(dir)?
        .lock_path(text(filename)?)
        .map_err(|e| status_for_profile(&e))?;
    path_bytes(&path)
}

fn path_bytes(path: &std::path::Path) -> Result<Vec<u8>, u32> {
    // A path the crate built from UTF-8 parts is UTF-8; anything else is
    // this module's bug, not the caller's.
    path.to_str()
        .map(|s| s.as_bytes().to_vec())
        .ok_or(STATUS_INTERNAL)
}

/// `secretkey.json` in this store, as a codec object `{client_id,
/// client_key}`: the client id as a string, and the key material as
/// bytes, in the form the file holds it.
pub fn secret_key(dir: &[u8]) -> Result<Vec<u8>, u32> {
    let mut file: SecretKeyFile = store(dir)?
        .load(SECRET_KEY_FILENAME)
        .map_err(|e| status_for_profile(&e))?;
    // Moved out rather than copied: `SecretKeyFile` wipes on drop, so its
    // fields cannot be moved out of it directly.
    let client_id = std::mem::take(&mut file.client_id);
    let client_key = std::mem::take(&mut file.client_key);
    encode(FfiValue::Object(vec![
        ("client_id".to_string(), string(client_id)),
        (
            "client_key".to_string(),
            FfiValue::Bytes(client_key.into_bytes().into()),
        ),
    ]))
}

/// `auth.json` in this store, read as [`stack_auth::Token`] so its shape is
/// the crate's, as a codec object: `access_token` and `token_type`
/// (strings), `expires_at` (seconds since the epoch, `u64`), and `region`,
/// `client_id` and `device_instance_id` (each a string or null). The
/// refresh token is not in it, on purpose: the host presents the access
/// token and refuses it at expiry; the auth strategy exports handle refresh.
pub fn token(dir: &[u8]) -> Result<Vec<u8>, u32> {
    let token: Token = store(dir)?
        .load(AUTH_FILENAME)
        .map_err(|e| status_for_profile(&e))?;
    encode(FfiValue::Object(vec![
        (
            "access_token".to_string(),
            string(token.access_token().as_str()),
        ),
        ("token_type".to_string(), string(token.token_type())),
        (
            "expires_at".to_string(),
            FfiValue::UInt64(token.expires_at()),
        ),
        ("region".to_string(), optional(token.region())),
        ("client_id".to_string(), optional(token.client_id())),
        (
            "device_instance_id".to_string(),
            optional(token.device_instance_id()),
        ),
    ]))
}

/// Whether auth.json exists, without parsing it. AutoStrategy makes this
/// selection before building a device strategy, so malformed JSON must still
/// select the device path and then report its profile error.
pub fn has_token(dir: &[u8]) -> Result<Vec<u8>, u32> {
    Ok(vec![u8::from(store(dir)?.exists_profile::<Token>())])
}

/// `device.json` in this store, read-only, as a codec object
/// `{device_instance_id, device_name}`. Creating one is the CLI's.
pub fn device_identity(dir: &[u8]) -> Result<Vec<u8>, u32> {
    let identity = DeviceIdentity::load(&store(dir)?).map_err(|e| status_for_profile(&e))?;
    encode(FfiValue::Object(vec![
        (
            "device_instance_id".to_string(),
            string(identity.device_instance_id.to_string()),
        ),
        ("device_name".to_string(), string(identity.device_name)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::*;

    const WS_A: &str = "AAAAAAAAAAAAAAAA";
    const WS_B: &str = "BBBBBBBBBBBBBBBB";

    fn dir(t: &tempfile::TempDir) -> Vec<u8> {
        t.path().to_str().unwrap().as_bytes().to_vec()
    }

    fn decode(bytes: &[u8]) -> FfiValue {
        codec::decode_value(&mut codec::Reader::new(bytes)).unwrap()
    }

    fn field<'a>(value: &'a FfiValue, key: &str) -> &'a FfiValue {
        let FfiValue::Object(entries) = value else {
            panic!("not an object");
        };
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("no field {key}"))
    }

    fn as_text(value: &FfiValue) -> String {
        let FfiValue::String(s) = value else {
            panic!("not a string");
        };
        String::from_utf8(s.risky_ref().to_vec()).unwrap()
    }

    fn as_bytes(value: &FfiValue) -> Vec<u8> {
        use vitaminc_protected::Controlled;
        let FfiValue::Bytes(b) = value else {
            panic!("not bytes");
        };
        b.risky_ref().to_vec()
    }

    #[test]
    fn has_token_selects_existing_profile_without_parsing_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUTH_FILENAME);
        let store_dir = dir.path().to_str().unwrap().as_bytes();
        assert_eq!(has_token(store_dir).unwrap(), vec![0]);
        std::fs::write(path, "{").unwrap();
        assert_eq!(has_token(store_dir).unwrap(), vec![1]);
    }

    /// The names this guest spells are the crates' own.
    #[test]
    fn spelled_filenames_are_the_crates() {
        use stack_profile::ProfileData;
        assert_eq!(AUTH_FILENAME, <Token as ProfileData>::FILENAME);
        assert_eq!(
            <DeviceIdentity as ProfileData>::FILENAME,
            "device.json",
            "the device identity is read through its own impl"
        );
    }

    #[test]
    fn a_directory_must_be_utf8_and_non_empty() {
        assert_eq!(store(b"").unwrap_err(), STATUS_ENCODING);
        assert_eq!(store(&[0xff, 0xfe]).unwrap_err(), STATUS_ENCODING);
        assert!(store(b"/profile").is_ok());
    }

    #[test]
    fn workspace_selection_round_trips_and_lists() {
        let t = tempfile::tempdir().unwrap();
        let d = dir(&t);
        assert_eq!(
            current_workspace(&d).unwrap_err(),
            STATUS_PROFILE_NO_CURRENT_WORKSPACE
        );
        // A workspace must exist before it can be current: a login makes
        // the directory, this guest never does.
        assert_eq!(
            set_current_workspace(&d, WS_A.as_bytes()).unwrap_err(),
            STATUS_PROFILE_WORKSPACE_NOT_FOUND
        );
        std::fs::create_dir_all(t.path().join("workspaces").join(WS_B)).unwrap();
        std::fs::create_dir_all(t.path().join("workspaces").join(WS_A)).unwrap();
        assert_eq!(set_current_workspace(&d, WS_A.as_bytes()).unwrap(), b"");
        assert_eq!(current_workspace(&d).unwrap(), WS_A.as_bytes());

        let listed = decode(&list_workspaces(&d).unwrap());
        let FfiValue::Array(items) = listed else {
            panic!("not an array");
        };
        let ids: Vec<String> = items.iter().map(as_text).collect();
        assert_eq!(ids, vec![WS_A, WS_B], "sorted, as the crate lists them");

        assert_eq!(clear_current_workspace(&d).unwrap(), b"");
        assert_eq!(
            current_workspace(&d).unwrap_err(),
            STATUS_PROFILE_NO_CURRENT_WORKSPACE
        );
        assert_eq!(
            clear_current_workspace(&d).unwrap(),
            b"",
            "clearing twice is not an error"
        );
    }

    #[test]
    fn workspace_dir_is_the_crates_and_the_id_is_validated_first() {
        let t = tempfile::tempdir().unwrap();
        let d = dir(&t);
        let scoped = workspace_dir(&d, WS_A.as_bytes()).unwrap();
        assert_eq!(
            std::path::Path::new(std::str::from_utf8(&scoped).unwrap()),
            t.path().join("workspaces").join(WS_A)
        );
        for bad in ["../escape", "", "aaaaaaaaaaaaaaaa", "0000000000000000"] {
            assert_eq!(
                workspace_dir(&d, bad.as_bytes()).unwrap_err(),
                STATUS_PROFILE_INVALID_WORKSPACE_ID,
                "{bad:?}"
            );
        }
        assert_eq!(
            workspace_dir(&d, &[0xff]).unwrap_err(),
            STATUS_ENCODING,
            "an id that is not UTF-8 is refused before validation"
        );
    }

    #[test]
    fn lock_path_names_the_sibling_lock_file_and_validates_the_filename() {
        let t = tempfile::tempdir().unwrap();
        let d = dir(&t);
        let path = lock_path(&d, b"auth.json").unwrap();
        assert_eq!(
            std::path::Path::new(std::str::from_utf8(&path).unwrap()),
            t.path().join(".auth.json.lock")
        );
        assert!(
            !t.path().join(".auth.json.lock").exists(),
            "nothing is created"
        );
        for bad in ["", "../auth.json", "/etc/auth.json", "a/b.json"] {
            assert_eq!(
                lock_path(&d, bad.as_bytes()).unwrap_err(),
                STATUS_PROFILE_INVALID_FILENAME,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn typed_reads_return_the_files_fields_and_not_found_otherwise() {
        let t = tempfile::tempdir().unwrap();
        let d = dir(&t);
        assert_eq!(secret_key(&d).unwrap_err(), STATUS_PROFILE_NOT_FOUND);
        assert_eq!(token(&d).unwrap_err(), STATUS_PROFILE_NOT_FOUND);
        assert_eq!(device_identity(&d).unwrap_err(), STATUS_PROFILE_NOT_FOUND);

        std::fs::write(
            t.path().join("secretkey.json"),
            r#"{"client_id":"6a70bd18-99ac-4650-b104-37eec3a15b09","client_key":"AAECAw=="}"#,
        )
        .unwrap();
        let key = decode(&secret_key(&d).unwrap());
        assert_eq!(
            as_text(field(&key, "client_id")),
            "6a70bd18-99ac-4650-b104-37eec3a15b09"
        );
        assert_eq!(
            as_bytes(field(&key, "client_key")),
            b"AAECAw==",
            "the key crosses as bytes, in the form the file holds"
        );

        std::fs::write(
            t.path().join("auth.json"),
            r#"{"access_token":"tok","refresh_token":"refresh","token_type":"Bearer","expires_at":1800000000,"region":"ap-southeast-2"}"#,
        )
        .unwrap();
        let tok = decode(&token(&d).unwrap());
        assert_eq!(as_text(field(&tok, "access_token")), "tok");
        assert_eq!(as_text(field(&tok, "token_type")), "Bearer");
        assert!(matches!(
            field(&tok, "expires_at"),
            FfiValue::UInt64(1_800_000_000)
        ));
        assert_eq!(as_text(field(&tok, "region")), "ap-southeast-2");
        assert!(matches!(field(&tok, "client_id"), FfiValue::Null));
        let FfiValue::Object(entries) = tok else {
            panic!("not an object");
        };
        assert!(
            entries.iter().all(|(k, _)| k != "refresh_token"),
            "the refresh token never crosses to the host"
        );

        std::fs::write(
            t.path().join("device.json"),
            r#"{"device_instance_id":"0f4a4fd7-4a1a-4c5e-9d3e-7a4c8e3a9c11","device_name":"laptop"}"#,
        )
        .unwrap();
        let identity = decode(&device_identity(&d).unwrap());
        assert_eq!(
            as_text(field(&identity, "device_instance_id")),
            "0f4a4fd7-4a1a-4c5e-9d3e-7a4c8e3a9c11"
        );
        assert_eq!(as_text(field(&identity, "device_name")), "laptop");
    }

    #[test]
    fn a_malformed_file_is_a_json_status_not_a_trap() {
        let t = tempfile::tempdir().unwrap();
        let d = dir(&t);
        std::fs::write(t.path().join("auth.json"), "{not json").unwrap();
        assert_eq!(token(&d).unwrap_err(), STATUS_PROFILE_JSON);
        std::fs::write(t.path().join("secretkey.json"), r#"{"client_id":"x"}"#).unwrap();
        assert_eq!(
            secret_key(&d).unwrap_err(),
            STATUS_PROFILE_JSON,
            "a missing field is a shape error"
        );
    }
}

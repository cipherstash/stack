//! The token operations on the step loop, on wasm32 under wazero, the Go
//! module's runtime: `stack-auth`'s real access-key strategy, with CTS
//! answered by hand through the steps. Only wasm32 runs them: natively,
//! `stack-auth` refreshes in a Tokio task the step loop does not poll.
//!
//! `mise run wasm:auth-guest:test` runs them, with wazero as the runner.
#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use stack_auth_guest::auth;
use stack_guest_abi::step::{self, Response, Step};
use zeroize::Zeroizing;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// An access-key strategy against a CTS these tests answer.
fn access_key() -> Vec<u8> {
    let config = serde_json::json!({
        "kind": "access_key",
        "crn": "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY",
        "access_key": "CSAKtestKeyId.testKeySecret",
        "base_url": "https://cts.example/",
    });
    auth::create(config.to_string().as_bytes()).unwrap()
}

/// A CTS token, named in its `sub` claim, that expires `expires_in`
/// seconds from now (negative: already expired).
fn cts(name: &str, expires_in: i64) -> Response {
    let exp = now() + expires_in;
    let b64 = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let claims = serde_json::json!({
        "iss": "https://cts.example/", "sub": name, "aud": "x", "iat": now(), "exp": exp,
        "workspace": "ZVATKW3VHMFG27DY", "org_id": "org", "scope": "",
    });
    let jwt = format!(
        "{}.{}.sig",
        b64(serde_json::json!({"alg": "HS256"})),
        b64(claims)
    );
    let body = serde_json::json!({"accessToken": jwt, "expiry": exp});
    Response::new(
        200,
        Vec::new(),
        Zeroizing::new(body.to_string().into_bytes()),
    )
}

/// The name of the CTS token an operation returned.
fn name(token: &[u8]) -> String {
    let token = std::str::from_utf8(token).unwrap();
    let claims = token.split('.').nth(1).unwrap();
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims)
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&claims).unwrap();
    claims["sub"].as_str().unwrap().to_owned()
}

fn fetch(strategy: &[u8]) -> Result<Step, u32> {
    step::start_parkable(auth::token(strategy).unwrap())
}

fn done(step: Result<Step, u32>) -> String {
    match step {
        Ok(Step::Done(token)) => name(&token),
        other => panic!("expected a token, got {other:?}"),
    }
}

/// The handle of an operation waiting on one request to CTS.
fn exchanging(step: Result<Step, u32>) -> u64 {
    match step {
        Ok(Step::NeedsIo { handle, requests }) => {
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].url, "https://cts.example/api/authorise");
            handle
        }
        other => panic!("expected a request to CTS, got {other:?}"),
    }
}

fn parked(step: Result<Step, u32>) -> u64 {
    match step {
        Ok(Step::Parked { handle }) => handle,
        other => panic!("expected a parked operation, got {other:?}"),
    }
}

/// A strategy with a token that expires `expires_in` seconds from now.
fn strategy_holding(name: &str, expires_in: i64) -> Vec<u8> {
    let strategy = access_key();
    let first = exchanging(fetch(&strategy));
    assert_eq!(done(step::resume(first, vec![cts(name, expires_in)])), name);
    strategy
}

#[test]
fn the_first_fetch_pauses_at_its_request_and_callers_meanwhile_park() {
    let strategy = access_key();
    let first = exchanging(fetch(&strategy));
    let second = parked(fetch(&strategy));
    let third = parked(fetch(&strategy));
    assert!(step::runnable().is_empty());
    assert_eq!(done(step::resume(first, vec![cts("one", 900)])), "one");
    // One waiter at a time: the lock passes from each to the next.
    assert_eq!(step::runnable(), vec![second]);
    assert_eq!(done(step::resume(second, vec![])), "one");
    assert_eq!(step::runnable(), vec![third]);
    assert_eq!(done(step::resume(third, vec![])), "one");
    assert_eq!(done(fetch(&strategy)), "one", "later calls read the cache");
    auth::free(&strategy).unwrap();
}

/// The fix for #1958: while one caller refreshes a token that is still
/// valid, every other caller gets that token at once.
#[test]
fn callers_during_a_refresh_of_a_valid_token_get_it_at_once() {
    // Inside the 90-second refresh window, and still valid.
    let strategy = strategy_holding("old", 60);
    let refreshing = exchanging(fetch(&strategy));
    assert_eq!(done(fetch(&strategy)), "old");
    assert_eq!(done(fetch(&strategy)), "old");
    assert_eq!(done(step::resume(refreshing, vec![cts("new", 900)])), "new");
    assert_eq!(done(fetch(&strategy)), "new");
    auth::free(&strategy).unwrap();
}

#[test]
fn a_failed_refresh_of_a_valid_token_still_returns_it() {
    let strategy = strategy_holding("old", 60);
    let refreshing = exchanging(fetch(&strategy));
    let failed = Response::new(503, Vec::new(), Zeroizing::new(b"{}".to_vec()));
    assert_eq!(done(step::resume(refreshing, vec![failed])), "old");
    auth::free(&strategy).unwrap();
}

#[test]
fn callers_after_expiry_park_behind_the_refresh() {
    let strategy = strategy_holding("expired", -5);
    let refreshing = exchanging(fetch(&strategy));
    let waiting = parked(fetch(&strategy));
    assert_eq!(done(step::resume(refreshing, vec![cts("new", 900)])), "new");
    assert_eq!(step::runnable(), vec![waiting]);
    assert_eq!(done(step::resume(waiting, vec![])), "new");
    auth::free(&strategy).unwrap();
}

/// A caller that gives up while parked is aborted; the exchange goes on.
#[test]
fn an_aborted_parked_caller_leaves_the_exchange_alone() {
    let strategy = access_key();
    let first = exchanging(fetch(&strategy));
    let gone = parked(fetch(&strategy));
    step::abort(gone).unwrap();
    assert!(step::runnable().is_empty());
    assert_eq!(done(step::resume(first, vec![cts("one", 900)])), "one");
    auth::free(&strategy).unwrap();
}

/// An access-key exchange rotates nothing: if the one exchanging is
/// dropped, a parked caller wakes and exchanges in its place.
#[test]
fn a_parked_caller_takes_over_an_exchange_that_was_dropped() {
    let strategy = access_key();
    let first = exchanging(fetch(&strategy));
    let waiting = parked(fetch(&strategy));
    step::abort(first).unwrap();
    assert_eq!(step::runnable(), vec![waiting]);
    let again = exchanging(step::resume(waiting, vec![]));
    assert_eq!(again, waiting);
    assert_eq!(done(step::resume(waiting, vec![cts("two", 900)])), "two");
    auth::free(&strategy).unwrap();
}

/// Freeing a strategy while an operation is paused on it: the operation
/// keeps the strategy and finishes; the handle is gone for new calls.
#[test]
fn freeing_a_strategy_lets_its_paused_operation_finish() {
    let strategy = access_key();
    let first = exchanging(fetch(&strategy));
    auth::free(&strategy).unwrap();
    assert!(auth::token(&strategy).is_err(), "the handle is freed");
    assert_eq!(done(step::resume(first, vec![cts("one", 900)])), "one");
}

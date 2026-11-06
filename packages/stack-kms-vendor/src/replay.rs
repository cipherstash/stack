//! Recorded HTTP exchanges for the tests of a key vendor backend.
//!
//! Every vendor crate tests its client against fixture files: JSON that
//! holds one exchange ([`Fixture`]) or a sequence of them. This module is
//! the one copy of the harness that reads them:
//!
//! * [`Fixtures`] finds and parses the files of one crate;
//! * [`Replay`] is a [`VendorTransport`] that checks each request against a
//!   fixture and answers with the fixture's response;
//! * [`Recording`] is a [`VendorTransport`] that sends through another one
//!   and keeps every exchange, to write fixtures from a live service.
//!
//! The vendor-specific parts (emulators, keys, constants) stay in each
//! crate's `tests/common/mod.rs`.
//!
//! ```ignore
//! use stack_kms_vendor::replay::{Fixtures, Replay};
//!
//! const FIXTURES: Fixtures =
//!     Fixtures::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"));
//!
//! let transport = Replay::new().expect(FIXTURES.load("encrypt.json"));
//! ```

// The harness is test code: it panics when a request differs from its
// fixture or a fixture file does not parse.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{TransportError, VendorRequest, VendorResponse, VendorTransport};

/// The request half of a recorded exchange.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureRequest {
    /// The HTTP method.
    pub method: String,
    /// The full URL.
    pub url: String,
    /// Every header, in the order it is sent.
    pub headers: Vec<(String, String)>,
    /// The body as JSON; see [`body_json`].
    pub body: Value,
}

/// The response half of a recorded exchange.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureResponse {
    /// The HTTP status.
    pub status: u16,
    /// The headers. Missing means none.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// The body: a JSON string is sent as its text, `null` as no bytes,
    /// and any other value as its JSON form.
    pub body: Value,
}

impl FixtureResponse {
    /// The response this fixture describes.
    pub fn to_response(&self) -> VendorResponse {
        let body = match &self.body {
            Value::String(text) => text.clone().into_bytes(),
            Value::Null => Vec::new(),
            other => serde_json::to_vec(other).unwrap(),
        };
        let mut response = VendorResponse::new(self.status, body);
        for (name, value) in &self.headers {
            response = response.header(name, value);
        }
        response
    }
}

/// One recorded exchange: a request and the response to it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fixture {
    /// The request the client must send.
    pub request: FixtureRequest,
    /// The response the vendor gave.
    pub response: FixtureResponse,
}

/// The fixture directory of one crate.
#[derive(Clone, Copy, Debug)]
pub struct Fixtures {
    dir: &'static str,
}

impl Fixtures {
    /// The fixtures in `dir`. Give an absolute path, such as
    /// `concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")`, so the
    /// tests do not depend on the working directory.
    pub const fn new(dir: &'static str) -> Self {
        Self { dir }
    }

    /// The path of the fixture file `name`.
    pub fn path(&self, name: &str) -> String {
        format!("{}/{name}", self.dir)
    }

    /// Parse the fixture file `name`. Panics with the path when the file
    /// cannot be read or parsed.
    pub fn load<T: DeserializeOwned>(&self, name: &str) -> T {
        let path = self.path(name);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// A [`Replay`] of the sequence of exchanges in the file `name`.
    pub fn replay(&self, name: &str) -> Replay {
        Replay::new().expect_all(self.load(name))
    }
}

/// A body as JSON, the form fixtures keep it in: no bytes is `null`, JSON
/// is its value, and any other bytes are a JSON string of their text.
pub fn body_json(body: &[u8]) -> Value {
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into()))
    }
}

/// A transport that checks each request against a recorded one and answers
/// with the recorded response. It panics on a request the fixtures do not
/// expect, and keeps the waits the client asks for instead of waiting.
#[derive(Debug, Default)]
pub struct Replay {
    exchanges: Mutex<VecDeque<(Option<FixtureRequest>, VendorResponse)>>,
    sleeps: Mutex<Vec<Duration>>,
}

impl Replay {
    /// A replay that expects no requests.
    pub fn new() -> Self {
        Self::default()
    }

    /// Expect `fixture`'s request and answer with its response.
    pub fn expect(self, fixture: Fixture) -> Self {
        let response = fixture.response.to_response();
        self.exchanges
            .lock()
            .unwrap()
            .push_back((Some(fixture.request), response));
        self
    }

    /// Expect each exchange of a recorded sequence, in order.
    pub fn expect_all(mut self, fixtures: Vec<Fixture>) -> Self {
        for fixture in fixtures {
            self = self.expect(fixture);
        }
        self
    }

    /// Answer the next request, whatever it is, with `response`.
    pub fn answer(self, response: VendorResponse) -> Self {
        self.exchanges.lock().unwrap().push_back((None, response));
        self
    }

    /// Whether every expected request was sent.
    pub fn is_done(&self) -> bool {
        self.exchanges.lock().unwrap().is_empty()
    }

    /// The waits the client asked for, in order.
    pub fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.lock().unwrap().clone()
    }
}

impl VendorTransport for Replay {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        let (expected, response) = self
            .exchanges
            .lock()
            .unwrap()
            .pop_front()
            .expect("a request the fixtures do not expect");
        if let Some(expected) = expected {
            let actual = json!({
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "body": body_json(&request.body),
            });
            let wanted = json!({
                "method": expected.method,
                "url": expected.url,
                "headers": expected.headers,
                "body": expected.body,
            });
            assert_eq!(
                actual,
                wanted,
                "the request differs from the fixture; actual:\n{}",
                serde_json::to_string_pretty(&actual).unwrap()
            );
        }
        Ok(response)
    }

    async fn sleep(&self, duration: Duration) {
        self.sleeps.lock().unwrap().push(duration);
    }
}

/// A transport that sends through `inner` and keeps every exchange, to
/// write fixtures. It keeps only the `content-type` header of a response.
#[derive(Debug)]
pub struct Recording<T> {
    /// The transport that sends.
    pub inner: T,
    /// The exchanges so far.
    pub exchanges: Mutex<Vec<Fixture>>,
}

impl<T> Recording<T> {
    /// A recording over `inner`, with no exchanges.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            exchanges: Mutex::new(Vec::new()),
        }
    }

    /// The exchanges so far, and forget them.
    pub fn take(&self) -> Vec<Fixture> {
        std::mem::take(&mut *self.exchanges.lock().unwrap())
    }
}

impl<T: VendorTransport + Send + Sync> VendorTransport for Recording<T> {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        let recorded = FixtureRequest {
            method: request.method.clone(),
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: body_json(&request.body),
        };
        let response = self.inner.send(request).await?;
        let headers = response
            .header_value("content-type")
            .map(|value| vec![("content-type".to_owned(), value.to_owned())])
            .unwrap_or_default();
        self.exchanges.lock().unwrap().push(Fixture {
            request: recorded,
            response: FixtureResponse {
                status: response.status,
                headers,
                body: body_json(&response.body),
            },
        });
        Ok(response)
    }

    async fn sleep(&self, duration: Duration) {
        self.inner.sleep(duration).await;
    }
}

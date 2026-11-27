//! How a step of a token operation crosses the boundary
//! ([`stack_guest_abi::step`]): the requests a paused operation hands the
//! host, the responses the host hands back, and the parked operations the
//! host may now resume. Each is one transport frame, a
//! [`HostValue`] as every other output of this guest is.
//!
//! When a token export pauses it returns `STATUS_NEEDS_IO` instead of an
//! output, and the host takes the step with `sa_auth_io`:
//!
//! ```text
//! { "handle": <u64>, "parked": <bool>,
//!   "requests": [ { "method": "POST", "url": <string>,
//!                   "headers": <bytes>, "body": <bytes> }, ... ] }
//! ```
//!
//! - **Waiting on the host** (`parked` false): the host performs every
//!   request and calls `sa_auth_resume` with the handle and their responses,
//!   in the same order:
//!
//!   ```text
//!   [ { "status": <i32>, "headers": <bytes>, "body": <bytes> }, ... ]
//!   ```
//!
//!   An empty `requests` list here is a yield: the host resumes at once,
//!   with no responses.
//! - **Parked** (`parked` true, `requests` empty): the operation waits on
//!   another one in this guest, such as the caller already exchanging the
//!   same credential. The host resumes it, with no responses, once
//!   `sa_auth_runnable` lists its handle. That list is a frame too: a list
//!   of handles (`u64`).
//!
//! `headers` is the `name: value` line format of
//! [`stack_guest_abi::headers`] both ways. A `status` is the HTTP status, or
//! negative for a request the host could not perform, with its error text as
//! the body. This is the step frame of the encrypt guest, field for field,
//! plus `parked`. A request carries the access key or a refresh token, and a
//! response a bearer token, so the guest wipes its copies, and the host
//! wipes the buffers with `se_dealloc`.

use stack_guest_abi::last_error::{internal, malformed};
use stack_guest_abi::step::{Request, Response};
use stack_guest_abi::value::HostValue;
use vitaminc_protected::{Controlled as _, Protected};
use zeroize::Zeroizing;

/// The step the host takes with `sa_auth_io`, as frame bytes. The caller
/// registers them, and the host's `se_dealloc` wipes them: they carry the
/// requests' credentials.
pub fn encode_step(handle: u64, parked: bool, requests: &[Request]) -> Result<Vec<u8>, u32> {
    let requests = requests
        .iter()
        .map(|request| {
            HostValue::Map(vec![
                ("method".to_owned(), HostValue::text(request.method)),
                ("url".to_owned(), HostValue::text(request.url.as_str())),
                (
                    "headers".to_owned(),
                    HostValue::Bytes(Protected::new(request.headers.to_vec())),
                ),
                (
                    "body".to_owned(),
                    HostValue::Bytes(Protected::new(request.body.to_vec())),
                ),
            ])
        })
        .collect();
    HostValue::Map(vec![
        ("handle".to_owned(), HostValue::UInt(handle)),
        ("parked".to_owned(), HostValue::Bool(parked)),
        ("requests".to_owned(), HostValue::List(requests)),
    ])
    .encode()
    .map_err(|_| internal("a step's requests could not be encoded"))
}

/// The parked operations the host may resume, as frame bytes.
pub fn encode_runnable(handles: &[u64]) -> Result<Vec<u8>, u32> {
    HostValue::List(handles.iter().copied().map(HostValue::UInt).collect())
        .encode()
        .map_err(|_| internal("the runnable operations could not be encoded"))
}

/// The responses the host handed `sa_auth_resume`, read into ones the guest
/// wipes. The refusal never quotes the bytes: a response carries a token.
pub fn decode_responses(bytes: &[u8]) -> Result<Vec<Response>, u32> {
    let refuse = || malformed("the responses are not a list of {status, headers, body} objects");
    let HostValue::List(items) = HostValue::decode(bytes).map_err(|_| refuse())? else {
        return Err(refuse());
    };
    items
        .into_iter()
        .map(|item| {
            let HostValue::Map(fields) = item else {
                return Err(refuse());
            };
            let (mut status, mut headers, mut body) = (None, None, None);
            for (key, value) in fields {
                match (key.as_str(), value) {
                    ("status", HostValue::UInt(u)) if status.is_none() => {
                        status = Some(i32::try_from(u).map_err(|_| refuse())?);
                    }
                    ("status", HostValue::Int(i)) if status.is_none() => {
                        status = Some(i32::try_from(i).map_err(|_| refuse())?);
                    }
                    ("headers", HostValue::Bytes(b)) if headers.is_none() => {
                        headers = Some(b.risky_ref().clone());
                    }
                    ("body", HostValue::Bytes(b)) if body.is_none() => {
                        body = Some(Zeroizing::new(b.risky_ref().clone()));
                    }
                    _ => return Err(refuse()),
                }
            }
            match (status, headers, body) {
                (Some(status), Some(headers), Some(body)) => {
                    Ok(Response::new(status, headers, body))
                }
                _ => Err(refuse()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_guest_abi::status::STATUS_ENCODING;

    fn frame(value: HostValue) -> Vec<u8> {
        value.encode().unwrap()
    }

    fn entry(key: &str, value: HostValue) -> (String, HostValue) {
        (key.to_owned(), value)
    }

    fn bytes(b: &[u8]) -> HostValue {
        HostValue::Bytes(Protected::new(b.to_vec()))
    }

    #[test]
    fn a_step_is_its_handle_whether_parked_and_its_requests() {
        let request = Request::new(
            "POST",
            "https://cts.example/api/authorise".to_owned(),
            Zeroizing::new(b"user-agent: x\n".to_vec()),
            Zeroizing::new(b"{\"accessKey\":\"k\"}".to_vec()),
        );
        let decoded = HostValue::decode(&encode_step(7, false, &[request]).unwrap()).unwrap();
        assert!(matches!(decoded.get("handle"), Some(HostValue::UInt(7))));
        assert!(matches!(
            decoded.get("parked"),
            Some(HostValue::Bool(false))
        ));
        let Some(HostValue::List(requests)) = decoded.get("requests") else {
            panic!("no requests");
        };
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].get("method").unwrap().as_text(), Some("POST"));
        assert_eq!(
            requests[0].get("url").unwrap().as_text(),
            Some("https://cts.example/api/authorise")
        );
        let Some(HostValue::Bytes(body)) = requests[0].get("body") else {
            panic!("no body");
        };
        assert_eq!(body.risky_ref(), b"{\"accessKey\":\"k\"}");
    }

    #[test]
    fn a_parked_step_asks_for_nothing() {
        let decoded = HostValue::decode(&encode_step(3, true, &[]).unwrap()).unwrap();
        assert!(matches!(decoded.get("parked"), Some(HostValue::Bool(true))));
        assert!(matches!(decoded.get("requests"), Some(HostValue::List(r)) if r.is_empty()));
    }

    #[test]
    fn runnable_is_a_list_of_handles() {
        let decoded = HostValue::decode(&encode_runnable(&[2, 9]).unwrap()).unwrap();
        let HostValue::List(items) = decoded else {
            panic!("not a list");
        };
        assert!(matches!(
            items.as_slice(),
            [HostValue::UInt(2), HostValue::UInt(9)]
        ));
    }

    #[test]
    fn responses_read_in_order_with_negative_statuses() {
        let responses = decode_responses(&frame(HostValue::List(vec![
            HostValue::Map(vec![
                entry("status", HostValue::UInt(200)),
                entry("headers", bytes(b"content-type: application/json")),
                entry("body", bytes(b"{}")),
            ]),
            HostValue::Map(vec![
                entry("status", HostValue::Int(-1)),
                entry("headers", bytes(b"")),
                entry("body", bytes(b"dial tcp: refused")),
            ]),
        ])))
        .unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].status, 200);
        assert_eq!(&*responses[0].body, b"{}");
        assert_eq!(responses[1].status, -1);
        assert_eq!(&*responses[1].body, b"dial tcp: refused");
    }

    #[test]
    fn malformed_responses_are_refused_without_echoing_them() {
        let response = |status: HostValue, headers: HostValue, more: Vec<(String, HostValue)>| {
            let mut fields = vec![
                entry("status", status),
                entry("headers", headers),
                entry("body", bytes(b"secret-looking")),
            ];
            fields.extend(more);
            HostValue::List(vec![HostValue::Map(fields)])
        };
        let missing_body = HostValue::List(vec![HostValue::Map(vec![
            entry("status", HostValue::UInt(200)),
            entry("headers", bytes(b"")),
        ])]);
        for bad in [
            HostValue::Null,
            missing_body,
            response(
                HostValue::UInt(200),
                bytes(b""),
                vec![entry("extra", HostValue::Bool(true))],
            ),
            response(HostValue::UInt(u64::from(u32::MAX)), bytes(b""), vec![]),
            response(
                HostValue::UInt(200),
                HostValue::text("secret-looking"),
                vec![],
            ),
        ] {
            assert_eq!(decode_responses(&frame(bad)).err(), Some(STATUS_ENCODING));
            let error = stack_guest_abi::last_error::take().unwrap();
            assert!(!String::from_utf8_lossy(&error).contains("secret-looking"));
        }
        assert_eq!(
            decode_responses(b"not a frame").err(),
            Some(STATUS_ENCODING)
        );
    }
}

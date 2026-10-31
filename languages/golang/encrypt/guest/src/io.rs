//! How a step of the step loop crosses the boundary
//! ([`stack_guest_abi::step`]): the requests a paused operation hands the
//! host, and the responses the host hands back. Both are transport frames,
//! read and written with serde.
//!
//! When an export pauses it returns `STATUS_NEEDS_IO` instead of an output,
//! and the host takes the step with `se_io`:
//!
//! ```text
//! { "handle": <u64>,
//!   "requests": [ { "method": "POST", "url": <string>,
//!                   "headers": <bytes>, "body": <bytes> }, ... ] }
//! ```
//!
//! The host performs every request and calls `se_resume` with the handle and
//! their responses, in the same order:
//!
//! ```text
//! [ { "status": <i32>, "headers": <bytes>, "body": <bytes> }, ... ]
//! ```
//!
//! `headers` is the `name: value` line format of
//! [`stack_guest_abi::headers`] both ways. A `status` is the HTTP status, or
//! negative for a request the host could not perform, with its error text as
//! the body: the contract `transport_send` had, field for field. A step
//! carries the bearer token and a request body that can hold key-material
//! contexts, and a response can carry wrapped keys, so the guest wipes its
//! copies, and the host wipes the buffers with `se_dealloc`.

use serde::{Deserialize, Serialize, Serializer};
use stack_encrypt::dynamic::frame::serde::{from_slice, to_vec};
use stack_guest_abi::last_error::malformed;
use stack_guest_abi::step::{Request, Response};
use zeroize::Zeroizing;

use crate::status::STATUS_ENCODING;

/// The step the host takes with `se_io`, as frame bytes. The bytes carry a
/// bearer token, so the caller registers them and the host's `se_dealloc`
/// wipes them; the staging buffer is wiped here.
pub fn encode_step(handle: u64, requests: &[Request]) -> Result<Vec<u8>, u32> {
    #[derive(Serialize)]
    struct Wire<'a> {
        handle: u64,
        requests: Vec<RequestWire<'a>>,
    }
    #[derive(Serialize)]
    struct RequestWire<'a> {
        method: &'a str,
        url: &'a str,
        headers: Bytes<'a>,
        body: Bytes<'a>,
    }
    let wire = Wire {
        handle,
        requests: requests
            .iter()
            .map(|request| RequestWire {
                method: request.method,
                url: &request.url,
                headers: Bytes(&request.headers),
                body: Bytes(&request.body),
            })
            .collect(),
    };
    let frame = Zeroizing::new(to_vec(&wire).map_err(|_| STATUS_ENCODING)?);
    // Sized exactly, as every output is: the registry would otherwise
    // reallocate a buffer with spare capacity and leave the old one unwiped.
    let mut out = Vec::new();
    out.try_reserve_exact(frame.len())
        .map_err(|_| stack_guest_abi::last_error::internal("no memory for a step's requests"))?;
    out.extend_from_slice(&frame);
    Ok(out)
}

/// The responses the host handed `se_resume`, copied out of its buffer into
/// ones the guest wipes.
pub fn decode_responses(bytes: &[u8]) -> Result<Vec<Response>, u32> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResponseWire<'a> {
        status: i32,
        #[serde(borrow)]
        headers: &'a [u8],
        #[serde(borrow)]
        body: &'a [u8],
    }
    let wire: Vec<ResponseWire<'_>> =
        from_slice(bytes).map_err(|e| malformed(format!("the responses: {e}")))?;
    Ok(wire
        .into_iter()
        .map(|r| {
            Response::new(
                r.status,
                r.headers.to_vec(),
                Zeroizing::new(r.body.to_vec()),
            )
        })
        .collect())
}

/// Bytes, written as a bytes leaf.
struct Bytes<'a>(&'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_frame::{frame, obj, V};

    #[test]
    fn a_step_is_its_handle_and_requests() {
        let request = Request::new(
            "POST",
            "https://kms.example/keys".to_owned(),
            Zeroizing::new(b"authorization: Bearer t\n".to_vec()),
            Zeroizing::new(b"{\"k\":1}".to_vec()),
        );
        let bytes = encode_step(7, &[request]).unwrap();
        let expected = frame(&obj(vec![
            ("handle", V::U64(7)),
            (
                "requests",
                V::Arr(vec![obj(vec![
                    ("method", V::Str("POST".into())),
                    ("url", V::Str("https://kms.example/keys".into())),
                    ("headers", V::Bytes(b"authorization: Bearer t\n".to_vec())),
                    ("body", V::Bytes(b"{\"k\":1}".to_vec())),
                ])]),
            ),
        ]));
        assert_eq!(bytes, expected);
        assert_eq!(bytes.capacity(), bytes.len());
    }

    #[test]
    fn responses_read_in_order() {
        let bytes = frame(&V::Arr(vec![
            obj(vec![
                ("status", V::I32(200)),
                (
                    "headers",
                    V::Bytes(b"content-type: application/json\n".to_vec()),
                ),
                ("body", V::Bytes(b"{}".to_vec())),
            ]),
            obj(vec![
                ("status", V::I32(-1)),
                ("headers", V::Bytes(Vec::new())),
                ("body", V::Bytes(b"dial tcp: refused".to_vec())),
            ]),
        ]));
        let responses = decode_responses(&bytes).unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].status, 200);
        assert_eq!(&*responses[0].body, b"{}");
        assert_eq!(responses[1].status, -1);
        assert_eq!(&*responses[1].body, b"dial tcp: refused");
    }

    #[test]
    fn malformed_responses_are_refused_without_echoing_them() {
        for bad in [
            V::Null,
            obj(vec![("status", V::I32(200))]),
            V::Arr(vec![obj(vec![
                ("status", V::I32(200)),
                ("headers", V::Str("secret-looking".into())),
                ("body", V::Bytes(Vec::new())),
            ])]),
            V::Arr(vec![obj(vec![
                ("status", V::I32(200)),
                ("headers", V::Bytes(Vec::new())),
                ("body", V::Bytes(Vec::new())),
                ("extra", V::Bool(true)),
            ])]),
        ] {
            assert_eq!(decode_responses(&frame(&bad)).err(), Some(STATUS_ENCODING));
            let error = stack_guest_abi::last_error::take().unwrap();
            assert!(!String::from_utf8_lossy(&error).contains("secret-looking"));
        }
    }
}

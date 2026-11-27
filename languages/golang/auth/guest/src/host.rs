//! The credential guest's only network route: the host performs each HTTP
//! request as a step of the operation that made it
//! ([`stack_guest_abi::step::request`], [`crate::io`] for the wire form), so
//! the guest is never running while a request is in flight. A provider
//! callback supplies the caller's current OIDC token on every token fetch;
//! the Rust federation strategy exchanges each distinct token once and
//! caches the result per token.

use std::io;

use stack_auth::{
    AuthError, HttpRequest, HttpResponse, HttpTransport, OidcProvider, RequestError, SecretToken,
};
use stack_guest_abi::{buffers, step};
use zeroize::Zeroizing;

use crate::headers::request_headers;

#[link(wasm_import_module = "cipherstash_transport")]
extern "C" {
    fn oidc_token_get(provider: u32, ptr_out: *mut u32, len_out: *mut u32) -> i32;
}

fn request_error(message: impl Into<String>) -> RequestError {
    RequestError(Box::new(io::Error::other(message.into())))
}

pub struct WasiAuthTransport;

impl HttpTransport for WasiAuthTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
        // The step's method is a static string; stack-auth sends these two.
        let method = match request.method() {
            "POST" => "POST",
            "GET" => "GET",
            _ => return Err(request_error("unsupported HTTP method")),
        };
        // stack-auth's headers, naming this host in the `user-agent`: the
        // edge in front of CTS refuses Go's default one (see `headers`).
        let headers = Zeroizing::new(request_headers(request.headers()));
        let body = Zeroizing::new(request.body().to_vec());
        let response = step::request(step::Request::new(
            method,
            request.url().as_str().to_owned(),
            headers,
            body,
        ))
        .await
        .map_err(|e| request_error(e.to_string()))?;
        if !(100..=599).contains(&response.status) {
            return Err(request_error(if response.status < 0 {
                String::from_utf8_lossy(&response.body).into_owned()
            } else {
                format!("invalid host HTTP status {}", response.status)
            }));
        }
        let response_headers = response
            .headers
            .split(|b| *b == b'\n')
            .filter_map(|line| {
                let line = std::str::from_utf8(line).ok()?;
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect();
        Ok(HttpResponse::new(
            response.status as u16,
            response_headers,
            response.body.to_vec(),
        ))
    }
}

pub struct HostOidcProvider(pub u32);

impl OidcProvider for HostOidcProvider {
    async fn fetch(&self) -> Result<SecretToken, AuthError> {
        let mut ptr = 0_u32;
        let mut len = 0_u32;
        // SAFETY: out-slots are live stack locals, filled synchronously.
        let status = unsafe { oidc_token_get(self.0, &mut ptr, &mut len) };
        // Reclaim even on failure: a host may have allocated before it failed.
        // SAFETY: the shared registry validates the host-provided pair.
        let bytes = unsafe { buffers::take(ptr as *mut u8, len as usize) }
            .map(Zeroizing::new)
            .ok_or_else(|| AuthError::Request(request_error("invalid OIDC token buffer")))?;
        if status != 0 {
            return Err(AuthError::Request(request_error(
                "OIDC provider could not supply a token",
            )));
        }
        let token = std::str::from_utf8(&bytes)
            .map_err(|_| AuthError::Request(request_error("OIDC token is not UTF-8")))?;
        if token.is_empty() || token.chars().any(char::is_control) {
            return Err(AuthError::Request(request_error(
                "OIDC token is empty or contains controls",
            )));
        }
        Ok(SecretToken::new(token))
    }
}

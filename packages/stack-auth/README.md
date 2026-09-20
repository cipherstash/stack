# stack-auth

[![Crates.io Version](https://img.shields.io/crates/v/stack-auth?style=for-the-badge)](https://crates.io/crates/stack-auth)
[![docs.rs](https://img.shields.io/docsrs/stack-auth?style=for-the-badge)](https://docs.rs/stack-auth/)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discord](https://discord.com/invite/5qwXUFb6PB)

Authentication strategies for [CipherStash](https://cipherstash.com) services.

All strategies implement the [`AuthStrategy`] trait, which provides a single
[`get_token`](AuthStrategy::get_token) method that returns a valid
[`ServiceToken`]. Token caching and refresh are handled automatically.

## Strategies

| Strategy | Use case | Credentials |
|---|---|---|
| [`AutoStrategy`] | Recommended default — detects credentials automatically | `CS_CLIENT_ACCESS_KEY` + `CS_WORKSPACE_CRN`, or `~/.cipherstash/auth.json` |
| [`AccessKeyStrategy`] | Service-to-service / CI | Static access key + workspace CRN |
| [`DeviceSessionStrategy`] | Long-lived sessions with refresh | OAuth token (from device code flow or disk) |
| [`DeviceCodeStrategy`] | CLI login ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)) | User authorizes in browser |
| `StaticTokenStrategy` | Tests only (`test-utils` feature) | Pre-obtained token used as-is |

## Quick start

For most applications, [`AutoStrategy`] is the simplest way to get started:

```no_run
use stack_auth::AutoStrategy;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let strategy = AutoStrategy::detect()?;
// That's it — get_token() handles the rest.
# Ok(())
# }
```

For service-to-service authentication with an access key:

```no_run
use stack_auth::AccessKeyStrategy;
use cts_common::Crn;

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let crn: Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse()?;
let key = "CSAKkeyId.keySecret".parse()?;
let strategy = AccessKeyStrategy::new(crn, key)?;
# Ok(())
# }
```

## Error handling

Every fallible operation returns [`AuthError`], a structured enum in which
each variant wraps a dedicated error struct. Errors are designed to tell the
developer exactly what to do next:

- **Stable machine-readable codes** — [`AuthError::error_code`] returns a
  `SCREAMING_CASE` identifier (e.g. `NOT_AUTHENTICATED`,
  `WORKSPACE_MISMATCH`) suitable for logs, metrics, and programmatic
  handling. The same taxonomy crosses the FFI boundary: the
  [`@cipherstash/auth`](https://www.npmjs.com/package/@cipherstash/auth) npm
  package surfaces these codes as the `type` discriminant of its typed
  `AuthFailure` union.
- **Actionable help** — every variant implements
  [`miette::Diagnostic`](https://docs.rs/miette), so `help()` (and `url()`
  when present) carry remediation guidance, e.g. `NOT_AUTHENTICATED` says
  ``Log in with `stash login`, or set `CS_CLIENT_ACCESS_KEY` for
  service-to-service auth.`` Applications that render errors through miette
  (like the Stash CLI) show this automatically.
- **Structured payload** — variants carry typed fields rather than
  pre-formatted strings; e.g. [`WorkspaceMismatch`] exposes
  `expected_workspace` and `token_workspace` so callers can act on the
  values, not parse a message.

```no_run
use miette::Diagnostic;
use stack_auth::{AuthError, AutoStrategy};

fn report(err: &AuthError) {
    eprintln!("[{}] {err}", err.error_code());
    if let Some(help) = err.help() {
        eprintln!("  help: {help}");
    }
    if let Some(url) = err.url() {
        eprintln!("  more: {url}");
    }
    if let AuthError::WorkspaceMismatch(m) = err {
        eprintln!(
            "  token belongs to {}, strategy expects {}",
            m.token_workspace, m.expected_workspace
        );
    }
}

match AutoStrategy::detect() {
    Ok(_strategy) => { /* authenticated */ }
    Err(err) => report(&err),
}
```

## Extensibility

`stack-auth` exposes two layers that can be plugged independently:

```text
            ┌──────────────────────────────────────────────────┐
            │  AuthStrategy ─ acquisition layer                │
            │  get_token() -> ServiceToken                     │
            │  AccessKeyStrategy / DeviceSessionStrategy / AutoStrategy│
            │  ── or ──                                        │
            │  AuthStrategyFn (closure → AuthStrategy)         │
            └────────────────────────┬─────────────────────────┘
                                     │ uses
            ┌────────────────────────▼─────────────────────────┐
            │  TokenStore ─ persistence layer                  │
            │  load() / save() of Token                        │
            │  InMemoryTokenStore / NoStore                    │
            │  ── or ──                                        │
            │  TokenStoreFn (closures → TokenStore)            │
            └──────────────────────────────────────────────────┘
```

Use [`TokenStoreFn`] when you want stack-auth's own strategies to handle
HTTP/refresh, but you need to plug in custom **persistence** (a cookie,
a KV blob, Redis). Wire it via the strategy's builder.

Use [`AuthStrategyFn`] when you want to bring your own **token acquisition**
end-to-end — typically because the strategy lives across an FFI boundary
(e.g. a JS `getToken()` reached via `protect-ffi`). The closure runs every
time a token is needed.

Beneath both sits the **transport**: every strategy sends its requests
through an [`HttpTransport`], and the bundled [`ReqwestTransport`] is only
the default. Implement the trait to run the real strategies over an HTTP
client that is not reqwest — a host runtime's, or a stub in a test — and hand
it to the strategy's builder. The trait is one method, in the shape of a
plain request and response:

```rust,no_run
use stack_auth::{AccessKey, AccessKeyStrategy, HttpRequest, HttpResponse, HttpTransport, RequestError};
use cts_common::Crn;

struct MyTransport;

impl HttpTransport for MyTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
        // `request.method()`, `request.url()`, `request.headers()`, `request.body()`
        let (status, headers, body) = my_http_client(request).await?;
        Ok(HttpResponse::new(status, headers, body))
    }
}
# async fn my_http_client(_: HttpRequest) -> Result<(u16, Vec<(String, String)>, Vec<u8>), RequestError> { unimplemented!() }

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let crn: Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse()?;
let key: AccessKey = "CSAKmyKeyId.myKeySecret".parse()?;
let strategy = AccessKeyStrategy::builder(crn, key)
    .transport(MyTransport)
    .build()?;
# Ok(())
# }
```

Without the `http` feature there is no bundled transport, so `.transport(..)`
is required rather than optional; nothing else about the strategies changes.

Module paths mirror this split: [`stack_auth::auth`](crate::auth) groups the
acquisition layer, [`stack_auth::store`](crate::store) groups the persistence
layer. All items are also re-exported at the crate root.

## Security

Sensitive values ([`SecretToken`]) are automatically zeroized when dropped
and are masked in [`Debug`](std::fmt::Debug) output to prevent accidental
leaks in logs.

## Token refresh

All strategies that cache tokens ([`AccessKeyStrategy`], [`DeviceSessionStrategy`],
[`AutoStrategy`]) share the same internal refresh engine. See the
[`AuthStrategy`] trait docs for a full description of the concurrency model
and flow diagram.

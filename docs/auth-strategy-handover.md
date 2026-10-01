# Passing a JS-defined `AuthStrategy` to `protect-ffi`

> **Status:** RFC. Cross-repo design — implementation lives in [`cipherstash/protectjs-ffi`](https://github.com/cipherstash/protectjs-ffi).
>
> **Prep landed in this repo:** [`stack_auth::AuthStrategyFn`](../packages/stack-auth/src/auth_strategy_fn.rs) — the helper protect-ffi will reach for. Sits on the acquisition layer ([`stack_auth::auth`](../packages/stack-auth/src/lib.rs)); its sibling [`stack_auth::TokenStoreFn`](../packages/stack-auth/src/token_store.rs) on the persistence layer is what `JsTokenStore` already uses for cookie-backed caching.

## Why

After PRs #1958 + #1959, JS consumers of `@cipherstash/auth` get a clean strategy primitive:

```ts
const strategy = AccessKeyStrategy.create(region, accessKey, {
  store: cookieStore({ request: req, responseHeaders }),
});
```

But `@cipherstash/protect-ffi` (the encryption binding consumers actually use today) has its own auth wiring built into `cipherstash-client`'s init path. Two systems doing auth side-by-side, neither aware of the other.

The eventual target state is a `stack-encrypt` crate with its own napi/wasm bindings that natively accept a `stack_auth::AuthStrategy`. That's a meaningful rewrite of the encryption surface and **is not what this RFC describes**.

This RFC describes the smaller, incremental step: let JS consumers pass an `@cipherstash/auth` strategy through `protect-ffi` into the underlying `cipherstash-client`. `protect-ffi` becomes auth-agnostic — it knows the strategy has a `.getToken(): Promise<TokenResult>` method, nothing more.

## End-to-end flow

```
JS consumer
  └─ AccessKeyStrategy.create(region, accessKey, { store: cookieStore(...) })
       │
       └─ passes the strategy object to protect-ffi:
           newClient({ authStrategy: strategy, /* ...rest */ })
              │
              └─ protect-ffi (Neon, Rust side):
                  │
                  ├─ wraps the JS callable in `JsAuthStrategy` adapter
                  ├─ `impl AuthStrategy for &JsAuthStrategy`
                  └─ hands it to `cipherstash_client::ZeroKMSBuilder::new(adapter)`
                       │
                       └─ cipherstash-client (no changes here):
                            │
                            └─ per HTTP request → `(&credentials).get_token().await`
                                 │
                                 └─ adapter calls into JS via Neon Channel
                                      │
                                      └─ strategy.getToken() → TokenResult
                                           │
                                           └─ adapter wraps in ServiceToken
                                                │
                                                └─ Authorization: Bearer <jwt>
```

## JS API

`protect-ffi`'s `newClient` gains an `authStrategy` option:

```ts
import { AccessKeyStrategy } from "@cipherstash/auth";
import { cookieStore } from "@cipherstash/auth/cookies";
import { newClient } from "@cipherstash/protect-ffi";

const strategy = AccessKeyStrategy.create(region, accessKey, {
  store: cookieStore({ request: req, responseHeaders }),
});

const client = await newClient({
  authStrategy: strategy,
  // ...other protect-ffi options (workspace, region, etc)
});
```

`protect-ffi` treats `authStrategy` as a black box. The contract is purely structural: **the value must have a `getToken(): Promise<TokenResult>` method**. Anything that satisfies that — `AccessKeyStrategy`, a future `OAuthStrategy.create(...)`, a hand-rolled mock — works.

This is intentionally not typed against `@cipherstash/auth`'s specific class. `protect-ffi` does not add a runtime dependency on `@cipherstash/auth`; consumers bring their own.

## Rust-side adapter (in protect-ffi)

The shape mirrors `JsTokenStore` from `packages/stack-auth/wasm/src/lib.rs:96-139` — different FFI substrate (Neon vs wasm-bindgen) but the same wrap-JS-callable-in-Rust-struct-and-impl-the-trait pattern.

```rust
use neon::prelude::*;
use neon::types::{Deferred, JsObject, JsPromise};
use stack_auth::{AuthError, AuthStrategy, SecretToken, ServiceToken};

/// Adapter that holds a JS `AccessKeyStrategy`-shaped object and surfaces
/// its `.getToken()` via the `AuthStrategy` trait. Used by
/// `cipherstash-client` (via `ZeroKMSBuilder::new`).
pub(crate) struct JsAuthStrategy {
    /// Persistent handle to the JS strategy object (kept alive across
    /// `cipherstash-client` calls).
    strategy: Root<JsObject>,
    /// Channel for scheduling work on the JS thread.
    channel: Channel,
}

impl JsAuthStrategy {
    pub(crate) fn new(cx: &mut impl Context, strategy: Handle<JsObject>) -> Self {
        Self {
            strategy: strategy.root(cx),
            channel: cx.channel(),
        }
    }
}

impl AuthStrategy for &JsAuthStrategy {
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>> + Send {
        // Build a oneshot to receive the JS result on the Rust async side.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let strategy = self.strategy.clone(/* on the JS thread */);

        // Schedule the JS call on the libuv main thread.
        self.channel.send(move |mut cx| {
            let strategy = strategy.into_inner(&mut cx);
            let get_token: Handle<JsFunction> = strategy.get(&mut cx, "getToken")?;
            let promise: Handle<JsPromise> = get_token.call(&mut cx, strategy, &[])?.downcast_or_throw(&mut cx)?;

            // Resolve the JS Promise, extract `token`, send to the Rust side.
            let _ = promise.to_future(&mut cx, |mut cx, result| {
                let result = result?;
                let result: Handle<JsObject> = result.downcast_or_throw(&mut cx)?;
                let token: Handle<JsString> = result.get(&mut cx, "token")?;
                let token = token.value(&mut cx);
                let _ = tx.send(Ok(token));
                Ok(cx.undefined())
            });
            Ok(())
        });

        async move {
            let jwt: String = rx.await
                .map_err(|_| AuthError::Server("JS strategy dropped before responding".into()))??;
            Ok(ServiceToken::new(SecretToken::new(jwt)))
        }
    }
}
```

Then the protect-ffi `newClient` Neon function:

1. Extracts `options.authStrategy` as a `JsObject`.
2. Builds `JsAuthStrategy::new(&mut cx, strategy)`.
3. Hands the adapter to `cipherstash_client::ZeroKMSBuilder::new(adapter)` (works because `&JsAuthStrategy: AuthStrategy` and the builder's bound is `for<'a> &'a C: AuthStrategy`).
4. Wraps the resulting client in whatever protect-ffi handle type Neon exposes to JS.

**The exact Neon API details (`promise.to_future`, `Deferred`, etc.) need to be confirmed against the current Neon version used by protect-ffi** — the sketch above is illustrative, not literal.

## FFI wire format

`strategy.getToken()` (JS) returns a `TokenResult`:

```ts
interface TokenResult {
  token: string;       // the JWT — the bearer credential
  subject: string;     // decoded claim
  workspaceId: string; // decoded claim
  issuer: string;      // decoded claim
  services: Record<string, string>;  // decoded claim
}
```

The Rust adapter pulls just `result.token` across the FFI and wraps it in `ServiceToken::new(SecretToken::new(token))`. Claim accessors (`.subject()`, `.workspace_id()`, `.services()`) re-decode on demand from the JWT payload — `cipherstash-client` mostly hits `.as_str()` for `Authorization` headers and only occasionally needs the claims (service discovery), so re-decoding is cheap.

The redundant decode (JS already decoded the claims into `TokenResult` fields, Rust re-decodes lazily) is the trade-off for a minimal wire format. The future `stack-encrypt`'s native binding wouldn't have this asymmetry.

## Error propagation

If the JS `getToken` throws or rejects, the adapter surfaces an `AuthError`. Recommendation:

- JS sync throw or promise reject → `AuthError::Server(message_from_js_error)`.
- Adapter-side dropouts (`oneshot::Receiver::recv` returning `Err`) → `AuthError::Server("JS strategy dropped before responding")`.

`cipherstash-client` treats this the same way it treats any other auth failure (no oracle leakage; standard surfaced via the existing error path).

## Lifecycle and zeroize

- **Strategy lifetime**: the JS strategy is held for the lifetime of the protect-ffi client. `JsAuthStrategy` holds a `Root<JsObject>` (Neon's persistent handle) to keep the JS callable alive. The `Drop` impl releases the root via `self.channel.send(...)`.
- **Token zeroize**: the JWT crosses the FFI boundary as a JS `String`, which has no `ZeroizeOnDrop` protection while in JS-land — the same caveat already established in `TokenResultPayload`'s docstring (`packages/stack-auth/wasm/src/lib.rs:42-46`). Once `ServiceToken::new(SecretToken::new(jwt))` lands on the Rust side, normal `ZeroizeOnDrop` protections resume for the rest of the request's lifetime.
- **Concurrent `get_token`**: `cipherstash-client` may issue concurrent ZeroKMS requests, each of which calls `(&credentials).get_token().await` — `JsAuthStrategy` must be safe to call from multiple async tasks. Neon's `Channel::send` is `Send + Sync`, so this is fine; the JS side runs each call serially on the libuv main thread, but the Rust side awaits independent oneshots so multiple in-flight `get_token` calls don't block each other.

## Shelf life

This is bridge scaffolding. Once `stack-encrypt` lands with its own napi/wasm bindings that accept a `stack_auth::AuthStrategy` natively (no JS-callback round-trip per ZeroKMS request), `protect-ffi`'s `JsAuthStrategy` adapter can be retired and consumers migrate to `@cipherstash/protect` (or whatever the published package becomes).

[`AuthStrategyFn`](../packages/stack-auth/src/auth_strategy_fn.rs) itself stays useful past that retirement — any foreign Rust consumer that wants to bring a non-`stack-auth`-native strategy to `cipherstash-client` (third-party integrations, test fixtures, future sidecars) uses the same pattern.

## Why no changes to cipherstash-suite production code

`cipherstash_client::ZeroKMSBuilder::new<C>` already accepts any `C` where `for<'a> &'a C: stack_auth::AuthStrategy` (see `src/zerokms/builder.rs:108-118` in the `cipherstash-client` crate, in cipherstash-suite). `JsAuthStrategy` satisfies that bound by virtue of `impl AuthStrategy for &JsAuthStrategy`. No generic refactor, no `dyn AuthStrategy`, no trait additions.

The only thing this repo ships in support of this RFC is:

- `stack_auth::AuthStrategyFn` — public helper on the acquisition layer, sibling of `stack_auth::TokenStoreFn` on the persistence layer. Saves protect-ffi (and any future foreign consumer) ~20 lines of trait-impl boilerplate.
- A doctest in `cipherstash-client::zerokms::builder` (compile-only) showing the `AuthStrategyFn` → `ZeroKMSBuilder::new` composition. Catches regressions if anyone tightens the builder's trait bound.

## Out of scope

- `protect-ffi` PR itself — separate repo.
- `stack-encrypt` design — eventual target state, separate work item.
- OAuth strategy via `protect-ffi` — same callback shape would work, but the JS-side OAuth bindings aren't shipped yet (deferred under CIP-3084's broader follow-ups).
- Encryption-at-rest decorator for the strategy — separate sub-issue [CIP-3112](https://linear.app/cipherstash/issue/CIP-3112); doesn't affect this handover wiring.

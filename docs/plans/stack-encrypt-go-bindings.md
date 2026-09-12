# stack-encrypt Go bindings

> **Plan, not specification.** This document is an indicative sketch of the
> steps required, written before the work was done. It is not kept in step
> with the implementation and must not be used as a formal specification or
> as a reference for reviewing what was actually built: the code, its
> rustdoc and the tests are the source of truth. Where the two disagree, the
> code wins and this document is simply out of date.

**Status:** in progress — Phases 0 through 3 are open as stacked draft PRs on #2156
**Date:** 2026-08-27
**Builds on:** #2099 (WASI/wazero beachhead), #2156 (`#[derive(EncryptFrom, DecryptInto)]`), vitaminc `bindings/go` (`vcvalue` + `vcencrypt`)

## Goal

Prove that `stack-encrypt` as it stands after #2156 — ZeroKMS-backed AEAD over
structured values, plus SEM index terms, plus batched records — can be driven
from Go with `CGO_ENABLED=0`, one embedded `.wasm`, and no per-platform build
matrix. The proof is a Go program that, against a real ZeroKMS:

1. encrypts a slice of records (ciphertext + equality + ORE term per field)
   in **one** `generate-data-key` call,
2. decrypts them back in one `retrieve-data-key` call,
3. builds a query probe term locally (no ZeroKMS call) that equals the stored
   term, and
4. round-trips ciphertexts and terms with the native Rust example
   (`encrypted_record.rs`) in both directions.

Everything that is not needed for that proof is a follow-up.

## Terminology

"Transport" is used with two opposite meanings across vitaminc and #2099. This
plan fixes the vocabulary and the rename is part of the work:

| term | means | bytes go |
|---|---|---|
| **storage format** / **sealed leaf** | `vcvalue.Sealed`, `stackencrypt.Sealed`, the `[tag] ++ payload` inside the envelope | into a database column; frozen, versioned |
| **FFI codec** (was "transport codec") | marshalling a value or ciphertext *tree* across wasm linear memory in one copy; `FfiValue`, `CT_*` framing, `Encoder`/`Encryptable` | host ↔ guest, inside the process; throwaway, never persisted |
| **transport** | HTTP to ZeroKMS: `cipherstash_transport::transport_send`, the future `stack-transport` crate | out of the process |

Renames implied: `vitaminc_aead_value::transport` → `::ffi`; the Go codec
module is `vcffi`, not "wire"/"transport"; READMEs say "FFI-only, not a
storage format". "Interop" is avoided as too broad (the reflection encoder is
interop too, but it is API, not a codec). Also: "cipher handle" (not "session
handle"), and the "Status: spike" labels come off the vitaminc `bindings/go`
READMEs — the code was reviewed and tested past that point, and `stackencrypt`
cannot build on something still labelled a spike.

## What is already done, and where

The work splits cleanly along the crate boundary, and most of it exists.

| Concern | Owner | State |
|---|---|---|
| Value model (`Plain`, `Sealed*`, `Object`), `Encryptable`/reflection encode, decode natives | vitaminc `bindings/go/vcvalue` + `vcencrypt` | done — reviewed and tested; the READMEs still self-label "spike", which is stale |
| FFI codec (`FfiValue` tree ↔ bytes, `CipherText<Leaf, P>` ↔ bytes) — today named "transport" in vitaminc | vitaminc `packages/aead-value/src/transport.rs` (Rust); unexported Go copy inside `vcencrypt` | done, but the Go codec is private to `vcencrypt` |
| Replaying a whole value tree through a `Cipher` in one guest call; `Encrypt for FfiValue` / `Decrypt for FfiValue` | vitaminc `aead-value` | done, generic over any `Cipher` — including `&StackCipher<K>` |
| Guest ABI conventions: `vc_alloc`/`vc_dealloc` with a guest-owned buffer registry + zeroize, packed-`u64` results, status codes, cipher handles, hostile-input validation | vitaminc `vcencrypt/guest/src/abi.rs` | done, but lives inside the `vcencrypt` guest crate |
| Go client shell: wazero runtime, process-wide compilation cache, mutex-serialised instance, sentinel errors, `driver.Valuer`/`sql.Scanner` on leaves | vitaminc `vcencrypt/client.go` | done |
| ZeroKMS transport over a single host import (`cipherstash_transport::transport_send`), `WasiHostConnection: ZeroKMSConnection`, `block_on` inside the guest | suite #2099 (`packages/stack-encrypt/guest`, unmerged) | proven end to end, but written against `cipherstash-client::zerokms::vitur_client` |
| Go host side of that import (`bridge.go`: `net/http` transport, bounds-checked memory ABI, `-check` import-surface gate) | suite #2099 | proven |
| Integration harness: boot `zerokms-server` trusting the mock auth server, mint a token, seed a client, `go test` | suite #2099 (`test:integration:wasi-spike`) | proven |
| `wasm:wasi-check` gate: HTTP-free core compiles for `wasm32-wasip1` with no `wasm-bindgen`/`web-sys`/`js-sys` | suite #2099 | done for `zerokms-protocol`, `cipherstash-core`, `recipher`, `cts-common`, `cllw-ore` |
| `StackCipher` (`Cipher` impl building a pending tree, `seal` batching, `StackDecipher: Decipher`), SEM terms, `EncryptFrom`/`Pending`, derive | suite `stack-encrypt` (#2147, #2156) | done |
| `ZeroKMSConnection` seam in the new client | suite `stack-kms/src/connection.rs` | trait exists; `StackKms` does not use it (see blockers) |

So the stack-encrypt side of the binding is, as expected, the **cipher/KMS
side**: getting `stack-kms` + `stack-auth` to build for WASI without HTTP,
exposing a `StackCipher` as a cipher handle across the ABI, and defining the
cross-language byte formats stack-encrypt owns (the sealed leaf and the
terms). The value model and the FFI plumbing are vitaminc's and are reused.

## Blockers found (measured, not predicted)

Ran `cargo check --target wasm32-wasip1 -p stack-encrypt --no-default-features`
on this branch (`claude/stack-encrypt-derive`):

```
error: Only features sync,macros,io-util,rt,time are supported on wasm.
   --> tokio-1.49.0/src/lib.rs:481:1
error: failed to run custom build command for `aws-lc-sys v0.44.0`
```

Both come from **`reqwest 0.13.4`** and only from it — via `stack-auth` and
`stack-kms` (the only two crates in the graph that depend on it). On
`wasm32-wasip1` reqwest 0.13.4 selects its *native* backend, dragging in
hyper/tokio-full/hickory/rustls/aws-lc-sys. The good news: **no
`wasm-bindgen`/`web-sys`/`js-sys` anywhere in the wasip1 tree**, so the
JS-host chain #2099 fought is gone; what remains is exactly the follow-up
#2099 named — reqwest has to be out of the WASI build *by construction*, not
by dead-code elimination.

To be clear about what `aws-lc-sys` is doing there: it is rustls's default
crypto provider for TLS inside reqwest's native backend, not the AEAD.
`vitaminc-encrypt` already selects its pure-Rust `aes-gcm` backend on
`cfg(target_arch = "wasm32")`, which covers wasip1, so the guest's own
cryptography builds today; only the network stack is missing.

Structural blockers on top of that:

1. **`StackKms<C>` hard-codes `Client<HttpConnection>`**
   (`packages/stack-kms/src/client.rs:386`). The low-level `Client<C:
   ZeroKMSConnection>` is already generic; the high-level wrapper is not, so
   there is no way to inject `WasiHostConnection` today.
2. **`stack-auth` uses reqwest unconditionally** in `device_client.rs`,
   `access_key_refresher.rs`, `oidc_refresher.rs`, `token.rs`, and
   `error.rs` (`RequestError(pub reqwest::Error)`, `From<reqwest::Error>
   for AuthError`). `AuthStrategyFn`, `ServiceToken`, `AuthStrategy`
   and the error enum are HTTP-free and are all a first guest needs
   (`StaticTokenStrategy` is test-utils-only and stays that way).
3. **`cfg(target_arch = "wasm32")` currently means "JS host"** in
   `stack-auth`/`stack-kms` (fetch semantics, no timeouts, `MaybeSend`
   drops `Send`). WASI under wazero is single-threaded too, so the `Send`
   relaxations are fine, but comments and a few branches (`AutoStrategy`'s
   wasm arm) assume no filesystem and a JS credential. Nothing breaks the
   proof; it needs tidying before anything ships.
4. **`SealedValue` has no frozen byte layout.** It derives serde and offers
   `into_parts()`, but the FFI codec is generic over `Leaf:
   AsRef<[u8]> + From<Vec<u8>>` and a Go database column needs *one* byte
   string. stack-encrypt states this leaf is "the only byte-format commitment
   the crate makes"; the commitment has to be written down.
5. **Terms have no cross-language byte encoding** in stack-encrypt.
   `EqualityTerm` is 32 bytes; `MatchTerm` is `Vec<u16>` positions;
   `OreTerm<T>`/`OpeTerm<T>` wrap `cllw_ore::…::Output`, whose serialisation
   lives in the EQL layer today.

## Architecture

Same shape as #2099 and the vitaminc Go bindings, applied to `stack-encrypt`:

```
Go application
  └─ github.com/cipherstash/…/stackencrypt   (Go, CGO_ENABLED=0)
       ├─ imports vcvalue (value model) + the FFI codec
       ├─ embeds stack_encrypt_guest.wasm
       ├─ host import  cipherstash_transport::transport_send  → net/http → ZeroKMS
       └─ host import  cipherstash_transport::token_get       → token source (phase 1: static)
             │
             ▼  wazero (wasm32-wasip1)
       stack-encrypt guest (Rust cdylib)
         ├─ StackCipher<StackKms<HostTokenStrategy, WasiHostConnection>>   (one per handle)
         ├─ FfiValue.encrypt_with_aad(&cipher, aad) → PendingStackCipherText → seal(kms)   (block_on)
         ├─ record plan → per-field EncryptFrom pendings → Pending::all → one generate_keys
         └─ term(value, context, kind) → local PRF/ORE, no I/O
```

Control stays in Rust: request assembly, key derivation, batching, AAD/PRF
context binding all run unmodified inside the guest. What crosses the boundary
per call is a value tree in, a ciphertext/record tree out, and — inside the
call — the same bytes that would cross TLS anyway. The client key enters guest
memory once at `init`; derived data keys and the index key never leave.

## Phases

### Phase 0 — salvage #2099 onto `stack-kms`

**Landed** as the first stacked PR: the gate, the CI workflow, Layer 6, and
this document. `WasiHostConnection`, the `bridge.go` host function and the
integration harness are ported in Phase 3 with the guest they serve; #2099
is left open with a pointer here for its author to close.

#2099 targets `cipherstash-client`, which is being replaced by `stack-kms`
(no parity fixes go into the old crate). Rebase the reusable pieces rather
than the branch:

- `wasm:wasi-check` mise task — keep, extend to `stack-kms`, `stack-auth`,
  `stack-encrypt`, and add `reqwest|tokio|aws-lc-sys` to the forbidden-tree
  grep (the wasip1 failure mode is now native-backend, not JS-backend).
- `WasiHostConnection` — port from `cipherstash_client::zerokms::vitur_client`
  to `stack_kms::ZeroKMSConnection` (the trait shape is identical; the port
  is mechanical).
- `bridge.go` `transportSend` host function and `checkImports` — keep as the
  host side; drop the msgpack request/response types (superseded by the
  vitaminc FFI codec).
- `test:integration:wasi-spike` harness (zerokms-server on a dedicated port,
  mock auth issuer override, mint token, seed client) — keep, rename.
- `wasm-analysis.md` Layer 6 — rewritten for the stack-kms target and the
  measured wasip1 blocker.
- Close #2099 with a pointer here; nothing from it merges as-is.

### Phase 1 — `stack-kms` and `stack-auth` build for WASI without HTTP

**Landed (stacked PR on Phase 0).** What shipped, against the plan below: a
default-on `http` feature in all three crates (`stack-encrypt/http` →
`stack-kms/http` → `stack-auth/http` → `dep:reqwest`); `StackKms<C, Conn>`
with `StackKms::connect(opts, credentials, client_key)` as the
transport-injecting constructor; `ZeroKMSConnection` grew
`ensure_base_url` / `has_base_url` so endpoint discovery from the token's
`services` claim works over any connection; `StackCipher::builder()` moved
to `impl StackCipher<FromEnv>` so it resolves without `http`;
`wasm:wasi-check` gates all eight crates. A unit test drives `StackKms`
end to end over the in-memory `TestConnection`. Verified:
`cargo check --target wasm32-wasip1 -p stack-encrypt --no-default-features`
passes with no `reqwest`/`hyper`/`aws-lc-sys` in the tree.

The plan as written before the work:

**stack-kms**

- `StackKms<C, Conn = HttpConnection>`; `StackKmsBuilder::with_connection(conn)`
  (or a `connect_with` constructor) so the guest can pass
  `WasiHostConnection`. `get_token`'s `ensure_base_url` moves behind a small
  trait method on the connection (`HttpConnection` needs it; the host
  connection ignores it — the Go host owns the URL).
- `HttpConnection` + `HttpConnectionOpts` behind `#[cfg(not(target_os =
  "wasi"))]` (or a default-on `http` feature — pick one and use the same in
  stack-auth). The `ZeroKMSConnection` trait, `Client<C>`, key derivation,
  `DataKeySource`/`IndexKeySource` stay unconditional.

**stack-auth**

- Default-on `http` feature gating everything that touches reqwest:
  `device_client`, `access_key_refresher`, `oidc_refresher`, the
  `AutoStrategy`/`AccessKeyStrategy`/`DeviceSession`/`OidcFederation`
  strategies, `RequestError`, `From<reqwest::Error>`. Left unconditional:
  `AuthStrategy`, `AuthStrategyBounds`, `AuthStrategyFn`, `ServiceToken`,
  `Token`, `AuthError` (minus the `Request` variant's payload), `SecretToken`.
  `AuthStrategyFn` is the supported production path for a no-`http` consumer
  that sources tokens externally; `StaticTokenStrategy` stays behind
  `cfg(any(test, feature = "test-utils"))` — it is a test double, not part of
  the no-`http` production surface.
- The guest's `HostTokenStrategy` (below) implements `AuthStrategy` over a
  host import, so nothing else is required for the proof.

**stack-encrypt**

- `StackCipher::new()` / `StackCipherBuilder<FromEnv>` are native-only
  (they use `AutoStrategy` + profile); gate them the same way. The generic
  `StackCipherBuilder<K>::kms(k).keyset(..).init()` path is what the guest
  uses and needs no change.
- Gate: `wasm:wasi-check` now passes for all three crates.

### Phase 2 — frozen byte formats stack-encrypt owns

**Landed (stacked PR on Phase 1).** What shipped, against the plan below:
`SealedValue::to_bytes`/`from_bytes` with the layout
`version(1) ‖ iv(16) ‖ tag_len(u16 LE) ‖ tag ‖ local_ciphertext`, the
version byte bound into the leaf AAD via a new labelled derivation
(`PAE("stack-encrypt/leaf", version, derived_aad, tag)` — replacing the
unlabelled `(aad, tag)` tuple, with the derivation bytes pinned by a unit
test; **breaking**: leaves sealed under the phase-1 AAD carry no version byte,
so they cannot be opened and fail with a plain AEAD error rather than an
`UnknownVersion` — acceptable because the crate is `publish = false` and only
dev-persisted data exists); term encodings frozen as raw-bytes (equality: the 32 PRF bytes;
ORE/OPE: the raw CLLW ciphertext, byte-identical to what EQL hex-encodes
into `hm`/`oc`/`op`; match: LE `u16` positions — EQL sends `bf` as a JSON
integer array, so the byte-string form is stack-encrypt's own *transport*
encoding across the wasm/FFI boundary, not a storage commitment — what is
stored and queried is the position list). The surface per type:
`to_bytes` and a fallible `TryFrom<&[u8]>` on all four; `from_bytes` on all
four (infallible over `[u8; 32]` for `EqualityTerm`, fallible over a slice
for the rest); `as_bytes` only where the term is a contiguous buffer
(`EqualityTerm`, `OreTerm`, `OpeTerm`) — a `MatchTerm` is canonically a
position list, so it has none, and its decoders range-check every position
against the `MatchConfig`'s filter size. Decode failures are the structured,
`PartialEq` `TermBytesError`. Also: length-validating
`TryFrom<&[u8]>` added to cllw-ore's variable-width ciphertext types; and
golden vectors in `tests/frozen_bytes.rs` for the Go decoder to test
against.

The plan as written before the work — these are storage commitments, so they
get decided and documented before the guest is written, independently of Go:

- **`SealedValue` leaf**: `to_bytes()` / `from_bytes()` with a canonical
  layout, e.g. `version(1) ‖ iv ‖ u16 tag_len ‖ tag ‖ local_ciphertext`
  (`local_ciphertext` is already `version ‖ nonce ‖ ct ‖ gcm_tag`). Bind the
  outer version byte into the leaf AAD the way vitaminc binds its version
  byte, so a relabelled leaf fails authentication rather than parsing. Rust
  `impl AsRef<[u8]>`-style access for the codec's `Leaf` bounds comes for
  free.
- **Terms**: `EqualityTerm` — the 32 bytes as-is. `MatchTerm` — `u16`
  little-endian positions. `OreTerm`/`OpeTerm` — adopt the EQL encoding of
  the underlying `cllw-ore` output rather than inventing one; Postgres is
  the real consumer and Go rows must be comparable with rows the Rust/EQL
  path wrote. Needs a look at what `eql-bindings` emits today.
- Add these as `#[cfg(test)]` golden vectors in `stack-encrypt` (Rust
  encodes → fixed hex) so the Go decoder tests against the same bytes.

### Phase 3 — the guest

**Landed (stacked PR on Phase 2).** What shipped, against the plan below:
the crate at the planned location (detached workspace), exporting
`se_alloc`/`se_dealloc`, `se_cipher_init`/`se_cipher_free`,
`se_encrypt`/`se_decrypt` (+`_element`), `se_encrypt_record`/
`se_decrypt_record`, and `se_term`, under the vitaminc guest's ABI
conventions (buffer registry with zeroizing dealloc, packed-`u64` results,
hostile-input validation; status codes 1–4 byte-identical to vitaminc's,
5–11 added for the ZeroKMS request outcomes and term failures).
`WasiHostConnection` implements `stack_kms::ZeroKMSConnection` over the
generalised `transport_send(method, url, headers, body)` import (headers as
`name: value` lines), with the endpoint pinned from the config or
discovered from the token's `services` claim via `ensure_base_url`;
`HostTokenStrategy` fetches the bearer token per request over `token_get`.
Records deviate from the sketch in two small ways: there is no separate
`aad` argument (each plan field's `context` *is* the AAD, as in the target
layer) and the result rides the ciphertext codec — per field a map of
output keys (`"c"`, `"eq"`, `"match"`, `"ore"`, `"ope"`) whose term nodes
are passthrough bytes. Batching all rows into one `generate_keys` goes
through a new public `PendingStackCipherText::into_pending` in
stack-encrypt (decoded `FfiValue`s are not `Clone`, so the `EncryptFrom`
path was not usable). Extracting the shared ABI into a `vitaminc-wasi-abi`
crate is out of this repo's reach and stays a vitaminc follow-up — the
registry/session modules are copies with a pointer back. The `bridge.go`
host function and the integration harness land with their consumer, the Go
module (Phases 4–5). Verified: native tests over `FakeDataKeySource`
(round trips, term-byte equality with the native `sem` calls, a counting
key source proving one ZeroKMS call per record batch), and the release
`.wasm` builds with an import surface of exactly WASI +
`cipherstash_transport` (`mise run wasm:guest:build` / `wasm:guest:test`).

Both tasks run in CI. The guest is a detached workspace, so the
workspace-wide jobs never compile, lint or test it; the WASI workflow
(`.github/workflows/test-wasi.yml`) watches the guest path and runs the two
tasks, which is the crate's only gate. The import surface is asserted, not
eyeballed: `scripts/check-wasm-imports.py` parses the linked module's
import section and fails closed — every import must be either WASI (with
the capability-granting `path_*`, `sock_*` and `fd_prestat*` names denied,
so a dependency cannot quietly acquire ambient filesystem or network
access) or one of the two required `cipherstash_transport` functions, and
both of those must be present. A build alone proves nothing here: the
property is about what the *linked* module can reach.

Three things worth stating plainly, because they are easy to read the wrong
way:

- **Batching is one *batch*, not always one *call*.** All rows and fields
  of an invocation are merged into a single pending batch, which the client
  then splits into one ZeroKMS request per `ClientOpts::max_keys_per_req`
  keyed leaves — 500 by default, sent sequentially (the guest pins
  `max_concurrent_reqs` to 1). So "one `generate_keys` call per batch" is
  exact up to 500 leaves and "one call per 500" past it. The default is
  kept rather than raised: it is the server-friendly request size, and a
  larger one is a promise ZeroKMS need not honour.
- **Record `"c"` leaves carry the aead-value *tagged* plaintext encoding**
  (`[type tag] ++ payload`), because that tag table is the cross-language
  contract Go, Node and this guest share. A Rust `#[derive(EncryptFrom)]`
  over a plain primitive seals untagged bytes instead, so a plain-primitive
  Rust derive and a Go plan do **not** interchange ciphertexts for the same
  field until the Rust side uses aead-value's tagged types. By design; a
  separate follow-up, not a defect in either side.
- **A plan context is the whole context, and it is structured.** Each
  plan field's context is a string, bytes, an integer (`i32`/`i64`/`u32`/
  `u64`) or a list of those, nested as needed (the guest's `context`
  module; CIP-4023, landed after Phase 3). The guest seals the field under
  exactly that. A bare string is what every plan carried before — the same
  AAD bytes and the same ZeroKMS descriptor as a Rust derive gives the
  field when the record is sealed with `encrypt_into` (no caller context).
  A list is what the Rust derive produces when it *extends* every field's
  context with the caller's: `encrypt_into_with_context(row, 7u64)` seals
  `users/email` under `("users/email", 7u64)`, descriptor
  `users/email|7u64`, and the plan spells that as `["users/email", 7u64]`
  — the same bytes on the AAD side (a list is an `AadPiece::List`, PAE of
  its parts like a tuple) and on the PRF side (leaves carry vitaminc's own
  typed encodings, lists are `PrfContext::pae`). Rows sealed from Rust
  under a caller context open through a plan that names the same parts, and
  the reverse; `se_term` takes the same form so a probe can match either.
  The Go struct tag grows the extension in Phase 4 (`tenant=` or similar),
  and the cross-language fixtures in Phase 5 cover both the flat and the
  extended shape.

The plan as written before the work:

Location: `bindings/go/stackencrypt/guest/` (mirrors vitaminc's layout;
detached workspace like #2099's guest and the fuzz crates so its wasm profile
never leaks into workspace builds). Dependencies: `stack-encrypt`,
`stack-kms`, `stack-auth` (all `default-features = false`),
`vitaminc-aead-value` (FFI codec + `FfiValue`), `futures` (`block_on`),
`zeroize`.

Reuse from vitaminc: extract `vcencrypt/guest/src/{abi,sessions,status}.rs`
buffer-registry/packing/status code into a small shared crate
(`vitaminc-wasi-abi` or similar) so both guests share one ABI implementation
instead of a copy. This is the one change the plan asks of vitaminc's guest
side.

Exports (same conventions as `vc_*`: host owns buffers, `se_dealloc` zeroizes
via the registry, packed `u64` results, status in the low word on error):

| export | does |
|---|---|
| `se_alloc(len)` / `se_dealloc(ptr, len)` | buffer lifecycle, as vitaminc |
| `se_cipher_init(cfg_ptr, cfg_len) → handle` | config (client id, client key, keyset id/name or default) encoded as an `FfiValue` object — no second codec. Builds `StackKms<HostTokenStrategy, WasiHostConnection>`, then `StackCipherBuilder::kms(..).keyset(..).init()` under `block_on` (one `load_keyset` call — the index key is now held in the guest). Client-key bytes zeroized after `ClientKey` is built. |
| `se_cipher_free(handle)` | drops the `StackCipher` (index key, client key wiped by `ZeroizeOnDrop`) |
| `se_encrypt(handle, value, aad)` / `se_decrypt(handle, ct, aad)` | decode `FfiValue` → `encrypt_with_aad(&cipher, aad)` → `seal(kms)` (`block_on`) → `encode_ciphertext::<SealedValue, _>`. Decrypt mirrors via `cipher.decipher(ct)` + `FfiValue::decrypt_with_aad`. |
| `se_encrypt_element` / `se_decrypt_element` | as vitaminc; row-at-a-time interop with batch-encrypted slices |
| `se_encrypt_record(handle, source, plan, aad)` | the runtime form of `#[derive(EncryptFrom)]`: `plan` is an `FfiValue` object `{ field → { context, outputs: [c \| eq \| match(opts) \| ore \| ope] } }`; per field the guest dispatches on the source `FfiValue` variant to the typed `EncryptFrom` impls (`u32`/`u64`/`i64`/`f64`/`String`), zips the pendings, `Pending::all` across an array source, and returns `{ field → { c: leaf, hm: bytes, ob: bytes, … } }`. One `generate_keys` call per invocation regardless of row count. |
| `se_decrypt_record(handle, record, plan, aad)` | inverse; only the `c` outputs participate |
| `se_term(handle, value, context, kind)` | query probe; `context` is codec-encoded in the plan-field grammar — one part (a string, bytes, or an `i32`/`i64`/`u32`/`u64`) or an array of parts, nested as deep as the transport codec allows (`vitaminc_aead_value::transport::MAX_DEPTH`, 128 levels from the root of the encoded value; deeper is `STATUS_ENCODING` before the context is parsed, not an interop bug). Shape is identity: `[x]` is not `x`, so a probe passes the context in exactly the shape the field was sealed under (the guest's `context` module is the one home of the grammar and of which Rust context each shape spells). Local PRF/ORE only, never touches ZeroKMS |

Host imports (two, both from the `cipherstash_transport` module #2099
defined):

- `transport_send(method, url, headers, body) → (status, headers, body)` —
  #2099's import generalised from its ZeroKMS shape `(endpoint, token,
  body)` to a plain HTTP request, mirroring `wasi:http/outgoing-handler`.
  Two reasons: `stack-auth`'s refreshers talk to CTS (a different host) and
  will reuse the same import in Phase 6; and when wazero grows component
  support, the WASI impl of `stack-transport` swaps this import for
  `wasi:http` without changing the trait. The bearer token crosses as a
  header — the same bytes cross TLS anyway.
- `token_get() → token` — Phase 1 auth: the Go host hands over a bearer
  token (in the proof, minted by the harness / read from the CLI profile,
  exactly as #2099's `mint-dev-token.sh` did). `HostTokenStrategy:
  AuthStrategy` wraps it. Refresh stays on the host until Phase 6.

Why host-provided HTTP and not HTTP inside the guest: wasip1 has no
`sock_connect` (receive/accept only), so outbound TCP needs a host import
regardless; TLS in the guest would mean rustls on a pure-Rust provider with
embedded roots and no AES-NI, strictly worse than Go's `crypto/tls` with
system roots; and `wasi:http` (the right long-term answer) is component
model, which wazero does not run. The host can already read guest memory, so
routing HTTP through it weakens nothing — what crosses the boundary is what
crosses TLS.

Wasm is single-threaded and the host function blocks inside the guest call,
so the whole instance is held for the duration of a ZeroKMS round trip. Fine
for the proof; the Go side pools instances later.

### Phase 4 — the Go module

`bindings/go/stackencrypt` (module path TBD — see decisions). Imports
`vcvalue` for the model. Surface mirrors `vcencrypt` so the two feel like one
SDK:

```go
client, _ := stackencrypt.NewClient(ctx, stackencrypt.Config{
    Transport: http.DefaultClient,          // or any RoundTripper
    Token:     stackencrypt.StaticToken(tok), // phase-1 auth
})
cipher, _ := client.NewCipher(ctx, stackencrypt.CipherConfig{
    ClientID: id, ClientKey: key, Keyset: "users",
})

ct, _  := cipher.Encrypt(ctx, user, aad)          // map[string]any of stackencrypt.Sealed / vcvalue.Plain
pt, _  := cipher.Decrypt(ctx, ct, aad)

rows, _ := cipher.EncryptRecords(ctx, users, aad)  // one ZeroKMS call for the slice
probe, _ := cipher.Term(ctx, uint32(34), "users/age", stackencrypt.Equality)
```

- `stackencrypt.Sealed` — the Phase 2 leaf; `driver.Valuer` + `sql.Scanner`
  like `vcvalue.Sealed`. Distinct type on purpose: a stack-encrypt leaf is
  not decryptable by `vcencrypt` and must not scan into its `Sealed`.
- Record plans come from struct tags, the Go stand-in for the derive:

  ```go
  type User struct {
      ID    int64  `stash:"plain"`
      Age   uint32 `stash:"context=users/age,index=eq;ore"`
      Email string `stash:"context=users/email,index=eq;match"`
  }
  ```

  Reflection builds the plan `FfiValue` once per type (cached) and sends
  source + plan in one call. Terms come back as `stackencrypt.Term` /
  `OreTerm` byte types with `Valuer`/`Scanner` and `Equal`/`Less` helpers.
- Errors: vitaminc's sentinels plus the ZeroKMS request kinds
  (`ErrUnauthorized`, `ErrForbidden`, `ErrNotFound`, `ErrConflict`,
  `ErrTransport`) mapped from `ViturRequestErrorKind` via status codes, so
  the Go caller can distinguish a bad token from a tampered ciphertext.
- Codec: whatever the decision on the FFI codec's home is, the Go code must
  not fork it.

### Phase 5 — validation and CI

- `mise run test:integration:wasi-go` (renamed #2099 harness): boots
  `zerokms-server` against the mock auth server, mints a token, seeds a
  client + keyset, then `CGO_ENABLED=0 go test ./...` in
  `bindings/go/stackencrypt`.
- Go tests: import-surface gate (exactly WASI + `cipherstash_transport`),
  stub-transport tests for the bridge, live encrypt/decrypt, live
  `EncryptRecords` asserting **one** `transport_send` for N rows
  (`TransportSends()` counter from #2099), probe-equals-stored-term, hostile
  ABI inputs (port `abi_hostile_test.go`).
- Cross-language fixtures, both directions: a Rust `gen_fixture` example
  (as vitaminc's) writes ciphertexts + terms + the AAD/context used; Go
  decrypts and compares terms. And the reverse: Go writes a fixture the Rust
  `encrypted_record` example decrypts. Terms must be byte-equal across
  languages, not just "decryptable".
- CI: extend `test-stack-encrypt.yml` (from #2099) with the wasi build +
  Go job; `wasm:wasi-check` in the blocking PR lane.

### Phase 6 — follow-ups (explicitly out of the proof)

- **`stack-transport`** — the trait crate #2099 proposed: `HttpTransport`
  with reqwest and WASI-host-import impls, consumed by `stack-kms`'s
  connection *and* `stack-auth`'s refreshers. That moves access-key exchange
  and refresh into the guest (`AccessKeyStrategy` generic over transport),
  retires `token_get`, and makes the `http` feature gates of Phase 1
  collapse into a transport choice. Bigger refactor; only start it once the
  proof shows the shape is right.
- Instance pool in the Go client for parallelism; per-instance memory
  limits.
- `cfg(target_arch = "wasm32")` → split JS-host vs WASI where semantics
  differ (timeouts, filesystem, credential discovery).
- Component model / WIT when wazero supports it (tracked in vitaminc's
  README, same decision here).
- Publishing: the `.wasm` build must be reproducible (pinned toolchain,
  `opt-level = "s"`, `lto`, `strip`); the Go module ships from a public repo
  — this monorepo is private, so the proof's module path is temporary.
- Retire `goencryption`'s cgo static-library matrix once parity is reached.

## Decisions to make first

1. **Where the Go FFI codec lives.** `vcvalue`'s README deliberately
   keeps it out of `vcvalue`; today it is unexported inside `vcencrypt`.
   Options: (a) a third vitaminc module `bindings/go/vcffi` (codec +
   `Encoder`/`Encryptable`, still zero external deps; the ciphertext
   decoder parameterised over the leaf type so `stackencrypt.Sealed` is
   not `vcvalue.Sealed`) that both `vcencrypt`
   and `stackencrypt` import; (b) vendor a copy into `stackencrypt`.
   Recommend (a): one codec, one set of fuzz tests.
2. **`SealedValue` byte layout** (Phase 2). Needs a version byte and the
   AAD binding decision; it is a storage format from the first Go row
   written.
3. **Term encodings** — align with EQL or define stack-encrypt's own.
   Recommend align: Postgres is the consumer that matters.
4. **Phase-1 auth**: host-supplied token (`token_get`) versus doing
   `stack-transport` first. Recommend host-supplied — it is what #2099
   proved, it keeps the proof to one new seam, and the refactor is better
   informed after the proof.
5. **Feature vs `cfg(target_os = "wasi")`** for gating reqwest in
   `stack-kms`/`stack-auth`. A feature is honest about "this build has no
   HTTP" and lets native tests exercise the HTTP-free path; a cfg is
   invisible to callers. Recommend the feature (`http`, default on).
6. **Repo location / module path** for the proof: `bindings/go/stackencrypt`
   in this repo (mirrors vitaminc) versus straight into a new public SDK
   repo. Recommend here for the proof; it needs the integration harness.

## Non-goals for the proof

- Typed Rust-static ↔ Go interop (vitaminc's decision 4 stands: fidelity
  comes from the schema/plan layer, not value tags).
- Device/OIDC/access-key auth flows inside the guest (Phase 6).
- EQL wire payloads (`{v,i,c,ob}` JSON) — that is `eql-bindings`' layer; the
  Go binding returns the record tree and leaves EQL framing to a schema-aware
  consumer, exactly as the Rust side does.
- Performance beyond "one ZeroKMS call per batch".

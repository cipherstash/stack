---
status: accepted
date: 2026-09-20
---

# A separate credential guest for the profile and auth crates

The Go binding reaches Rust through one WASI module, the crypto guest, run by
wazero with `CGO_ENABLED=0`. That guest has no filesystem and no environment:
its module config grants a name, a random source and two clocks, and its only
routes out are the two host imports the Go side owns — an HTTP transport and a
token source. The napi pattern the Node bindings use (a cdylib per crate) does
not carry over, because a cdylib needs cgo.

Go therefore has neither `stack-profile` nor `stack-auth`. Anything that needs
the developer profile re-derives its on-disk layout by hand, and the only
`TokenSource` implementations are escape hatches. This ADR records where those
two crates run for Go, and why it is a second module rather than the first one
widened.

## The problem

CIP-4053 lays out three mechanisms. Extend the crypto guest and mount the
profile directory into it. Build a second, separate module for the credential
crates. Reimplement both in Go and pin the on-disk layout with a conformance
test.

Two constraints decide it, and they pull in different directions. The crypto
guest's sandbox is a clean property today: a bug or compromise inside it
cannot read credentials off disk, because it cannot read anything off disk.
Mounting the profile into that module trades the property away, and it is the
module that handles plaintext and data keys. Against that, `stack-auth`'s
refresh path guards the token exchange with a cross-process file lock and
re-reads the token after acquiring it, because the identity provider rotates
refresh tokens and detects replay: two processes that both post the same
refresh token get the whole chain revoked. A Go reimplementation that got that
wrong would break a developer's login from a second terminal in a way that
looks like a server fault.

A spike (2026-09-20) ran the real `stack-profile` crate as a wasip1 module
under wazero with a temporary profile mounted, and settled the facts the
decision rests on:

- The crate compiles for wasm32-wasip1 with two gates. The `gethostname`
  dependency has no wasip1 body, and the atomic write embeds
  `std::process::id()` in its temp filename, which aborts the module rather
  than returning an error. Nothing else changed. `stack-auth` with default
  features off already builds, since the crypto guest depends on it.
- Every operation the napi binding exposes worked through the mount: current
  workspace, listing, typed loads, atomic rewrite, directory creation. A read
  outside the mount was refused. `CS_CONFIG_PATH` reached the guest through
  wazero's environment config; the home directory did not exist on wasi.
- Every file the guest created came out mode 0600 and every directory 0700,
  under a host umask of 022. The crate's own mode handling is `cfg(unix)` and
  was skipped; the mode comes from wazero, which passes 0600 on every create.
- `File::lock` returned "operation not supported on this platform" cleanly.
  WASI preview 1 has no file locking at all.
- Outside tests, `reqwest` appears in six call sites of one shape: post a form
  or JSON body, read status and body back, plus two error conversions. That
  is the shape of the crypto guest's existing `transport_send` import.

## Decision

### 1. One credential guest, with one mount and no environment

`stack-profile` and `stack-auth` compile into a second WASI module, the
credential guest, embedded in its own Go package. wazero mounts exactly one
directory into it, the profile root, at a fixed guest path. The guest is given
no environment: the Go side resolves `CS_CONFIG_PATH` and the home directory
the way `ProfileStore::resolve` does, mounts the result, and constructs the
store with the guest path explicitly. The crypto guest is unchanged.

The two modules have different blast radii, and the split is what makes that
true. The credential guest can reach one directory of credentials and, once
the auth half lands, HTTP. The crypto guest can reach neither.

### 2. The lock stays on the host, around the whole refresh call

WASI preview 1 cannot lock a file, so no wasm-hosted refresher can hold the
lock itself. But the discipline the refresher needs is "acquire, re-read from
disk, exchange, write, release", and that is satisfied if the Go side takes
the lock and only then calls into the guest: the guest reads the profile at
call time, after acquisition, by construction.

So the guest has no lock calls at all. Go takes the same lock the Rust CLI
takes — `flock(LOCK_EX)` on Unix, `LockFileEx` with the exclusive flag over
offset zero and a length of all ones on Windows, on the sibling lock file the
guest names — around the device-session refresh export, and nowhere else.
Today the refresher's wasm32 arm only compiles the lock out and says nothing
about who holds it; the auth half (CIP-4054) rewrites that arm to document
that the host does, when the strategies move into the guest. No lock state
crosses the ABI, no guest code path can forget to release, and the import
surface stays filesystem plus transport. Go never spells a profile path: the lock
file's path comes from a `stack-profile` accessor exposed through the guest.

Go acquires with a try-lock and backoff under the caller's context, where the
Rust CLI blocks. Mutual exclusion is identical; only who gives up first
differs, and a library that blocks a Go application indefinitely on a wedged
lock holder is a wedged process.

### 3. Nothing the guest cannot do is faked

The process id and the hostname are compiled out on wasm32, not stubbed. In
particular the creating half of `DeviceIdentity::load_or_create` is
native-only: its only production caller is the client-provisioning step at
login, which is CLI territory, and the refresh path takes the device instance
id from a claim in the token it is refreshing, not from the file. A guest that
could create an identity named after a fake hostname would be worse than one
that cannot create one. The read-only `load` stays.

The 0600 mode on created files is wazero's default, not the crate's code. It
is the right outcome, but it holds by a property of the runtime, so the Go
side pins it with a test alongside the outside-mount refusal, the same way the
crypto guest pins its import surface.

### 4. One Go module, one package, shared plumbing behind `internal`

The Go module moves up to `bindings/go`, so it contains `stackencrypt`,
`stackauth` and an internal package both import. `stackauth` is one package
over the one guest, with `ProfileStore` and the Rust type names inside it;
nobody uses the profile without auth, and two packages over one embedded guest
would be two packages that must agree on one instance. Neither public package
imports the other.

The internal package holds the locked, non-dumpable guest memory from
CIP-4111, which the credential guest gets from day one since it holds the
client key and tokens; the decoder for the status table; and the opaque
`ClientKey` type. Both public packages expose that type as an alias, so
`stackauth.ClientKey` and `stackencrypt.ClientKey` are one type by identity
without either package depending on the other, and a binary that only wants
the profile does not carry the crypto guest.

On the Rust side the guest ABI plumbing — allocator, buffer registry, status
table, the `cipherstash_transport` host import — is extracted into a
workspace crate, `stack-guest-abi`, `publish = false`, before the second guest
is written. Two consumers is the trigger CIP-3997 was waiting for, and copying
would mean making the memory-hygiene fixes twice. The status table is one
numbering for both guests: existing numbers keep their values, and the
credential guest's profile codes append.

### 5. Secrets: the client key is opaque and wiped; tokens stay strings

`Config.ClientKey` becomes the opaque type rather than a string. A string is
immutable and unwipeable, and a byte slice prints its contents under `%v`.
The opaque type has a redacted `String` and `GoString`, is handed out by
`stackauth`'s typed read, and is consumed and wiped by `stackencrypt` once it
has marshalled the config. Nothing has shipped, so this is a change, not a
breaking one.

Bearer tokens stay strings, and `TokenSource` keeps its name and shape. The
name is the `golang.org/x/oauth2` idiom every Go developer already knows, and
its ecosystem is strings end to end; a token is hours-lived and already
crosses TLS as text, where the client key is key material that lives for the
process. A one-function adapter from an x/oauth2 token source ships with the
package.

Until refresh lands, the profile-backed `TokenSource` re-reads the auth file
on every call, so a login or refresh by the CLI in another terminal is picked
up without a restart, and it refuses a token at its real expiry timestamp
with an error that names `stash auth login`. The 90-second refresh-ahead
margin belongs to refreshing and applies there once it exists.

### 6. The profile half ships first; the transport seam gates the auth half

Sequence: the `stack-profile` wasm32 gates and lock-path accessor; the shared
ABI crate; the module move and internal package, stacked on CIP-4111; the
credential guest and `stackauth` with the full napi profile surface. That
closes CIP-4053 and unblocks the env-plus-profile part of CIP-4052.

Then `stack-auth` gains a transport trait mirroring the host import exactly —
method, URL, headers and body in, status, headers and body out, bytes, no
streaming — with reqwest as one implementation behind the `http` feature and
the guest's import as the other (CIP-4116). The trait returns `impl Future`,
the crate's convention for async traits, so it is not object-safe; a
crate-internal adapter boxes the future once at construction, so no public
strategy type grows a type parameter and the concrete transport is never
named again after the builder's `.transport(..)`. Then the strategies run
inside the guest: access key, device
session, OIDC federation with a Go callback for the identity-provider token,
and auto. `AutoStrategy`'s detection order runs in Go against the environment
Go already owns, pinned against the Rust order by a test; the guest stays
environment-free. The Go package exposes typed constructors; one tagged
config crosses the guest ABI and Rust validates its variant before creating
the corresponding strategy. This keeps the public API typed without adding
separate pointer and length signatures for each strategy export.

The token exchanges are tested against an in-process `httptest` server,
since HTTP goes through the Go host: exact request bodies, the error
taxonomy, and two goroutines racing a refresh under the lock.

### 7. Three platforms, one wasm build

The lock has Unix and Windows implementations from day one, since the CLI's
own lock works on both and a developer sharing a profile with the CLI is the
replay scenario the lock exists for. CI builds both guests once on Linux and
hands the artifacts to macOS and Windows runners that run both packages' Go
suites.

## Considered options

**Extend the crypto guest.** Rejected. It mounts a directory of credentials
into the module that handles plaintext and data keys, trading away a sandbox
property that is currently clean, to save one module.

**Reimplement in Go.** Rejected. The lock has to be Go's regardless, so what
a Rust guest buys is one implementation of the on-disk layout, the token
wire protocol, the error taxonomy and expiry parsing. The layout has moved
once already, and the expiry bugs in CIP-3233 and CIP-3238 are exactly the
drift a Go copy would reintroduce.

**Lock as a host import.** Rejected. The guest would call acquire and release
from inside `refresh`, so lock state crosses the ABI and a guest path can
forget to release. Wrapping the export gives the same ordering with no new
import.

**Environment into the guest, by allowlist.** Rejected. Credential resolution
is Go's under CIP-4052 anyway, and a guest with zero environment and one
mount is easier to reason about and to pin than one with a list.

**Two Go packages mirroring the two crates.** Rejected, as decision 4 says.

## Consequences

Two modules to build, embed and assert the import surface of. The memory
hygiene work covers both. `stack-profile` gains two wasm32 gates, joins the
`wasi-check` task, and widens its API by a lock-path accessor. `stack-auth`
gains a transport trait, which is the largest piece of work here and the one
CIP-3553 already anticipated. The Go module path and layout change before
anything ships. The CI matrix grows by two operating systems.

What it does **not** fix: the client key still passes through Go host memory
between the two guests, since two wasm instances cannot share memory. It is
wiped there, not absent. And a token is a Go string on the host side, which
cannot be wiped; that is accepted for a credential that lives for hours.

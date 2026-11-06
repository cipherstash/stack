---
status: proposed
date: 2026-11-04
---

# Hand-written vendor clients, signed in the guest

> **Amended 2026-11-06**, after the review of the key vendor backend stack.
> The decision is unchanged. Two of its claims were not true, and are
> corrected here.
>
> 1. **Key material crosses to the host.** The guest sends each vendor
>    request through `transport_send`, and the host does the TLS. So the Go
>    host, and any `WithTransport` RoundTripper, see the vendor traffic in
>    plaintext: the key a wrap request sends, and the key that an unwrap or
>    generate response returns (AWS `Decrypt` and `GenerateDataKey`, Google
>    Cloud KMS and Vault `decrypt`, Azure `unwrapkey`). That key is a root
>    key under derived data keys and a data key under wrapped data keys, and
>    it is usable alone. A ZeroKMS response is not, which is why the property
>    held for ZeroKMS. The host wipes the bodies it holds, but not the
>    buffers of net/http, TLS or the RoundTripper. Keys the guest derives
>    from it still never cross back. Keeping vendor keys from the host needs
>    TLS inside the guest; that is not planned.
> 2. **Long-lived credentials can cross to the guest.** The credential import
>    carries whatever the Go source returns. `AWSCredentialsFromEnv` returns
>    an IAM user's long-lived keys when no session token is set, and a Vault
>    token can be long-lived. A `StaticKey` backend's key crosses once, in
>    the guest config. The guest still does no RSA and reads no signing key
>    file.
>
> The Go package documentation, `guest/src/host.rs` and `transport.go` now
> say this.

The Go SDK reaches Stack Encrypt through a WASI guest. The guest builds the
ZeroKMS requests and derives the keys. The Go host is only an HTTP pipe
(`transport_send`) and a token source, and no key material crosses back to the
host (ADR-0005). Key vendor backends (ADR-0009) must keep that property.

The official Rust SDKs (`aws-sdk-kms`, the Google Cloud and Azure crates)
depend on tokio and hyper and do not build for wasm32-wasip1. We therefore
write a small REST client for each vendor, over one transport trait of the
same shape as `ZeroKMSConnection`. Native Rust and the guest use the same
code. Each vendor is a separate crate (`stack-kms-aws` and so on), so that no
user compiles all four.

The guest signs each vendor request itself (SigV4, the Google OAuth JWT, the
Azure AD token, the Vault token). It gets short-lived signing credentials from
the Go host through a new credential import, of the same shape as `token_get`.
The host fills the import from the vendor's own Go credential chain, so we do
not implement IMDS, the GCP metadata server or Azure managed identity in the
guest. Credentials cross the boundary. Key material derived in the guest
does not, but the vendor's own traffic does (see the amendment).

The Go module ships one guest that contains all vendor clients, not one guest
for each vendor. This decision depends on a measurement of the guest size.

## Considered options

- **Official SDKs on native Rust and hand-written clients in the guest.**
  Rejected. There would be two code paths for each vendor, and the guest path
  would be the less tested one.
- **The Go host calls the vendor's Go SDK and passes the unwrapped key to the
  guest.** Rejected. The host would parse each unwrapped key itself, and each
  vendor would need a Go client as well as a Rust one. (This record first
  said the option broke the rule that key material never crosses to the
  host. The chosen design does not keep that rule either; see the
  amendment.)
- **One guest for each vendor.** Rejected for now. It multiplies the embedded
  `.wasm` files, the deterministic test builds and the release workflow by up
  to five.

## Consequences

We own the request signing code for four vendors, and its tests. Recorded
HTTP fixtures cover every vendor. LocalStack and `vault server -dev` run on
every PR. Live Google Cloud and Azure tests run in an opt-in, credentialed
workflow.

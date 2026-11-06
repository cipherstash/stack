---
status: proposed
date: 2026-11-04
---

# Hand-written vendor clients, signed in the guest

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
guest. Credentials cross the boundary. Key material does not.

The Go module ships one guest that contains all vendor clients, not one guest
for each vendor. This decision depends on a measurement of the guest size.

## Considered options

- **Official SDKs on native Rust and hand-written clients in the guest.**
  Rejected. There would be two code paths for each vendor, and the guest path
  would be the less tested one.
- **The Go host calls the vendor's Go SDK and passes the unwrapped key to the
  guest.** Rejected. It breaks the rule that key material never crosses to the
  host.
- **One guest for each vendor.** Rejected for now. It multiplies the embedded
  `.wasm` files, the deterministic test builds and the release workflow by up
  to five.

## Consequences

We own the request signing code for four vendors, and its tests. Recorded
HTTP fixtures cover every vendor. LocalStack and `vault server -dev` run on
every PR. Live Google Cloud and Azure tests run in an opt-in, credentialed
workflow.

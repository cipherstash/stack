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
| [`AccessKeyStrategy`] | Service-to-service / CI | Static access key + region |
| [`OAuthStrategy`] | Long-lived sessions with refresh | OAuth token (from device code flow or disk) |
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
use cts_common::Region;

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let region = Region::aws("ap-southeast-2")?;
let key = "CSAKkeyId.keySecret".parse()?;
let strategy = AccessKeyStrategy::new(region, key)?;
# Ok(())
# }
```

## Security

Sensitive values ([`SecretToken`]) are automatically zeroized when dropped
and are masked in [`Debug`](std::fmt::Debug) output to prevent accidental
leaks in logs.

## Token refresh

All strategies that cache tokens ([`AccessKeyStrategy`], [`OAuthStrategy`],
[`AutoStrategy`]) share the same internal refresh engine. See the
[`AuthStrategy`] trait docs for a full description of the concurrency model
and flow diagram.

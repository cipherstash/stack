# Stash telemetry proxy

A Cloudflare Worker that receives the `stash` CLI's anonymous analytics at
`telemetry.cipherstash.com` and forwards them to PostHog. See `worker.js` for why
the CLI proxies instead of calling PostHog directly (first-party requests, and
so the US→EU migration needs no CLI re-release).

## Deploy

Requires [`wrangler`](https://developers.cloudflare.com/workers/wrangler/) and
access to the Cloudflare account that holds the `cipherstash.com` zone.

```bash
cd infra/telemetry-proxy
wrangler deploy
```

The `custom_domain` route provisions `telemetry.cipherstash.com` and its TLS
certificate automatically on first deploy.

## Verify

```bash
# 404 for an unknown path (the Worker is not an open proxy)
curl -sS -o /dev/null -w '%{http_code}\n' https://telemetry.cipherstash.com/

# A capture POST is accepted and forwarded to PostHog
curl -sS -X POST https://telemetry.cipherstash.com/batch/ \
  -H 'content-type: application/json' \
  -d '{"api_key":"<public-key>","batch":[]}'
```

## Moving to PostHog Cloud EU (future)

The forward target is the `POSTHOG_HOST` var, not anything baked into the CLI.
To migrate the entire installed CLI fleet:

1. Edit `POSTHOG_HOST` in `wrangler.toml` to `eu.i.posthog.com`.
2. `wrangler deploy`.

No CLI change, no release. Every already-installed `stash` follows the proxy.

## Wiring the CLI

The CLI targets `https://telemetry.cipherstash.com` and carries the public,
write-only PostHog project key (embedded at release in
`packages/cli/src/telemetry/index.ts`; overridable with `STASH_POSTHOG_KEY` for
testing). Until a real key is embedded, CLI telemetry is dormant — no events are
sent regardless of this proxy.

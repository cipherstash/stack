/**
 * CipherStash telemetry reverse proxy (Cloudflare Worker).
 *
 * The `stash` CLI sends anonymous analytics to `telemetry.cipherstash.com`, and
 * this Worker forwards them to PostHog. Two reasons the CLI never talks to
 * PostHog directly:
 *
 *   1. First-party + transparent — requests stay on our domain and sail through
 *      corporate firewall allowlists.
 *   2. Indirection — a released CLI hard-codes whatever host it shipped with,
 *      forever. Because the target lives in the `POSTHOG_HOST` var, a future
 *      US→EU migration is a var change + redeploy here, with NO CLI re-release:
 *      every already-installed `stash` follows automatically.
 *
 * A bare DNS CNAME to PostHog can't do this — PostHog serves its own TLS cert
 * and routes by Host header — so the domain must be terminated and rewritten,
 * which is exactly what this Worker does.
 */

// PostHog ingestion path prefixes. Restricting to these keeps the Worker from
// being a general-purpose open proxy while still covering posthog-node's
// batch/capture endpoints.
const ALLOWED_PREFIXES = ['/batch', '/capture', '/e', '/i/', '/flags', '/array']

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    if (request.method !== 'POST' && request.method !== 'GET') {
      return new Response('Method Not Allowed', { status: 405 })
    }
    if (!ALLOWED_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) {
      return new Response('Not Found', { status: 404 })
    }

    const target = env.POSTHOG_HOST // "us.i.posthog.com" now; "eu.i.posthog.com" later
    url.hostname = target
    url.port = ''
    url.protocol = 'https:'

    const forwarded = new Request(url, request)
    forwarded.headers.set('Host', target)

    return fetch(forwarded)
  },
}

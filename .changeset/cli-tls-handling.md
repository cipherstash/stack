---
'stash': minor
---

The CLI now handles database TLS properly, so the discoverable fix for a certificate failure is never `NODE_TLS_REJECT_UNAUTHORIZED=0`.

- Every CLI database connection honours `sslmode` and `sslrootcert` from the connection string: `verify-full` (and `require`/`verify-ca`/`prefer`, kept as full verification — node-postgres's current behaviour) verifies the server certificate; `no-verify` is honoured with a one-line stderr warning; `disable` turns TLS off. Client-certificate setups (`sslcert`/`sslkey`) pass through untouched.
- CA resolution: `sslrootcert=<path>` (libpq semantics — sole trust anchor; `sslrootcert=system` selects the system store) → `PGSSLROOTCERT` → for `*.supabase.co`/`*.supabase.com` hosts a **bundled Supabase root CA** (appended to the system roots) → the system store. `sslmode=verify-full` against Supabase — direct hosts and the pgBouncer pooler — now verifies out of the box.
- Certificate-verification failures name the host and the supported remedies in order (`sslrootcert=…`, then `sslmode=no-verify` as a last resort with the consequence spelled out), and explicitly warn against `NODE_TLS_REJECT_UNAUTHORIZED=0`, which is process-wide and would also disable verification for the connections carrying CipherStash credentials.
- The node-postgres "SSL modes … are treated as aliases for verify-full" SECURITY WARNING no longer appears on every invocation against `sslmode=require` URLs: the CLI decides the TLS config itself and hands pg a URL with the TLS params stripped (fixes the upstream-advisory passthrough).

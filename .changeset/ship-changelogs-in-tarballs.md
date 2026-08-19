---
'@cipherstash/stack-prisma': patch
'@cipherstash/protect-ffi': patch
---

Ship `CHANGELOG.md` inside the published tarball. It was missing from `files`,
so the release notes for these packages were readable on GitHub and on the npm
web page but not in the package you actually install — which is the copy you
have when something breaks offline, or when the repository has moved.

`@cipherstash/stack-drizzle` and `@cipherstash/stack-supabase` gain it in the
same release, as do the six `@cipherstash/protect-ffi-<platform>` packages.

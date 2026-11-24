---
"@cipherstash/stack": minor
"stash": patch
"@cipherstash/wizard": patch
"@cipherstash/migrate": patch
---

Move from zod 3.25.76 to zod 4.6.7, out of the range of GHSA-mrhx-c7xc-m3w5 (zod
before 4.6.6 can run out of memory validating a very large array). None of these
packages validates end-user input with zod, so none was exposed in practice.

The encryption config that `@cipherstash/stack` builds is unchanged: the same
schemas give the same output under zod 4 as under zod 3, including for index
options left out.

`@cipherstash/stack/schema` exports zod schemas (`encryptConfigSchema`,
`castAsEnum`, `eqlCastAsEnum`), and these are now zod 4 schemas. Calling
`.parse` or `.safeParse` on them works as before. Code that combines them with
its own zod 3 schemas, or reads zod 3 error fields such as `.errors`, needs zod 4.

---
"@cipherstash/wizard": patch
---

Stop the agent guard from blocking `.env.example`.

`SENSITIVE_FILE_PATTERNS` matched `/\.env($|\.)/`, which tests true against
`.env.example`. Because the guard covers `Edit` and `Write` as well as `Read`,
the wizard's agent was blocked from creating or editing the very file the
CipherStash doctrine tells it to write ("New env keys go in `.env.example` with
placeholders"). Committed env templates carry placeholder key names, not values.

`.env.example`, `.env.sample` and `.env.template` are now readable and writable.
Everything else is unchanged: `.env`, `.env.local`, `.env.production`, and
value-bearing files that merely start with a template name
(`.env.example.local`, `.env.example.bak`) stay blocked, as do `auth.json`,
`secretkey.json` and credential files. Bash access to any env file — including
the templates — remains blocked; `Read`/`Write` is the sanctioned path.

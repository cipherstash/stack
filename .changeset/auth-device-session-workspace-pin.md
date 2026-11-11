---
"@cipherstash/auth": patch
"stash": patch
---

`@cipherstash/auth`'s `AutoStrategy` now honours `CS_WORKSPACE_CRN` when you are signed in through the CLI (no access key). The default `@cipherstash/stack` client resolves credentials in `@cipherstash/protect-ffi` and does not pick this up until that package does. Previously the CRN was ignored and the CLI's *current* workspace was used, so switching workspaces with the CLI silently changed which workspace a process authenticated against. Now the session saved for the workspace named by the CRN is used, and every token is checked against that workspace, failing with `WORKSPACE_MISMATCH` otherwise. If no session exists for that workspace, the result is `NOT_AUTHENTICATED`. Without a CRN, behaviour is unchanged.

The client key (`secretkey.json`) that `stack-encrypt` reads from the CLI profile follows the same workspace, so the token and the client key never come from different ones.

---
'stash': major
'@cipherstash/wizard': major
---

Remove the `--proxy` / `--no-proxy` choice from `stash init`, and the wizard step that depended on it.

`--proxy` never configured a connection to CipherStash Proxy. It recorded a declaration of intent: the flag (or an interactive prompt) set `usesProxy` in `.cipherstash/context.json`, and exactly one piece of code acted on it — the wizard's post-agent step, which ran `stash db push` when it was true and logged a skip notice when it was false. `stash plan` and `stash impl` read the field into state and never branched on it.

`stash db push` writes `eql_v2_configuration`, which only ever applied to EQL v2 with Proxy. With the v2 surface going away there is no condition under which that step should run, so the flag it gated goes with it.

Removed:

- `--proxy` / `--no-proxy` on `stash init`, and the interactive "Proxy or SDK?" prompt (`init` is now six steps, not seven)
- `usesProxy` from `.cipherstash/context.json`, from `InitState`, and from the wizard's gathered context
- The wizard post-agent `stash db push` step and its skip notice

**Upgrading:** drop `--proxy` / `--no-proxy` from any scripted `stash init` invocation. The CLI's argument parser is permissive, so a leftover flag is ignored rather than rejected — it will not fail your pipeline, but it will not do anything either. A `context.json` written by an older CLI may still carry `usesProxy`; it is now an ignored extra property and needs no migration.

`stash db push` itself is unchanged here and is being retired separately with the rest of the EQL v2 surface. `--proxy-url` on `stash encrypt cutover` is a different flag — a real Proxy connection URL used to call `eql_v2.reload_config()` — and is also untouched.

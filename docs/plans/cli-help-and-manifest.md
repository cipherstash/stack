# Proposal: a command-descriptor registry for `stash` help + a `manifest --json`

**Status:** proposal / for discussion
**Area:** `packages/cli`
**Motivated by:** the docs V2 CLI reference, which is generated from the CLI
(cipherstash/docs#45). Today it parses `stash --help`; this proposal gives it —
and agents — a real structured source, and makes per-command help consistent.

## Problem

1. **The help text drifts from the implementation.** The top-level help is a
   hand-written template string, `HELP`, in
   [`packages/cli/src/bin/main.ts`](../../packages/cli/src/bin/main.ts),
   maintained separately from the command modules in `packages/cli/src/commands/*`.
   Nothing ties the two together, so the help lags real behaviour. (Concretely:
   the published `stash@0.16.0 --help` still lists the `db` group while `main.ts`
   on `main` has already moved install/upgrade/status to `eql` — the docs
   generated from the published `--help` were a whole command surface behind.)

2. **Per-command help is inconsistent.** `auth` implements its own `--help`
   ([`commands/auth/index.ts`](../../packages/cli/src/commands/auth/index.ts)),
   but `stash eql install --help`, `stash db push --help`, etc. fall through to
   the top-level help. There is no per-command help for most commands.

3. **No machine-readable output.** Docs have to scrape `--help`, and agents
   running `npx stash` have no authoritative, versioned command surface to read.
   The `--help` is also thin: no per-command args, no per-command examples,
   `auth`/`encrypt` subcommands undetailed.

## Goals

- One source of truth for command metadata; help and docs can't drift from it.
- Consistent `stash <command> --help` for every command.
- `stash manifest --json` — a structured, versioned command surface for the docs
  generator and for agents.
- Room for rich per-command **long descriptions** and **examples**
  (GitHub-CLI / cobra model), so `--help` and the docs read well.

## Design: a command-descriptor registry

Replace the hand-written `HELP` string with a registry of descriptors — one per
command — and render everything (top-level help, per-command help, JSON) from it.
Command *handlers* (`commands/*`) are unchanged; the descriptor just carries
metadata and points at the handler.

```ts
interface Flag {
  name: string;            // "--supabase"
  value?: string;          // "<path>" for value-taking flags
  description: string;
  appliesTo?: string[];    // for shared groups: subcommands this flag applies to
  default?: string;
  env?: string;            // e.g. "DATABASE_URL"
}

interface CommandDescriptor {
  name: string;            // "eql install", "auth login"
  group: string;           // "Setup & workflow" | "Database" | "EQL" | ...
  summary: string;         // one line (today's Commands: text)
  long?: string;           // rich multi-paragraph help (cobra `Long`)
  examples?: string[];     // curated, per command (cobra `Example`)
  flags?: Flag[];
  hidden?: boolean;        // deprecated aliases (the old `db install`, …)
  run: (args: string[], flags: Record<string, unknown>) => Promise<void>;
}
```

Three renderers over the registry:

- `renderTopLevelHelp(registry)` → today's `stash --help` (kills the `HELP` string).
- `renderCommandHelp(registry, "eql install")` → per-command help, for **every**
  command, uniformly. `auth`'s bespoke `HELP` block goes away.
- `emitManifest(registry)` → `stash manifest --json` (schema below).

Dispatch already routes `argv` to a handler; it now looks the handler up in the
registry, and a missing/`--help` arg prints `renderCommandHelp`.

## `stash manifest --json` — the contract

This is the exact shape the docs generator (cipherstash/docs#45) already targets,
so once this lands the docs swap `--help` parsing for:

```
npx stash@<latest> manifest --json
```

```jsonc
{
  "name": "stash",
  "version": "0.17.0",
  "groups": [
    {
      "title": "Auth",
      "commands": [
        {
          "name": "auth login",
          "summary": "Authenticate with CipherStash",
          "long": "Runs the OAuth 2.0 device authorization flow: pick a region, approve in the browser (the URL is printed so it works headless/over SSH), then your device is bound to the workspace's default keyset…",
          "examples": ["stash auth login", "stash auth login --supabase"],
          "flags": [
            { "name": "--supabase", "description": "Track Supabase as the referrer" }
          ]
        }
      ]
    }
  ]
}
```

`version` comes from the CLI's own `package.json`, so a page generated from the
manifest is always stamped with the exact version it describes.

## Worked example: `auth`

Today `auth` is described in **two** places — a line in `main.ts`'s `HELP` and
the `HELP` string in `commands/auth/index.ts` — and the device-code-flow detail
(region → verification URL → poll → bind device to the default keyset) lives only
in code. As a descriptor it's declared once:

```ts
{
  name: "auth login",
  group: "Auth",
  summary: "Authenticate with CipherStash",
  long: [
    "Runs the OAuth 2.0 device authorization flow:",
    "1. Pick a region for your workspace.",
    "2. Approve in the browser — the URL is printed, so it works over SSH/headless.",
    "3. The CLI polls until you approve, then stores a short-lived token.",
    "4. Your device is bound to the workspace's default keyset, so later",
    "   commands authenticate without a fresh login.",
  ].join("\n"),
  examples: ["stash auth login", "stash auth login --supabase"],
  flags: [
    { name: "--supabase", description: "Track Supabase as the referrer" },
    { name: "--drizzle",  description: "Track Drizzle as the referrer" },
  ],
  run: authLogin,
}
```

That one declaration now feeds `stash auth --help`, `stash auth login --help`,
the top-level help line, the JSON manifest, and the generated docs page.

## How the docs consume it

- `cipherstash/docs` runs `npx stash@<latest> manifest --json` in `prebuild`,
  renders one versioned page per command, and stamps `verifiedAgainst.cli`.
  (Prototype today parses `--help`; swapping to the manifest deletes the parser
  and keeps the page format identical — see cipherstash/docs#45.)
- **Content split (GitHub-CLI model):** per-command *reference* — summary, flags,
  `long`, examples — lives here in the CLI and is generated. *Cross-command*
  narrative (the profile / workspace model, switching) stays as a hand-written
  docs concept page the command pages link to; it isn't any one command's help.

## Prior art

GitHub CLI (cobra): each command carries `Short` / `Long` / `Example` / flags;
`gh help <cmd>` and the generated cli.github.com/manual both come from those,
while conceptual pages (docs.github.com "About …") are separate. This proposal is
the same split for `stash`.

## Migration (incremental, non-breaking)

1. Add the descriptor type + registry and `stash manifest --json`, populated from
   the existing help data. Additive; nothing changes for users. **Unblocks docs.**
2. Render the top-level `--help` from the registry; delete the `HELP` string.
3. Add `renderCommandHelp`; route `stash <cmd> --help` to it; remove `auth`'s
   bespoke help. Do it group by group (Setup → EQL/DB → Encrypt → …).
4. Backfill `long` + `examples` per command as the reference content matures.

## Open questions

- Adopt a tiny declarative arg layer, or keep the hand-rolled parser and only add
  the metadata registry? (Registry-only is the smaller change.)
- Where do `long` / `examples` strings live — inline in the descriptor, or in
  co-located `.md`/`.ts` files per command to keep `main.ts` lean?
- Policy on `long` length — keep it reference-grade, push deeper concepts to docs.

# Domain docs

How engineering skills should consume this repository's domain documentation.

## Before exploring

- Read `CONTEXT-MAP.md` at the repository root when it exists. It points to the
  `CONTEXT.md` files relevant to each context.
- Read the context documents relevant to the task.
- Read system-wide ADRs under `docs/adr/` and context-specific ADRs under the
  relevant package's `docs/adr/` directory.

If these files do not exist, proceed silently. Do not propose empty placeholder
documents. The domain-modeling workflow creates them lazily when terminology or
decisions are actually resolved.

## Multi-context layout

```text
/
├── CONTEXT-MAP.md
├── docs/adr/                       system-wide decisions
└── packages/
    ├── stack/
    │   ├── CONTEXT.md
    │   └── docs/adr/               stack-specific decisions
    ├── cli/
    │   ├── CONTEXT.md
    │   └── docs/adr/               CLI-specific decisions
    └── <context>/
        ├── CONTEXT.md
        └── docs/adr/
```

Nested subtrees with their own architecture, such as `packages/eql`, may define
further contexts. `CONTEXT-MAP.md` is the authority for locating them.

## Use the glossary's vocabulary

When output names a domain concept—in an issue title, proposal, hypothesis, or
test name—use the term defined in the relevant `CONTEXT.md`. Do not drift to a
synonym that the glossary explicitly avoids.

If a needed concept is absent, reconsider whether the project already has a
different term. If the gap is real, record it for domain modeling.

## Flag ADR conflicts

If proposed work contradicts an existing ADR, identify the conflict explicitly
rather than silently overriding the decision.

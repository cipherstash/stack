---
'stash': patch
---

Fix invalid YAML in `skills/stash-managed-platforms/SKILL.md` frontmatter: the
unquoted `description` contained a colon-space, so any YAML parser rejected the
file (this broke cipherstash.com deploys, which mirror these skills at build
time). Rewritten as a folded block scalar; the parsed description is
byte-for-byte identical.

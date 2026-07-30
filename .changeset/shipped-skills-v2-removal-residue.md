---
'stash': patch
---

Correct the EQL v2 callout in the shipped `stash-encryption` skill.

The skill opened by pointing at an older EQL v2 schema surface "with chainable
capability builders" that "still exists for existing deployments". The v2 schema
builders and the `@cipherstash/stack/client` subpath were removed; v2 is a
read-compatibility path for stored payloads only, which is what the same file
already said two sections later. The opening callout now says so — it is the
first thing an agent reads in a customer's repo, and `SKILL_MAP.drizzle` installs
this skill into every Drizzle project.

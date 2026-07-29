---
'stash': patch
---

Correct `types.TOrd` in the `stash-indexing` skill, which named a factory that
does not exist. The ordering factories are `types.<N>Ord` (over the numeric and
time domains) and `types.TextOrd` — as the table directly above that line
already showed. An agent following the skill would have written a schema that
does not compile.

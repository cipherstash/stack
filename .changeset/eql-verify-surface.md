---
'stash': minor
---

New `stash eql verify`: assert the installed EQL surface is complete and coherent, independent of any application schema. A partial install — domains present, some of their comparison functions or operators absent — used to report success at install time and fail at query time on a specific predicate (e.g. `weight >= x`); nothing detected it. `eql verify` compares the database against everything the pinned bundle installs (every domain, function overload, operator, cast, and the ORE operator class) via read-only catalog queries, reports damage grouped per domain, and distinguishes expected absence from damage: the ORE operator class being skipped on managed Postgres, with its loud-failure fallback in place, reads as the supported configuration it is rather than a failed install. Exits 1 on damage; `--json` emits the structured report for agents. `stash eql install` now runs the same check automatically before declaring success.

# Failure modes to consider

Prompts, ordered roughly by how often they are missed by line-level review. For each changed behaviour, ask which apply. Discard the ones with no mechanism.

## Contract and compatibility
- A published API, type, CLI flag, config key, file format or wire payload changes shape. Who reads or writes it? Do old and new versions coexist (installed packages, stored data, running services)?
- A default changes. Callers that relied on the old default now behave differently without any code change.
- A type is tightened or loosened. Does the runtime behaviour still match the type for callers that bypass it (casts, plain JavaScript, deserialised data)?
- Packaging: module formats, bundling and code splitting, `exports` map entries, generated declaration files. Does every entry point a consumer can import still behave and type-check the same way?

## Broken invariants and assumptions
- A guard, validation or early return is removed or reordered.
- Values are encoded into or parsed out of strings, paths or keys. What inputs break the encoding?
- An optional value becomes required, or `undefined`/`null`/empty is handled differently.
- A string match (regex, prefix) narrows or widens, so inputs that used to match no longer do.

## Silent wrong results
- The code exits 0 but leaves the system in a wrong state.
- A check that should fail closed now fails open, or the reverse. In shell especially, how are exit statuses of pipelines and conditionals interpreted?
- A detection or classification step returns the wrong answer for some inputs, and later steps act on it.

## Data integrity and persistence
- Data written in a new format that old readers cannot read, or vice versa.
- Migrations: does it run on a populated table? Is it idempotent? Can it be re-run after partial failure? Rolled back? What happens when old and new application versions run against the same schema?
- Backfills that skip, duplicate or truncate rows.

## Security boundaries
- Plaintext reaching logs, errors, storage, a third-party API or a query parameter.
- Authorization or identity context dropped, defaulted, or applied to the wrong operation.
- Credentials, tokens or keys: scope, lifetime, caching keyed wrongly, shared between principals.

## Ordering, retries, idempotency, concurrency
- Steps that assume a previous step's result is already visible elsewhere.
- Re-running after partial failure: does it repeat side effects, skip needed work, or fail on "already exists"?
- Conditions that decide whether work runs: what do they evaluate to when an upstream step was skipped, failed or cancelled?
- Races between concurrent runs of the same pipeline or process.

## Build, release and supply chain
- A pipeline produces an artefact for the wrong platform, version or commit.
- Version numbers move out of lockstep across artefacts that must match.
- A release job fails after some artefacts are published (partial release).
- A dependency upgrade changes runtime behaviour, licences, or native binaries.
- CI that no longer runs a check (path filters, `if:` conditions) reads as green.

## Rollback
- Can the change be reverted without a data migration? Will a reverted version read data the new version wrote?
- Once a package version is published it cannot be unpublished in practice; a broken release needs a new release.

## Change risk: Focused review required

**Impact if something goes wrong:** low · **Verification confidence:** medium · `2ab2b9447e..eb8194bf37`

This change only affects CLI guidance text. `stash decrypt drop` no longer tells the user to delete the column's entry from `.cipherstash/migrations.json`. `stash encrypt status` now shows the flag `reversed` instead of `reversed (remove from migrations.json)`. The stash-cli skill now says the entry stays permanently and the file must not be hand-edited. No data path, SQL, migration file, recorded state or encryption behaviour changes: the manifest was never edited by the command before, and it still is not. Two risks remain, both low. First, two doc comments still describe the old remove-it-yourself workflow and now contradict the code and the skill. Second, a reversed column's entry now stays in the manifest for good, so `stash encrypt plan` keeps reporting it as `already at dropped` and `stash plan` keeps counting it as tracked. That state already existed before, but only until the user removed the entry. The tests that were updated pin the new text but were not run here. Overall impact is low. A focused review is recommended because of the stale comments.

### Failure scenarios

**FS-1 · Stale doc comments still prescribe the old manual manifest removal** (low impact, observed in the code)

- Trigger: A maintainer or agent reads the `decryptDropCommand` doc comment or the `removeManifestColumn` doc comment (the latter is part of @cipherstash/migrate's exported API docs).
- Mechanism: The commit updated the inline comment and the user-facing text, but drop.ts lines 75-79 still say 'The user removes the entry once it is applied'. manifest.ts lines 194-197 still say decrypt drop 'leaves the entry for the user to remove after applying'.
- Consequence: The sources disagree about who owns the manifest entry. That could lead someone to put the removal advice back, or to call removeManifestColumn on the wrong basis. No runtime effect.
- Affects: Doc comments in decrypt/drop.ts and @cipherstash/migrate manifest.ts (removeManifestColumn), skills/stash-cli/SKILL.md (ships in the stash tarball and is copied into customer repos)
- Evidence: [`languages/typescript/packages/cli/src/commands/decrypt/drop.ts:75-79`](https://github.com/cipherstash/stack/blob/eb8194bf37e0b6f9b50d99e7ae2941930ec684d0/languages/typescript/packages/cli/src/commands/decrypt/drop.ts#L75-L79); [`languages/typescript/packages/migrate/src/manifest.ts:194-197`](https://github.com/cipherstash/stack/blob/eb8194bf37e0b6f9b50d99e7ae2941930ec684d0/languages/typescript/packages/migrate/src/manifest.ts#L194-L197); [`skills/stash-cli/SKILL.md:717`](https://github.com/cipherstash/stack/blob/eb8194bf37e0b6f9b50d99e7ae2941930ec684d0/skills/stash-cli/SKILL.md#L717)
- Missing verification: Nothing checks doc comments against the skill text.
- Mitigation: Update both doc comments to match the new rule: the entry stays, `reversed` is its final state, and the CLI owns `.cipherstash/`.

**FS-2 · A permanent manifest entry for a reversed column keeps showing as a completed encryption target** (low impact, plausible)

- Trigger: A user finishes a reverse migration (decrypt drop, then applies the migration) and follows the new guidance to leave migrations.json alone. They then run `stash encrypt plan`, `stash plan` or `stash status`.
- Mechanism: encrypt plan compares each manifest entry's targetPhase with the forward state keyed by the plaintext column. That state is still the forward 'dropped', so it prints '✓ <table>.<col>: already at dropped' for a column that is plaintext again. detectPlanStep counts the entry as tracked. Before, this state lasted only until the user removed the entry. Now it is permanent, and only `encrypt status` was taught to say `reversed`.
- Consequence: Plan and status views (and agents reading them) may claim a column is encrypted when it is now plaintext. This could hide that a once-encrypted column holds plaintext again. It is a reporting mismatch only; no data is changed.
- Affects: `stash encrypt plan` and `stash plan` manifest readers, skills/stash-cli/SKILL.md (ships in the stash tarball and is copied into customer repos)
- Evidence: [`languages/typescript/packages/cli/src/commands/encrypt/plan.ts:33-47`](https://github.com/cipherstash/stack/blob/eb8194bf37e0b6f9b50d99e7ae2941930ec684d0/languages/typescript/packages/cli/src/commands/encrypt/plan.ts#L33-L47); [`languages/typescript/packages/cli/src/commands/plan/index.ts:141-151`](https://github.com/cipherstash/stack/blob/eb8194bf37e0b6f9b50d99e7ae2941930ec684d0/languages/typescript/packages/cli/src/commands/plan/index.ts#L141-L151); [`skills/stash-cli/SKILL.md:717`](https://github.com/cipherstash/stack/blob/eb8194bf37e0b6f9b50d99e7ae2941930ec684d0/skills/stash-cli/SKILL.md#L717)
- Missing verification: No test was found that runs `encrypt plan` or `stash plan` against a manifest entry whose encrypted column has the phase `encrypted-dropped`.
- Mitigation: Either teach encrypt plan and stash plan to recognise the reverse lifecycle (as encrypt status does), or have the CLI remove the entry itself once the drop is observed as applied (removeManifestColumn exists for this). Without that, record the limitation in the skill.

### Coverage limitations and questions

- No tests, helper scripts or repository code were run. The skill's validator and renderer were also not run, as instructed. Verification confidence cannot exceed medium. Schema validity of this JSON was checked by hand only.
- Whether `stash decrypt drop` has already shipped was inferred from a pending changeset and a CHANGELOG grep, not from the npm registry. If it shipped, existing users may have followed the old advice and deleted the entry. Both outcomes (entry present or absent) look like they would be handled, but this was not verified.
- The stash status/quest renderer and status/index.ts were only skimmed for reverse-phase handling. Other places that may show a reversed column as encrypted could exist beyond those named in FS-2.

### Review checklist

- [ ] Update the doc comments at drop.ts:75-79 and manifest.ts:194-197 to match the new guidance. (FS-1)
- [ ] Decide whether a permanent reversed entry is acceptable in `encrypt plan` and `stash plan`. If not, make them report it as reversed, or make the CLI remove the entry, and add a test. (FS-2, VG-2)
- [ ] Run `pnpm --filter stash test`, which covers the two updated unit tests, and confirm it passes before merge. (VG-1)

_Inputs unavailable: pr_description, ci_results, codeowners, history_signals._

_Advisory only. Claude Code (change-risk skill) · claude-opus-5-5 · change-risk 1._

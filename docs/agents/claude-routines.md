# Claude routines

Three Claude Code routines work on this repository. Two run on a schedule each
morning and handle dependency vulnerabilities reported by Vanta; the third
reviews pull requests. They run as Claude Code cloud sessions in auto
permission mode, and each loads its skills from
[`cipherstash/skills`](https://github.com/cipherstash/skills).

1. **vanta-triage** (4:44am Sydney) pulls vulnerabilities from Vanta and files
   Linear issues.
2. **vanta-remediate** (5:55am Sydney) picks up those Linear issues, patches
   dependencies and opens pull requests.
3. **Code review** runs when a pull request is ready for review and posts a
   review.

## At a glance

| | vanta-triage | vanta-remediate | Code review |
| --- | --- | --- | --- |
| Trigger | Daily, 4:44am Sydney | Daily, 5:55am Sydney | `.github/workflows/code-review.yml` |
| Skills | `company-skills:vanta-triage` | `company-skills:vanta-remediate` | `/code-review medium`, `company-skills:cross-check-review-findings` |
| Reads | Vanta, Linear | Linear, repositories | The pull request diff and its existing review comments |
| Writes | Linear issues (AppSec project) | Branches, pull requests, Linear status | Inline and summary pull request comments |
| Connectors | Linear, Claude Docs, visualize | Linear, Claude Docs, visualize | Claude Docs, visualize |
| Notifications | Push | Push | Push, email, Slack |
| Repositories | stack, proxy, cipherstash-suite, cipherstash-dynamodb, ore.rs, vitaminc, sqltk, envelopers (8) | Triage's 8, plus skills, docs, cipherstash-js-suite (11) | stack, proxy, cipherstash-suite, cipherstash-dynamodb, ore.rs, vitaminc, skills (7) |

All repositories are in the `cipherstash` GitHub organization. The lists are
taken from each routine's most recent run.

## vanta-triage

Keeps Linear in step with Vanta. It runs `/company-skills:vanta-triage` and
stops with `FAILED` if the skill cannot be loaded from `cipherstash/skills`.

1. **Connect to Vanta** through the Vanta API credential set on the cloud
   environment, not through a routine connector.
2. **Pull vulnerabilities**: Dependabot package alerts and AWS Inspector
   container findings, grouped by repository and package.
3. **Cross-check** them against the existing Linear AppSec issues.
4. **Update Linear**: file issues for new findings, retarget issues when Vanta
   raises the fix version, and close issues Vanta no longer reports.

It does not patch code or open pull requests.

Open question: `cipherstash/skills` is not in triage's repository list, yet its
last run succeeded. Add the repository so skill loading does not depend on a
fallback.

## vanta-remediate

Turns triage's Linear issues into pull requests, about an hour after triage. It
runs `/company-skills:vanta-remediate` and stops with `FAILED` if a skill cannot
be loaded.

1. **Check Linear** for open `[Vanta] Remediate {package} to {version} ({repo})`
   issues.
2. **Patch**: find every lockfile that resolves a vulnerable version, bump it
   with the repository's package manager, and verify the fix landed.
3. **Open a pull request** on the affected repository and move the Linear issue
   to In Review.

Container OS-package (`[Vanta] Assess`) issues are only assessed on request. It
does not query Vanta or file issues.

## Code review

A separate routine with no schedule. `.github/workflows/code-review.yml` fires
it through the routines API when a pull request is opened, reopened or marked
ready for review. Drafts, bot pull requests (Dependabot, release-plz) and forks
are skipped. It reviews once per event, not on every push: mark a pull request
draft and then ready again for a fresh review.

1. **Review** the pull request with `/code-review medium`.
2. **Cross-check** the findings against existing review feedback with
   `company-skills:cross-check-review-findings`, keeping only new ones.
3. **Post** inline comments and a summary comment. The summary names the review
   source as an attestation, even when there are no findings, and flags any
   blocking issues.

The workflow needs the `CLAUDE_ROUTINE_TOKEN` secret and the
`CLAUDE_ROUTINE_TRIGGER_ID` variable. The review is advisory: a failed request
shows as a failed step, not a red check. The routine runs in its own cloud
environment, separate from the Vanta routines, and has no Linear access.

`.github/workflows/claude-review.yml` is a second, CI-based review through
`claude-code-action`. It is off unless the `CLAUDE_REVIEW_ENABLED` variable is
`true`; with both on, a pull request is reviewed twice.

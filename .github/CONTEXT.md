# CI

This context covers the checks that verify a change, and the machines that run those checks.
The context covers the GitHub Actions workflows of `cipherstash/stack`.
The context also covers the CI spending of the other repositories that share the CI budget with `cipherstash/stack`.

The entries below name two services that run CI jobs.
Blacksmith provides hosted machines that GitHub Actions jobs run on.
RunsOn starts a new machine in our AWS account for each job.

## Language

**CI budget**:
The most money that the repositories sharing the budget may spend on CI in one calendar month.
Vendor invoices are the measure of spending against the budget, including fixed costs such as licences and cloud infrastructure.
When an invoice also covers repositories that do not share the budget, only the part for the repositories that share it counts.
Estimates at list price track the spending between invoices, but do not replace the invoices.
_Avoid_: build minutes, runner minutes

**PR push**:
A new head commit on the branch of a pull request.
Each PR push starts the push checks again.
_Avoid_: PR run, CI run

**Push check**:
A check that runs on each PR push, if the change includes a file in the check's trigger paths.
The author of the pull request then learns of a failure while still working on the change.
_Avoid_: fast check, PR check

**Gate check**:
A check that runs when a pull request is in a merge queue, instead of on every PR push.
A failed gate check blocks the merge.
Architecture decision record (ADR) 0003 plans a merge queue for `main` and one for `next`, but neither exists yet.
Under ADR 0003, an author can ask for a gate check to run earlier, on the pull request.
_Avoid_: heavy check, full CI, merge check

**Early run**:
A run of the gate checks on a pull request before the pull request joins a merge queue.
An author asks for an early run by adding the `ci:full` label.
Each time someone adds the label, the pull request gets one early run.
No workflow reads the label yet, because work on ADR 0003 is paused.
_Avoid_: full run, ci:full run

**Queue commit**:
The commit that GitHub builds for a pull request in a merge queue.
A queue commit contains the queue entry ahead of the pull request, plus the pull request.
Checks in the merge queue test the queue commit.
_Avoid_: merge group commit, temporary branch

**Trigger paths**:
The paths that make a check run when a change includes a file in one of them.
Trigger paths apply on PR pushes and in the merge queue.
Every check has trigger paths, or a written reason for running on every change.
_Avoid_: path filter, relevance filter, affected checks

**Selector job**:
The first job of a workflow.
The selector job selects the checks that run, by comparing the files in a change with the trigger paths of each check.
When the selector job cannot decide, it fails.
The change then cannot merge until someone runs the selector job again.
_Avoid_: path-filter job, decider, router

**Summary job**:
The last job of a workflow.
The summary job passes when every check that the selector job selected has passed.
The summary job is the only job in the workflow that branch rules require.
_Avoid_: required job, status job

**Failsafe**:
The test that fails when the selector job does not decide whether a job runs.
The failsafe passes a job that has a written exemption.
The failsafe reads workflow files, rather than acting while a workflow runs.
_Avoid_: lint, selector guard, path-filter lint

**Light job**:
A job that runs acceptably on a GitHub-hosted standard runner.
ADR 0002 planned to run light jobs on GitHub-hosted standard runners.
Because ADR 0004 superseded that plan, being light no longer decides where a job runs.
Being light does not decide when a job runs: a light job can be a gate check.
_Avoid_: small job, cheap job

**Heavy job**:
A job that needs a larger machine than a GitHub-hosted standard runner.
ADR 0002 planned to run heavy jobs on a self-provisioned cloud runner instead.
Because ADR 0004 superseded that plan, being heavy no longer decides where a job runs.
Being heavy does not decide when a job runs: a heavy job can be a push check.
_Avoid_: big job, 16-core job

**Same-size swap**:
The change that moves each Blacksmith job to a RunsOn machine with the same vCPU count, architecture, and Ubuntu version.
Memory and disk may be smaller than on Blacksmith.
The triggers of each job stay the same.
The swap can add steps, such as a Docker Hub login before an image pull.
_Avoid_: like-for-like replacement, migration

## Relationships

- Two separate choices apply to each check.
  The trigger paths of a check decide whether the check runs at all.
  Being a push check or a gate check decides when the check runs.
- Being a light job or a heavy job is a third, separate property.
  Under ADR 0002, that property decided where a check runs.
  ADR 0004 superseded the plan in ADR 0002.
- For example, the fuzz regression replay is a light job and a gate check.
- Mutation testing is expensive but important.
  So mutation testing only runs after the design and implementation of a change are settled.
  Failures in mutation testing must be fixed before the change merges.
  Those facts make mutation testing a heavy job and a gate check.
- A same-size swap does not use the distinction between light and heavy jobs.
  A Blacksmith job moves to RunsOn even if a GitHub-hosted standard runner could run it.

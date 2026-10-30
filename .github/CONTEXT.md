# CI

This context covers the checks that verify a change, and the machines that run
them. It covers the GitHub Actions workflows of `cipherstash/stack`. It also
covers the CI spend of the other repositories that share its budget.

## Language

**CI budget**:
The most that the repositories sharing it may spend on CI in one calendar
month. Vendor invoices measure it, including fixed costs such as licences and
cloud infrastructure. When an invoice also covers other repositories, only the
part for these repositories counts. List-price estimates track it between
invoices, but do not replace it.
_Avoid_: build minutes, runner minutes

**PR push**:
A new head commit on a pull request's branch. Each one starts the push checks
again.
_Avoid_: PR run, CI run

**Push check**:
A check that runs on every PR push, so the author learns of a failure while
still working on the change.
_Avoid_: fast check, PR check

**Gate check**:
A check that runs when a pull request is in a merge queue, instead of on every
PR push. `main` and `next` each have a merge queue. An author can ask for a
gate check to run earlier on the pull request. A failed gate check blocks the
merge.
_Avoid_: heavy check, full CI, merge check

**Early run**:
A run of the gate checks on a pull request before it joins a merge queue. An
author asks for one by adding the `ci:full` label. Each time the label is
added gives one early run.
_Avoid_: full run, ci:full run

**Queue commit**:
The commit GitHub builds for a pull request in a merge queue. It contains
the entry ahead of it, plus the pull request. Checks in the queue test this commit.
_Avoid_: merge group commit, temporary branch

**Trigger paths**:
The paths whose change makes a check run, on PR pushes and in the merge queue.
Every check has them, or a written reason for running on every change.
_Avoid_: path filter, relevance filter, affected checks

**Selector job**:
The first job of a workflow. It selects the checks that run, by comparing the
files a change touches with each check's trigger paths. When it cannot decide,
it fails. The change then cannot merge until someone runs it again.
_Avoid_: path-filter job, decider, router

**Summary job**:
The last job of a workflow. It passes when every check that the selector job
selected has passed. It is the only job of the workflow that branch rules
require.
_Avoid_: required job, status job

**Failsafe**:
The test that fails when the selector job does not decide whether a job runs.
A job with a written exemption passes. The failsafe reads workflow files. It
does not act while a workflow runs.
_Avoid_: lint, selector guard, path-filter lint

**Light job**:
A job that runs acceptably on a GitHub-hosted standard runner. Whether a job is
light says where it runs, not when: a light job can be a gate check.
_Avoid_: small job, cheap job

**Heavy job**:
A job that needs more machine than a GitHub-hosted standard runner gives it,
and runs on a self-provisioned cloud runner instead. Whether a job is heavy
says where it runs, not when: a heavy job can be a push check.
_Avoid_: big job, 16-core job

## Relationships

- Three separate choices apply to each check. Its trigger paths decide whether
  it runs at all. Being a push check or a gate check decides when it runs.
  Being a light job or a heavy job decides where it runs.
- The fuzz regression replay, for example, is a light job and a gate check.
- Mutation testing is expensive but important. So it runs only once the
  design and implementation of a change are settled. Its failures must be
  fixed before the change merges. That makes it a heavy job and a gate check.

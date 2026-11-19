---
status: accepted
---

# Swap Blacksmith for RunsOn machines of the same size

In November 2026 we decided to move every Blacksmith job in this repository to
RunsOn. Each job gets the same vCPU count, architecture, and Ubuntu version.
`.github/CONTEXT.md` calls this a same-size swap. Nothing else about the jobs
changes: their triggers, steps, and trigger paths stay as they are.

We made the change to cut cost at once. At November 2026's pace, CI for this
repository costs about $3,470 a month on Blacksmith. On RunsOn machines of the
same size, we estimate $1,140 to $1,350 a month for the machines. RunsOn's own
AWS resources add $40 to $60 a month. The estimate applies the cost ratios from
the runner trial in pull request #1297 to Blacksmith's November bill.

This decision supersedes ADR 0002. It sets aside the $1,000 monthly budget in
the CI budget entry of `.github/CONTEXT.md` as the measure of success. Work on
ADR 0003 is paused until the swap is in place.

## What changes

Each Blacksmith label becomes a RunsOn label with the same vCPU count and
Ubuntu version:

| Blacksmith label | RunsOn label |
|---|---|
| `blacksmith-16vcpu-ubuntu-2204` | `runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=16/image=ubuntu22-full-x64/volume=80gb/extras=s3-cache` |
| `blacksmith-4vcpu-ubuntu-2404` | `runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache` |

- **Which jobs:** every job that names a Blacksmith label, in every workflow
  of this repository. That includes the Linux targets of the FFI release
  matrix. `scripts/ffi-release-matrix.mjs` assigns their labels. On 19 November 2026,
  `main` had 55 such job definitions in 27 workflows.
- **Which jobs stay:** jobs on GitHub-hosted runners stay there. Examples are
  `ubuntu-latest`, macOS, and Windows jobs.
- **Other repositories:** `proxy` and the other repositories that use
  Blacksmith keep it for now.
- **Memory:** c8a machines have 2 GB per vCPU. Blacksmith's x64 machines have
  4 GB per vCPU. A job that fails for lack of memory moves to `family=m8a`.
  The m8a machines have 4 GB per vCPU.
- **Disk:** every job gets 80 GB. Blacksmith gives 80 GB at 4 vCPU and 750 GB
  at 16 vCPU.
- **Cache:** `extras=s3-cache` sends `actions/cache` to an S3 bucket in our AWS
  account. The jobs need no extra step for this. RunsOn job logs from
  October 2026 show cache restores working with the label alone.
- **Machine family:** RunsOn uses spot c8a machines first. The `m8a` family
  gives it a second choice when AWS has no spare c8a spot machines.

Two changes go in with the swap, because RunsOn needs them:

- **Docker Hub logins.** A job logs in to Docker Hub before it pulls an image.
  It uses a free Docker Hub account. The login needs the `DOCKER_HUB_USERNAME`
  and `DOCKER_HUB_PASSWORD` secrets. Dependabot runs read Dependabot secrets,
  so both secrets need a Dependabot copy too. Runs for pull requests from forks
  get no secrets, so they pull without a login.
- **Time limits.** Every job sets `timeout-minutes`. On RunsOn, a stuck job
  costs money until its limit ends it. In the trial, one job without a limit
  ran for over 2 hours.

## The RunsOn setup

These settings are in place, or requested, in the AWS account:

- RunsOn v3.6.2, upgraded on 19 November 2026. Older versions failed jobs when
  the on-demand vCPU quota was full. From v3.6.0, those jobs wait.
- Spot machines first, with on-demand machines when spot capacity runs out.
  RunsOn reruns a job that AWS interrupts.
- No warm machines. They cost money while idle.
- One RunsOn installation, in `us-west-2`.
- vCPU quotas of 5,000 for spot and for on-demand standard instances. AWS had
  not yet approved the requests on 19 November 2026. Until it does, the
  quotas are 512 vCPUs each, and jobs above them wait. The swap does not
  wait for the approval.
- `AppSize` moves from `small` to `medium` once AWS raises the
  `RunInstances` request rate from 2 to 4 a second. We asked AWS for that on
  19 November 2026. Both sizes cost the same.

## How we judge the swap

We judge the swap on cost alone. The AWS account holds only RunsOn. So while
only this repository uses RunsOn, the account's bill is the cost of its CI. We
revert the swap only if CI stops working.

## Considered options

- **Match Blacksmith's memory with m8a machines.** We estimate 10 to 20% more
  per hour than c8a. The trial found no memory failures on c8a in 44 jobs.
- **Match Blacksmith's disk sizes.** A 750 GB disk adds about a fifth to the
  spot price of a 16 vCPU machine. The open pull requests ran 16 vCPU jobs on
  80 GB disks with every check passing.
- **Keep ADR 0002's plan.** Light jobs on GitHub-hosted runners and heavy jobs
  on 8 vCPU machines cost less. That plan needs more changes, and ADR 0003's
  merge queues, before it brings its full saving.
- **Switch in stages, Test EQL first.** Test EQL is 53% of November's spend.
  Two stages would need two reviews and two switches. Most of the risk is in
  Test EQL anyway.
- **Use on-demand machines only.** Jobs would never be interrupted. The cost
  would be about 2.3 times the spot price.
- **Keep warm machines ready.** Jobs would start faster. Warm machines cost
  money while idle.
- **Pay for a Docker Team or Pro plan.** Either plan removes the pull limit.
  Billed yearly, Team costs $15 a user a month and Pro costs $9. A Team plan
  also gives a token that belongs to the organisation, not to one person.

## Consequences

- A RunsOn job started 40 to 50 seconds later than a Blacksmith job in the
  trial.
- Blacksmith ran any number of jobs at once. RunsOn runs as many as the AWS
  vCPU quotas allow. In October 2026, the peak need was between 2,700 and
  4,700 vCPUs.
- AWS can interrupt a spot machine. RunsOn then reruns the job, so it takes
  longer.
- A 16 vCPU job has 32 GB of memory, not 64 GB.
- Each RunsOn machine has its own public address. Docker Hub still refused
  anonymous pulls in the October 2026 trial, so jobs log in.
- The free Docker Hub account allows 200 pulls in 6 hours, for all jobs
  together. In busy hours, jobs can reach that limit, and their pulls fail.
- A pull request from a fork runs its code on a machine in our AWS account. So
  this repository requires approval before any outside contributor's
  workflows run.
- Blacksmith's GitHub App stays installed for the other repositories. A revert
  of the swap returns these jobs to Blacksmith.
- The light and heavy job entries in `.github/CONTEXT.md` no longer decide
  where a job runs. A Blacksmith job moves to RunsOn even if a GitHub-hosted
  runner could run it.

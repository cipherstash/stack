---
status: accepted
supersedes: ADR-0002
---

# Swap Blacksmith for RunsOn machines of the same size

In November 2026, we decided to move every Blacksmith job in this repository to RunsOn.
RunsOn runs each job on a machine in our AWS account.
Each job gets the same vCPU count, architecture, and Ubuntu version as on Blacksmith.
`.github/CONTEXT.md` calls this a same-size swap.
The jobs' triggers and trigger paths stay as they are.

We made the change to cut cost at once.
At November 2026's pace, CI for this repository costs about $3,470 a month on Blacksmith.
On RunsOn machines of the same size, we estimate $1,140 to $1,350 a month for the machines.
RunsOn's own AWS resources add $40 to $60 a month.
The estimate applies the cost ratios from the runner trial in pull request #1297 to Blacksmith's November bill.

This architecture decision record (ADR) supersedes [ADR 0002](0002-light-ci-jobs-on-github-hosted-runners-heavy-jobs-on-runs-on.md).
The $1,000 monthly budget in the CI budget entry of `.github/CONTEXT.md` is not this decision's measure of success.
Work on ADR 0003 is paused until the swap is in place.

## What changes

Each Blacksmith label becomes a RunsOn label with the same vCPU count and Ubuntu version:

| Blacksmith label | RunsOn label |
|---|---|
| `blacksmith-16vcpu-ubuntu-2204` | `runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=16/image=ubuntu22-full-x64/volume=80gb/extras=s3-cache` |
| `blacksmith-4vcpu-ubuntu-2404` | `runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache` |

- **Jobs that move.**
  Every job that names a Blacksmith label moves, in every workflow of this repository.
  That includes the Linux targets of the foreign function interface (FFI) release matrix.
  `scripts/ffi-release-matrix.mjs` assigns their labels.
  On 19 November 2026, `main` had 55 such job definitions in 27 workflows.
- **Jobs that stay.**
  Jobs on GitHub-hosted runners stay there, such as `ubuntu-latest`, macOS, and Windows jobs.
- **Other repositories.**
  `proxy` and the other repositories that use Blacksmith keep it for now.
- **Memory.**
  The c8a machines have 2 GB per vCPU.
  Blacksmith's x64 machines have 4 GB per vCPU.
  A job that fails for lack of memory moves to `family=m8a`.
  The m8a machines have 4 GB per vCPU.
- **Disk.**
  Every job gets an 80 GB disk.
  Blacksmith gives a 4 vCPU machine 80 GB.
  Blacksmith gives a 16 vCPU machine 750 GB.
- **Cache.**
  `extras=s3-cache` makes `actions/cache` use an Amazon Simple Storage Service (S3) bucket in our AWS account.
  The jobs need no extra step for this.
  RunsOn job logs from October 2026 show cache restores working with the label alone.
- **Machine family.**
  RunsOn uses spot c8a machines first.
  Spot machines cost less than on-demand machines.
  AWS can interrupt a spot machine.
  When AWS has no spare c8a spot machines, the `m8a` family gives RunsOn a second choice.

Two changes go in with the swap, because RunsOn needs them:

- **Docker Hub logins.**
  A job logs in to Docker Hub before it pulls an image.
  The login uses a free Docker Hub account.
  The login needs the `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD` secrets.
  Dependabot runs read Dependabot secrets, so both secrets need a Dependabot copy too.
  Runs for pull requests from forks get no secrets, so they pull without a login.
- **Time limits.**
  Every job sets `timeout-minutes`.
  On RunsOn, a stuck job costs money until its time limit ends it.
  In the trial, one job without a limit ran for more than 2 hours.

## The RunsOn setup on 19 November 2026

This section records the RunsOn setup on 19 November 2026.
Two of these items were requests that AWS had not answered on that date.
The AWS Service Quotas console shows the current vCPU quotas.

These settings were in place in the AWS account, or had been requested:

- We upgraded RunsOn to v3.6.2 on 19 November 2026.
  Before v3.6.0, RunsOn failed a job when the on-demand vCPU quota was full.
  From v3.6.0, the job waits.
- RunsOn uses spot machines first, and on-demand machines when spot capacity runs out.
  RunsOn reruns a job that AWS interrupts.
- RunsOn keeps no warm machines ready.
  Warm machines cost money while idle.
- There is one RunsOn installation, in the `us-west-2` region.
- We asked for vCPU quotas of 5,000 for spot and for on-demand standard instances.
  AWS had not yet approved the requests on 19 November 2026.
  Until AWS approves them, each quota is 512 vCPUs.
  Jobs above the quotas wait.
  The swap does not wait for the approval.
- When AWS raises the `RunInstances` request rate from 2 to 4 a second, the RunsOn `AppSize` setting moves from `small` to `medium`.
  We asked AWS for the higher rate on 19 November 2026.
  Both sizes cost the same.

## How we judge the swap

We judge the swap on cost alone.
The AWS account contains only RunsOn.
So while only this repository uses RunsOn, the account's bill is the cost of this repository's CI.
We revert the swap only if CI stops working.

## Considered options

We rejected each of these options:

- **Match Blacksmith's memory with m8a machines.**
  We estimate that m8a machines cost 10 to 20% more per hour than c8a machines.
  In the trial, none of 44 jobs on c8a machines failed for lack of memory.
- **Match Blacksmith's disk sizes.**
  A 750 GB disk adds about a fifth to the spot price of a 16 vCPU machine.
  In the pull requests open at the time, 16 vCPU jobs ran on 80 GB disks, and every check passed.
- **Keep ADR 0002's plan.**
  Light jobs on GitHub-hosted runners and heavy jobs on 8 vCPU machines cost less than the same-size swap.
  That plan gives its full saving only after more changes and ADR 0003's merge queues.
- **Switch in stages, starting with Test EQL.**
  The Test EQL workflow is 53% of November's spend.
  Two stages would need two reviews and two switches.
  Most of the risk is in Test EQL anyway.
- **Use on-demand machines only.**
  AWS would never interrupt a job.
  The cost would be about 2.3 times the spot price.
- **Keep warm machines ready.**
  Jobs would start faster, because they would not wait for a new machine to boot.
  Warm machines cost money while idle.
- **Pay for a Docker Team or Pro plan.**
  Either plan removes the pull limit.
  Billed yearly, Team costs $15 a user a month, for at least 2 users.
  Pro costs $9 a month.
  A Team plan also gives a token that belongs to the organisation, not to one person.
  We keep the free account, for two reasons.
  The swap is meant to reduce costs.
  The swap is also an experiment to prove that RunsOn is viable for this repository.

## Consequences

- In the trial, a RunsOn job started 40 to 50 seconds later than a Blacksmith job.
- Blacksmith ran any number of jobs at once.
  RunsOn runs as many jobs as the AWS vCPU quotas allow.
  In October 2026, the peak need was between 2,700 and 4,700 vCPUs.
- AWS can interrupt a spot machine.
  RunsOn then reruns the job, so the job takes longer.
- A 16 vCPU job has 32 GB of memory, not 64 GB.
- Each RunsOn machine has its own public address.
  In the October 2026 trial, Docker Hub still refused anonymous pulls.
  So jobs log in.
- The free Docker Hub account allows 200 pulls in 6 hours, for all jobs together.
  That figure comes from Docker's documentation, at https://docs.docker.com/docker-hub/usage/pulls/.
  Docker's pricing page says 100 pulls an hour instead.
  In busy hours, jobs can reach the limit, and their pulls fail.
- A pull request from a fork runs its code on a machine in our AWS account.
  So this repository requires approval before any outside contributor's workflows run.
- Blacksmith's GitHub App stays installed for the other repositories.
  A revert of the swap returns these jobs to Blacksmith.
- Where a job runs no longer depends on the light job and heavy job entries in `.github/CONTEXT.md`.
  A Blacksmith job moves to RunsOn even if a GitHub-hosted runner could run it.

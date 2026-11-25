# Stacked pull requests with `gh stack`

When the user asks for a stack of pull requests, build a GitHub stack with the `gh stack` extension.
Do not build the chain by hand.
Setting each pull request's base branch to the branch below it does not make a stack.
GitHub treats each of those pull requests on its own.

This guide is for agents that work in `cipherstash/stack`.
The sections follow the order in which you need them.
Repository settings can change.
Where a step depends on a setting, this guide gives the command that checks it.
Dated examples describe what happened in past runs.

## A stack is a GitHub feature

A stack is an object that GitHub stores.
The stack links two or more pull requests in order.
The bottom pull request targets `main`.
Each pull request above it targets the branch of the pull request below it.

When pull requests are in a stack, GitHub:

- shows a stack map on each pull request
- applies the rules and checks for `main` to every pull request in the stack
- merges a pull request together with every unmerged pull request below it
- rebases the rest of the stack after a merge

`gh stack` is a GitHub CLI extension that GitHub publishes.
The extension creates the branches, keeps them rebased, pushes them, and creates the stack through GitHub's Stacks API.
The source code is at <https://github.com/github/gh-stack>.
GitHub's documentation starts at <https://docs.github.com/en/pull-requests/get-started/about-stacked-prs>.

## Stacks need no setup in this repository

GitHub's documentation says that stacked pull requests need no setup or enablement.
GitHub announced the public preview on 30 July 2026.
This repository already has stacks.
`gh api repos/cipherstash/stack/stacks` lists them.

If a `gh stack` command exits with code 9, GitHub refused the Stacks API for the repository.
Tell the user.
Do not build a chain by hand instead.

To check whether a pull request is in a stack, read its `stack` field:

```bash
gh api repos/cipherstash/stack/pulls/<number> --jq .stack
```

For a pull request in a stack, the command prints the stack's number and size, and the pull request's position.
For a pull request that is not in a stack, the response has no `stack` field.
The command then prints nothing.

## Use a stack when pull requests depend on each other

Build a stack in these cases:

- The user asks for a stack, a "PR stack", or stacked pull requests.
- You split one change into several pull requests that each need the code in the pull request below.

Open independent pull requests against `main` instead.
A stack is a single line: each branch has one branch below it and at most one above it.
Every branch must be in this repository, because GitHub does not support stacks across forks.

## Install the extension

```bash
gh extension install github/gh-stack
gh stack --version
```

This guide was checked against version 0.3.0.
If `gh stack --version` prints another version, check each command's flags before you use it.
Run `gh stack <command> --help` to list the flags of a command.
`gh stack help <command>` prints only the general help.

## Run `gh stack` without prompts

Some commands open a prompt or a full-screen view when they detect a terminal.
Give every command its arguments, so that it never waits for input.

| Run this | Not this |
|---|---|
| `gh stack init --base main <branch> ...` | `gh stack init` with no branch |
| `gh stack add <branch>` | `gh stack add` with no branch name |
| `gh stack submit --auto --remote origin` | `gh stack submit` |
| `gh stack view --json` | `gh stack view` |
| `gh stack checkout <stack, pull request or branch>` | `gh stack checkout` with no argument |
| `gh stack up`, `down`, `top`, or `bottom` | `gh stack switch` |
| `gh stack merge <pull request> --yes --merge` | `gh pr merge` on a pull request in a stack |

Never run `gh stack modify`, because it works only in a full-screen view.
If a command reports a paused `modify` session with exit code 10, run `gh stack modify --abort`.

Pass `--remote origin` to `push`, `submit`, `sync`, `rebase`, and `link`.
Without the flag, gh-stack stops when a clone has several remotes with no default.

Always name the branch.
With `-m` and no branch name, `gh stack add` generates a name from the date and the commit message.
That name does not follow the branch names that `meta-pr-creation` sets.

## Follow the commit and push rules

`meta-pr-creation` sets the rules for signed commits and force-pushes.
These points are specific to a stack:

- `gh stack rebase` and `gh stack sync` run `git rebase` on your machine. Git signs the new commits, because `commit.gpgsign` is on.
- `gh stack push`, `submit`, and `sync` push each branch with `--force-with-lease=refs/heads/<branch>:<sha>`.
- If you push one branch yourself, run `git push --force-with-lease origin <branch>`.
- Rebase with `gh stack` on your machine, not with the **Rebase stack** button on GitHub. GitHub's pages disagree about whether that button signs commits. The button's commits never have your SSH signature.

Before every push, check the signatures of the whole stack, not only the current branch:

```bash
git log --format='%h %G? %s' origin/main..<top branch>
```

Read the result as `meta-pr-creation` says.

### Re-sign a branch in a stack

Do not run `git rebase --force-rebase origin/main` on a branch above the bottom of a stack.
That command replays the commits of the branches below as well.
The branch then no longer builds on the branch below it.

Re-sign from the lowest branch that has an unsigned commit.
Record each branch's commit before you start, and compare again before the push.
"Check for commits that someone else pushed" gives the steps.

```bash
gh stack checkout <lowest branch with an unsigned commit>
git rebase --force-rebase <branch below it>   # use origin/main for the bottom branch
gh stack rebase --upstack --remote origin      # replays every branch above it
git log --format='%h %G? %s' origin/main..<top branch>
gh stack push --remote origin
```

This sequence follows gh-stack's documented behaviour.
Nobody ran it when this guide was written.

### Check for commits that someone else pushed

`gh stack push`, `submit`, and `sync` fetch each branch just before they push it.
The lease then checks the branch against the commit they fetched.
So the lease never stops these commands.
The push deletes any commit that someone else pushed to the branch.

Protect those commits before every `gh stack push`, `submit`, or `sync`:

1. Before you change any branch of the stack, run `git fetch origin`. Then record the commit that GitHub has for each branch:

   ```bash
   git rev-parse origin/<branch>
   ```

2. Before each push, run `git fetch origin` again. Compare each branch's `git rev-parse origin/<branch>` with the commit you recorded.
3. If a branch's commit has changed, someone else pushed to it. `git log --oneline <recorded commit>..origin/<branch>` lists their commits. Bring their work into your branch, or ask the user, before you push.
4. After each push, record the commits again.

This check compares commit IDs, not the changes inside the commits.
So your own amend, squash, or rebase does not trigger it.
It still finds a commit whose message someone else changed.

### Check other worktrees first

Agents in this repository work in separate git worktrees.
gh-stack stores one list of stacks for the whole clone, in the shared git directory.
Every worktree uses that list.
`gh stack rebase` and `gh stack sync` also rebase a stack branch that is checked out in another clean worktree.

Run `git worktree list` before you rebase or sync.
If another worktree has a branch of your stack checked out, ask the user before you continue.

Exit code 8 means that another `gh stack` command has taken the lock.
Wait, then try again.
Do not delete the lock file.

## Create a stack

Create the stack before you write the code.
Put the code that other code depends on in the lowest branch.

First, bring your local `main` up to date with `origin/main`.
`init` records your local `main` commit as the base of the bottom branch.
"An out-of-date local `main`" below explains why that matters.

```bash
git fetch origin main:main
```

Git refuses this command when `main` is checked out in a worktree.
In that case, run `git merge --ff-only origin/main` in that worktree.
If the worktree is not yours, ask the user first.

Then create the first branch and the stack:

```bash
git switch -c <first branch> origin/main
gh stack init --base main <first branch>
```

Create the first branch from `origin/main` yourself, so that it starts from GitHub's latest commit.
Write the first part of the change and commit it.

To turn branches that already exist into a stack, update your local `main` as above.
Then name the branches from the bottom up:

```bash
gh stack init --base main <bottom branch> <next branch> <top branch>
```

`init` adopts the branches that exist and creates the ones that do not.
`init` does not push anything.
`init` adopts a branch that is checked out in another worktree without checking it out here.

`init` checks out the top branch in the current worktree.
If you need the branch you were on, switch back to it after `init`.

On 20 November 2026, `init` adopted two branches that already existed.
Neither branch was checked out in another worktree.
The worktree was on the bottom branch before `init`, and on the top branch after it.
`init` printed `You're on <top branch> (top of stack).`

### An out-of-date local `main`

`init` records the commit of your local `main` as the base of the bottom branch.
It does this even when the bottom branch builds on a newer `origin/main`.

These things happened on 20 November 2026:

- Local `main` was five commits behind `origin/main`.
- The bottom branch had been rebased onto `origin/main` before `init`.
- After `init`, `gh stack view --json` showed the local `main` commit as the bottom branch's `base`, with `"needsRebase": false`.
- The stack on GitHub showed the `origin/main` commit as the base of the bottom pull request.

So the local record and GitHub named different base commits.

CodeRabbit reviewed the first version of this guide and read gh-stack's source.
It found a risk.
Sometimes gh-stack cannot find where a branch started.
gh-stack then uses the recorded base as the starting point of a rebase.

With an out-of-date base, a later `rebase` or `sync` replays commits that `origin/main` already has.
The replay can stop on conflicts, or repeat work.
Nobody has seen this happen in a run.
That is why you update your local `main` before `init`.

## Add a branch

Run `gh stack add` from the top branch of the stack.
`add` creates the new branch from the current commit and checks it out.

```bash
gh stack top
gh stack add <next branch>
```

Commit your changes first.
After `add`, any uncommitted changes are still in the working tree, on the new branch.

To change a lower branch, check it out first.
Never commit a lower branch's change on the top branch.

## Push the branches and open the pull requests

Open the pull requests with `gh pr create`, then link them with `gh stack submit`.
This order keeps the titles and descriptions that `meta-pr-creation` asks for.

1. Push every branch in the stack.

   ```bash
   gh stack push --remote origin
   ```

2. Open each pull request as a draft, from the bottom up. Set its base to the branch below it. Use `main` as the base of the bottom branch.

   ```bash
   gh pr create --draft --base main --head <bottom branch> --title '...' --body '...'
   gh pr create --draft --base <bottom branch> --head <next branch> --title '...' --body '...'
   ```

3. Link the pull requests into a stack.

   ```bash
   gh stack submit --auto --remote origin
   ```

   `submit` finds the existing pull requests and creates the stack on GitHub.
   `submit` does not change their titles or descriptions.

4. Check that every pull request is in the stack.

   ```bash
   gh stack view --json
   gh api repos/cipherstash/stack/pulls/<number> --jq .stack
   ```

   If `gh api` prints nothing for a pull request, that pull request is not in the stack.

Never pass `--open` to `submit` or `link`.
The flag marks every pull request in the stack ready for review, including drafts that already exist.
`meta-pr-creation` says when you may mark a pull request ready.

If you skip step 2, `submit --auto` opens draft pull requests itself.
`submit` takes each title from the branch's only commit, or from the branch name.
`submit` also adds a gh-stack footer to the description.
Edit each of those pull requests with `gh pr edit`.

## Update the stack after a change lower down

When you change a lower branch, rebase every branch above it.
Record each branch's commit before you start, and compare again before the push.
"Check for commits that someone else pushed" gives the steps.

```bash
gh stack checkout <branch to change>
# edit, then commit
gh stack rebase --upstack --remote origin
git log --format='%h %G? %s' origin/main..<top branch>
gh stack push --remote origin
gh stack top
```

If a rebase stops on a conflict, it exits with code 3.
The command lists the files that conflict.
Fix the files, run `git add`, then run `gh stack rebase --continue`.
To undo the whole rebase, run `gh stack rebase --abort`.

When `main` moves ahead, compare each branch's commit with the one you recorded, then run `gh stack sync --remote origin`.
`sync` fetches, rebases the whole stack onto `main`, and pushes.
If `sync` hits a conflict, it restores every branch.
`sync` then exits with code 3.
Run `gh stack rebase --remote origin` to repeat the rebase and resolve the conflict.

GitHub merges a stack only when the history between its branches is linear.
The rebase commands keep that history linear.

## Update your stack after the bottom pull request merges

GitHub rebases the rest of the stack onto `main` when the bottom pull request merges.
GitHub did these things on 7 October 2026, when #1094 merged:

1. GitHub changed the base of the next pull request, #1095, to `main`.
2. GitHub deleted the merged branch, because this repository deleted branches after a merge.
3. GitHub rebased the remaining branches and force-pushed them. GitHub was the committer. GitHub marked the commits as verified.

GitHub's rebased commits are verified.
They are not signed with your key.
Your local branches still hold the commits from before GitHub's rebase.

### `sync` pushes over GitHub's rebase

Do not run `gh stack sync` before you ask the user.
The gh-stack v0.3.0 source shows that `sync` replaces GitHub's rebased commits:

- In `cmd/sync.go`, `sync` force-pushes whenever it has rebased a branch.
- In `internal/git/gitops.go`, the lease for each branch is the commit that `sync` fetched immediately before the push.

So the lease always passes.
Every remaining pull request gets new commits.
CI runs again on each one.
That finding comes from reading the source, not from a run.

### Ask the user which commits to keep

There are two ways to update your local branches.
Ask the user which they want, unless they have already chosen.

**Keep GitHub's commits.**
This is the default.
Nothing is pushed.
CI does not run again.
Nobody has run these steps yet.

1. Run `git fetch origin`.
2. Run `git worktree list`, as "Check other worktrees first" says. Check that no branch of the stack has uncommitted changes.
3. For each remaining branch, run `git cherry -v origin/<branch> <branch>`. A line that starts with `+` is a local commit that GitHub does not have. If any branch has one, ask the user before you continue.
4. For each remaining branch, run `git switch <branch>`, then `git reset --keep origin/<branch>`. `--keep` refuses to discard uncommitted changes.
5. Run `gh stack view --json`, and report what it shows for each branch.

Leave the local branch of the merged pull request in place, and tell the user it is there.
Nobody has checked how gh-stack's local record handles these resets.
So read the output of `gh stack view --json` carefully.

**Sign the commits with your key.**
Run this only when the user chooses it:

```bash
gh stack sync --prune --remote origin
gh stack view --json
```

`sync` rebases your local branches onto the new `main`.
Git signs the new commits with your key.
`sync` then force-pushes every remaining branch, replacing GitHub's commits.
That push starts CI again on each remaining pull request.
`--prune` deletes the local branch of the merged pull request.

### After the last merge

After every pull request in a stack has merged, GitHub closes the stack.
`gh stack submit` then starts a new stack for any new branches.

## Merge only when the user asks

`meta-pr-creation` says not to merge unless the user asks.
When they ask, merge with `gh stack merge`, because `gh pr merge` cannot merge a pull request in a stack.

```bash
gh stack merge <pull request number> --yes --merge
```

- Merging a pull request also merges every unmerged pull request below it. Either all of them merge, or none do.
- Merge from the bottom up. You cannot merge a pull request and leave one below it unmerged.
- Always pass a method flag. Without one, gh-stack uses the method you used last.
- Use a method that both the repository and the rules for `main` allow. To list the repository's methods, run `gh api repos/cipherstash/stack --jq '{merge: .allow_merge_commit, squash: .allow_squash_merge, rebase: .allow_rebase_merge}'`. The rules command in the next items lists `allowed_merge_methods`.
- Each pull request in the group needs the approvals that the rules for `main` require. Run `gh api repos/cipherstash/stack/rules/branches/main`. The `pull_request` rule gives `required_approving_review_count`.
- The same output shows a rule of type `merge_queue` if `main` has a merge queue. If it does, ask the user before you merge.
- `gh stack merge` refuses a draft and exits with code 5. Do not mark pull requests ready to make the merge work. Ask the user.
- Do not bypass the rules. `gh stack merge --help` says that bypassing merge requirements is not supported for stacks.
- Stacks do not support auto-merge. Do not turn it on for a pull request in a stack.

A group merge on 8 October 2026 made one merge commit for four pull requests.
That commit is `6f388478c`.
Its title names only the top pull request, #1110.
GitHub's reference page says that a group merge makes one merge commit for each pull request.
To get one merge commit for each pull request, merge them one at a time from the bottom.

## CI runs on every pull request in a stack

GitHub runs workflows for every pull request in a stack as if it targeted `main`.
`codeql.yml` and `osv-scanner.yml` start only for pull requests into `main`.
Pull request #1580 is in the middle of a stack.
Both workflows still ran for it on 17 November 2026.

In a hand-built chain, GitHub matches the workflow filter against each pull request's own base branch.
Those two workflows then do not start for the upper pull requests.

## Restructure a stack

`gh stack` has no command that reorders a stack without a full-screen view.
To reorder, rename, or remove a branch, follow these steps:

1. Run `gh stack unstack`. This command removes the stack on GitHub and the local record. The branches and pull requests stay.
2. Change the branches with git. Put the commits in the new order first.
3. Run `gh stack init --base main <branches from the bottom up>`.
4. Run `gh stack submit --auto --remote origin` to link the pull requests again.

GitHub keeps merged and queued pull requests in their stack.
`unstack` cannot remove them.

`gh stack link <pull request> <pull request> ...` creates a stack on GitHub without a local record.
Use it when another tool manages the branches.
Navigation commands such as `gh stack up` do not work on a stack that `link` made.

## `gh stack` exit codes

| Code | Meaning | What to do |
|---|---|---|
| 1 | The command failed, and has already printed the error. | Read the error, then stop and tell the user. |
| 2 | The branch is not in a stack. | Run `gh stack init` or `gh stack checkout <target>`. |
| 3 | A rebase hit a conflict. | Fix the files, run `git add`, then run `gh stack rebase --continue`. |
| 4 | A GitHub API call failed. | Run `gh auth status`, then try again. |
| 5 | The arguments are not valid. `gh stack merge` also returns 5 for a draft, a closed pull request, or one outside the stack. | Read the error. For a draft, ask the user. Do not mark it ready yourself. |
| 6 | gh-stack cannot choose between several stacks or remotes. | Check out a branch that only one stack contains, and pass `--remote origin`. |
| 7 | A rebase is already in progress. | Run `gh stack rebase --continue` or `gh stack rebase --abort`. |
| 8 | Another `gh stack` command has taken the lock. | Wait, then try again. |
| 9 | GitHub refused the Stacks API. | Tell the user. |
| 10 | A `modify` session is paused. | Run `gh stack modify --abort`. |

gh-stack defines these codes in `cmd/utils.go`, checked at v0.3.0.
For any code that this table does not list, stop and tell the user.

`sync` exits with code 0 when the local stack and the stack on GitHub have diverged.
In that case `sync` prints `Sync aborted` and changes nothing.
Check for that message.

## Open questions about stacks in this repository

Nobody has checked the answers to these questions in a run:

- After the resets in "Keep GitHub's commits", does `gh stack view --json` show the stack correctly? Does gh-stack still list the merged branch?
- Does the re-sign sequence in this guide work? It follows gh-stack's documentation.
- Does the **Rebase stack** button sign commits? GitHub's reference page on stacks says yes. GitHub's page on managing stacks says no.
- Which branch does `github.base_ref` name for a pull request in the middle of a stack? `impact.yml` and `mutants.yml` read that value.
- How does the `main` ruleset setting `require_extra_approval_for_unattributed_changes` treat the rebase that GitHub runs after a merge? No public documentation for that setting was found.
- When `init` records an out-of-date local `main` commit as the base, does a later `gh stack rebase` or `sync` replay commits from `main`?

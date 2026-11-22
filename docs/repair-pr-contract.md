# Publish an approved repair

Publish an approved repair explicitly from the CLI:

```sh
vorda --state STATE repair --config CONFIG publish --item KEY --digest SHA256 \
  --repository OWNER/REPO --base BASE --branch NEW_BRANCH
```

You can also publish from the dashboard with the host repair config and an
explicit destination; its write session must pass auth, CSRF and reviewer checks.
Repair MCP never exposes publish, and publishing is never automatic.

Only active, tested, unlocked npm manifest drafts are supported, and the current
plan and draft must match the reviewed digest. Publishing requires current
approval quorum (including an eligible human), fleet permission and repair
policy. It verifies the active finding, unchanged draft, committed manifest diff
and tested commit without rerunning tests. See the [repair contract](repair-contract.md)
for reviewer identity, mode and approval rules.

You supply the GitHub owner/repository, base and new branch. Vorda checks the
remote branch does not exist, pushes the exact tested commit over HTTPS via
`gh auth git-credential`, and runs `gh pr create --draft`. Auth uses your
existing `gh` login; Vorda stores no GitHub token. The base comes from you and
is not inferred or merge-tested.

Success returns `url`, `commit` and `branch`, and marks the claim `published`;
a second publish refuses. Refusals and errors are audited locally. Failed PR
creation can leave a pushed branch and a `pr-pushed` claim: inspect it, delete
the remote branch, and run `repair recover` (moving the claim to `failed`, then
releasable) before retrying. Publishing does not apply the repair locally or
verify a fix. Close unmerged PRs or delete branches on GitHub yourself; Vorda
never merges PRs or deletes branches.

Locked npm drafts, OS plans, GitLab and Gitea are unsupported.
[Locked repairs](locked-repair-contract.md) stay a local reviewed apply workflow.
The remaining Python publisher and tests are historical only, not native API or
operational instructions.

Source: [native publisher](../rust/src/repair/publish.rs),
[CLI dispatch](../rust/src/surfaces/mod.rs), and
[dashboard handler](../rust/src/surfaces/dashboard/control.rs).

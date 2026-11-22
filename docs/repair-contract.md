# Verified vulnerability repairs

Run `vorda --state STATE repair --config CONFIG ACTION --item KEY --agent NAME`.
Actions: claim, plan, apply, verify, release, approve, deny, draft, drafts,
dismiss, publish and recover. Apply defaults to dry-run; `--apply` mutates
source after the checks below. Approval is local, and publishing is a separate
owner action.

`vorda --state STATE repair-mcp --config CONFIG --agent NAME` serves nine stdio
tools: claim, plan, apply, verify, release, draft, dismiss, can and drafts. The
host fixes the agent identity; input cannot switch agents. MCP has no approve,
deny, publish or mode setter. The CLI is a trusted local owner surface, not an
identity boundary against other processes on the same OS account.

The host config is JSON:

```json
{"policy":"/absolute/vorda-policy.yaml","fleet":"/absolute/vorda.yaml","machine":"build-box","repositories":{"/absolute/repo":["/usr/bin/npm","test"]}}
```

Policy files use JSON or a strict YAML subset: top-level string lists and an
integer max_changes_per_run. Unknown fields and unsupported YAML syntax refuse
to load. Windows are daily UTC HH:MM-HH:MM (overnight allowed).

```yaml
allow:
  - patch
approve:
  - os-upgrade
deny:
  - sensitive-package
windows:
  - 23:00-04:00
max_changes_per_run: 1
```

Protected kernel, SSH, bootloader and package-manager names are always denied,
even with human approval. Each apply changes one named package;
max_changes_per_run caps mutation attempts per Repairs instance (one CLI call or
MCP session), and failed attempts count. Policy reloads on every apply. Claims
live in repairs.db with a transaction audit trail; inspect and recover any
interrupted applying claim by hand. CLI `repair recover --item ID` (not in MCP)
moves an `applying`, `rollback-failed` or `pr-pushed` claim to `failed`, logs
the prior status, and makes it releasable. Recovery needs an allowed human
reviewer, just like approval, and a late apply cannot overwrite a recovered
claim. State and config are trusted local files; use separate OS accounts to
protect them from an untrusted agent with shell access.

Repo plan flags: `--repo ROOT --package NAME --old 1.2.3 --new 1.2.4`.
The host must preconfigure the repo and exact test argv. Only exact npm patch
bumps in clean package.json repos are supported, plus reviewed npm lockfile
v2/v3 candidates in the [native locked workflow](locked-repair-contract.md).
Unsupported lockfiles, version ranges, other ecosystems and major/minor bumps
refuse instead of leaving a bad lockfile. Tests run bounded with no shell, but
they are trusted host commands that can run repo code, write files or reach the
network; this is not a sandbox. Drafting builds a branch and tested commit in a
state-dir clone. Applying creates a branch and commit in the source repo.
Neither opens a PR automatically.

OS plan flags: `--manager apt --package NAME --old VERSION --new VERSION`.
Only apt is supported; dnf/pacman/apk/brew/winget/choco refuse changes. Vorda
checks the installed version first and keeps it as a rollback pin. The exact old
version must still be available in configured repos. Vorda tries automatic
rollback if apply or rescan fails, and records any rollback failure explicitly.
There is no btrfs/ZFS/LVM snapshot coverage.

The host rescans the real manifest or installed version against vulnerability
feeds. Missing coverage or feed errors fail verification. Only a covered rescan
showing the finding gone closes the mailbox item. Failed repo verification
switches back to your original branch and leaves the repair branch to inspect.

## Modes and review

`vorda mode --fleet FILE` shows the active mode and why.
`mode fix --machine build-box` edits your local fleet file; `can AGENT lockfiles
--machine build-box` answers yes/ask/no. The dashboard also has an owner mode
control. Dashboard writes need `--allow-writes`, a configured token, an
authenticated session and CSRF checks; repair writes also need the host repair
config. A dashboard session does not create a separate reviewer identity.

The default mode is advise. Lower scopes tighten fleet → group → machine →
wildcard agent → named agent; the fleet file can set `delegate: true` globally
or in one scope rule. An inherited `never` stays final even with delegation.
Action classes are browsers, lockfiles, os-packages, containers, agent-tools and
config. Fleet files accept JSON or YAML via the native parser, with no Python or
PyYAML needed. Unknown fields refuse to load.

The fleet-level `review` object takes `humans` (names, default local-owner),
`agents` (`{"name":{"approve":true}}`), `where` (cli/dashboard/pr), and `approvals`
(positive integer, default one). They set eligible identities, channels and
quorum; they do not add MCP approval tools or PR review ingestion. CLI and
dashboard approval paths record human votes only. Votes are distinct by identity
and kind, and rechecked against current review config on apply and publish.
Nonzero `auto_apply_after_hours` is rejected.

With explicit `review.humans`, CLI and dashboard use the current OS username as
reviewer; otherwise they use `local-owner`. CLI `--reviewer`, if given, must
match your OS username and cannot pick someone else. Named-human quorum needs
distinct OS accounts; shared dashboard sessions cannot cast distinct human votes.
Approval and denial require the reviewed plan digest (`--digest SHA256` in the
CLI), and dashboard actions also need a matching active draft. Release clears
approvals, so a new plan needs fresh review even with the same digest. Denial
clears votes and marks the claim denied. Repo roots must be standalone top-level
checkouts; monorepo subdirs, linked worktrees and submodule/gitlink repos refuse
repair. Git status ignores submodules, and executable Git filters or signers are
refused before repo work starts. Nested scope rules and scope-specific review
objects refuse to load; keep all scope maps and the review object at fleet level.

`draft`, `drafts` and `dismiss` work in both repair CLI and MCP. Repo drafts
hold a tested branch, commit and full manifest diff in an isolated clone under
the state dir. OS drafts hold a real simulation result and exact commands. Apply
creates or reuses a prechecked draft (even on dry-run) and reruns policy, so
dry-run writes local state and runs draft checks or simulations; it is not
read-only. Locked apply needs digest-bound human quorum; unlocked apply needs it
when mode permission is ask or policy requires approval. The dashboard needs
quorum for every apply. Dismissed drafts cannot be reapplied, though you can
draft a later, different plan for the same item. Watch mode refuses drafting too.
Advise mode allows drafting but refuses apply until the owner enables fix mode.
Draft clones stay on disk for human review.

## Network and publication

Planning and drafting never edit the source repo, but they write local state or
scratch files. Locked planning queries the public npm registry and advisory feeds
in an isolated clone; see the [locked workflow](locked-repair-contract.md) for
runtime and source limits. Apt drafting checks installed and available versions;
apt apply and rollback can reach configured repos. Apply rescans vulnerability
feeds. None of these promise offline runs, and host checks have their own network
and write behavior.

CLI `repair publish` (given item, digest, repository, base and branch) and the
dashboard publish action push the exact tested commit and open a draft GitHub PR.
Both need an active, approved, unlocked npm manifest draft, matching digest,
current quorum with an eligible human, fleet permission and repair policy. Locked
drafts and OS plans cannot be published. Publishing does not apply the repair
locally, close its finding, merge PRs or delete branches. If PR creation fails,
it can leave a pushed branch and a `pr-pushed` claim; delete the branch by hand
and run `repair recover`. See the [publication contract](repair-pr-contract.md)
for destination and auth rules.

Unsupported: config/browser draft adapters, timed auto-apply, non-apt OS changes,
non-npm repo repair and locked-draft PR publishing. Platform acceptance covers
only the checks actually run; local tests do not certify every OS or external
provider. The retired Python repair code and tests are historical only, not
runtime instructions.

## Native controls and source

Focused offline controls:

```sh
cargo test --locked --manifest-path rust/Cargo.toml --test surfaces_repair
cargo test --locked --manifest-path rust/Cargo.toml --test npm_preflight
```

The real registry and feed check is opt-in; see the [locked workflow](locked-repair-contract.md).
Native code: [CLI and reviewer identity](../rust/src/surfaces/mod.rs),
[MCP schemas and identity binding](../rust/src/surfaces/mcp.rs),
[repair state, approvals and apply](../rust/src/repair/mod.rs),
[policy and modes](../rust/src/policy/mod.rs),
[dashboard writes](../rust/src/surfaces/dashboard/control.rs), and
[publication](../rust/src/repair/publish.rs).

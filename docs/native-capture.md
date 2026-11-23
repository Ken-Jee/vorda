# Native capture

Save a strict lockfile snapshot under the scanner lock with `vorda --state DIR capture REQUEST.json`. For fully checkable files, it records the same ecosystem/name/version set as `vorda inventory --root DIR` using the same lockfile reader. Unlike inventory and scans (which keep healthy entries and report partial coverage unknown), capture needs complete input coverage and refuses the artifact on any uncheckable entry. It is not a host inventory: installed software, OS packages, browsers, and tools are excluded.

## Request

A trusted local request supplies `token`, `binding` (tenant, site, device, generation, scope, source), an absolute canonical `root`, relative `inputs`, and decimal-string `observed_at` and `completed_at`. Bindings never come from hostnames or paths. One authority (the first five binding fields) has one immutable root/source config. IDs derive from the full binding, token, and location, not versions. Use a fresh token for new observations.

Inputs are relative paths matching the [accepted lockfile versions](reference.md): `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pylock.toml`, `pylock.<name>.toml`, `Cargo.lock`, `go.mod`, `go.sum`, `Gemfile.lock`, `composer.lock`, `packages.lock.json` (NuGet), and `requirements*.txt`. Unknown or missing required version markers are refused, as is binary `bun.lockb` (export `bun.lock` instead). Paths cannot contain `..`, backslashes, empty segments, or control characters. Empty inputs are refused even in mixed selections.

An optional `provider` field records an unsuccessful OSV check you supply: name=osv, request (the trusted binding), status=unavailable, checked_at (original decimal string), and response_utf8 (exact string or null). Capture never runs a provider; a null response has no digest. Omit it to mark advisories unrequested. `legacy_import=true` requires null observation/completion times and no provider; it imports only bound inputs with unknown coverage and unavailable times, without inferring native history.

## What is recorded

Each lockfile yields one record per distinct package (ecosystem, name, version). A package listed more than once at the same version in one lockfile (like nested `node_modules`) becomes one record. Dev, optional, and workspace flags are excluded, and `fix_verified` is always false. Each record keeps its input path, stable location and component, and a `native_asset` alias.

A location identifies a package in a lockfile by ecosystem and name. If one lockfile holds several versions of the same name, the location adds the version, so a version change creates a new component instead of an upgrade. For all other packages, a version change keeps the same component.

Any ambiguous lockfile is refused instead of guessed at: a JSON lockfile with a repeated key (`duplicate_input_key`), a package missing a resolved version, an unsupported requirements line or other scanner refusal (`unsupported_input`, with the scanner message in `detail`), or an explicit empty dependency set (`unsupported_empty_input`). Content that has no readable packages is refused as `unsupported_input`. Any refused input makes the capture unsuccessful (coverage `unsupported`) and saves nothing. Normal read failures can keep prior observations if another selected input succeeds. Unselected inputs and other scopes stay untouched, while a re-read input replaces all its previous records. Package rows never assert empty coverage or findings. A capture request cannot contain JSON numbers in any form (`1.5`, `1e2`, `-0`, or a 20-digit integer); any number fails with `invalid_number` and stores nothing. Numbers inside lockfiles are unaffected.

## Limits

| Limit | Value | When exceeded |
| --- | --- | --- |
| Request | 4 MiB | `input_size_limit` |
| Each lockfile | 4 MiB | input refused as `unsupported_input_field` |
| Selected inputs | 256 | `invalid_capture_selection` |
| Input path | 256 bytes | `invalid_capture_path` |
| Retained envelope (request plus input bytes) | 4 MiB | `capture_size_limit`, nothing stored |
| Package records an authority currently holds | 1,500 | unsuccessful capture, see below |
| Saved view (the reader's snapshot bound) | 4 MiB less 64 KiB | `capture_view_size_limit`, nothing stored |

These input, path, package, and view caps match the hub's own limits: up to 256 inputs with paths up to 256 bytes, 1,500 records, and a 4 MiB view. The device leaves 64 KiB free so the hub can stamp receipt times on every record without rejecting a committed capture as oversized.

The package cap counts all records the authority would hold after the capture: untouched inputs stay, and re-read inputs replace their old records. Exceeding the cap refuses the whole capture with no truncation: outcome is `unsuccessful`, coverage is `unsupported`, the input that crossed the cap gets `error: capture_package_limit` with a `detail` count, the retained snapshot stays unchanged, and the refusal replays by token. Use another scope to hold more packages.

A saved view uses about 1.8 KiB per record plus about 1.5 times the lockfile size, because lockfile text is escaped twice and each record appears in both the view and artifact. In a test with a synthetic 1,500-package npm lockfile (736,013 bytes, pretty-printed, about 490 bytes per package), the artifact was 1,537,668 bytes and the exported view was 3,858,537 bytes (92% of the 4 MiB bound). Real npm lockfiles hit the view limit before the 1,500-package cap: averaging over about 640 bytes per package (common with `peerDependencies`, `funding`, or `bin`) triggers `capture_view_size_limit` below 1,500 packages. The reader's 4096-byte string cap applies across the view except for `retained_payload_utf8`, which is capped only by the 4 MiB snapshot.

The hub accepts capture output through native admission ([linking.md](linking.md#native-assessments)), re-reading every input with the same lockfile reader and refusing any mismatch. Deliver a committed capture separately with `link queue-native` and `send`.

## Outcomes, replay and export

Unsuccessful outcomes save separately from authoritative revisions and report the retained snapshot ID; inspect one after restart with `capture-attempt TOKEN`. Replaying a token checks the full request plus current input bytes and read outcomes: an exact match returns the saved result (including a package-cap refusal), while any conflict refuses. If files changed after commit, recover from the saved outcome or snapshot ID instead of reusing the old token.

Run `capture-retire --scope SCOPE --source SOURCE` to retire a captured source, saving a revision with no inputs or records and inventory coverage `retired` ([linking.md](linking.md#retiring-a-source-and-an-advisory-provider-that-did-not-answer)). A request with provider status `unavailable` saves advisory coverage `unavailable`.

`capture-export SNAPSHOT FILE` writes immutable saved bytes via a temporary file and atomic rename. Reopening or exporting older snapshots never changes the current selection. Saved-view membership is the intersection of frozen captured membership and the view's selected observations; export refuses any row that differs from its frozen observation. Artifact, lockfile, and provider digests stay separate, with reader binding using the artifact digest. Original decimal timestamps never come from native REAL columns.

State, native assets, checkpoints, capture bytes, token outcomes, revisions, and views commit in one outer SQLite savepoint. Derived exports run only after that savepoint commits, and failed exports can be retried with the same snapshot ID. Updates replace only the re-read input; failed or unselected inputs keep their saved metadata. Link v1 is untouched, and capture never queues, sends, or acknowledges batches.

The producer source pin hashes the four integration source files embedded at compile time (cli, store, capture, assets); it identifies source, not a binary attestation. Local metadata and imported provider assertions are not authentication. Capture provides no server, enrollment, new provider, remote repair, empty-scope coverage, or typed findings.

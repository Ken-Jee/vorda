# Scope and coverage

Read this when a question names a site, device or source, or when an answer depends on how much
was collected.

## Scope

- Every fleet list carries `effective_scope`: `sites` (org and site pairs), `devices` (`"all"` or a
  count) and `sources` (`"all"` or the list of granted source names). It is the service's
  statement of what you can see. The `device` detail answer has no `effective_scope`.
- Under a grant limited to named sources, `findings` answers total 0 with `as_of` null and
  `device` answers `findings: []` and `finding_count: null`. The finding data is not
  answerable under that grant; it is not zero. Use `sources`, `inventory` and `evidence`.
- `sites`, `devices` and `sources` arguments narrow that scope. A value outside it matches
  nothing and is indistinguishable from a value that does not exist. An empty result for a name
  you were given may mean "outside the grant"; say that instead of "no such device".
- Device ids and source names are chosen by endpoints. Use them as given; do not infer an owner
  or a trust level from a name.
- If the user needs something outside the grant, say who can widen it (the hub owner). Do not
  retry with other credentials or look for another route to the same data.

## Coverage fields

| Where | Field | Meaning |
| - | - | - |
| `sources` rows | `coverage.inventory.state`, `coverage.advisories.state` | `complete`, `partial`, `not_requested`, `unknown`; `reason` explains it |
| `sources` rows | `coverage.inputs` | counts of inputs in state `complete` and of every other input (`failed`, whatever its state) |
| `sources` rows | `observed_at`, `age_seconds`, `freshness` | when the data was observed, its age and `fresh`, `stale`, `unknown` or `future` |
| `sources` rows | `advisory_checked_at` | when advisories were last matched; may differ from `observed_at` |
| `sources` rows | `last_received` | when the hub last accepted a delivery |
| `inventory` | `view_coverage` | tallies of inventory and advisory states for the view, with a note on absence |
| `status` | `devices`, `sources` | counts: `checked_in_fresh`, `checked_in_stale`, `never_checked_in`, `with_failed_inputs`, `by_inventory_state` |
| `devices`, `sources`, `inventory`, `status` | `freshness_policy` | the window used (`fresh_for_seconds`); `fresh_for_seconds` only changes that window. Not on `findings`, `device`, `changes` or `evidence` |
| `devices` rows, `device` | `received`, `finding_count`, `findings` | the older delivery path: its receipt time and finding lists. Under a source-limited grant they are null or empty |
| `findings` | `as_of` | the newest receipt time in the view, not an observation time and not one device's age |

`unknown` is not `fresh`. `future` means the device clock is ahead; treat its time as unreliable.
A revoked device (`revoked: true`) is not expected to check in; say so instead of calling it stale.
A "checked in" count is a delivery time, not an observation time.

## Reading absence

- Presence needs `inventory`; absence needs `inventory` coverage `complete` for that source.
- `partial` or `unknown` coverage means a package can be present and unseen.
- A source with a non-complete input (`coverage.inputs.failed` above 0) is incomplete however
  recent it is.
- No sources for a device means no native assessment has been published for it. It may still have
  findings and a `received` time from the older delivery path (check `devices`/`device`), and its
  `status` check-in counts both. No sources and no findings is a gap, not a clearance.
- A finding list is dated by its own `received`/`as_of`, never by a source's freshness; a clean
  `findings` list says nothing about what a native assessment covered.

## Local equivalents

On the local service, read the `check` result's `errors` and `coverage_evidence`, and the
`agent_inventory`/`agent_check` statements about skipped or unsupported coverage. Unavailable
coverage is unknown, never clean.

Project checks read supported lockfiles and pinned `requirements*.txt`. Recognised unsupported
manifests (including Maven/Gradle, npm shrinkwrap, Deno, and lockless JavaScript,
Rust, Ruby or PHP manifests), skipped or
unreadable supported files, and project discovery with zero packages produce `status: unknown`. Errors name
unread inputs; `coverage_evidence` stays partial. Manifests can use a supported lockfile
of their own ecosystem in an ancestor within the selected root, including installed
PHP/Ruby trees and Python members beneath uv.lock. Go modules and Pipfiles instead need
adjacent go.sum and Pipfile.lock respectively. Lockfile membership is not checked.
Central Directory.Packages.props versions can also use discovered NuGet locks below them.
Ignored folders such as `node_modules`
remain excluded; arbitrary other filenames are not classified.
Underscore requirement names and requirement-looking .txt/.in inputs nested under a
requirements directory are recognised as unsupported when any line resembles a requirement
or starts with a dash (conservatively a pip directive), even alongside prose or comments.
Pure prose is ignored. A pip-tools .in input is covered by its supported, same-stem
compiled .txt; freshness and dependency membership are not checked. Tool-only pyproject.toml files
without dependency declarations do not add dependencies. Missing-lock messages name the
usual generation command; unsupported formats have a separate message. Non-ignored
symlink directories are unknown and remain unread. Constraints files do not add installed dependencies;
their presence alone does not make an otherwise covered project unknown.

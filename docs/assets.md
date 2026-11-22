# Private asset summary

See what you actually scanned on your own machines, separate from the public advisory site. Advisory records are lookup data, never local assets. This summary only reads saved results from scans you ran; it never starts a scan, turns on extra discovery, or publishes inventory. Scan flags and consent stay the same. Pick only the project, image, host inventory, or AI home you need. A saved import selects that inventory explicitly, and its producer is responsible for limiting its scope.

## Integration

`vorda check` / `scan` JSON and saved `last-scan.json` include `assets`, as does saved `agentbom` output (`--no-save` stays print-only). Native callers read `vorda::surfaces::dashboard::data::snapshot(state, now, Some(&scopes))?["assets"]`: pass `None` for all saved scopes (including scans with zero assets), or an empty set for none. Regular scans expose `scan_scope` and `scan_roots`; AI scans put the scope on each item. That same selection filters dashboard findings, news, history, and BOM. Legacy host-wide scans and readers without project attribution drop out when a scope is chosen; legacy mailboxes without saved observations keep their old view until a new scan or scope choice. The authenticated private dashboard endpoint `GET /api/assets` returns this summary. Repeat `?scope=ID&scope=ID` to pick saved scopes (unknown IDs return zero assets; omitting it selects all saved scopes). Each project card shows its latest scan and links to its findings. Known-root links carry `host=HOST&project=ROOT` and keep active findings for that path across scope picks, while the latest scan sets age and coverage; older records without root metadata keep scope links. Explicit scope picks still filter the view. An empty selection shows "No scans in this view"; "No scans yet" only appears when the mailbox has no scans. Lower-level `assets::summary` still defaults to the latest saved scope, while the dashboard selects all scopes when none is given.

Schema 1 example (`items` omitted):

```json
{
  "schema": 1,
  "categories": [
    {"category": "Environments", "total": 1, "critical": 0, "needs_review": 0, "flags": 0, "items_scanned": 1, "healthy": 1},
    {"category": "Applications", "total": 2, "critical": 1, "needs_review": 1, "flags": 2, "items_scanned": 1, "healthy": 0},
    {"category": "Developer Tools", "total": 1, "critical": 0, "needs_review": 0, "flags": 0, "items_scanned": 1, "healthy": 1}
  ],
  "total": 4, "critical": 1, "needs_review": 1, "flags": 2,
  "items_scanned": 3, "healthy": 2, "finding_count": 2
}
```

Map row Flags/Total to `flags`/`total`, and headline Critical/Needs review/Items scanned to `critical`/`needs_review`/`items_scanned`. `items_scanned` counts fresh items with complete advisory coverage, not all discovered assets or running processes. A partial scan may check some packages, but its assets still need review. Total includes unknown inventory and can exceed Items scanned. Category sums match each headline: `total = critical + needs_review + healthy` and `flags = critical + needs_review`. Critical overrides review. Multiple findings flag one asset once; `finding_count` counts matched active findings separately. Health mail and findings without observed inventory never invent assets. Legacy mailboxes need another selected scan to populate inventory; zero inventory never clears their existing findings.

`items` keeps `id`, `host`, original `record`, `aliases`, category, subtype, ownership confidence `known`, evidence, scope, observed time, coverage `complete`/`checked`, `stale`, status, and finding count. Each ID wraps the package identity (path/ecosystem/name/version) with host without changing original package or finding IDs. Different versions or locations count as separate installations; advisories do not. AI items keep their original ID: a direct package and its config findings share one asset, while transitive packages are separate dependency assets. A configured tool is never merged with another install by name alone. Overlapping scopes deduplicate by identity and keep incomplete or older evidence conservatively. Project ownership beats tool ownership for the same package. There are no runtime probes: `installed`, `configured`, and `selected` never mean running.

## Supported scanner mapping

Grouping follows how an item was found, not its registry or package name. Only selected outputs are classified. This table covers every current inventory path and its fallback:

| Output path | Group / subtype | Limits |
| --- | --- | --- |
| Project lockfiles: npm, pnpm, Yarn, Bun text, Poetry, uv, Pipfile, Cargo, Go, Bundler, Composer, NuGet; requirements files | Applications / project | Reads only [accepted format versions](reference.md). Dev/test deps stay app-owned. Binary Bun locks report unsupported input, not an asset. |
| Opt-in dpkg-query, rpm, apk, pacman packages | Environments / os-package | Counts OS packages as environment parts without telling which are running services or tools. No synthetic host parent is added. Advisory support depends on distro, release, and feeds. |
| Opt-in Homebrew, Chocolatey, and Winget packages | Applications / installed | No tool ownership is guessed from publisher or name. Unsupported advisory mapping needs review. |
| Opt-in version probes: Node, Python, Bun, Deno, Claude, Codex, Gemini, OpenCode | Developer Tools / tool | Selected tool installs; unsupported version or feed coverage needs review. |
| Opt-in browser/Electron/Playwright Chromium discovery | Applications / browser | Needs trusted version evidence; does not show the browser is open. |
| Explicit OCI/Docker archive, Syft artifacts: deb/apk and npm/Python/Rust/Go/gem/Composer, unmapped artifacts | Applications / image | All packages belong to the selected image, including OS packages. Not a running container; unsupported items need review. No extra image parent is counted. |
| AI/MCP: mcp, mcp-config, plugin, skill, hook, settings-env, command, subagent, cli, mcp-package, ide-extension, model | Developer Tools / original kind | Explicit agentbom runs pick home or project scope. Direct npm/PyPI packages and relevant deps get advisory checks. Static, config, and inventory-only items cannot prove full CVE coverage and stay in review. |
| Saved imported inventory | Provenance above, otherwise Applications / unknown | Keeps producer fields, but requires review if ownership is unknown. Importing never proves runtime. |
| Unknown future item kind or provenance | Applications / unknown | Visible and always review; no ecosystem or name guess. |
| Native/vendor/upstream feed matches, static findings, health mail | No new asset | Findings attach only to observed inventory by existing asset and host ID. |
| Result linking v1 | No inventory totals | Findings-only transport cannot prove installs without findings. No schema or custody changes. |
| Public advisory catalog | Excluded | Never proves a local install, and no inventory goes to the catalog. |

Vorda does not scan VMs, cloud accounts, LAN services, live Docker, or running processes. You can scan an archive, not discover infrastructure. Failed, inventory-only (`--offline`), or incomplete scans keep earlier observations in that scope in review; complete scans (including complete `--offline-db` scans) replace only their own scope. Skipped AI kinds mark that scope partial. Observations older than two days turn stale and need review. Inventory-only and unmapped records cannot be healthy even with zero findings. Finding reconciliation, linking coverage, hashed export allowlist, deny policy, and credential custody stay unchanged; private summary paths and records stay out of linking v1.

## Selection behavior

Environments counts **scanned OS components**, not hosts, VMs, or running environments. One host with 100 OS packages adds 100 components; you cannot infer a host count from that. All three Total values count components or installs, never invented host or runtime totals.

`scan`, `check`, and `inventory` default to the current project only; OS packages, tools, and browsers need explicit flags. `--oci` checks only that archive. `agentbom --root PROJECT` reads only that project's AI config, skills, models, and relevant server dependencies, skipping unrelated home clients, remembered projects, global CLIs, and extensions. Pass `--include-home` to add home AI discovery, or run `agentbom` with no project roots to check home AI tooling. A selected server's installed dependencies still count even when installed outside the project.

`watch install --root PROJECT` schedules only that selection. To include OS packages, tools, or browsers, pass `watch install --os-packages --tools --browsers`; reinstalling without those flags drops them. Reinstall existing schedules to pick up this behavior. MCP check only allows nonempty configured roots and turns on no optional scanners. Neither the installer nor the dashboard starts scans. The public site reads OSV, FIRST, and the public CISA KEV mirror in your browser, with no private mailbox reads or writes.

Watch resolves its advisory mode at install time (explicit `--offline-db` or `--online`, otherwise `VORDA_ADVISORIES`, `config.json` `advisories`, or the `offline-db` default) and pins that choice into the generated command, so reinstalling without a flag re-resolves the default rather than reusing `watch.json`. Offline watch scans never automatically refresh the database or fall back to online lookups; run `db update` daily, because a missing or stale database reports `unknown` health.

Missing or linked AI roots fail incomplete and keep prior findings; root paths are checked before canonicalization. The private summary and dashboard use the same scope. Older findings without a matching selected observation are left out rather than assigned to a guessed scope.

Saved imports need producer `status` complete (or a successful saved scan status), no partial or unknown coverage entries, and fresh observations. `observed` is a Unix timestamp; without it there is no fresh evidence, and file mtime is never substituted, so copying or touching a file cannot make it look newer. Missing completion metadata, partial or error coverage, and observations older than two days stay unknown and cannot clear inventory. Legacy lists still parse but stay in review until completion metadata is added. Regular `inventory` JSON includes `status` and `observed` for this. Explicit scope parameters stay on dashboard navigation links.

The legacy saved BOM updates from the same scoped observations. Incomplete AI runs keep prior BOM rows and timestamps, labeled `Unknown` (or `Stale` when aged) in the Agents view. One selected scope cannot overwrite another scope's BOM. Old entries retire only with positive removal evidence from reading the source or confirming removal; unavailable roots never count.

Saved local scans include `coverage_evidence` with `status` (`complete`/`partial`) and typed `observations`: supported input, explicit tool absence, completed browser inventory or archive, declared imported inventory, or confirmed removal. That evidence and prior findings decide resolution; package counts or completed paths alone are not enough. Having no supported input stays partial even with easy-setup exit 0. Completed empty supported input and confirmed removal can resolve findings. The linker reads only the status, keeping its wire allowlist and custody contract intact.

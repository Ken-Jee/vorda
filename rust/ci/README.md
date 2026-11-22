# Rust acceptance

One entrypoint runs locked, offline Cargo tests (including doctests) and native
MCP protocol checks. Every acceptance invocation runs tests. A compiled cache is never
treated as proof that tests passed, and diagnostic JSON is never replayed.

## Dev loop

### What CI runs and why

Linux CI (`.github/workflows/rust-ci.yml`) installs the pinned Rust toolchain
and a pinned `cargo-nextest` release, builds and tests the controller, then the
controller `ci` mode runs, in order:

1. `cargo nextest run --test-threads=4 --retries=0` (locked, offline, host target);
2. `cargo test --doc`, because nextest does not run doctests;
3. `cargo build --bin ci_helper` and the explicit-binary protocol smoke.

Any failing step fails acceptance and no success receipt is written. Compiled-unit
counts in the result still come from Cargo's JSON compiler messages.

- **nextest** runs every test in its own process and schedules across test
  binaries, which is where the wall-clock gain below comes from.
- **nextest comes from a checksum-verified release binary.** The workflow pins the
  version and the SHA-256 of the release archive and stops before extracting
  anything if they differ. To bump it, change both values together, using the
  checksum published with the release and confirming it by hashing the download.
- **4 threads, no retries.** In a 10-run series each, 4 threads failed 0 of 10
  runs and 8 threads failed 2 of 10 (tests with real time bounds starve on a
  2 vCPU runner). A retry in the acceptance gate could hide a real intermittent
  failure, so there are none. A later run with one more timing pin got 0 of 10
  at 8 threads, but a cold-page-cache warm-up run still failed on a real
  700 ms bound, so CI stays at 4 until that is re-measured.
- **`CARGO_INCREMENTAL=0` stays in CI.** The workflow sets it; it takes
  precedence over the profile settings in `Cargo.toml`.
- **mold is not used in CI.** It is not installed on the 2 vCPU box used for
  the measurements (`command -v mold` was empty) and the GitHub-hosted image has
  not been checked. In the cold-build measurement below it saved about 1 s, so
  CI has no step for it. See "mold" below to use it locally.
- **The compiled-cache restore is still in the workflow.** See "Measured".

### Local fast loop

Run these from `rust/`. Install `cargo-nextest` first: use the release archive and
checksum pinned in the workflow, or `cargo install --locked cargo-nextest`. The
trusted local entrypoint below needs it on `PATH` too.

```sh
cargo nextest run                          # all tests except doctests; one thread per CPU
cargo nextest run --test-threads 8         # 8 threads is fine on a machine with spare CPUs
cargo test --doc                           # doctests (nextest skips them)
cargo nextest run offline_receipts         # tests whose name contains a substring
cargo nextest run -E 'binary(storage_link) & test(offline_receipts)'   # one test in one binary
cargo test --test storage_link offline_receipts   # same test with plain cargo test
```

CI uses 4 threads rather than 8 because of the flake rates above; locally a
failure at a high thread count can be a timing bound, so rerun with
`--test-threads 4` before assuming a regression.

**mold (opt-in, local only).** Needs `mold` installed. Do not add it to a
committed Cargo config: it breaks every machine without mold. Per shell:

```sh
export RUSTFLAGS="-C link-arg=-fuse-ld=mold"
```

or in your own `~/.cargo/config.toml`:

```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

Changing `RUSTFLAGS` rebuilds everything once. `rustc` 1.99.1 already links with
rust-lld by default, so switching to lld changes nothing. The gain is small, see below.

**Incremental compilation (on locally, off in CI).** `rust/Cargo.toml` sets
`incremental = true` for the dev and test profiles, so local `check`, `build` and
`test` reuse earlier work after an edit. The costs are a cold build about 6 %
slower and a `target/` about 1 GB larger (see "Measured"). To turn it off for a
shell:

```sh
export CARGO_INCREMENTAL=0
```

The environment variable overrides the profile setting. CI exports
`CARGO_INCREMENTAL=0`, so the CI path is unchanged, and the release profile is
untouched.

### Measured

All times are seconds. "NVD pause" is the patch that lets fixture feeds skip the
NVD rate-limit sleep, "import transaction" wraps the `import_authority`
quiet-scope inserts in one transaction, "backoff assert" is the flaky
`storage_link` assertion fix. **These three are separate PRs; the rows below that
include them only apply once those PRs have merged.**

| What | Machine, fs, n | Before | After |
| --- | --- | --- | --- |
| Whole PR job, step sum, cold: main, plain `cargo test` | 2 vCPU CI-sized box, median of 3 | 219.6 | |
| + NVD pause | same | | 168.1 |
| + NVD pause + nextest, 8 threads | same | | 109.1 |
| Same comparison interleaved on one other clean box | another clean 2 vCPU box | 218.1 | 111.2 (NVD pause + import transaction + nextest 8 threads) |
| Tests only, 10 runs each, alternating (main + NVD pause + import transaction + backoff assert) | 2 vCPU CI-sized box | | 4 threads: median 55.5 (49.9-63.1), 0/10 failed; 8 threads: median 36.5, 2/10 failed |
| Test run: `cargo test` vs nextest (main + NVD pause) | WSL, 4 CPUs, n not recorded | 19.7 | 10.8 |
| Link with mold vs default, cold build (main + NVD pause) | WSL, 4 CPUs, median of 5, noise 0.7 % | 39.0 | 38.0 |
| Link with mold vs default, rebuild after a library edit (main + NVD pause) | same | 14.0 | 12.9 |
| Link with mold vs default, rebuild after a test-file edit (main + NVD pause) | same | 0.53 | 0.40 |
| Incremental on vs off, `check` / edit + build / edit + one test (main + NVD pause + mold) | WSL, 12 CPUs (build jobs capped at 4), separate build disk, 3 baseline and 2 incremental rounds, noise 3.4 % | 3.9 / 12.4 / 6.4 | 1.4 / 7.5 / 1.9 |
| Incremental on vs off, cold build (same setup) | same | 35.4 | 37.7 |
| Compiled-cache restore: with vs without | 2 vCPU CI-sized box, interleaved | 218.1 baseline | 201.2 with cache; restore step costs 15.7 |

Limits:

- The 2 vCPU numbers are from a box with the same step sequence as the
  workflow, not from GitHub's runner. GitHub's own median is 166 s for the Linux
  job. Applying that ratio (about 0.45-0.55 of baseline) to that is a
  projection, not a measurement.
- The 90 s target is only reached on a persistent warm box (43-61 s per run
  with nextest at 8 threads), not on a cold runner.
- Some WSL medians have n of 2-4 because the benchmark harness lost samples.
- "Compiled cache" buys 3-17 s on the cold box and costs 15.7 s to restore. It is
  left in place; main pushes now run the full suite instead of a seed, and
  removing the cache and the unused `--compile-only` mode is a follow-up.
- Test hotspots left: `import_authority`, `storage_link`, `storage_pressure`
  (about 15-19 s each on the 2 vCPU box before the patches), and one 5 s deadline test
  in `src/link/server.rs` and one 256 MiB-limit test in `src/store/mod.rs` were
  not touched.

## Trusted local development

Configure an existing capacity launcher with owned persistent `target`,
`cargo-home`, `tmp` and evidence directories. Prepare locked dependencies once
inside that admission boundary. Do not copy credentials or a whole user home.

```sh
bash rust/ci/local.sh /absolute/path/to/vorda-capacity
```

The launcher must implement `run -- COMMAND`, set `CARGO_TARGET_DIR` and
`CARGO_HOME`, and run the command in its resource-limited build cgroup. This
adapter uses the existing `vorda-rust-build-*` cgroup contract. The trusted local
entrypoint refuses direct execution outside that cgroup. Separate callers queue
with a ten-minute lock wait before admission; they cannot compile concurrently
into the same cache. Each queued caller still runs tests.

Compiled output lives below `CARGO_TARGET_DIR/acceptance-v2`. Namespace identity
includes source checkout location, rustc identity/target, profile, default
features and compiler/profile flags. Source, dependency lock and documentation
changes do **not** allocate a fresh namespace. Cargo handles dependency and
feature invalidation within the existing target. A compiler/flag namespace
change preserves the previous namespace until reclamation.

The supported local trust model is package-managed tools and trusted same-user
source. Compiler outputs/build scripts must never be shared with untrusted PR
execution. Changes to external headers, mutable system libraries or build-script
inputs that Cargo does not declare require an explicit fresh build:

```sh
bash rust/ci/local.sh /absolute/path/to/vorda-capacity --fresh
```

This clears only the selected owned target under the same lock. PIN/EVIDENCE
markers refuse clearing. It does not remove dependency downloads or other
projects. Source changes during acceptance fail the check; a mutation restored
before the final digest is outside this cooperative checkout model. Use an
immutable checkout for release acceptance.

## Storage and failure behavior

The existing launcher retains its admission free-space reserves, RAM/process
limits, whole-task budget and cancellation. The entrypoint additionally samples
owned data every two seconds: 2 GiB per namespace, 3 GiB across namespaces,
256 MiB free-space floor, 8 MiB command log, 50,000 entries/five seconds per
accounting walk. These directory budgets are sampled, not filesystem quotas;
temporary overshoot is possible. Outer admission must reserve build headroom.
Before a build, an unpinned selected namespace at or above 1.5 GiB loses only its
compiled target to restore headroom. This deliberately trades a cold rebuild for
bounded growth, before launching another compiler. It emits a byte receipt.

Inactive owned namespaces older than seven days are reclaimed on invocation.
Under budget pressure, oldest inactive namespaces go first. Active, PIN and
EVIDENCE namespaces are never evicted; unknown directories and symlinks cause a
refusal. Cleanup emits namespace/byte receipts. There is no background janitor
and no deletion of unrelated caches. Successful process exit preserves compiled
output. After namespace admission, the previous success report is removed before
preparation or commands; earlier admission failures may retain historical
diagnostics, never a successful result for the failed request. Command process
groups are terminated on signals, accounting failure or time limits. Interrupted Cargo state is not a
passed result; a subsequent invocation runs Cargo/tests again.

`last-check.json` records source digest, compiled/fresh unit counts, elapsed time
and retained bytes. It is diagnostic only. Acceptance `check.log` and compile-only
`seed.log` are separate bounded slots, each replaced by its next run. The result
receipt names its log. Save failure evidence before rerunning the same mode.

## CI and release

Linux PR CI builds the pinned standalone development controller before product compilation and calls it in an ephemeral runner,
with a runner-temporary `CARGO_TARGET_DIR`. It builds the development-only `ci_helper`, then executes all tests and explicit-binary smoke
regardless of cache hits or local evidence. Manual dispatch also runs acceptance.
Registry and compiled caches remain partitioned by runner provider and toolchain.

Every push to main that changes the same paths as a PR runs the same full job
(acceptance, clippy, the self-scan, the dependency audit and the fault tests);
a push whose previous commit cannot be compared runs it whatever it changed. The controller's `--compile-only` mode is no longer used by
the workflow. It runs the same locked offline Cargo test-target selection with
`--no-run`; it does not run Rust tests, doctests or protocol smoke, and emits only
a `compiled` diagnostic with `tests_executed: false` in `last-seed.json`, never a
passed acceptance receipt.
The ordinary PR path always executes acceptance, including doctests. `ci_helper smoke BINARY` drives a supplied executable with bounded protocol requests; `ci_helper provenance PACKAGE` writes metadata and its checksum once for a fresh
x86_64 Linux GNU release/default-feature workflow package. Other package targets,
an existing manifest, or an existing manifest checksum are refused before writes.
Use a fresh package directory to regenerate metadata. Target/profile/features are
workflow assumptions, not properties discovered from binary bytes; the filename
check only rejects obvious mismatches. Source HEAD and rustc describe the collection
environment. The controlled release build must bind that context to the artifact;
this helper alone does not attest how an arbitrary executable was built.

Main checkout and cache access stay on the trusted main ref: no PR artifact is
downloaded or promoted. PR and fork event boundaries and read-only permissions
are unchanged. Each main push has its own concurrency group (its commit), so a
later push never cancels the test run of an earlier one. Main dispatch acceptance
and PR runs have separate groups.

Each main run still costs compilation, cache transfer and retained storage. No net
savings or populated cross-PR restore is established. Observe main-ref saves and
later distinct-PR populated restores only on already-needed deliveries.
Repository required checks must be configured and verified separately;
checked-in YAML alone cannot enforce branch protection.

Release acceptance remains fresh, platform-specific and bound to immutable
source/artifact checksums. Existing licenses, exact-package checks and promotion
gates remain required. No publishing, deployment, signing or account changes are
performed by this entrypoint.

The controller is separate from the product crate. Its source hashes are pinned
in `controller/sources.sha256`; the local adapter also checks the installed
controller and capacity launcher bytes against a task-owned receipt before admission.

No session daemon, test-result policy hash list or remote receipt service is
needed. Cache eviction can cost a rebuild; it must never alter test correctness.

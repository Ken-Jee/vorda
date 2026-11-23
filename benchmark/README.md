# Scanner benchmark

A reproducible head-to-head of Vorda against osv-scanner, Trivy and Grype on one corpus.
Results: [results/2026-11-22.md](results/2026-11-22.md) (JSON copy alongside).

Nothing in the corpus is installed, built or run. Lockfiles and manifests are read as text,
repositories are cloned without running any package manager, and container images are saved
as archives and never started.

## Tools

Pinned in [tools.json](tools.json) with SHA-256 checksums. `setup-tools.sh` downloads them into
`$BENCH_HOME/tools`; nothing is installed system-wide. Snyk CLI is left out because `snyk test`
needs an account.

## Corpus

| part | what | where |
|---|---|---|
| (a) ground truth | 16 lockfiles across 11 ecosystems, each with known vulnerable versions and one clean control | `corpus/ground-truth/` |
| (b) real repos | 20 public repositories at pinned commits, cloned with `--depth 1` | `corpus/repos.json` |
| (c) manifest only | 8 projects with a manifest and no lockfile, to test transitive resolution | `corpus/manifest-only/` |
| (d) images | 6 public images pinned by digest, saved as OCI archives | `corpus/images.json` |

The `corpus/` folder holds the vulnerable lockfiles and labels and stays in the private repository rather than the public release, while `results/` and this README are public.

Labels:

- (a) `label.py ground-truth` looks up every package version in OSV.dev (`querybatch`) and the GitHub
  Advisory Database (`gh api /advisories?affects=`). Advisories are grouped through their aliases, so
  a tool that reports the CVE, the GHSA or the OSV id of the same advisory gets the same credit.
  Withdrawn advisories are dropped. Snapshot: `corpus/ground-truth/labels.json`.
- (c) `label.py manifest` resolves each direct dependency with deps.dev where it offers a dependency
  graph (npm, Maven, PyPI) and labels direct and transitive packages; elsewhere only direct
  dependencies are labelled. Snapshot: `corpus/manifest-only/labels.json`.
- (b) The union of packages any tool found in a repository is labelled from OSV (no GHSA lookup,
  for rate limits). Recall there is measured against what the tools between them could find.
- (d) Images have no independent labels. A CVE counts as agreed when at least two tools report it for
  the same image online; each run is scored on how many agreed CVEs it found and how many CVEs no other
  tool reports. Package names are not compared, because osv-scanner names Debian and Ubuntu packages
  by source package.

## Scoring

- **Advisory hit:** the tool reports any id or alias of a labelled advisory on the same package.
- **Miss:** a labelled advisory the tool does not report.
- **False alarm:** an advisory reported on a labelled package that matches no label, where OSV holds
  that record for the package (so OSV says this version is not affected, or the record is withdrawn).
- **Unverified extra:** an advisory reported on a labelled package whose id OSV does not hold for that
  package (often an NVD-only CVE). Listed separately, neither credited nor counted as a false alarm.
- **False clean:** the tool's answer is clean (success exit, no findings, no unknown status) on a
  target that holds labelled vulnerabilities. A warning printed on stderr does not count as
  saying unknown, because the exit code a CI job sees is still clean; such cases are marked "warned".
- **Unknown / error:** the tool says it could not complete (Vorda exit 2; osv-scanner exit 128),
  or crashed or exited with an error.
- **Can't scan:** the tool saw none of the target's labelled packages.
- **Time:** wall time per run, tools run one at a time. Database download time and size are
  recorded separately.
- **Network:** every tool runs twice: online (its default) and offline, inside a network namespace
  with no interface (`unshare --net`), after its database was fetched. A tool that needs the network
  offline shows up as errors or misses in the offline rows.

## Run

Linux with `unshare` (user namespaces), `git`, `curl`, `bc` and Python 3. Labelling ground truth
also needs a signed-in `gh` for GHSA lookups; the committed `labels.json` files make that optional.

```sh
export BENCH_HOME=/path/to/scratch          # peaks near 5 GB: one large database at a time
./setup-tools.sh
./fetch-corpus.sh
./run-all.sh                                # vorda, osv-scanner, trivy, grype in turn
python3 -I score.py repos-union "$BENCH_HOME/raw/repos-union.json"
python3 -I label.py inventory "$BENCH_HOME/raw/repos-union.json" "$BENCH_HOME/raw/repos-labels.json" --no-ghsa
python3 -I score.py score "$BENCH_HOME/raw/repos-labels.json" results/DATE.json "$BENCH_HOME/tables.md"
```

`run.py TOOL --only CORPUS --targets NAME,... --modes online` reruns a subset. `run-tool.sh`
deletes the Trivy and Grype databases after their runs (each is over 3 GB). Remove `$BENCH_HOME`
when done. The results page is the written summary followed by the generated tables.

Notes from the 2026-11-22 run:

- osv-scanner and Trivy cannot open an OCI archive, so `fetch-corpus.sh` also saves each image as a
  Docker archive and `run.py` gives them that copy.
- Online Maven resolution by osv-scanner and Trivy got this machine rate limited by Maven Central
  (HTTP 429, about 30 minutes). Space out reruns of the Maven targets.
- Go `stdlib` entries (from the `go` directive) are left out of repository scoring, and RubyGems
  platform builds (`1.19.0-x86_64-darwin`) are folded into their version; both are counted
  separately as `stdlib_findings` and `duplicate_findings` in the JSON.

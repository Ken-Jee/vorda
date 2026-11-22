# Saved inventory reader

`snapshot::read(snapshot_json, grant_json, query_json, as_of)` returns a typed
`ReadResponse` or `ReadError` with no I/O. Success JSON includes an `op` discriminant,
a shared snapshot/scope/coverage envelope, and a list, count, detail, or evidence view.
Errors serialize as snake_case tags; a transport would need to wrap them as `{error: tag, data: null}`.

This boundary takes trusted immutable fixture or import assertions and an injected grant.
It does not authenticate a caller, and has no MCP, network, credential resolver,
enrollment, collector, or revision allocator. Existing Link v1 and local repair behavior
do not change.

A snapshot holds `contract_version: "m0b-derived-1"`, `header`, `catalog_tuples`,
`assessment_bindings`, `records`, `evidence`, and `retained_payload_utf8`. The header
gives snapshot/catalog IDs and positive revisions. Each assessment ID/revision binds an
input digest, and every record must match a catalog tuple and its assessment and
evidence input digest. Source payloads are UTF-8 strings hashed raw without
normalization. Hashes check integrity only, not that source bytes prove the package or
time assertions.

The grant sets the same four header fields, positive `grant_revision`, and complete
clauses for tenant/site/device/generation/scope/source/evidence_class/evidence. Axes are
AND within a clause; clauses are OR. Multi-value axes allow catalog-valid Cartesian
combinations; empty axes or clauses deny access. Queries may narrow scope and filter
exact ecosystem/name; unknown or ungranted scopes return the same refusal. Missing and
inaccessible detail/evidence IDs share one error. Validation runs snapshot, grant,
query, then view.

All inputs reject duplicate keys and unknown fields. Limits: 4 MiB snapshot, 64 KiB
grant, 16 KiB query, depth 24, strings 4096 bytes (except `retained_payload_utf8` texts,
bounded only by snapshot size), keys 128 bytes, arrays/objects 2000 entries, 128
clauses/catalog tuples/evidence. IDs are bounded opaque strings, not paths or patterns.
Times are nonnegative decimal strings with at most 18 integer and 18 fractional digits;
original strings stay intact and age subtraction is exact. Optional EPSS is a decimal
string. Unknown observations keep null age; future times flag skew. Missing record
coverage becomes explicit unknown coverage; noncomplete coverage needs a reason. This
boundary never emits global-clean or verified-fix claims.

Safe records drop locations, aliases, and qualifiers. Counts use full internal package
tuples, including qualifiers. Coverage is restricted to authorized assessment/scope bindings
before package filtering. Evidence holds only matching safe member records.
`projection_utf8` is compact sorted-key JSON with unescaped Unicode and ID-ordered
records; `projection_sha256` hashes those exact bytes. `source_sha256` still binds the
original retained artifact.

`rust/tests/fixtures/snapshot-reader.json` freezes 44 original and 27 supplemental
acceptance cases, with explicit safe-projection and count-output corrections. Fixtures
deduplicate identical inputs; each case gets fresh serialized inputs. Original fixture
docs and the independent expectation-preparation receipt stay in private evidence outside this repo.
This is not fleet alpha acceptance, authentication, or a production service.

## Local command

`vorda snapshot-read SNAPSHOT.json GRANT.json QUERY.json AS_OF` reads three explicit local
files and prints one JSON response to stdout. `AS_OF` is a trusted decimal timestamp, such
as `1793898330`. Snapshot, grant, and clock are trusted-local inputs, not authentication.
It does no file search, scan, network request, or state init, even if you pass
`--state DIR` before the command.

Success exits 0. Refusals exit 2 with `{ "error": TAG, "data": null }` on stdout and never
leak input paths or contents. Missing, unreadable, non-file, malformed, or oversized files
map to `integrity_failure` (snapshots), `invalid_grant` (grants), or `invalid_query`
(queries or clock). Each read stops at its size limit plus one byte. Validation runs
snapshot, then grant, then query. A wrong argument count is a usage error: exit 64
(EX_USAGE), nothing on stdout, and `{"error": MESSAGE, "status": "usage_error"}` on
stderr. `snapshot-read --help` prints usage.

For before/after checks, run the command once per saved snapshot with its bound grant,
then compare scoped responses by component ID. It never diffs snapshots or infers fixes
from missing records.

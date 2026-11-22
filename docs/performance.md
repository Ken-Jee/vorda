# Hub read and ingest performance

These figures come from one run of a hub with 10 devices and 50,000 stored observation rows, filled through real admission and then read. This page covers what was measured, what was not, and how to repeat it. It records one machine on one day, not a service-level promise.

**You can reach 10 devices and 50,000 observations through normal admission.** One `perf_hub admit` run admitted 25,000 assessments (50,000 observation rows) through `Admission::admit_at` within the default 1 GiB ceiling with no `503`. All reads below ran on that same hub; no hub on this page was filled by direct database writes.

| | Schema 2 (default) | Schema 3 (after `migrate --change-log`) |
| - | - | - |
| Full `changes` walk, 50,000 rows, limit 100 | 551 s, 618 pages, page p50 885 ms | 14.5 s, 618 pages, page p50 22.8 ms, p95 28.5 ms |
| Process memory peak during the reads | 573 MiB | 27 MiB |
| Admission p95 while a `changes` walk runs | 86 ms (max 137 ms, the wait limit is 200 ms) | 41 ms (max 45 ms) |
| Database file | 545 MiB | 592 MiB (+8.6%) |

Measured on commit `6f8d381` (main after the change log landed). Every number in these tables is detailed in "Results" with its run ID.

## The hub

One hub, built once:

- 10 devices (two per site, five sites), 391 authorities (scope and source pairs), and 25,000 assessments of 2 observations each (50,000 `v2_observations` rows). Most authorities hit the retention cap of 64 assessments (`MAX_ASSESSMENTS_PER_AUTHORITY`). The hub also holds 782 current records, two per authority.
- Filled authority by authority in order through `Admission::admit_at` with synthetic artifacts. A producer store captured and exported each request before admission, so every row went through normal checks and transactions.
- Tested in two states from the same data: **schema 2** as admitted, and **schema 3** after `vorda link migrate --change-log`. `migrate` saves the schema 2 hub as `hub.db.v2-backup`, copied for this comparison. Both states answer every route identically and differ only in how `changes` is computed (`docs/linking.md`, "Schema 3: the change log").

Most rows are retained history. Readers see only current records; older assessments are used only by `changes` and storage.

## Machine and method

- A desktop PC running Linux in a WSL2 VM: AMD Ryzen 5 5600X (12 logical CPUs), 25.4 GiB visible memory, Linux 6.6 WSL2 kernel, rustc 1.99.1, release build with `--locked`. The database sat on the VM's local ext-family virtual disk, with nothing else running (starting load average 0.3).
- Run once on 2026-11-09. Nothing was repeated unless a table says "run 2".
- Uses `rust/examples/perf_hub.rs` as committed. `perf_hub query` runs server and client in one process on a loopback socket, with a fresh connection per request, 1 warm-up and 20 timed rounds, one request at a time. Memory covers that whole process, not a separate `link serve`.
- The reader is granted every site. Responses are real HTTP answers (answer size is body length). `query` panics on any non-200 reply (or no answer) across single requests and walks, and the process exits with an error. It is not read-only: each run adds one reader grant to the `.readers` file beside the hub.
- Ingest runs `Admission::admit_at` on the database host directly, with no network, TLS, or `link serve` listener.

### How to repeat

From `rust/`, using fresh `$DB`, `$DB_S2`, and `$WORK` paths on a disk with at least 4 GB free:

```
cargo build --release --locked --bin vorda --example perf_hub
/usr/bin/time -v target/release/examples/perf_hub admit "$DB" "$WORK" 50000
/usr/bin/time -v target/release/vorda link --db "$DB" migrate --change-log
target/release/examples/perf_hub verify-log "$DB"
cp "$DB.v2-backup" "$DB_S2"
/usr/bin/time -v target/release/examples/perf_hub query "$DB" 20
/usr/bin/time -v target/release/examples/perf_hub query "$DB_S2" 20
```

To time admissions during a walk, run on fresh hub copies (each run adds a device and reader grant). This runs `256` admissions, one every `50` ms, with no reader (`idle`) and back-to-back `changes` reads (`walk`):

```
cp "$DB" "$C3"; cp "$DB.v2-backup" "$C2"
target/release/examples/perf_hub admit-during-walk "$C3" "$WORK1" 256 50 idle
target/release/examples/perf_hub admit-during-walk "$C3" "$WORK2" 256 50 walk
target/release/examples/perf_hub admit-during-walk "$C2" "$WORK3" 256 50 idle
target/release/examples/perf_hub admit-during-walk "$C2" "$WORK4" 256 50 walk
```

Commands ran sequentially. `admit` takes about 9 minutes (mostly generating requests); schema 2 `query` takes about 10 minutes because `changes` replays history on every page. Expect the same orders of magnitude and schema 2 vs. schema 3 ratios, not the exact milliseconds.

## Runs and logs

Every figure below cites its run. Maintainers keep the raw `perf_hub` JSON and `/usr/bin/time -v` logs outside this repository.

| Run | Command | Log |
| - | - | - |
| R1 | `admit "$DB" "$WORK" 50000` | `gate.log` |
| R2 | `migrate --change-log`, then `verify-log` | `gate.log` |
| R3 | `query` on the schema 3 hub, run 1 | `gate2.log` |
| R4 | `query` on the schema 3 hub, run 2 | `gate2.log` |
| R5 | `query` on the schema 2 copy | `gate2.log` |
| R6, R7 | `admit-during-walk` on schema 3, `idle` then `walk` | `gate2.log` |
| R8, R9 | `admit-during-walk` on schema 2, `idle` then `walk` | `gate2.log` |

An earlier attempt at R3 right after copying files for R5 to R9 (before `gate2.log`) failed when one `status` read got no reply: the hub closed the connection after at least 5 seconds (see "Limits"). R3 and all later runs were repeated on the same hub files and passed.

## Results

### Ingest (R1)

| | |
| - | - |
| Requests admitted | 25,000 (50,000 observation rows, 391 authorities) |
| Answers of `503` | 0 (target reached at the 1 GiB default) |
| Hub admission time, summed | 144.7 s |
| Per request | p50 5.5 ms, p95 7.7 ms, max 51.3 ms (budget: 1 s) |
| Producing the requests (capture and export) | 324.5 s, not part of ingest |
| Whole `admit` process | 8 min 59 s wall, 14.5 MiB peak resident |

Only overall percentiles were logged, not admission time by hub size.

### Migrating to schema 3 (R2)

`migrate --change-log` on the 50,000-row schema 2 hub took 8.2 s wall and 51.2 MiB peak resident, writing a full 545 MiB `hub.db.v2-backup`. `verify-log` checked all 50,000 log rows across 391 authorities against an in-memory replay: `stored_equals_replay: true` in 2.0 s.

### Disk (R1, R2, R3)

| | Schema 2 | Schema 3 |
| - | - | - |
| Database file | 571,383,808 bytes (22.9 kB per assessment, 11.4 kB per observation row) | 620,437,504 bytes (12.4 kB per observation row) |
| Write-ahead log file | none | none |

The change log adds 49,053,696 bytes (8.6%). At that rate, the default 1 GiB ceiling holds about 86,000 observation rows on schema 3 (about 94,000 on schema 2).

Payload bytes per table (`SUM(length(column))` over all columns, excluding pages and indexes; R1 for schema 2, R3 for the two schema 3 tables):

| Table | Rows | Bytes |
| - | - | - |
| `v2_views` | 25,000 | 181,773,896 |
| `v2_assessments` | 25,000 | 158,202,415 |
| `v2_observations` | 50,000 | 82,923,124 |
| `v2_deliveries` | 25,000 | 23,207,405 |
| `v2_coverage`, `v2_current`, `v2_authorities` | 782, 782, 391 | 178,296, 151,708, 73,899 |
| version 1 tables with rows (`devices`, `credentials`, `audit`) | 10 each | 880, 1,070, 578 |
| **Schema 3 only:** `v2_changes` | 50,000 | 29,889,470 |
| **Schema 3 only:** `v2_change_state` | 391 | 334,496 |

Schema 2 payload is 446.5 MB of the 571.4 MB file; schema 3 is 476.7 MB of 620.4 MB. Stored views (one per published assessment) take the most space, followed by retained artifacts, then observations.

### Reads, p50 / p95 in milliseconds, and answer size

20 timed rounds each, one request at a time, after 1 warm-up. Schema 3 is R3 (run 1) and R4 (run 2); schema 2 is R5. Every request and walk page returned 200.

| Request | Schema 3, run 1 (R3) | Schema 3, run 2 (R4) | Schema 2 copy (R5) | Answer bytes |
| - | - | - | - | - |
| `devices` | 1.9 / 2.5 | 1.8 / 2.3 | 2.1 / 2.2 | 2,725 |
| `devices` limit 100 | 1.8 / 2.3 | 1.8 / 2.3 | 1.9 / 2.1 | 2,726 |
| `findings` | 1.4 / 1.7 | 1.4 / 1.8 | 1.6 / 2.0 | 634 |
| `status` | 83.0 / 86.7 | 82.0 / 85.4 | 87.2 / 92.3 | 1,452 |
| `sources` | 85.4 / 90.2 | 86.1 / 92.0 | 85.8 / 90.5 | 29,428 |
| `inventory` | 111.5 / 117.7 | 110.5 / 117.0 | 109.8 / 115.7 | 44,929 |
| `inventory` name filter | 99.3 / 102.5 | 100.6 / 107.1 | 98.5 / 101.5 | 1,940 |
| `changes` since start | 16.0 / 17.1 | 16.1 / 17.5 | 888.3 / 916.8 | 52,717 |
| `changes` since start, limit 100 | 17.0 / 18.3 | 16.7 / 18.3 | 885.4 / 916.8 | 77,177 |

Full paginated walks (limit 100 per page; a byte cap trims `changes` pages to about 81 rows on average), one request after another:

| Listing | Schema 3, run 1 (R3) | Schema 3, run 2 (R4) | Schema 2 copy (R5) |
| - | - | - | - |
| `inventory` | 11 pages, 782 rows, 1.23 s (page p50 111 ms, p95 119 ms) | 11 pages, 782 rows, 1.24 s | 11 pages, 782 rows, 1.22 s |
| `changes` | 618 pages, 50,000 rows, 14.5 s (page p50 22.8 ms, p95 28.5 ms, max 39.2 ms) | 618 pages, 50,000 rows, 14.2 s (page p50 22.2 ms, p95 27.4 ms) | 618 pages, 50,000 rows, **551 s** (page p50 885 ms, p95 942 ms, max 1,018 ms) |

Both states return all 50,000 `changes` rows.

Process memory (the whole `perf_hub query` process):

| | Resident before the requests | After | Peak |
| - | - | - | - |
| Schema 3, run 1 (R3) | 7.8 MiB | 8.6 MiB | 26.9 MiB |
| Schema 3, run 2 (R4) | 8.3 MiB | 9.2 MiB | 27.3 MiB |
| Schema 2 copy (R5) | 7.6 MiB | 14.2 MiB | 573.5 MiB |

Schema 2 peaks during `changes` because each page reads and replays every retained row in memory.

### Admissions while a `changes` walk runs (R6 to R9)

256 admissions, one every 50 ms, into a new device outside the reader's view while a reader walks `changes` continuously. Writers wait up to 200 ms for the database lock, so slow reads show up as `503`.

| | Admission p50 / p95 / max | Refused (503) | What the walk saw |
| - | - | - | - |
| Schema 3, idle (R6) | 6.5 / 8.3 / 13.0 ms | 0 | no reader |
| Schema 3, walk (R7) | 16.2 / 40.7 / 44.5 ms | 0 | 813 pages in 21.8 s (one full walk and part of another), page p50 23.9 ms, p95 39.4 ms, no non-200 |
| Schema 2, idle (R8) | 6.1 / 8.3 / 10.3 ms | 0 | no reader |
| Schema 2, walk (R9) | 6.5 / 85.9 / 137.1 ms | 0 | 21 pages in 19.9 s (a walk of 618 pages was not finished), page p50 905 ms, p95 960 ms, no non-200 |

On schema 2, admissions wait for any in-flight page reading retained rows. The 137 ms max is close to the 200 ms limit, from one run.

### What the numbers say

- `devices` and `findings` read only current rows and version 1 tables, so history size does not affect them.
- `status`, `sources`, and `inventory` take about 80 to 120 ms at 391 authorities and 782 current records on both schemas. They scale with authority count, not the change log, and tie up the single-connection listener while running. These runs predate the reply-grace fix: a finished answer now gets at least 225 ms of bounded write time even if processing used the original five-second socket budget. Request receive deadlines and query/admission budgets are unchanged; see `docs/linking.md`.
- `changes` on schema 3 is bounded: 16 to 18 ms per request, about 23 ms per page, and 14 s for all 618 pages. Schema 2 replays history per page: about 0.9 s a page, 551 s total, and twenty times the peak memory. The change log makes a 50,000-row hub readable end to end for 8.6% more disk and slightly more admission work.
- Responses stay small (max 77,177 bytes against the 256 KiB cap) because pages are capped, not because the hub is small.
- Admission p95 is 7.7 ms into a quiet hub (R1) and 8.3 ms idle on schema 3 (R6), against a 1 s budget. During a `changes` walk it rises to 41 ms on schema 3 and 86 ms on schema 2.

## Full assessments

The hub accepts full device assessments: up to 1,500 records, 256 inputs, and 4 MiB (requests up to 4 MiB and 64 KiB; current-record view per authority up to 4 MiB). `evidence` lists at most 100 records with the total count and a truncation note. These figures are **one machine, one run each** on the WSL2 desktop above (release build, `perf_hub full`, in-process `Admission::admit_at`, 1,500 records of one lockfile per assessment, schema 3, default 1 s admission budget). Logs: `perf-full.log` and `perf-lockfile.log` (recorded before a behavior-preserving helper cleanup; log headers say `dirty` from rsyncing the tree).

Admission time after the first assessment, in milliseconds. "In order" sends oldest revisions first; "late" sends newest first, so each later arrival is `historical_only` and recomputes its authority's history from all retained revisions.

| Arrival | Retained revisions | p50 | p95 | max |
| - | - | - | - | - |
| in order | 20 | 192 | 208 | 208 |
| in order | 64 | 214 | 231 | 240 |
| late | 20 | 230 | 338 | 357 |
| late | 64 | 497 | 820 | 837 |
| in order / late, on the lockfile hub below | 20 | 195 / 238 | 214 / 361 | 220 / 364 |

First admission per authority took 168 to 171 ms in every run (`perf-full.log`) and 176 to 177 ms on the lockfile hub. In-order p95 stayed under the 250 ms target narrowly (231 ms at 64 revisions). **Late arrivals at full retention stay under the 1 s deadline with little margin**: p95 820 ms, max 837 ms at 64 retained revisions. Late admissions rebuild the authority's change log from revision one, so cost grows with retained revisions (recomputing only from the first affected revision is not implemented, and no hub checks were relaxed). Headroom is about 16%, measured once on a 32 GB desktop with 1.5 MB artifacts. Slower hosts or larger artifacts (up to 4 MiB) can miss the deadline and get `503 admission_deadline` on every retry because nothing is written and the work repeats. Senders must treat repeated `503` responses on one entry as needing operator attention instead of blocking forever. The one-second budget also starts no later than one second before the 5-second socket deadline, so slow uploads cut into it, and a 4 MiB request needs roughly 7 Mbit/s of upload to arrive at all. Peak process memory was about 0.18 GiB (20 revisions) and 0.5 GiB (64 revisions).

**A 50,000-row hub of lockfile-sized assessments** (`perf_hub admit ... change-log lockfile`: 10 devices, 50 assessments of 1,000 records each, 25 authorities, 50,000 observation rows, no `503`; `perf-lockfile.log`):

| Measure | Result |
| - | - |
| Admission p50 / p95 / max | 107 / 113 / 119 ms |
| Database file | 409,571,328 bytes (about 8 KiB per observation row) |
| `verify-log` | 26,250 change rows, equal to replay, 1.1 s |
| `changes` walk | 321 pages, 26,250 rows, 16.0 s (page p50 48 ms, p95 53 ms) |
| `inventory`, one request | p50 736 ms, p95 864 ms |
| `inventory` name filter | p50 386 ms, p95 429 ms |
| `inventory` full walk | 348 pages, 25,000 rows, **285 s** (page p50 802 ms, p95 924 ms, max 2.4 s) |
| `status`, `sources` | p50 51 and 50 ms |
| Process peak memory during the reads | 482 MiB |

The `changes` walk meets the m6s3 gate under 60 s. `inventory` does not: each page reads all 25,000 current records of the grant before slicing, costing about 0.8 s per page and about five minutes for a full walk. Cost grows linearly with rows in the grant: at about 150,000 current rows (roughly 100 devices sending full assessments), one page would exceed the original five-second socket budget. Reply grace avoids dropping a finished reply, but does not speed up the query; it still holds the single request slot and delays admissions. That query cost is unchanged.

**Disk.** The 64-revision hub in `perf-full.log` holds 128 assessments of 1,500 records in 1,183,645,696 bytes (about 9.2 MB each). Assessments (472 MB) and observations (325 MB) come to about 6.2 MB per assessment, plus about 4 MB for each of the 65 published views (258 MB): about 6 MB per assessment, or about 10 MB if it publishes a view. The default 1 GiB ceiling therefore holds on the order of 100 to 170 full assessments (about 116 at this mix), versus tens of thousands of two-record ones. Raise `--max-db-mib` (`docs/linking.md`) when serving full assessments. Per-device caps no longer isolate devices: one device can fill the default ceiling, after which every device gets `503`. Per-device byte quotas are a future item.

## Limits of these measurements

- **One machine, one day, one run.** Every figure is one run of 20 timed requests, except schema 3 reads, which were run twice (R3, R4); they agreed within a few percent, which is the only variance information there is. Admission and migration are single runs.
- **Loopback, single process.** Client and server share one process over loopback, with no network, TLS, `link serve`, real device, or concurrent readers.
- **Synthetic data.** Generated artifacts repeat the same shape per authority. Real devices vary in artifact size, source count, and change frequency.
- **One slow read, one dropped connection.** The first schema 3 `query` on the fresh hub failed when the hub closed a `status` connection with no answer. Because the 5 second socket deadline starts at accept, that read took at least 5 seconds against about 83 ms normally (which of the 21 `status` requests, warm-up included, is unknown). About 2.9 GB had just been written to the same disk (migration plus three 600 MB copies). It never recurred across about 540 later `status` requests, a rerun, or a one-round check on a copy. Disk writeback right after the copies is the likely cause, though unproven. It is a real measurement of a worst case: a read can spike far past its median, and these runs do not show how often.
- **Schema 2 replay is slower.** On schema 2 (the default before `migrate --change-log`), `changes` takes about 0.9 s per page: about nine minutes and over 570 MiB peak for 50,000 rows, while concurrent admissions can use much of their 200 ms allowance (p95 86 ms, max 137 ms in R9).
- **Late arrivals are measured only with full assessments.** Earlier tables are all in order. Late (`historical_only`) arrivals appear only in "Full assessments", close to the 1 s deadline at 64 retained revisions.
- **Nothing was measured cold.** The page cache was warm for every read, and the disk is not an HDD.
- **Not measured at all:** network ingest, `link serve`, TLS, real devices, concurrent readers, heavy-read ingest (beyond R6 to R9), `evidence` and `device` routes, filtered `changes`, cursor reuse after writes, non-default freshness policies, hubs over 50,000 rows (retention allows 81,920 for 10 devices), restore, and schema 3 to schema 2 rollback.
- **Not a promise that a hub should hold 50,000 rows.** This shows one machine reached 50,000 rows through admission and read them end to end on schema 3, once.
- **Unused tool command.** `perf_hub clone` still exists (direct SQL rows, no ingest measurement), and no figure here uses it.

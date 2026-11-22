# Verification and repair

Read this when asked whether something was fixed, or to fix it.

## What counts as verified

A repair is verified only by a new native assessment that is eligible to show it: collected
after the change, covering the same device, scope and source, with `inventory` and `advisories`
coverage `complete` and no failed inputs. Read it through `sources` (new `assessment_revision`,
later `observed_at`, complete coverage), `changes` (the component moved between assessments) and
`evidence`; then the package version in `inventory` should be the fixed one.

`findings` and `device` lists come from the older delivery path, which can be older than the
native assessment or absent for a device that only delivers natively. A finding missing from
them is never verification by itself. If only those lists exist for the device, say that there
is no new native assessment and the repair is unverified.

Not verification:

- The user, a log or a package manager says it was updated.
- The `findings` list is empty or shorter, whatever its coverage: it is dated by its own
  `received` time and is not an assessment of the changed package.
- An `ack` (delivery only) or a dismissed message.
- `changes` showing a version difference with no later complete assessment.
- A different source or scope looking clean.
- A source the device retired (`retired`): it says the device stopped reporting that source, not
  that its packages were fixed. Its components show as `retired` in `changes`, never `resolved`.
- A `late: true` row in `changes`: it came from a revision that arrived after a newer one, so
  it is not the newest state of that component. Take the newest state from `inventory`/`sources`.
- Advisories coverage `unavailable`: the provider did not answer, so even a complete inventory
  says nothing about advisories until a later assessment has them.

## Reading `changes` rows

An assessment that arrives in order adds its own rows. A late one makes the hub recompute that
source's rows from its first retained revision, so rows you read earlier for it can differ
later; re-read before quoting an old page. Rows are ordered by receipt time, not by when the
change happened.

`evidence` coverage may carry `fix_verified` and `global_clean`. They are booleans the
delivering device asserts, so they are the device's own claims. The hub refuses an artifact
that sets either to `true` (it accepts only `false` there, and a non-boolean is refused as
well), so a stored row shows `false`; treat a `true` you meet anywhere else as unverified.
`true` is never verification by itself; report them with their `coverage` and do not turn
`null` or `false` into a claim.

## Who does what

- Fleet tools cannot scan or repair. If a fresh assessment is needed, the device owner runs
  a scan and delivers it; then read again. Name the device and what must be re-collected.
- On the local service, a scan (`check`) is a collection step. Run it only when the user asks, or
  after telling them and getting a yes; say that it ran, and read its coverage before trusting
  it. It does not apply changes.
- Applying a repair belongs to the user and the host's policy, through a separately configured
  repair interface. A read grant is not authority to change files. Show the proposed change first
  (a dry run where one exists), say what it touches and what it cannot undo, and wait for the
  user's decision. A repair interface may offer a tool named `verify`; it reports the repair's
  own status and proof, which is not verification as defined here.
- After a repair, request or wait for a new assessment before saying anything is fixed. Until
  then say "applied, not yet verified" and give the time of the last observation you saw.

## Reporting

Say what was done by whom, which assessment (device, source, `assessment_revision`,
`observed_at`) shows the result, what coverage it had, and what remains unverified. If the new
assessment is still partial, name the gap and the step that would close it.

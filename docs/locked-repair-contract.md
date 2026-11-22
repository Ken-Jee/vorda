# Native npm lock repair

This workflow updates one exact direct npm dependency to a higher stable patch
version with npm lockfile v2/v3. The host supplies absolute Node and npm JS
paths and an exact check argv. Runtime files must be regular, owner/root owned,
and not group/other writable. Clean standalone Git repos only.

The resolver runs in an isolated clone with empty user/global npm config, scripts
off, no audit/fund calls, and the public npm registry. Existing and new lock
entries must use HTTPS registry.npmjs.org tarballs with no credentials, custom
ports, links or Git/file dependencies. Unsupported sources and custom .npmrc
files need manual repair. Planning and drafting never touch the source repo.

Review the exact manifest/lock diff and plan digest. Draft checks must pass, and
locked apply requires explicit host approval naming that digest. Changed or dirty
source, stale findings, mismatched drafts and unknown rescan coverage block
apply. A covered rescan of the repaired package must show the claimed advisory
gone; sibling findings stay active. Failed apply uses the rollback/recovery path,
and unresolved recovery blocks further repairs.

Manual fallback: update on a separate branch with the project's trusted package
manager, review the lock diff, run your checks, then rescan the same source.
Unsupported formats, ranges, major/minor bumps and provider PR publishing are
outside this workflow.

Run offline controls with `cargo test --locked --manifest-path rust/Cargo.toml`.
The opt-in network integration test is:

```sh
VORDA_TEST_NODE=/absolute/node VORDA_TEST_NPM=/absolute/npm/bin/npm-cli.js \
cargo test --locked --manifest-path rust/Cargo.toml --test real_npm_repair -- --ignored
```

It hits the real public npm registry and advisory feeds against synthetic repos,
updates minimist 1.2.5 to 1.2.8, tests the reviewed-digest approval guard and
keeps unrelated evidence. It is opt-in and does not certify other runtimes or
platforms.

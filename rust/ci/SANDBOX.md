# Isolated development acceptance

Set `VORDA_EXPECTED_SHA` to the reviewed commit, then run
`VORDA_CI_ROOT=/path/to/dedicated-directory bash source/rust/ci/sandbox.sh`
inside a disposable Linux sandbox. Put the trusted checkout at `$VORDA_CI_ROOT/source`.
The checkout must have no tracked, untracked or ignored changes.
Install Rust, Git, jq, bubblewrap and util-linux first, and set `VORDA_CONTROLLER`
to a verified native development controller binary. Set
`VORDA_CONTROLLER_SHA256` to its reviewed digest. The script checks this digest
and the pinned controller sources before running product Cargo. The outer controller must
limit VM memory and lifetime, serialize users, retain logs and stop the VM on every
outcome. Never give source jobs hosting or source-control credentials.

Each invocation fetches locked archives, executes all acceptance tests using the
persistent compiled target, then smoke-tests a copied binary before and after
promotion. A previous binary is retained for rollback and smoke-tested on subsequent
runs. This deploys only a local executable; it does not publish a service.
Global Node package directories are hidden, wherever present on the host, in a temporary mount namespace to keep
fixture expectations independent of installed agent tools.

Diagnostic cache reports never replace test execution. The controller can suppress
duplicate deliveries of a completed commit, but a newly admitted run always tests.
A GitHub status must name the exact tested commit. Private repository plan limits
may prevent making that status a required merge check; a posted status is not merge
enforcement.

# Scanner test fixtures

These lockfiles, OCI archives, and JSON feeds are test data for Vorda's scanner tests. Many pin deliberately vulnerable package versions so the tests can find them; never install from these files or copy them into a project. Automated dependency update tools ignore this folder and `rust/tests/fixtures`, so update pull requests should not appear; do not merge any that do. The finding ID strings in `feeds.json` are made-up fixture IDs, not secrets.

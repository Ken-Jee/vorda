# Security policy

## Reporting a vulnerability

Please report security problems in Vorda privately through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue, pull request or discussion for
a security problem.

Include what you can of:

- the Vorda version (`vorda --version`) or source commit, and your platform;
- the command, input files or configuration that show the problem;
- what happened and what you expected, and the impact you see.

You will get an acknowledgement through the report. Fixes are made in private and
the report is published as a GitHub security advisory once a fix is available.

## Scope

In scope: the `vorda` executable and its MCP servers, the local dashboard, the hub
(`vorda link`, `vorda hub-mcp`), the installer scripts, the GitHub Action and the
agent plugin in this repository.

Especially relevant:

- a scan that reports clean (exit 0) when it did not check something;
- reading or writing outside the folder or state directory you selected;
- the dashboard, MCP servers or hub acting on a request they should refuse;
- text from scanned files or advisory feeds reaching an agent as instructions;
- a way around `verify-self` or the installer's checksum check.

Out of scope: vulnerabilities in the packages Vorda reports (report those to their
maintainers), and mistakes in public advisory data (report those to the source, such
as OSV.dev).

## Supported versions

Fixes go to the latest release (`0.2.1`) and the latest commit on the default branch.

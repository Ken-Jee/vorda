# Vorda documentation

Start with the [README](../README.md), then [status and limits](status.md).

## Install and run

- [Install and verify](install.md): installers, checksums and signatures
- [Support matrix](support-matrix.md): what each platform has been checked on
- [Command reference](cli.md): every command's usage
- [Technical reference](reference.md): inputs, matching, offline database, exit codes, modes,
  schedules and the dashboard
- [Storage](storage.md): the state directory and recovery

## Use with agents and CI

- [Vorda for AI agents](agents.md): MCP setup, JSON and exit codes
- [Native MCP workflow](native-mcp-workflow.md)
- [Scan MCP servers, skills and agent tools](scan-mcp-servers-for-cves.md)
- [Vulnerability alerts for AI coding agents](vulnerability-alerts-for-ai-agents.md)
- [GitHub Action and SARIF](github-action.md)
- [Live alerts page](alerts/index.html): a static page that reads OSV.dev, FIRST EPSS and
  CISA's known-exploited list in your browser

## Results and inventory

- [Private asset summary](assets.md)
- [Saved public updates (dashboard Feed)](feed.md)
- [Chrome applicability](browser-applicability.md)
- [Installed-software metadata](installed-sources.md)
- [Local OCI archive inventory contract](oci-archive-contract.md)
- [Saved inventory reader contract](saved-snapshot-reader.md)

## Repairs

- [Verified vulnerability repairs](repair-contract.md)
- [Native npm lock repair](locked-repair-contract.md)
- [Publish an approved repair as a pull request](repair-pr-contract.md)

## The hub (experimental)

- [Self-hosted result linking](linking.md)
- [Deploy result linking](linking-deployment.md)
- [Attach an agent client to the hub](fleet-clients.md)
- [Native capture](native-capture.md)
- [Hub limits and measured performance](performance.md)

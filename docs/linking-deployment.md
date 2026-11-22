# Deploy result linking

Run a small local hub you control, with no cloud account. Start with [enrollment and data consent](linking.md), and keep hub and outbox databases separate. These setups add no org login, collectors, remote commands, or remediation. Local scans still work if delivery fails.

## Authenticated HTTPS

Install the [native executable](install.md) on each machine (no Python or venv needed) after checking the [support matrix](support-matrix.md). Get a certificate whose subject alternative names include the hub name, and put its private key in your secret manager. Set owner-only permissions on the key and database folder (on Windows, limit ACLs to the task account). Never commit keys or credentials.

On the hub:

```sh
vorda link --db ./hub.db serve --bind 0.0.0.0 --port 7781 --cert ./hub.crt --key ./hub.key
```

Without both certificate and key, the hub refuses any non-loopback bind. It requires TLS 1.2 or later, handles one request at a time, and applies a five-second connection and handshake timeout. Limit firewall access and connection rates to your clients; this small listener is not a public edge server.

Register an invite locally (linking.md). On the endpoint, inject invite and device credentials from your secret manager:

```sh
vorda link --db ./outbox.db enroll --hub https://hub.example.test:7781 --ca-file ./issuer.crt --invite-env LINK_INVITE --credential-env LINK_DEVICE
vorda link --db ./outbox.db queue --result ./state/last-scan.json --consent
vorda link --db ./outbox.db send --hub https://hub.example.test:7781 --ca-file ./issuer.crt --credential-env LINK_DEVICE
vorda link --db ./outbox.db health
```

Skip `--ca-file` if your certificate chains to the system trust store. A private CA file sets the trusted roots without disabling hostname or certificate checks. Redirects fail; unknown CAs and name mismatches fail while keeping queued results. Each send tries one batch, so check `delivered`, `queued`, `attempts`, and `next_attempt` in its JSON. Exit zero means the command ran, not that it delivered. Revocation and permanent errors need operator action.

You can also terminate TLS at a reverse proxy in front of the default loopback HTTP listener. Keep the hub on loopback, preserve the Authorization header, and never log or forward bearer tokens elsewhere. Set a 1 MiB body limit, connection limits, and timeouts at the proxy. Direct requests without a valid invite or device credential still fail. There is no network admin or snapshot route.

You can run this same HTTPS connection over an existing private Tailscale or WireGuard network. Use a hub name in the certificate with the matching trusted CA, and limit access to enrolled endpoint operators. Tunnel headers never grant Vorda identity, and no vendor integration is needed. Cloudflare Access service-token/JWT verification and vendor proxies are not implemented; do not treat Access as origin auth or swap app auth for browser login. No account, public tunnel, or DNS setup is included.

## Linux user services

Install the verified binary under `$HOME/.local` (`$HOME/.local/bin/vorda`). Put the cert and key at `$HOME/.config/vorda/hub.crt` and `hub.key`, and make `$HOME/.local/state/vorda` private. Test the binary before copying [vorda-hub.service](../packaging/linking/vorda-hub.service) to `$HOME/.config/systemd/user/`:

```sh
"$HOME/.local/bin/vorda" --help
```

If the binary is missing, install it first. The unit runs this absolute path with `link` and needs no shell PATH, Python, or venv. Quoted paths support spaces in home folders. If you used another prefix, update the unit's quoted path and keep state, cert, and key paths absolute and quoted.

Verify the unit before starting it, then enable it as your normal user:

```sh
systemd-analyze --user verify "$HOME/.config/systemd/user/vorda-hub.service"
systemctl --user daemon-reload
systemctl --user enable --now vorda-hub.service
journalctl --user -u vorda-hub.service
```

The hub stores credential verifiers, not the secrets, so the service needs no device secrets. Register invites and rotate or revoke locally on the same database. Port 7781 is default; change the bind address to use one interface. User services stay up while your user manager runs; surviving logout or reboot depends on host linger policy. These commands do not change that policy and need no root for user-space scans.

On an endpoint, make an executable `$HOME/.local/bin/vorda-send` wrapper that injects `LINK_DEVICE` from your secret manager and runs this command with absolute paths:

```sh
"$HOME/.local/bin/vorda" link --db "$HOME/.local/state/vorda/outbox.db" send --hub https://hub.example.test:7781 --ca-file "$HOME/.config/vorda/issuer.crt" --credential-env LINK_DEVICE
```

Swap in that endpoint's paths and pass back the command's exit code. Keep credentials in your secret manager, never in the wrapper, unit, or EnvironmentFile. Copy [vorda-send.service](../packaging/linking/vorda-send.service) and [vorda-send.timer](../packaging/linking/vorda-send.timer) to the user unit folder, then run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now vorda-send.timer
systemctl --user start vorda-send.service
journalctl --user -u vorda-send.service
```

The timer retries one queued batch about once a minute, respecting saved backoff. It never scans or queues the same saved scan again; queue each new scan once with its consent and redaction policy. Check health separately, as a quiet timer does not prove an empty outbox.

## Windows scheduled delivery

Install `vorda.exe` and store state on local NTFS. Enroll and queue from PowerShell using the same CLI commands. Write a local `Send-Vorda.ps1` wrapper that fetches `LINK_DEVICE` from your secret manager for this process only, runs `send` with absolute paths, and passes back its exit code. Once the secret is injected, the call looks like this:

```powershell
$Vorda = Join-Path $env:LOCALAPPDATA 'Vorda\bin\vorda.exe'
& $Vorda link --db "$env:LOCALAPPDATA\Vorda\outbox.db" send --hub https://hub.example.test:7781 --ca-file "$env:LOCALAPPDATA\Vorda\issuer.crt" --credential-env LINK_DEVICE
exit $LASTEXITCODE
```

The call operator and quoted arguments handle spaces in paths. Never store the secret in the script, task arguments, task XML, or a permanent user environment variable. Test the wrapper noninteractively before scheduling it. This setup does not certify Windows tasks or installers.

Set `$SendScript` to the wrapper's absolute path, then run this as the normal task user:

```powershell
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -File "{0}"' -f $SendScript)
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName 'VordaSend' -Action $Action -Trigger $Trigger -Settings $Settings -Description 'Retry one queued Vorda result'
Start-ScheduledTask -TaskName 'VordaSend'
Get-ScheduledTaskInfo -TaskName 'VordaSend'
```

By default, the task runs under your interactive logon and is not guaranteed to run after logout. For unattended runs, pick a suitable Windows task identity and secret-manager access policy. No elevation is needed for delivery or supported user-space scans. Check wrapper output and outbox health, not just LastTaskResult. Remove the task with `Unregister-ScheduledTask -TaskName 'VordaSend'`. Native Windows execution stays a separate deployment check.

## Offline file round trip

`export` is only a redacted preview, not a delivery bundle. For offline delivery, register an invite on the hub and enroll locally with separate injected credentials:

```sh
vorda link --db ./hub.db enroll-local --invite-env LINK_INVITE --credential-env LINK_DEVICE > identity.json
```

Send only `identity.json` to the endpoint over a trusted channel. Put the device credential in its secret manager separately; identity files and bundles never hold it. Revoke unused identities if setup stops. On the endpoint:

```sh
vorda link --db ./outbox.db bind --identity ./identity.json
vorda link --db ./outbox.db queue --result ./state/last-scan.json --consent
vorda link --db ./outbox.db bundle > batch.json
```

Review the batch and copy it to the hub without editing its identity, sequence, or payload. `bundle` keeps exporting the oldest pending row without removing it. On the hub, with that device's credential injected:

```sh
vorda link --db ./hub.db import --batch ./batch.json --credential-env LINK_DEVICE > receipt.json
```

Only exit zero produces a usable receipt; keep the batch if import fails. Import runs the same auth, validation, sequence and replay checks, and durable commit as HTTPS. A duplicate returns the original receipt. Copy the receipt back, then on the endpoint:

```sh
vorda link --db ./outbox.db ack --receipt ./receipt.json --credential-env LINK_DEVICE
vorda link --db ./outbox.db health
```

The receipt carries the acknowledgement signed with HMAC-SHA256 under the device credential. Before removing the oldest batch, the endpoint checks that signature plus its identity, generation, sequence, and digest. Forged, edited, or stale receipts leave the queue intact. If a receipt is lost, retry the same bundle and import. A second `ack` fails safely; check health to see what is next. Finish receipt exchange before rotating credentials, or re-import with the new credential for a fresh receipt.

Each batch, receipt, or identity read is capped at 1 MiB. Copied files and removable media still reveal package inventory, so protect them per your data policy and keep them off the public site. Never send source files or device credentials with a bundle. File transport is not encryption, a hub backup, or a site collector.

These steps do not certify two-host routing, native Windows scheduling, vendor tunnels, or org capacity. Test those in an isolated approved environment before deploying.

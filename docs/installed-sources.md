# Selected installed-software metadata

Read metadata from Windows registered apps with `vorda inventory --installed-apps`, or point `--installed-root PATH` at one supported metadata file or one macOS `.app` bundle (repeat for more). Inventory reads do not check advisories; `scan` and `check` evaluate supported packages separately.

```sh
vorda inventory --installed-apps
vorda inventory --installed-root /Applications/Example.app
vorda inventory --installed-root /selected/environment/example.dist-info/METADATA
vorda inventory --installed-root /selected/image-sbom/syft.json
```

For MCP, set top-level `installed_apps` and `installed_roots` in your local `config.json`; agents cannot enable extra host sources. See [native MCP workflow](native-mcp-workflow.md) and [Assets](assets.md).

## Sources and limits

| Source | Reads | Evidence and limits |
| --- | --- | --- |
| Windows Uninstall | Current-user HKCU and readable HKLM `Software\Microsoft\Windows\CurrentVersion\Uninstall`, separate 32-bit and 64-bit views | Reads key, DisplayName, DisplayVersion, Publisher, and InstallLocation. Each hive/view gets its own outcome. Names alone never merge entries. Excludes MSIX/AppX and other users' hives. |
| Current-user MSIX activation registrations | Immediate key names under HKCU `Software\Classes\ActivatableClasses\Package` via read-only native registry calls | Included by `installed_apps`, with its own `windows-msix:HKCU:activatable-packages` outcome. Reads full package ID and four-component version (keeping malformed or unknown versions). Excludes packages without activation registrations; completion covers this registry key only, not all MSIX apps. Reads no key values, child keys, manifests, binaries, or other accounts. |
| Selected MSIX manifest | One regular `AppxManifest.xml` | Reads Identity Name and Version from the file only, not user registration, install state, publisher trust, or execution. Advisory mapping is unsupported. Runs no package-manager commands or other-user checks. |
| macOS bundle | Selected `.app/Contents/Info.plist` or `Info.plist` (XML or binary plist) | Reads bundle ID, name, short version, and build. No recursion or launches. A present bundle with unreadable metadata stays unknown. |
| Flatpak | Selected regular `metadata` file | Reads app/runtime ID and referenced runtime. Branches are not app versions; versions and advisory mapping stay unknown. Pick a regular deployment file or copy; symlinks are refused. |
| Snap | Selected regular `snap.yaml` | Reads name and declared version. No snapd calls, image extraction, or package commands. Advisory mapping is unsupported. |
| Nix | Selected regular `manifest.json`, manifest versions 1–3 | Reads active named or attribute-path entries and store refs. No store walks, evaluation, realization, or version guesses from store names. Entries without a usable ID stay unknown. Older `manifest.nix` is unsupported. |
| Python environment | Selected `METADATA` | Reads Metadata-Version, Name, and Version headers. No Python execution, env activation, imports, or package installs. |
| Portable/bundled npm | Selected `package.json` | Package's own name and version only. Dependencies are not treated as installed. No binary/PE scans or scripts. |
| Maven artifact | Selected `pom.properties` | Reads explicit groupId, artifactId, and version; refuses escaped Java properties. No POM interpolation, dep resolution, JAR extraction, or Maven runs. |
| NuGet | Selected `packages.lock.json`, or found inside an explicit project `--root` | Reads resolved Direct, Transitive, and CentralTransitive entries (skips project refs); lock versions 1–2 only. Framework maps do not prove installs. Missing resolved versions stay incomplete. No MSBuild eval or restore. |
| Image/SBOM metadata | Selected `syft.json` file, via the existing Syft adapter | Reads language packages supported by that adapter; RPM entries stay visible as `Unmapped:rpm`. An SBOM is imported evidence, not a fresh image scan, so observation time and age stay unknown. No image pulls, daemon access, or converter runs. |

Selected files are capped at 4,000,000 bytes under standard regular-file, symlink, and hard-link rules. Arbitrary directories are refused, except a single `.app` bundle's fixed metadata path. Collectors never search home folders or follow install paths, dependencies, store refs, Flatpak runtimes, or SBOM paths.

Each Windows hive/view and the MSIX source cap at 10,000 subkeys, 4,000,000 bytes of accumulated metadata, and five seconds of enumeration work. Uninstall buffers hold 4,096 UTF-16 code units; MSIX key-name buffers hold 256. A limit or error result is partial, not a successful empty inventory. Reads use current permissions only: no elevation, launches, uninstall-string reads/runs, Win32_Product queries, network calls, registry writes, daemon control, or repairs.

MSIX scope follows Microsoft's [current-user registry guidance](https://learn.microsoft.com/en-us/windows/configuration/store/find-aumid), reading only immediate package names instead of the recursive AUMID query.

Windows views follow Microsoft's [alternate registry view guidance](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view). Flatpak and Nix formats follow their [metadata reference](https://docs.flatpak.org/en/latest/flatpak-command-reference.html#flatpak-metadata) and [profile implementation](https://github.com/NixOS/nix/blob/master/src/nix/profile.cc). Format fixtures do not certify a platform.

## Results and unknowns

JSON output includes `source_outcomes` and matching evidence in `input_evidence.observations`. Each source reports its path, collector, observation time, outcome (complete, missing, partial, denied, malformed, unsupported, or unknown), errors, and package count. Failed reads never produce a completed path. An absent selected file or registry source can record observed absence; missing metadata inside an existing bundle cannot.

Each package keeps its source ID, metadata path (when applicable), observation time, presence type (registration, selected metadata, referenced coordinates, selected bundle, or imported metadata), raw version, version evidence, and advisory mapping. Running state is always unknown. Missing or unusable versions become `unknown`, with the raw value kept. Metadata can complete even when vulnerability checks are unavailable.

Display names, bundle IDs, and Flatpak, Snap, Nix, or RPM records never get vulnerability matches just by looking like a package name. Unsupported mapping never means zero vulnerabilities. Even mapped packages do not prove code is running or reachable.

The built-in OCI reader keeps its own [archive contract](oci-archive-contract.md). Still unsupported: direct binary RPM-DB reads, language discovery across image layers, automatic Flatpak/Snap/Nix host scans, full MSIX host discovery, portable PE version resources, whole-environment scans, and Maven project dependency resolution. Point at known metadata or pass a Syft JSON export instead. These limits are separate from reading a selected source.

## Remaining source work

These are deliberate scope limits, not full host discovery:

| Requested breadth | Implemented contract | Remaining work and reason |
| --- | --- | --- |
| Current-user MSIX | Native current-user activation registrations, plus selected manifest identity | Activation registrations are only a subset of MSIX apps; frameworks, resources, and non-activatable packages may be missing. No all-user, staged, or full PackageManager discovery is claimed. A manifest alone never proves registration. |
| Portable PE | Selected portable package metadata only | PE version-resource reading is not built. Filenames and display names cannot establish advisory IDs. This source still needs a bounded native version-resource reader with explicit unknown mapping. |
| Native macOS | Selected XML/binary bundle plist | Not runtime-tested on a macOS host. Reading a selected plist does not certify macOS permissions, bundle discovery, runtime behavior, or installers. |
| Archive-wide language/RPM metadata | Selected Syft adapter and bounded built-in OCI package reader | The adapter does not crawl archives or verify producer completeness or time. Empty Syft input stays partial and cannot retire old evidence. Direct RPM-DB and archive-wide language reads are not built; no daemon or converter runs automatically. |

Selected metadata and explicit Syft imports are what work today; native host scans and archive-wide extraction above remain future work, not finished features. The selected-source controls do not mark native host or archive discovery as done, so those gaps still apply if you need them. Explicit selection keeps the least-access contract, and any future discovery must keep separate source outcomes and bounded access.

Validation scope: Windows current-user collection and MCP opt-ins were tested under a non-elevated, Medium-integrity filtered admin token with the admin role disabled, not a separate standard-user account. Activation-registration coverage stays a subset, and native failure races were tested synthetically.

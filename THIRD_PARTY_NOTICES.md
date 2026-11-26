# Third-party notices

Vorda is MIT licensed. The native executable is built from the locked Rust crates and
embedded fonts listed, with versions and licenses, in
[rust/THIRD_PARTY_NOTICES.md](rust/THIRD_PARTY_NOTICES.md). Original license texts are
kept in `rust/LICENSES/` and embedded in the executable; run `vorda licenses` to print
them. Native packages include these notices and their checksums.

## Fonts

| Name | Version | License | Source | Used for |
|---|---|---|---|---|
| Mona Sans | 2.0.27 | SIL Open Font License 1.1, Reserved Font Name "Mona"; text in `LICENSES/OFL-1.1-mona-sans.txt` | https://github.com/github/mona-sans | Modified (Latin subset, weights 400-700, optical size pinned to text) and renamed "Vorda Sans" because the name "Mona" is reserved. Dashboard text face, and `docs/fonts/vorda-sans.woff2` for the alerts page, with the licence text beside it |
| Geist Mono | 1.9.0 | SIL Open Font License 1.1; text in `LICENSES/OFL-1.1-geist-mono.txt` | https://github.com/vercel/geist-font | Latin subset, weights 400-500, for versions, hashes and commands in the dashboard, and `docs/fonts/geist-mono.woff2` for the alerts page, with the licence text beside it |

## Formats and data

- Release signatures use the [minisign](https://jedisct1.github.io/minisign/) format,
  checked with the `minisign-verify` crate. No minisign code is copied.
- Vorda reads public vulnerability data at run time from the sources listed in
  [data sources](docs/reference.md#data-sources).

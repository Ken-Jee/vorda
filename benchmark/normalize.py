"""Turn each scanner's raw JSON into one shape:

    {"ok": bool, "status": "clean|vulnerable|unknown|error", "exit": ..., "seconds": ...,
     "packages": [[eco, name, version], ...],
     "findings": [{"eco", "name", "version", "ids": [...]}, ...],
     "errors": [text, ...], "warnings": int}

Names are compared through key(), which folds case and PyPI separators.
"""

import json
import pathlib
import re
import urllib.parse

PURL_ECO = {
    "npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "golang": "Go", "maven": "Maven",
    "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist", "pub": "Pub", "hex": "Hex",
    "swift": "SwiftURL", "cocoapods": "CocoaPods", "conan": "ConanCenter", "cran": "CRAN",
    "hackage": "Hackage",
}
TRIVY_ECO = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm",
    "pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "uv": "PyPI", "python-pkg": "PyPI", "conda-pkg": "conda",
    "cargo": "crates.io", "rust-binary": "crates.io", "gomod": "Go", "gobinary": "Go",
    "pom": "Maven", "gradle": "Maven", "jar": "Maven", "sbt": "Maven",
    "nuget": "NuGet", "dotnet-core": "NuGet", "packages-props": "NuGet",
    "bundler": "RubyGems", "gemspec": "RubyGems", "composer": "Packagist", "composer-vendor": "Packagist",
    "pub": "Pub", "hex": "Hex", "swift": "SwiftURL", "cocoapods": "CocoaPods", "conan": "ConanCenter",
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
}
WARN = re.compile(r"\b(WARN|WARNING|ERROR|FATAL|warn|warning|error|failed)\b")


def eco_base(eco):
    """Debian:10 -> Debian, Alpine:v3.12 -> Alpine."""
    return (eco or "").split(":")[0]


def key(eco, name):
    eco = eco_base(eco)
    name = (name or "").strip().lower()
    if eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", name)
    if eco == "SwiftURL":
        name = re.sub(r"^https?://", "", name)
        name = re.sub(r"\.git$", "", name)
    return f"{eco}|{name}"


GEM_PLATFORM = re.compile(r"-(x86|x64|aarch64|arm|arm64|universal|java|mingw|mswin|i686|powerpc|s390x)[-_a-z0-9.]*$")
GO_PSEUDO = {"stdlib", "toolchain"}


def vkey(version, eco=None):
    """Version key; a RubyGems platform build (1.19.0-x86_64-darwin) folds into its version."""
    v = (version or "").strip()
    v = v[1:] if v[:1] == "v" and v[1:2].isdigit() else v
    if eco_base(eco) == "RubyGems":
        v = GEM_PLATFORM.sub("", v)
    return v


def go_pseudo(eco, name):
    """Go stdlib/toolchain entries derived from the go directive, not from a dependency."""
    return eco_base(eco) == "Go" and (name or "") in GO_PSEUDO


def purl_parts(purl):
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?")[0].split("#")[0]
    typ, _, rest = body.partition("/")
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    path = urllib.parse.unquote(path)
    version = urllib.parse.unquote(version)
    if typ == "maven":
        name = path.replace("/", ":")
    elif typ in ("deb", "apk", "rpm"):
        distro = path.split("/")[0]
        return (distro.capitalize() if distro != "alpine" else "Alpine", path.split("/", 1)[-1], version)
    else:
        name = path
    eco = PURL_ECO.get(typ)
    return (eco, name, version) if eco else (typ, name, version)


def _load(path):
    try:
        text = pathlib.Path(path).read_text(errors="replace")
        return json.loads(text) if text.strip() else None
    except (OSError, json.JSONDecodeError):
        return None


def warnings_in(err_text):
    return sum(1 for line in err_text.splitlines() if WARN.search(line))


def vorda(d, meta):
    out = {"packages": [], "findings": [], "errors": []}
    if not d:
        return out | {"ok": False, "status": "error"}
    out["packages"] = [[p.get("ecosystem"), p.get("name"), p.get("version")] for p in d.get("packages", [])]
    for f in d.get("findings", []):
        p = f.get("package", {})
        ids = [f.get("advisory")] + list(f.get("aliases") or [])
        out["findings"].append({"eco": p.get("ecosystem"), "name": p.get("name"), "version": p.get("version"),
                                "ids": sorted({i for i in ids if i})})
    out["errors"] = [e.get("error", str(e)) if isinstance(e, dict) else str(e) for e in d.get("errors", [])]
    # Vorda says "no-known-findings" for a clean answer.
    status = {"no-known-findings": "clean"}.get(d.get("status"), d.get("status", "error"))
    return out | {"ok": True, "status": status}


def osv_scanner(d, meta):
    out = {"packages": [], "findings": [], "errors": []}
    rc = meta["exit"]
    if rc not in (0, 1) or not d:
        status = "error" if rc not in (0, 1, 128) else "unknown"
        return out | {"ok": bool(d), "status": status}
    for r in d.get("results", []):
        for p in r.get("packages", []):
            pk = p["package"]
            eco = pk.get("ecosystem") or (purl_parts(pk.get("purl")) or [None])[0]
            out["packages"].append([eco, pk.get("name"), pk.get("version")])
            # One finding per advisory. Distro records (DLA-, DEBIAN-CVE-, UBUNTU-CVE-) carry the CVE in `upstream`.
            for v in p.get("vulnerabilities", []):
                ids = {v["id"]} | set(v.get("aliases") or []) | set(v.get("upstream") or [])
                out["findings"].append({"eco": eco, "name": pk.get("name"), "version": pk.get("version"),
                                        "ids": sorted(ids)})
    return out | {"ok": True, "status": "vulnerable" if out["findings"] else "clean"}


def trivy(d, meta):
    out = {"packages": [], "findings": [], "errors": []}
    if meta["exit"] != 0 or not d:
        return out | {"ok": False, "status": "error"}
    for r in d.get("Results", []) or []:
        typ = r.get("Type", "")
        default_eco = TRIVY_ECO.get(typ, typ)
        for p in r.get("Packages", []) or []:
            pp = purl_parts((p.get("Identifier") or {}).get("PURL"))
            eco, name = (pp[0], pp[1]) if pp else (default_eco, p.get("Name"))
            out["packages"].append([eco, name, p.get("Version")])
        for v in r.get("Vulnerabilities", []) or []:
            pp = purl_parts((v.get("PkgIdentifier") or {}).get("PURL"))
            eco, name = (pp[0], pp[1]) if pp else (default_eco, v.get("PkgName"))
            ids = {v["VulnerabilityID"]} | set(v.get("VendorIDs") or [])
            out["findings"].append({"eco": eco, "name": name, "version": v.get("InstalledVersion"), "ids": sorted(ids)})
    return out | {"ok": True, "status": "vulnerable" if out["findings"] else "clean"}


def grype(d, meta, cdx):
    out = {"packages": [], "findings": [], "errors": []}
    if meta["exit"] != 0 or not d:
        return out | {"ok": False, "status": "error"}
    for c in (cdx or {}).get("components", []) or []:
        pp = purl_parts(c.get("purl"))
        if pp:
            out["packages"].append(list(pp))
    for m in d.get("matches", []) or []:
        a = m.get("artifact", {})
        pp = purl_parts(a.get("purl")) or (a.get("type"), a.get("name"), a.get("version"))
        ids = {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", []) or []}
        out["findings"].append({"eco": pp[0], "name": pp[1], "version": a.get("version"), "ids": sorted(ids)})
    return out | {"ok": True, "status": "vulnerable" if out["findings"] else "clean"}


def normalize(base):
    """base is the raw path without suffix: .../TOOL/MODE/CORPUS/TARGET."""
    base = pathlib.Path(base)
    meta = json.loads(pathlib.Path(f"{base}.meta.json").read_text())
    err = pathlib.Path(f"{base}.err").read_text(errors="replace") if pathlib.Path(f"{base}.err").exists() else ""
    d = _load(pathlib.Path(f"{base}.out"))
    tool = meta["tool"]
    if meta["exit"] == "timeout":
        res = {"ok": False, "status": "error", "packages": [], "findings": [], "errors": ["timed out"]}
    elif tool == "vorda":
        res = vorda(d, meta)
    elif tool == "osv-scanner":
        res = osv_scanner(d, meta)
    elif tool == "trivy":
        res = trivy(d, meta)
    else:
        res = grype(d, meta, _load(str(pathlib.Path(f"{base}.out")) + ".cdx"))
    if res["status"] == "error" and not res["errors"]:
        tail = [line for line in err.splitlines() if line.strip()][-3:]
        res["errors"] = tail or [f"exit {meta['exit']} with no output"]
    res["warnings"] = warnings_in(err)
    res["exit"] = meta["exit"]
    res["seconds"] = meta["seconds"]
    return res

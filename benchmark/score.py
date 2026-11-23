"""Score every run in $BENCH_HOME/raw and write results JSON + markdown tables.

    python3 -I score.py repos-union OUT.json      # union of packages seen in repos, for label.py inventory
    python3 -I score.py score REPO_LABELS.json OUT.json OUT.md

Scoring rules (also in README.md):
- An advisory is hit when a tool reports any of its ids or aliases on the same package.
- An extra is an advisory a tool reports on a labelled package that matches no label. It is a
  false alarm when OSV has that record for the package (so OSV says this version is not affected,
  or the record is withdrawn); otherwise it is unverified (an id OSV does not hold for that package).
- False clean: the tool's own answer is "clean" (success exit, no findings, no unknown) on a
  target that holds labelled vulnerabilities. A warning on stderr does not change the exit code.
- Can't scan: the tool saw none of the target's labelled packages.
"""

import collections
import json
import os
import pathlib
import sys
import time
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import normalize as nz  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
BENCH = pathlib.Path(os.environ["BENCH_HOME"])
RAW = BENCH / "raw"
TOOLS = ["vorda", "osv-scanner", "trivy", "grype"]
MODES = ["online", "offline"]
OSV_CACHE = RAW / "osv-record-cache.json"


def runs():
    """{(tool, mode, corpus, target): normalized}"""
    out = {}
    for meta in RAW.glob("*/*/*/*.meta.json"):
        tool, mode, corpus = meta.parts[-4], meta.parts[-3], meta.parts[-2]
        target = meta.name[:-len(".meta.json")]
        out[(tool, mode, corpus, target)] = nz.normalize(meta.parent / target)
    return out


class OsvRecords:
    def __init__(self):
        self.cache = json.loads(OSV_CACHE.read_text()) if OSV_CACHE.exists() else {}

    def get(self, vid):
        if vid not in self.cache:
            try:
                with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=60) as r:
                    rec = json.load(r)
                self.cache[vid] = {"withdrawn": bool(rec.get("withdrawn")),
                                   "packages": sorted({nz.key(a["package"]["ecosystem"], a["package"]["name"])
                                                       for a in rec.get("affected", []) if "package" in a})}
            except Exception:
                self.cache[vid] = None
            time.sleep(0.05)
        return self.cache[vid]

    def save(self):
        OSV_CACHE.write_text(json.dumps(self.cache, sort_keys=True))


def tool_groups(id_lists):
    """Merge a tool's own id lists (id + aliases) into groups."""
    groups = []
    for ids in id_lists:
        s = set(ids)
        merged = [g for g in groups if g & s]
        for g in merged:
            s |= g
            groups.remove(g)
        groups.append(s)
    return groups


def score_target(res, labelled, osv):
    """Score one run against one labelled target."""
    by_pkg = collections.defaultdict(list)
    versions = collections.defaultdict(set)  # (package key, id) -> versions the tool reported it on
    for f in res["findings"]:
        k = nz.key(f["eco"], f["name"])
        by_pkg[k].append(f["ids"])
        for i in f["ids"]:
            versions[(k, i)].add(nz.vkey(f["version"], f["eco"]))
    inventory = {nz.key(e, n) for e, n, v in res["packages"]} | set(by_pkg)
    s = collections.Counter()
    detail = {"missed": [], "false_alarms": [], "unverified": []}
    for p in labelled:
        k = nz.key(p["ecosystem"], p["name"])
        s["packages"] += 1
        s["seen"] += k in inventory
        groups = tool_groups(by_pkg.get(k, []))
        label_ids = set()
        if p["advisories"]:
            s["vuln_packages"] += 1
            hit_pkg = False
            for a in p["advisories"]:
                s["advisories"] += 1
                aliases = set(a["aliases"])
                label_ids |= aliases
                if any(g & aliases for g in groups):
                    s["hits"] += 1
                    hit_pkg = True
                else:
                    detail["missed"].append(f"{p['name']}@{p['version']} {a['id']}")
            s["vuln_packages_hit"] += hit_pkg
        for g in groups:
            if g & label_ids:
                continue
            gid = sorted(g)[0]
            verdict = "unverified"
            # A tool that resolved a manifest to another version is not wrong about the labelled one.
            on_label_version = nz.vkey(p["version"], p["ecosystem"]) in set().union(*(versions[(k, i)] for i in g))
            for vid in sorted(g) if on_label_version else []:
                rec = osv.get(vid)
                if rec and (rec["withdrawn"] or k in rec["packages"]):
                    verdict = "false_alarm"
                    break
            s[verdict] += 1
            detail["false_alarms" if verdict == "false_alarm" else "unverified"].append(f"{p['name']}@{p['version']} {gid}")
    has_vulns = s["vuln_packages"] > 0
    claim = res["status"]
    s["false_clean"] = int(claim == "clean" and has_vulns)
    s["false_clean_warned"] = int(claim == "clean" and has_vulns and res["warnings"] > 0)
    # Vulnerable packages missed while the tool still gave a definite answer (clean or vulnerable).
    s["silent_missed_packages"] = (s["vuln_packages"] - s["vuln_packages_hit"]) if claim in ("clean", "vulnerable") else 0
    s["unknown"] = int(claim == "unknown")
    s["error"] = int(claim == "error")
    s["cant_scan"] = int(s["seen"] == 0)
    return s, detail, claim


def labelled_targets():
    out = {}
    for corpus in ("ground-truth", "manifest-only"):
        labels = json.load(open(HERE / "corpus" / corpus / "labels.json"))
        for t, v in labels["targets"].items():
            out[(corpus, t)] = v
    return out


def repos_union(all_runs):
    seen = {}
    for (tool, mode, corpus, target), res in all_runs.items():
        if corpus != "repos":
            continue
        for e, n, v in res["packages"] + [[f["eco"], f["name"], f["version"]] for f in res["findings"]]:
            if e in nz.PURL_ECO.values() and n and v:
                if not nz.go_pseudo(e, n):
                    seen.setdefault((nz.key(e, n), nz.vkey(v, e)), [nz.eco_base(e), n, nz.vkey(v, e)])
    return sorted(seen.values())


def score_repos(all_runs, repo_labels, osv):
    lab = {(nz.key(p["ecosystem"], p["name"]), nz.vkey(p["version"], p["ecosystem"])): p for p in repo_labels["packages"]}
    out = {}
    targets = sorted({t for (_, _, c, t) in all_runs if c == "repos"})
    for tool in TOOLS:
        for mode in MODES:
            agg = collections.Counter()
            per = {}
            for t in targets:
                res = all_runs.get((tool, mode, "repos", t))
                if not res:
                    continue
                union = set()
                for (tl, md, c, tt), r in all_runs.items():
                    if c == "repos" and tt == t:
                        union |= {(nz.key(e, n), nz.vkey(v, e)) for e, n, v in r["packages"] if not nz.go_pseudo(e, n)}
                        union |= {(nz.key(f["eco"], f["name"]), nz.vkey(f["version"], f["eco"])) for f in r["findings"]
                                  if not nz.go_pseudo(f["eco"], f["name"])}
                mine = {(nz.key(e, n), nz.vkey(v, e)) for e, n, v in res["packages"]}
                found = collections.defaultdict(list)
                for f in res["findings"]:
                    found[(nz.key(f["eco"], f["name"]), nz.vkey(f["version"], f["eco"]))].append(f["ids"])
                c = collections.Counter()
                for pk in union:
                    p = lab.get(pk)
                    if not p or not p["advisories"]:
                        continue
                    groups = tool_groups(found.get(pk, []))
                    for a in p["advisories"]:
                        c["advisories"] += 1
                        c["hits"] += any(g & set(a["aliases"]) for g in groups)
                # Noise that the recall numbers hide: go-directive stdlib findings, and the same
                # advisory repeated on one package (e.g. once per RubyGems platform build).
                c["stdlib_findings"] = sum(len(f["ids"]) > 0 for f in res["findings"] if nz.go_pseudo(f["eco"], f["name"]))
                per_pkg = collections.Counter()
                for f in res["findings"]:
                    if f["ids"]:
                        per_pkg[(nz.key(f["eco"], f["name"]), nz.vkey(f["version"], f["eco"]), min(f["ids"]))] += 1
                c["duplicate_findings"] = sum(n - 1 for n in per_pkg.values())
                c["union_packages"] = len(union)
                c["packages_seen"] = len(mine & union) if mine else len(set(found) & union)
                c["false_clean"] = int(res["status"] == "clean" and c["advisories"] > 0)
                c["unknown"] = int(res["status"] == "unknown")
                c["error"] = int(res["status"] == "error")
                c["seconds"] = res["seconds"]
                per[t] = dict(c) | {"status": res["status"], "errors": res["errors"][:3]}
                agg.update(c)
            out[f"{tool}/{mode}"] = {"total": dict(agg), "repos": per}
    return out


def image_cves(res):
    """CVE ids per image. Package names are not compared: osv-scanner names Debian and Ubuntu
    packages by source package while Trivy and Grype use binary package names."""
    ids = set()
    for f in res["findings"]:
        cves = [i for i in f["ids"] if i.startswith("CVE-")]
        ids.update(cves or f["ids"][:1])
    return ids


def score_images(all_runs):
    """Agreement = CVEs that at least two tools report in their online runs; every run is scored against it."""
    out = {}
    images = sorted({t for (_, _, c, t) in all_runs if c == "images"})
    for img in images:
        online = {tool: image_cves(all_runs[(tool, "online", "images", img)])
                  for tool in TOOLS if (tool, "online", "images", img) in all_runs}
        consensus = {x for x in set().union(*online.values()) if sum(x in s for s in online.values()) >= 2}
        for mode in MODES:
            for tool in TOOLS:
                res = all_runs.get((tool, mode, "images", img))
                if not res:
                    continue
                ids = image_cves(res)
                others = set().union(*(s for t2, s in online.items() if t2 != tool))
                out.setdefault(f"{tool}/{mode}", {})[img] = {
                    "status": res["status"], "packages": len(res["packages"]), "cves": len(ids),
                    "consensus": len(consensus), "consensus_hit": len(ids & consensus),
                    "unique": len(ids - others), "seconds": res["seconds"], "errors": res["errors"][:2]}
    return out


def pct(a, b):
    return "n/a" if not b else f"{100 * a / b:.0f}%"


def main():
    cmd = sys.argv[1]
    all_runs = runs()
    if cmd == "repos-union":
        pathlib.Path(sys.argv[2]).write_text(json.dumps(repos_union(all_runs)))
        return
    repo_labels = json.load(open(sys.argv[2]))
    osv = OsvRecords()
    targets = labelled_targets()
    results = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "labelled": {}, "details": {}}
    for tool in TOOLS:
        for mode in MODES:
            for (corpus, t), v in targets.items():
                res = all_runs.get((tool, mode, corpus, t))
                if not res:
                    continue
                s, detail, claim = score_target(res, v["packages"], osv)
                row = dict(s) | {"ecosystem": v["ecosystem"], "status": claim, "seconds": res["seconds"],
                                 "warnings": res["warnings"], "errors": res["errors"][:3]}
                results["labelled"].setdefault(f"{tool}/{mode}", {}).setdefault(corpus, {})[t] = row
                results["details"].setdefault(f"{tool}/{mode}", {})[f"{corpus}/{t}"] = detail
    osv.save()
    results["repos"] = score_repos(all_runs, repo_labels, osv)
    results["images"] = score_images(all_runs)
    osv.save()
    db = RAW / "db-prep.tsv"
    results["db_prep"] = [line.split("\t") for line in db.read_text().splitlines()[1:]] if db.exists() else []
    # Tool messages quote absolute paths; keep the machine's folders out of the published files.
    def scrub(text):
        return text.replace(str(BENCH), "$BENCH_HOME").replace(str(HERE), "benchmark")
    pathlib.Path(sys.argv[3]).write_text(scrub(json.dumps(results, indent=1, sort_keys=True) + "\n"))
    pathlib.Path(sys.argv[4]).write_text(scrub(tables(results)))


def tables(r):
    lines = []
    def agg(tm, corpus, eco=None):
        c = collections.Counter()
        for t, row in r["labelled"].get(tm, {}).get(corpus, {}).items():
            if eco and row["ecosystem"] != eco:
                continue
            c.update({k: v for k, v in row.items() if isinstance(v, (int, float)) and not isinstance(v, bool)})
            c["targets"] += 1
        return c
    keys = [f"{t}/{m}" for t in TOOLS for m in MODES]
    for corpus, title in (("ground-truth", "Ground truth (lockfiles, labelled from OSV + GHSA)"),
                          ("manifest-only", "Manifest only (no lockfile; transitive labels from deps.dev)")):
        lines += [f"### {title}", "",
                  "| tool / mode | advisories hit | vulnerable packages hit | silent misses | false alarms | unverified extras | false clean | unknown | errors | can't scan | seconds |",
                  "|---|---|---|---|---|---|---|---|---|---|---|"]
        for tm in keys:
            c = agg(tm, corpus)
            if not c:
                continue
            lines.append(f"| {tm} | {c['hits']}/{c['advisories']} ({pct(c['hits'], c['advisories'])}) | "
                         f"{c['vuln_packages_hit']}/{c['vuln_packages']} | {c['silent_missed_packages']} | {c['false_alarm']} | {c['unverified']} | "
                         f"{c['false_clean']} | {c['unknown']} | {c['error']} | {c['cant_scan']}/{c['targets']} | {c['seconds']:.1f} |")
        lines.append("")
        ecos = sorted({row["ecosystem"] for tm in keys for row in r["labelled"].get(tm, {}).get(corpus, {}).values()})
        lines += [f"Advisory recall per ecosystem ({corpus}); FC = false clean, U = unknown, E = error, X = can't scan", "",
                  "| ecosystem | " + " | ".join(keys) + " |", "|---|" + "---|" * len(keys)]
        for eco in ecos:
            cells = []
            for tm in keys:
                c = agg(tm, corpus, eco)
                flags = "".join(f for f, k in (("FC", "false_clean"), ("U", "unknown"), ("E", "error"), ("X", "cant_scan")) if c[k])
                cells.append(f"{pct(c['hits'], c['advisories'])} {flags}".strip())
            lines.append(f"| {eco} | " + " | ".join(cells) + " |")
        lines.append("")
    lines += ["### Real repositories (labels: OSV for the union of packages any tool found)", "",
              "| tool / mode | advisories hit | packages seen / union | false clean | unknown | errors | seconds |",
              "|---|---|---|---|---|---|---|"]
    for tm in keys:
        c = r["repos"].get(tm, {}).get("total")
        if not c:
            continue
        lines.append(f"| {tm} | {c.get('hits', 0)}/{c.get('advisories', 0)} ({pct(c.get('hits', 0), c.get('advisories', 0))}) | "
                     f"{c.get('packages_seen', 0)}/{c.get('union_packages', 0)} | {c.get('false_clean', 0)} | {c.get('unknown', 0)} | "
                     f"{c.get('error', 0)} | {c.get('seconds', 0):.1f} |")
    lines += ["", "### Container images (agreement: CVEs at least two tools report online)", "",
              "| tool / mode | agreed CVEs found | CVEs no other tool reports | packages | statuses | seconds |", "|---|---|---|---|---|---|"]
    for tm in keys:
        rows = r["images"].get(tm)
        if not rows:
            continue
        hit = sum(x["consensus_hit"] for x in rows.values())
        tot = sum(x["consensus"] for x in rows.values())
        st = collections.Counter(x["status"] for x in rows.values())
        lines.append(f"| {tm} | {hit}/{tot} ({pct(hit, tot)}) | {sum(x['unique'] for x in rows.values())} | "
                     f"{sum(x['packages'] for x in rows.values())} | {', '.join(f'{k} {v}' for k, v in sorted(st.items()))} | "
                     f"{sum(x['seconds'] for x in rows.values()):.1f} |")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()

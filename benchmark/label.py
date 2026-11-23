"""Label packages with the advisories that affect them, from OSV.dev and the GitHub Advisory Database.

    python3 label.py ground-truth corpus/ground-truth/expected.json corpus/ground-truth/labels.json
    python3 label.py inventory INVENTORY.json OUT.json [--no-ghsa]

The ground-truth mode reads the package list written into each lockfile. The inventory mode reads
a list of [ecosystem, name, version] rows (the union of what any scanner found in a real repo) and
labels it the same way. GHSA lookups use the `gh` CLI, so they need a signed-in gh; OSV needs none.
Labels are a snapshot: the output records when it was fetched.
"""

import concurrent.futures
import datetime
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request

OSV = "https://api.osv.dev/v1"
GHSA_ECOSYSTEM = {
    "npm": "npm", "PyPI": "pip", "crates.io": "rust", "Go": "go", "Maven": "maven",
    "NuGet": "nuget", "RubyGems": "rubygems", "Packagist": "composer", "Pub": "pub",
    "Hex": "erlang", "SwiftURL": "swift",
}


def post(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except Exception:
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)


def get(url):
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt == 3:
                raise
        except Exception:
            if attempt == 3:
                raise
        time.sleep(2 ** attempt)


def osv_ids(rows):
    """Advisory ids per row from OSV querybatch, following page tokens."""
    out = [set() for _ in rows]
    # OSV rejects a whole batch over one unknown ecosystem (CocoaPods has no OSV feed), so skip those.
    known = [i for i, (e, _, _) in enumerate(rows) if e in GHSA_ECOSYSTEM]
    for start in range(0, len(known), 500):
        chunk = known[start:start + 500]
        queries = [{"package": {"ecosystem": rows[j][0], "name": rows[j][1]}, "version": rows[j][2]} for j in chunk]
        pending = list(range(len(chunk)))
        while pending:
            res = post(OSV + "/querybatch", {"queries": [queries[i] for i in pending]})["results"]
            nxt = []
            for i, r in zip(pending, res):
                out[chunk[i]].update(v["id"] for v in r.get("vulns", []))
                if r.get("next_page_token"):
                    queries[i]["page_token"] = r["next_page_token"]
                    nxt.append(i)
            pending = nxt
    return out


def ghsa(ecosystem, name, version):
    eco = GHSA_ECOSYSTEM.get(ecosystem)
    if not eco:
        return []
    cmd = ["gh", "api", "-X", "GET", "/advisories", "--paginate", "-f", f"ecosystem={eco}",
           "-f", f"affects={name}@{version}", "-f", "per_page=100"]
    for attempt in range(3):
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode == 0:
            text = p.stdout.replace("][", ",")
            return [a for a in json.loads(text or "[]") if not a.get("withdrawn_at")]
        time.sleep(5)
    raise RuntimeError(f"gh api failed for {ecosystem} {name}@{version}: {p.stderr.strip()}")


class Groups:
    """Union-find over advisory ids, joined through their aliases."""

    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def join(self, ids):
        ids = list(ids)
        for x in ids:
            self.find(x)
        for other in ids[1:]:
            a, b = self.find(ids[0]), self.find(other)
            if a != b:
                self.parent[b] = a

    def members(self):
        out = {}
        for x in self.parent:
            out.setdefault(self.find(x), set()).add(x)
        return out


def canonical(ids):
    for prefix in ("GHSA-", "CVE-"):
        hits = sorted(i for i in ids if i.startswith(prefix))
        if hits:
            return hits[0]
    return sorted(ids)[0]


def label(rows, use_ghsa):
    groups = Groups()
    per_row = osv_ids(rows)
    wanted = sorted(set().union(*per_row)) if per_row else []
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        records = dict(zip(wanted, pool.map(lambda vid: get(f"{OSV}/vulns/{vid}") or {}, wanted)))
    sources = {}
    row_ids = []
    for (eco, name, version), ids in zip(rows, per_row):
        mine = set()
        for vid in ids:
            rec = records[vid]
            if rec.get("withdrawn"):
                continue
            groups.join([vid] + rec.get("aliases", []))
            mine.add(vid)
            sources.setdefault(vid, set()).add("osv")
        if use_ghsa:
            for adv in ghsa(eco, name, version):
                ids2 = [adv["ghsa_id"]] + [i["value"] for i in adv.get("identifiers", [])]
                groups.join(ids2)
                mine.add(adv["ghsa_id"])
                sources.setdefault(adv["ghsa_id"], set()).add("ghsa")
        row_ids.append(mine)
    members = groups.members()
    labelled = []
    for (eco, name, version), ids in zip(rows, row_ids):
        roots = {groups.find(i) for i in ids}
        advisories = []
        for r in sorted(roots, key=lambda r: canonical(members[r])):
            m = members[r]
            src = sorted(set().union(*(sources.get(i, set()) for i in m)))
            advisories.append({"id": canonical(m), "aliases": sorted(m), "sources": src})
        labelled.append({"ecosystem": eco, "name": name, "version": version, "advisories": advisories})
    return labelled


def main():
    mode, src, dst = sys.argv[1:4]
    use_ghsa = "--no-ghsa" not in sys.argv
    fetched = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if mode == "ground-truth":
        spec = json.load(open(src))["targets"]
        rows, owners = [], []
        for target, t in spec.items():
            for name, version in t["packages"]:
                rows.append((t["ecosystem"], name, version))
                owners.append(target)
        labelled = label(rows, use_ghsa)
        out = {"fetched_at": fetched, "sources": ["osv.dev"] + (["github-advisory-database"] if use_ghsa else []),
               "targets": {}}
        for target, row in zip(owners, labelled):
            out["targets"].setdefault(target, {"ecosystem": spec[target]["ecosystem"], "packages": []})
            out["targets"][target]["packages"].append(row)
    elif mode == "manifest":
        spec = json.load(open(src))["targets"]
        rows, owners, relation = [], [], []
        for target, t in spec.items():
            seen = set()
            for name, version in t["direct"]:
                nodes = [(name, version, "DIRECT")]
                if t["depsdev"]:
                    url = (f"https://api.deps.dev/v3alpha/systems/{t['depsdev']}/packages/"
                           f"{urllib.parse.quote(name, safe='')}/versions/{version}:dependencies")
                    graph = get(url) or {"nodes": []}
                    nodes += [(n["versionKey"]["name"], n["versionKey"]["version"], n["relation"])
                              for n in graph["nodes"] if n["relation"] != "SELF"]
                for n, v, rel in nodes:
                    if (n, v) in seen:
                        continue
                    seen.add((n, v))
                    rows.append((t["ecosystem"], n, v))
                    owners.append(target)
                    relation.append("direct" if rel == "DIRECT" and n == name else "transitive")
        labelled = label(rows, use_ghsa)
        out = {"fetched_at": fetched, "resolver": "deps.dev v3alpha :dependencies, per direct dependency",
               "sources": ["osv.dev"] + (["github-advisory-database"] if use_ghsa else []), "targets": {}}
        for target, row, rel in zip(owners, labelled, relation):
            row["relation"] = rel
            out["targets"].setdefault(target, {"ecosystem": spec[target]["ecosystem"], "packages": []})
            out["targets"][target]["packages"].append(row)
    else:
        rows = [tuple(r) for r in json.load(open(src))]
        out = {"fetched_at": fetched, "sources": ["osv.dev"] + (["github-advisory-database"] if use_ghsa else []),
               "packages": label(rows, use_ghsa)}
    with open(dst, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()

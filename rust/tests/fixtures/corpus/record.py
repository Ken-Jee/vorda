"""Re-record the accuracy corpus: python3 record.py PATH/TO/vorda [CASE... | --no-live]

Scans the named projects under projects/ live (all of them when none are named,
none with --no-live),
each with a fresh state, and adds the feed answers they fetched to feeds.json,
trimmed to the fields the scanner reads. Answers recorded earlier for other cases
are kept. Then it scans every project offline against feeds.json, exactly as the
test does, and rewrites expected.json from what that prints.

Each case in expected.json may carry "osv_groups": the advisory group count
osv-scanner reports for the same project, and "beyond_osv": package names Vorda
reports by design and osv-scanner does not, left out of that count. Both are
entered by hand, kept across re-records, and checked by the test (equal for a
finished scan, at most that many for an unknown one); this script prints every
case where the new count disagrees. Check those against osv-scanner before
committing.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

here = os.path.dirname(os.path.abspath(__file__))
vorda = os.path.abspath(sys.argv[1])
only = sys.argv[2:]
projects = os.path.join(here, "projects")
feeds_path = os.path.join(here, "feeds.json")
expected_path = os.path.join(here, "expected.json")
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEAD = "http://127.0.0.1:9"
cases = sorted(os.listdir(projects))


def load(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def trim(url, data):
    if url.endswith("/querybatch"):
        return {"results": [
            {k: ([{"id": v["id"]} for v in r[k]] if k == "vulns" else r[k]) for k in r}
            for r in data["results"]
        ]}
    if "/vulns/" in url:
        keep = {k: data[k] for k in ("id", "aliases", "upstream", "withdrawn", "published", "severity") if k in data}
        keep["affected"] = [
            {
                "package": {k: a["package"][k] for k in ("name", "ecosystem")},
                "ranges": [r for r in a.get("ranges", []) if r.get("type") in ("SEMVER", "ECOSYSTEM")],
            }
            for a in data.get("affected", [])
        ]
        return keep
    if url.startswith("https://api.first.org/"):
        return {"data": [{"cve": r["cve"], "epss": r["epss"]} for r in data["data"]]}
    return data


def scan(state, root, env=None):
    run = subprocess.run(
        [vorda, "--state", state, "scan", "--json", "--root", root],
        capture_output=True, timeout=900, check=False, env=env,
    )
    # Numbers stay as printed, so EPSS reads the same here and in the test.
    return run.returncode, json.loads(run.stdout, parse_float=str)


def severity(value):
    if isinstance(value, list):
        value = ",".join(sorted(s.get("score", "") for s in value))
    return value if isinstance(value, str) and value else "no-severity"


def finding(f):
    p = f["package"]
    text = f"{p['name']}@{p['version']} {f['advisory']} {severity(f.get('severity'))}"
    if f.get("kev") is True:
        text += " kev"
    if f.get("epss") is not None:
        text += f" epss={f['epss']}"
    return text


def refused(root, errors):
    out = []
    for e in errors:
        if e["source"] != "inventory":
            continue
        text = e["error"].removeprefix(root + "/")
        out.append(text.split(". ")[0])
    return sorted(out)


live = [] if only == ["--no-live"] else only or cases
recorded = {} if not only else load(feeds_path)
old = load(expected_path)
with tempfile.TemporaryDirectory() as temp:
    for case in live:
        state = os.path.join(temp, "live", case)
        code, _ = scan(state, os.path.join(projects, case))
        print("live", case, code, flush=True)
        cache = os.path.join(state, "cache")
        for name in os.listdir(cache) if os.path.isdir(cache) else []:
            if name.endswith(".json"):
                with open(os.path.join(cache, name)) as f:
                    entry = json.load(f)
                # KEV is one answer for everyone: keep the newest full copy and trim it below.
                if name not in recorded or entry["source_url"] == KEV:
                    recorded[name] = {"source_url": entry["source_url"], "data": trim(entry["source_url"], entry["data"])}

    cves = {
        a
        for entry in recorded.values()
        if "/vulns/" in entry["source_url"]
        for a in entry["data"].get("aliases", []) + [entry["data"]["id"]]
        if a.startswith("CVE-")
    }
    for entry in recorded.values():
        if entry["source_url"] == KEV:
            entry["data"] = {"vulnerabilities": [
                {"cveID": v["cveID"]} for v in entry["data"]["vulnerabilities"] if v["cveID"] in cves
            ]}
    with open(feeds_path, "w") as f:
        f.write("{\n" + ",\n".join(
            json.dumps(name) + ":" + json.dumps(recorded[name], sort_keys=True, separators=(",", ":"))
            for name in sorted(recorded)
        ) + "\n}\n")

    # The verdicts come from an offline scan against feeds.json, the same way the test runs.
    env = dict(os.environ, NO_PROXY="", no_proxy="")
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        env[var] = DEAD
    expected = {}
    for case in cases:
        state = os.path.join(temp, "offline", case)
        os.makedirs(os.path.join(state, "cache"))
        for name, entry in recorded.items():
            with open(os.path.join(state, "cache", name), "w") as f:
                json.dump(dict(entry, checked=time.time(), fetched_at="recorded"), f)
        root = os.path.join(projects, case)
        code, result = scan(state, root, env)
        want = {
            "exit": code,
            "status": result["status"],
            "findings": sorted(finding(f) for f in result["findings"]),
            "refused": refused(root, result["errors"]),
        }
        feed_errors = [e for e in result["errors"] if e["source"] != "inventory"]
        for key in ("osv_groups", "beyond_osv"):
            if key in old.get(case, {}):
                want[key] = old[case][key]
        beyond = want.get("beyond_osv", [])
        n = sum(f["package"]["name"] not in beyond for f in result["findings"])
        osv = want.get("osv_groups")
        disagrees = osv is not None and (n > osv if code == 2 else n != osv)
        print(case, code, n, f"osv={osv}", "OSV-DISAGREES" if disagrees else "",
              f"FEED-ERRORS {feed_errors}" if feed_errors else "", flush=True)
        expected[case] = want

with open(expected_path, "w") as f:
    json.dump(expected, f, indent=1, sort_keys=True)
    f.write("\n")

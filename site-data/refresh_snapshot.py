#!/usr/bin/env python3
"""Regenerate docs/data/snapshot.json from OSV.dev for the site's watch list.

Search, Explore, Advisory, Package and Sources read this file. The watch list is
the one already in the file, so editing the watch list means editing the file.

The output depends only on what OSV.dev returns and the clock: records are kept
in a fixed order and trimmed to the fields the site shows. Any failed request
aborts before the file is written, so a bad run never leaves a half-filled file.

Usage: python3 site-data/refresh_snapshot.py [--out PATH] [--now ISO8601]
Standard library only.
"""

import argparse
import datetime
import json
import os
import sys
import tempfile
import urllib.request

QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "data", "snapshot.json")
VERSION_SAMPLE = 40  # the site's label says "N of M listed versions (a sample in text order)"
SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}


def post_json(url, body):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "vorda-site-refresh"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def query_package(pkg, post=None):
    """Every OSV record for one package, following page tokens."""
    post = post or post_json
    body = {"package": {"ecosystem": pkg["ecosystem"], "name": pkg["name"]}}
    vulns = []
    while True:
        page = post(QUERY_URL, body)
        vulns.extend(page.get("vulns", []))
        token = page.get("next_page_token")
        if not token:
            return vulns
        body = dict(body, page_token=token)


def ranges_of(affected):
    out = []
    for rng in affected.get("ranges", []):
        if rng.get("type") == "GIT":
            continue
        cur = None
        for ev in rng.get("events", []):
            if "introduced" in ev:
                if cur:
                    out.append(cur)
                cur = {"introduced": ev["introduced"]}
            elif "fixed" in ev or "last_affected" in ev:
                key = "fixed" if "fixed" in ev else "last_affected"
                cur = cur or {"introduced": "0"}  # a bound with no start means from the first version
                cur[key] = ev[key]
                out.append(cur)
                cur = None
        if cur:
            out.append(cur)
    return out


def trim(record, watched):
    """The site's shape for one record, or None if it touches no watched package."""
    merged = {}
    for aff in record.get("affected", []):
        p = aff.get("package", {})
        key = (p.get("ecosystem"), p.get("name"))
        if key not in watched:
            continue
        # One package can appear in several affected entries; the site shows one.
        entry = merged.setdefault(key, {"ranges": [], "versions": set()})
        entry["ranges"].extend(ranges_of(aff))
        entry["versions"].update(aff.get("versions", []))
    packages = []
    for (eco, name), entry in merged.items():
        versions = sorted(entry["versions"])
        packages.append({
            "ecosystem": eco,
            "name": name,
            "group": watched[(eco, name)],
            "ranges": entry["ranges"],
            "versions": versions[-VERSION_SAMPLE:],
            "versionCount": len(versions),
        })
    if not packages:
        return None
    label = (record.get("database_specific") or {}).get("severity")
    return {
        "id": record["id"],
        "aliases": sorted(record.get("aliases", [])),
        "summary": record.get("summary", ""),
        "severity": SEVERITY.get(str(label).upper()) if label else None,
        "published": record.get("published", ""),
        "modified": record.get("modified", ""),
        "packages": packages,
    }


def build(previous, now, post=None):
    watch = previous["watch"]
    watched = {(w["ecosystem"], w["name"]): w["group"] for w in watch}
    records = {}
    for w in watch:
        for rec in query_package(w, post):
            if rec.get("withdrawn"):
                continue
            records.setdefault(rec["id"], rec)
    advisories = [a for a in (trim(r, watched) for r in records.values()) if a]
    if not advisories:
        raise RuntimeError("OSV.dev returned no advisories for the watch list; refusing to write an empty snapshot")
    advisories.sort(key=lambda a: (a["published"], a["id"]), reverse=True)
    return {
        "schema": previous["schema"],
        "generatedAt": now,
        "source": previous["source"],
        "watch": watch,
        "advisories": advisories,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.normpath(DEFAULT_OUT))
    ap.add_argument("--now", help="override the generatedAt timestamp (UTC, ISO 8601)")
    args = ap.parse_args(argv)
    with open(args.out) as f:
        previous = json.load(f)
    now = args.now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    snap = build(previous, now)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(args.out), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(snap, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")
        os.replace(tmp, args.out)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(f"{len(snap['advisories'])} advisories for {len(snap['watch'])} packages, taken {now}", file=sys.stderr)


if __name__ == "__main__":
    main()

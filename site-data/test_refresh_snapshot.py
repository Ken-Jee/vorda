"""Offline tests for refresh_snapshot.py: run with python3 -m unittest discover site-data"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refresh_snapshot as rs  # noqa: E402

PREVIOUS = {
    "schema": 1,
    "generatedAt": "2026-01-01T00:00:00Z",
    "source": {"name": "OSV.dev", "url": "https://osv.dev/", "note": "n"},
    "watch": [
        {"group": "mcp", "ecosystem": "PyPI", "name": "mcp"},
        {"group": "agents", "ecosystem": "npm", "name": "agent"},
    ],
    "advisories": [],
}


def rec(id_, published, affected, severity=None, **extra):
    r = {"id": id_, "summary": "s " + id_, "aliases": ["CVE-2", "CVE-1"], "published": published,
         "modified": published, "affected": affected}
    if severity:
        r["database_specific"] = {"severity": severity}
    r.update(extra)
    return r


def aff(eco, name, events, versions=(), kind="ECOSYSTEM"):
    return {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": kind, "events": events}],
            "versions": list(versions)}


SHARED = rec("GHSA-b", "2026-02-01T00:00:00Z", [
    aff("PyPI", "mcp", [{"introduced": "0"}, {"fixed": "1.0"}], ["0.9", "0.1"]),
    aff("PyPI", "mcp", [{"introduced": "2.0"}, {"last_affected": "2.1"}], ["2.0", "0.9"]),
    aff("PyPI", "mcp", [{"introduced": "0"}, {"fixed": "abc123"}], kind="GIT"),
    aff("PyPI", "other", [{"introduced": "0"}]),
    aff("npm", "agent", [{"introduced": "0"}]),
], severity="MODERATE")

RESPONSES = {
    ("PyPI", "mcp", None): {"vulns": [SHARED], "next_page_token": "p2"},
    ("PyPI", "mcp", "p2"): {"vulns": [
        rec("PYSEC-a", "2026-03-01T00:00:00Z", [aff("PyPI", "mcp", [{"introduced": "1"}])]),
        rec("GHSA-gone", "2026-04-01T00:00:00Z", [aff("PyPI", "mcp", [{"introduced": "0"}])], withdrawn="x"),
    ]},
    ("npm", "agent", None): {"vulns": [SHARED]},
}


def fake_post(url, body):
    p = body["package"]
    return RESPONSES[(p["ecosystem"], p["name"], body.get("page_token"))]


class RefreshTest(unittest.TestCase):
    def test_build_trims_merges_and_orders(self):
        snap = rs.build(PREVIOUS, "2026-11-26T00:00:00Z", post=fake_post)
        self.assertEqual(snap["generatedAt"], "2026-11-26T00:00:00Z")
        self.assertEqual(snap["watch"], PREVIOUS["watch"])
        self.assertEqual([a["id"] for a in snap["advisories"]], ["PYSEC-a", "GHSA-b"])  # newest first, withdrawn dropped
        b = snap["advisories"][1]
        self.assertEqual(b["severity"], "Medium")
        self.assertEqual(b["aliases"], ["CVE-1", "CVE-2"])
        self.assertEqual(b["packages"], [
            {"ecosystem": "PyPI", "name": "mcp", "group": "mcp",
             "ranges": [{"introduced": "0", "fixed": "1.0"}, {"introduced": "2.0", "last_affected": "2.1"}],
             "versions": ["0.1", "0.9", "2.0"], "versionCount": 3},
            {"ecosystem": "npm", "name": "agent", "group": "agents",
             "ranges": [{"introduced": "0"}], "versions": [], "versionCount": 0},
        ])
        self.assertIsNone(snap["advisories"][0]["severity"])

    def test_bound_without_start_counts_from_zero(self):
        self.assertEqual(rs.ranges_of({"ranges": [{"type": "SEMVER", "events": [{"fixed": "1.2"}]}]}),
                         [{"introduced": "0", "fixed": "1.2"}])

    def test_version_sample_keeps_count(self):
        many = [f"1.{i:03d}" for i in range(100)]
        out = rs.trim(rec("X", "t", [aff("PyPI", "mcp", [{"introduced": "0"}], many)]), {("PyPI", "mcp"): "mcp"})
        self.assertEqual(out["packages"][0]["versionCount"], 100)
        self.assertEqual(out["packages"][0]["versions"], many[-40:])

    def test_refuses_empty_result(self):
        with self.assertRaises(RuntimeError):
            rs.build(PREVIOUS, "now", post=lambda url, body: {"vulns": []})

    def test_same_input_same_bytes(self):
        a = rs.build(PREVIOUS, "t", post=fake_post)
        b = rs.build(PREVIOUS, "t", post=fake_post)
        self.assertEqual(json.dumps(a), json.dumps(b))

    def test_failed_fetch_leaves_file_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "snapshot.json")
            with open(path, "w") as f:
                json.dump(PREVIOUS, f)
            before = open(path).read()

            def boom(url, body):
                raise OSError("network down")
            real, rs.post_json = rs.post_json, boom
            try:
                with self.assertRaises(OSError):
                    rs.main(["--out", path])
            finally:
                rs.post_json = real
            self.assertEqual(open(path).read(), before)
            self.assertEqual(os.listdir(d), ["snapshot.json"])


if __name__ == "__main__":
    unittest.main()

"""Run one scanner over the whole corpus, in online and offline mode, and keep its raw output.

    python3 -I run.py TOOL [--only CORPUS,...] [--targets NAME,...] [--modes online,offline] [--no-prefetch]

TOOL is vorda, osv-scanner, trivy or grype. Offline runs happen inside a fresh network
namespace with no interface but loopback (unshare --net), so a tool that needs the network
fails visibly instead of quietly going online. Each run writes
$BENCH_HOME/raw/TOOL/MODE/CORPUS/TARGET.{out,err,meta.json}.
"""

import json
import os
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
BENCH = pathlib.Path(os.environ["BENCH_HOME"])
TIMEOUT = 900
NO_NET = ["unshare", "--user", "--map-current-user", "--net", "--"]


def targets(only=None):
    """(corpus, name, path, kind) for every target; kind is dir or image."""
    out = []
    for corpus, spec in (("ground-truth", "corpus/ground-truth/expected.json"),
                         ("manifest-only", "corpus/manifest-only/expected.json")):
        for name, t in json.load(open(HERE / spec))["targets"].items():
            out.append((corpus, name, HERE / "corpus" / corpus / pathlib.Path(t["file"]).parent, "dir"))
    for r in json.load(open(HERE / "corpus/repos.json"))["repos"]:
        out.append(("repos", r["name"], BENCH / "corpus/repos" / r["name"], "dir"))
    for i in json.load(open(HERE / "corpus/images.json"))["images"]:
        out.append(("images", i["name"], BENCH / "corpus/images" / f"{i['name']}.tar", "image"))
    return [t for t in out if not only or t[0] in only]


def command(tool, mode, path, kind, outfile):
    p = str(path)
    if tool == "vorda":
        net = ["--online"] if mode == "online" else ["--offline-db"]
        if kind == "image":
            return ["vorda", "scan", "--oci", p, "--os-packages", *net, "--json"]
        return ["vorda", "scan", "--root", p, *net, "--json"]
    if tool == "osv-scanner":
        net = [] if mode == "online" else ["--offline"]
        if kind == "image":
            docker_tar = p[:-len(".tar")] + ".docker.tar"
            return ["osv-scanner", "scan", "image", "--archive", docker_tar, "--all-packages", "--format", "json", *net]
        return ["osv-scanner", "scan", "source", "-r", p, "--all-packages", "--format", "json", *net]
    if tool == "trivy":
        net = [] if mode == "online" else ["--offline-scan", "--skip-db-update", "--skip-java-db-update"]
        # Trivy opens an OCI layout only as a folder, not as an archive, so it gets the Docker archive.
        sub = ["image", "--input", p[:-len(".tar")] + ".docker.tar"] if kind == "image" else ["fs", p]
        return ["trivy", *sub, "--scanners", "vuln", "--list-all-pkgs", "--format", "json",
                "--output", str(outfile), "--quiet", *net]
    if tool == "grype":
        src = f"oci-archive:{p}" if kind == "image" else f"dir:{p}"
        return ["grype", src, "-o", f"json={outfile}", "-o", f"cyclonedx-json={outfile}.cdx"]
    raise SystemExit(f"unknown tool {tool}")


def env_for(tool, mode):
    env = dict(os.environ)
    if tool == "grype" and mode == "offline":
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
    return env


def prefetch_osv(items):
    """osv-scanner downloads its offline databases per ecosystem on a first online pass."""
    log = BENCH / "raw/osv-scanner/prefetch.tsv"
    log.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for corpus, name, path, kind in items:
        sub = ["image", "--archive"] if kind == "image" else ["source", "-r"]
        if kind == "image":
            path = pathlib.Path(str(path)[:-len(".tar")] + ".docker.tar")
        cmd = ["osv-scanner", "scan", *sub, str(path), "--offline-vulnerabilities", "--download-offline-databases",
               "--format", "json"]
        t0 = time.monotonic()
        p = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT)
        rows.append(f"{corpus}\t{name}\t{time.monotonic() - t0:.1f}\t{p.returncode}")
    log.write_text("corpus\ttarget\tseconds\texit\n" + "\n".join(rows) + "\n")


def run_one(tool, mode, corpus, name, path, kind):
    base = BENCH / "raw" / tool / mode / corpus / name
    base.parent.mkdir(parents=True, exist_ok=True)
    outfile = pathlib.Path(f"{base}.out")
    cmd = command(tool, mode, path, kind, outfile)
    full = (NO_NET if mode == "offline" else []) + cmd
    t0 = time.monotonic()
    try:
        p = subprocess.run(full, capture_output=True, timeout=TIMEOUT, env=env_for(tool, mode), cwd=str(BENCH))
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = "timeout", e.stdout or b"", (e.stderr or b"") + b"\nbenchmark: timed out"
    seconds = time.monotonic() - t0
    if tool not in ("trivy", "grype"):
        outfile.write_bytes(out)
    pathlib.Path(f"{base}.err").write_bytes(err)
    meta = {"tool": tool, "mode": mode, "corpus": corpus, "target": name, "kind": kind,
            "cmd": [c.replace(str(BENCH), "$BENCH_HOME") for c in full], "exit": rc, "seconds": round(seconds, 2)}
    pathlib.Path(f"{base}.meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    return meta


def main():
    tool = sys.argv[1]
    args = sys.argv[2:]
    only = args[args.index("--only") + 1].split(",") if "--only" in args else None
    modes = args[args.index("--modes") + 1].split(",") if "--modes" in args else ["online", "offline"]
    items = targets(only)
    if "--targets" in args:
        names = args[args.index("--targets") + 1].split(",")
        items = [t for t in items if t[1] in names]
    if tool == "osv-scanner" and "offline" in modes and "--no-prefetch" not in args:
        prefetch_osv(items)
    for mode in modes:
        for corpus, name, path, kind in items:
            m = run_one(tool, mode, corpus, name, path, kind)
            print(f"{tool}\t{mode}\t{corpus}\t{name}\texit={m['exit']}\t{m['seconds']}s", flush=True)


if __name__ == "__main__":
    main()

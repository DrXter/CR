"""Source-code review of an uploaded archive. Pure analysis: nothing in the archive is executed."""
import json
import math
import pathlib
import re
import shutil
import subprocess
import tarfile
import zipfile
from collections import Counter

import yaml

from . import settings
from .findings import Sink

RULES = pathlib.Path(__file__).parent / "rules"
SKIP_DIRS = {".git", "node_modules", "build", "dist", "out", ".gradle", "target", "__pycache__", ".idea"}
TEXT_EXT = {"java", "gs", "gsx", "gst", "gsp", "pcf", "xml", "properties", "wsc", "js", "jsx", "ts", "tsx", "json", "gradle", "kts", "yml", "yaml", "sh", "bat", "ps1",
            "html", "etx", "eti", "tti", "tix", "ttx", "sql", "conf", "cfg", "ini", "env", "txt", "md", "pom"}
PER_RULE_CAP = 150


# ------------------------------------------------------------ safe extraction
def safe_extract(archive, dest):
    dest = pathlib.Path(dest); dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve(); total = files = 0
    limit = settings.MAX_UNPACKED_MB * 1024 * 1024

    def target(name):
        p = (root / name).resolve()
        if root not in p.parents and p != root:
            raise ValueError(f"Unsafe path in archive: {name}")
        return p

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for i in z.infolist():
                if (i.external_attr >> 16) & 0o170000 == 0o120000:
                    continue   # symlink: skipped
                total += i.file_size; files += 1
                if total > limit or files > settings.MAX_FILES:
                    raise ValueError("Archive exceeds size or file-count limits")
                t = target(i.filename)
                if i.is_dir(): t.mkdir(parents=True, exist_ok=True); continue
                t.parent.mkdir(parents=True, exist_ok=True)
                with z.open(i) as src, open(t, "wb") as out:
                    shutil.copyfileobj(src, out)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            for m in tf:
                if not (m.isreg() or m.isdir()): continue
                total += m.size; files += 1
                if total > limit or files > settings.MAX_FILES:
                    raise ValueError("Archive exceeds size or file-count limits")
                t = target(m.name)
                if m.isdir(): t.mkdir(parents=True, exist_ok=True); continue
                t.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(m) as src, open(t, "wb") as out:
                    shutil.copyfileobj(src, out)
    else:
        raise ValueError("Upload a .zip, .tar, .tar.gz or .tgz archive")
    return files, total


def iter_files(root):
    root = pathlib.Path(root)
    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink() or any(part in SKIP_DIRS for part in p.parts): continue
        ext = p.suffix.lstrip(".").lower()
        if ext in TEXT_EXT or p.name in {"Dockerfile", ".npmrc", ".env", "gradle.properties"}:
            if p.stat().st_size <= 2_000_000:
                yield p, ext


# ------------------------------------------------------------ helpers
def entropy(s):
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def mask(t):
    """Never store secret values: mask quoted strings, values after = or :, and any long token-looking run."""
    t = re.sub(r'(["\'])[^"\']{3,}(["\'])', r'\1****\2', t)
    t = re.sub(r'([=:]\s*)(?!\*\*\*\*)[^\s"\',;]{3,}', r'\1****', t)
    return re.sub(r'[A-Za-z0-9+/_\-]{16,}', lambda m: m.group(0)[:3] + "****", t)


# ------------------------------------------------------------ dependency parsing
GRADLE = re.compile(r"""['"]([\w.\-]+):([\w.\-]+):([^'"\s]+)['"]""")


def parse_deps(root):
    deps = []   # (ecosystem, name, version, file, flags)
    root = pathlib.Path(root)
    for p in root.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.parts): continue
        n = p.name; rel = str(p.relative_to(root))
        try:
            if n in ("build.gradle", "build.gradle.kts") or n.endswith(".gradle"):
                for g, a, v in GRADLE.findall(p.read_text(errors="replace")):
                    deps.append(("maven", f"{g}:{a}", v, rel, "dynamic" if ("$" in v or "+" in v or v in ("latest.release", "latest.integration")) else ""))
            elif n == "pom.xml":
                t = p.read_text(errors="replace")
                for blk in re.findall(r"<dependency>(.*?)</dependency>", t, re.S):
                    g = re.search(r"<groupId>(.*?)</groupId>", blk); a = re.search(r"<artifactId>(.*?)</artifactId>", blk); v = re.search(r"<version>(.*?)</version>", blk)
                    if g and a: deps.append(("maven", f"{g.group(1)}:{a.group(1)}", v.group(1) if v else "", rel, "dynamic" if (v and "$" in v.group(1)) else ""))
            elif n == "package.json":
                j = json.loads(p.read_text(errors="replace"))
                for sec in ("dependencies", "devDependencies"):
                    for name, ver in (j.get(sec) or {}).items():
                        flag = "dynamic" if ver.strip() in ("*", "latest", "") or ver.startswith(("git", "http")) else ""
                        deps.append(("npm", name, re.sub(r"^[\^~>=<\s]+", "", ver), rel, flag))
            elif n == "package-lock.json":
                j = json.loads(p.read_text(errors="replace"))
                for path, info in (j.get("packages") or {}).items():
                    if path.startswith("node_modules/") and info.get("version"):
                        deps.append(("npm", path.split("node_modules/")[-1], info["version"], rel, "locked"))
        except Exception:  # noqa: BLE001
            continue
    return deps


def sbom(deps):
    comps, seen = [], set()
    for eco, name, ver, f, _ in deps:
        if not ver or (eco, name, ver) in seen: continue
        seen.add((eco, name, ver))
        purl = f"pkg:maven/{name.replace(':', '/')}@{ver}" if eco == "maven" else f"pkg:npm/{name}@{ver}"
        comps.append({"type": "library", "name": name, "version": ver, "purl": purl})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": comps}


# ------------------------------------------------------------ external tools
def run_external(root, outdir, S):
    out = {}
    od = pathlib.Path(outdir); od.mkdir(parents=True, exist_ok=True)
    jobs = {"gitleaks": ["gitleaks", "detect", "--no-git", "--source", str(root), "--report-format", "json", "--report-path", str(od / "gitleaks.json"), "--redact"],
            "semgrep": ["semgrep", "--config", "auto", "--json", "-o", str(od / "semgrep.json"), str(root)],
            "osv-scanner": ["osv-scanner", "--format", "json", "--output", str(od / "osv.json"), "-r", str(root)]}
    for name, cmd in jobs.items():
        if not shutil.which(cmd[0]):
            out[name] = "not installed"; S.add("source", "GW-COD-002", f"{name} not installed", "code", "INFO", f"{name} was not found on the server; only the built-in analysis ran."); continue
        S.log(f"Running {name}")
        try:
            subprocess.run(cmd, check=False, timeout=1800, capture_output=True)
            out[name] = ingest(name, od, S)
        except Exception as e:  # noqa: BLE001
            out[name] = f"error: {e}"; S.add("source", "GW-COD-002", f"{name} failed", "code", "ERROR", str(e)[:200])
    return out


def ingest(name, od, S):
    p = od / {"gitleaks": "gitleaks.json", "semgrep": "semgrep.json", "osv-scanner": "osv.json"}[name]
    if not p.exists(): return "no output"
    j = json.loads(p.read_text() or "null") or ([] if name == "gitleaks" else {})
    n = 0
    if name == "gitleaks":
        for r in j[:500]:
            S.add("source", "GW-COD-014", f"gitleaks: {r.get('RuleID')}", "code", "CANDIDATE", f"{r.get('File')}:{r.get('StartLine')} {r.get('Description', '')}", f"{r.get('File')}:{r.get('StartLine')}", "High"); n += 1
    elif name == "semgrep":
        for r in (j.get("results") or [])[:1000]:
            sev = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}.get(r.get("extra", {}).get("severity"), "")
            S.add("source", "GW-COD-002", f"semgrep: {r.get('check_id', '')[-80:]}", "code", "CANDIDATE", f"{r.get('path')}:{r.get('start', {}).get('line')} {r.get('extra', {}).get('message', '')[:200]}", f"{r.get('path')}:{r.get('start', {}).get('line')}", sev); n += 1
    else:
        for res in (j.get("results") or []):
            for pk in res.get("packages", []):
                for v in pk.get("vulnerabilities", [])[:20]:
                    S.add("source", "GW-COD-026", f"osv: {pk['package']['name']} {pk['package']['version']}", "code", "FAIL", f"{v.get('id')} {v.get('summary', '')[:150]}", res.get("source", {}).get("path", ""), "High"); n += 1
    return f"{n} result(s) ingested"


# ------------------------------------------------------------ main scan
def scan(root, S: Sink, opts, outdir):
    root = pathlib.Path(root)
    rules = yaml.safe_load((RULES / "source_rules.yaml").read_text())["rules"]
    comp = []
    for r in rules:
        c = dict(r)
        if r["type"] == "line": c["_re"] = re.compile(r["regex"])
        else: c["_pre"] = re.compile(r["present"]); c["_abs"] = re.compile(r["absent"])
        comp.append(c)
    S.log("Inventory and pattern analysis", 15)
    exts, loc, nfiles = Counter(), 0, 0
    hits_by_rule = Counter()
    secret_re = re.compile(r"""(?i)(key|secret|token|passw|credential|apikey)[\w\-]*\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']""")
    marks = Counter()
    for p, ext in iter_files(root):
        try: text = p.read_text(errors="replace")
        except OSError: continue
        nfiles += 1; exts[ext] += 1
        lines = text.splitlines(); loc += len(lines)
        rel = str(p.relative_to(root))
        for d in ("gsrc", "pcf", "config", "configuration", "modules"):
            if f"/{d}/" in "/" + rel: marks[d] += 1
        for r in comp:
            ex = r.get("ext", ["*"])
            if "*" not in ex and ext not in ex: continue
            if r["type"] == "line":
                for i, line in enumerate(lines, 1):
                    if len(line) > 600 or not r["_re"].search(line): continue
                    hits_by_rule[r["id"]] += 1
                    if hits_by_rule[r["id"]] <= PER_RULE_CAP:
                        sn = line.strip()[:160]
                        S.add("source", r["control"], f"{r['id']} {r['name']}", "code", "CANDIDATE", f"{rel}:{i}  {mask(sn) if r.get('secret') else sn}" + (f"  [{r['note']}]" if r.get("note") else ""), f"{rel}:{i}", r["severity"])
            elif r["_pre"].search(text) and not r["_abs"].search(text):
                hits_by_rule[r["id"]] += 1
                if hits_by_rule[r["id"]] <= PER_RULE_CAP:
                    S.add("source", r["control"], f"{r['id']} {r['name']}", "code", "CANDIDATE", f"{rel}  [{r.get('note', 'file-level check')}]", rel, r["severity"])
        if ext not in ("min", "map"):
            for i, line in enumerate(lines, 1):
                if len(line) > 400: continue
                m = secret_re.search(line)
                if m and entropy(m.group(2)) >= 4.0 and not re.search(r"(?i)(example|changeme|placeholder|xxxx|your[_-])", line):
                    hits_by_rule["ENT"] += 1
                    if hits_by_rule["ENT"] <= PER_RULE_CAP:
                        S.add("source", "GW-COD-014", "High-entropy value assigned to a secret-like name", "code", "CANDIDATE", f"{rel}:{i}  {mask(line.strip()[:140])}", f"{rel}:{i}", "High")
    for rid, n in hits_by_rule.items():
        if n > PER_RULE_CAP:
            S.add("source", "-", f"{rid}: more matches not listed", "code", "INFO", f"{n} matches in total; first {PER_RULE_CAP} listed. Narrow the review by package.")
    top = ", ".join(f"{e}:{n}" for e, n in exts.most_common(8))
    S.add("source", "GW-COD-002", "Code inventory", "code", "INFO", f"{nfiles} text files, {loc} lines. By type: {top}. Folder markers: {dict(marks) or 'none of gsrc/pcf/config seen'}. Gosu and PCF have no built-in tool support: rules are pattern-based, not data-flow.")
    S.log("Dependencies and SBOM", 45)
    deps = parse_deps(root)
    vl = yaml.safe_load((RULES / "vuln_libs.yaml").read_text())
    bad = dyn = 0
    for eco, name, ver, f, flag in deps:
        v = (vl.get(eco) or {}).get(name)
        if v and ver and re.match(r"\d", ver) and vkey(ver) < vkey(v["fixed"]):
            bad += 1
            S.add("source", "GW-COD-026", f"Vulnerable library: {name} {ver}", "code", "FAIL", f"{f}: fixed in {v['fixed']}. {v['cve']}. {v['note']}", f, "High")
        if flag == "dynamic":
            dyn += 1
            if dyn <= 30: S.add("source", "GW-COD-029", f"Unpinned dependency version: {name}", "code", "CANDIDATE", f"{f}: version '{ver}'", f, "Medium")
    npm_dirs = {pathlib.Path(d[3]).parent for d in deps if d[0] == "npm" and pathlib.Path(d[3]).name == "package.json"}
    for d in npm_dirs:
        if not any((x[3] == str(d / n)) for x in deps for n in ("package-lock.json",)) and not (root / d / "yarn.lock").exists() and not (root / d / "pnpm-lock.yaml").exists():
            S.add("source", "GW-COD-029", "npm package without a lock file", "code", "FAIL", f"{d / 'package.json'}: no package-lock.json, yarn.lock or pnpm-lock.yaml", str(d / "package.json"), "Medium")
    S.add("source", "GW-COD-026", "Dependency inventory (SBOM)", "code", "INFO", f"{len({(e, n, v) for e, n, v, _, _ in deps})} unique components; {bad} known-vulnerable from the built-in list. The list is a curated starter: run osv-scanner for full coverage.")
    pathlib.Path(outdir).mkdir(parents=True, exist_ok=True)
    (pathlib.Path(outdir) / "sbom.json").write_text(json.dumps(sbom(deps), indent=1))
    ext_out = {}
    if opts.get("external", True):
        S.log("External tools (if installed)", 60)
        ext_out = run_external(root, pathlib.Path(outdir) / "external", S)
    return {"files": nfiles, "lines": loc, "components": len(deps), "external": ext_out}

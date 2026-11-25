"""Check exported configuration files (config.xml, server.xml, web.xml, JVM start scripts...) against the rules."""
import fnmatch
import pathlib
import re

import yaml

from .findings import Sink
from .srcscan import RULES, iter_files, mask, vkey

PARAM_XML = [re.compile(r'<param\b[^>]*\bname\s*=\s*"([^"]+)"[^>]*\bvalue\s*=\s*"([^"]*)"', re.I),
             re.compile(r'<param\b[^>]*\bvalue\s*=\s*"([^"]*)"[^>]*\bname\s*=\s*"([^"]+)"', re.I)]
KV = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=:]\s*(.+?)\s*$")
DFLAG = re.compile(r"-D([A-Za-z0-9_.\-]+)=(\S+)")


def params_of(files):
    out = {}
    for p, text in files:
        for i, line in enumerate(text.splitlines(), 1):
            m = PARAM_XML[0].search(line)
            if m: out.setdefault(m.group(1), []).append((m.group(2), p, i)); continue
            m = PARAM_XML[1].search(line)
            if m: out.setdefault(m.group(2), []).append((m.group(1), p, i)); continue
            for k, v in DFLAG.findall(line): out.setdefault(k, []).append((v, p, i))
            if p.endswith((".properties", ".conf", ".cfg", ".env")):
                m = KV.match(line)
                if m: out.setdefault(m.group(1), []).append((m.group(2), p, i))
    return out


def cmp(op, a, e):
    try: a, e = float(a), float(e)
    except ValueError: a, e = str(a).strip().lower(), str(e).strip().lower()
    return {"eq": a == e, "ne": a != e, "le": a <= e, "ge": a >= e, "in": str(a) in [x.strip().lower() for x in str(e).split(",")]}[op]


def run(root, S: Sink, policy_override=None):
    cfg = yaml.safe_load((RULES / "config_rules.yaml").read_text())
    policy = {**cfg.get("policy", {}), **(policy_override or {})}
    root = pathlib.Path(root)
    files = []
    for p, _ in iter_files(root):
        try: files.append((str(p.relative_to(root)), p.read_text(errors="replace")))
        except OSError: pass
    params = params_of(files)
    n = {"PASS": 0, "FAIL": 0, "MANUAL": 0}
    def add(r, st, obs, sev="Medium"):
        n[st] += 1
        S.add("config", r["control"], f"{r['id']} {r['name']}", "config exports", st, obs, "", sev if st == "FAIL" else "")
    for r in cfg["rules"]:
        t = r["type"]
        if t == "param":
            exp = str(r["expected"]); m = re.fullmatch(r"\{policy\.(\w+)\}", exp)
            if m: exp = str(policy[m.group(1)])
            found = params.get(r["param"])
            if not found: add(r, "MANUAL", f"{r['param']} not found in the supplied files; check Server Tools or supply the right file"); continue
            bad = [x for x in found if not cmp(r["op"], x[0], exp)]
            add(r, "FAIL" if bad else "PASS", f"{r['param']}: " + "; ".join(f"{f}:{ln}={v}" for v, f, ln in found[:5]) + f" (expected {r['op']} {exp})", "High")
            continue
        scope = [(f, tx) for f, tx in files if any(fnmatch.fnmatch(pathlib.Path(f).name.lower(), pt.lower()) for pt in r["files"])]
        if not scope: add(r, "MANUAL", f"No file matching {r['files']} supplied"); continue
        rx = re.compile(r["regex"]); hits = []
        for f, tx in scope:
            for i, line in enumerate(tx.splitlines(), 1):
                m = rx.search(line)
                if m: hits.append((f, i, m))
        if t == "absent":
            snip = [f"{f}:{i} {(mask(m.group(0)) if r.get('secret') else m.group(0))[:80]}" for f, i, m in hits[:5]]
            add(r, "FAIL" if hits else "PASS", ("; ".join(snip) + (f" (+{len(hits) - 5} more)" if len(hits) > 5 else "")) if hits else f"Not found in {len(scope)} file(s)", "High")
        elif t == "present":
            add(r, "PASS" if hits else "FAIL", f"Found in {hits[0][0]}:{hits[0][1]}" if hits else f"Not found in {', '.join(f for f, _ in scope[:3])}")
        elif t == "version_lt":
            low = [(f, i, m.group(1)) for f, i, m in hits if vkey(m.group(1)) < vkey(r["than"])]
            add(r, "FAIL" if low else "PASS", ("; ".join(f"{f}:{i} {v}" for f, i, v in low[:5]) + f" (minimum {r['than']})") if low else "Library not referenced or version is current", "High")
    S.log(f"Config rules: {n}")
    return n

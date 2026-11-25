"""Config review of a live URL: anonymous checks, authenticated bounded crawl with passive checks, access matrix, logout replay.

Rules of engagement are enforced by the Guard. Only GET navigation and read-only requests are made.
No brute force, fuzzing, injection payloads or load. Bounded pages, one request per interval.
"""
import asyncio
import re
import secrets
import socket
import ssl
import datetime as dt
import urllib.parse as up
from collections import defaultdict

import httpx
from playwright.async_api import async_playwright

from . import db, security, settings
from .findings import Sink
from .guard import Guard, GuardError, host_port

LOGIN_RE = re.compile(r"(?i)(login|signin|sign-in|sso|saml|oauth2?|authorize|/auth/|logon|okta)")
TRACE_RE = re.compile(r"(?i)(exception|stack ?trace|\bat [\w.$]+\([\w.]+:\d+\)|java\.lang\.|org\.apache\.|\bgw\.\w+)")
VERSION_RE = re.compile(r"\d+\.\d+")
SKIP_LINK = re.compile(r"(?i)(logout|log-out|signout|sign-out|delete|remove|destroy|purge|reset|approve|reject|cancel|void|bind|issue|submit|pay|refund|write-?off|disburse|merge)")
GW_RE = re.compile(r"(PolicyCenter|ClaimCenter|BillingCenter|ContactManager|InsuranceNow|Jutro)[\s\-:]*(v?\d+(?:\.\d+){1,3})?", re.I)
JWT_RE = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")
CSRF_RE = re.compile(r"(?i)(csrf|xsrf|token|authenticity|nonce|__RequestVerification)")
DEFAULT_PATHS = ["/ServerTools.do", "/.git/config", "/actuator/health", "/actuator/env", "/swagger-ui/index.html", "/v3/api-docs", "/robots.txt", "/server-status"]
UA = "gwreview/1.0 (authorised security review)"


class GH:
    """Guarded httpx client."""
    def __init__(self, g: Guard):
        self.g = g
        self.c = httpx.AsyncClient(timeout=20, follow_redirects=False, headers={"User-Agent": UA})

    async def req(self, method, url, headers=None, cookies=None, follow=3):
        r = None
        for hop in range(follow + 1):
            if not self.g.allowed(url):
                raise GuardError(f"Blocked: {host_port(url)[0]} is out of scope")
            await self.g.gate("http", method, url)
            r = await self.c.request(method, url, headers=headers, cookies=cookies)
            db.x("UPDATE traffic SET status=? WHERE id=(SELECT MAX(id) FROM traffic WHERE engagement_id=?)", (r.status_code, self.g.eid))
            if r.is_redirect and hop < follow:
                nxt = up.urljoin(url, r.headers.get("location", ""))
                if not self.g.allowed(nxt):
                    r.blocked = nxt
                    return r
                url = nxt
                continue
            return r
        return r

    async def close(self): await self.c.aclose()


def tls_probe(host, port):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=15) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
        cert = ss.getpeercert()
        return ss.version(), ss.cipher()[0], cert["notAfter"]


async def anon_checks(g: Guard, gh: GH, S: Sink, opts):
    e = g.e; base = e["url"]; T = e["host"]
    S.log("Anonymous checks: TLS, headers, banner, error page, methods, CORS, exposed paths")
    if base.startswith("https"):
        await g.gate("tls", "HANDSHAKE", base)
        try:
            ver, cipher, na = await asyncio.to_thread(tls_probe, g.host, host_port(base)[1])
            days = (dt.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc) - dt.datetime.now(dt.timezone.utc)).days
            ok = ver in ("TLSv1.2", "TLSv1.3") and days > 0
            S.add("live", "GW-WEB-011", "TLS version, cipher and certificate chain", T, "PASS" if ok else "FAIL", f"{ver} {cipher}; chain valid; certificate expires in {days} days. Full cipher enumeration needs testssl.sh at low rate.", severity="Medium")
        except Exception as ex:  # noqa: BLE001
            S.add("live", "GW-WEB-011", "TLS handshake with chain validation", T, "FAIL", f"TLS error: {ex}", severity="High")
    else:
        S.add("live", "GW-WEB-011", "TLS in use", T, "FAIL", "Target is served over plain HTTP", severity="High")
    r = await gh.req("GET", base)
    hd = {k.lower(): v for k, v in r.headers.items()}
    note = f" (headers from last in-scope response; redirected to {r.blocked})" if getattr(r, "blocked", None) else ""
    missing = []
    if base.startswith("https") and "strict-transport-security" not in hd: missing.append("Strict-Transport-Security")
    if hd.get("x-content-type-options", "").lower() != "nosniff": missing.append("X-Content-Type-Options")
    csp = hd.get("content-security-policy", "")
    if "x-frame-options" not in hd and "frame-ancestors" not in csp: missing.append("X-Frame-Options or CSP frame-ancestors")
    if not csp: missing.append("Content-Security-Policy")
    soft = [n for n in ("referrer-policy", "permissions-policy") if n not in hd]
    S.add("live", "GW-WEB-008", "Security headers (landing page)", T, "FAIL" if missing else ("INFO" if soft else "PASS"),
          ("Missing: " + ", ".join(missing) if missing else "Core headers present") + (f". Also absent: {', '.join(soft)}" if soft else "") + note, severity="Medium")
    leak = [f"{k}: {hd[k]}" for k in ("server", "x-powered-by", "x-aspnet-version") if k in hd and VERSION_RE.search(hd[k])]
    S.add("live", "GW-WEB-010", "Server banner / version disclosure", T, "FAIL" if leak else "PASS", "; ".join(leak) or "No version in Server / X-Powered-By", severity="Low")
    pr = await gh.req("GET", up.urljoin(base if base.endswith("/") else base + "/", f"gwreview-probe-{secrets.token_hex(4)}"))
    body = pr.text[:20000] if "text" in pr.headers.get("content-type", "text") else ""
    m = TRACE_RE.search(body)
    S.add("live", "GW-WEB-010", "Error page leaks stack trace or internals", T, "FAIL" if m else "PASS", f"Status {pr.status_code}; matched '{m.group(0)[:60]}'" if m else f"Status {pr.status_code}; no stack-trace markers", severity="Medium")
    o = await gh.req("OPTIONS", base); allow = o.headers.get("allow", "")
    tr = await gh.req("TRACE", base)
    risky = [x for x in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if x in allow.upper()]
    S.add("live", "GW-WEB-013", "HTTP methods", T, "FAIL" if (tr.status_code == 200 or risky) else "PASS", f"OPTIONS {o.status_code} Allow='{allow}'; TRACE -> {tr.status_code}", severity="Low")
    origin = "https://gwreview-probe.invalid"
    c = await gh.req("GET", base, headers={"Origin": origin})
    acao, acac = c.headers.get("access-control-allow-origin", ""), c.headers.get("access-control-allow-credentials", "")
    S.add("live", "GW-WEB-017", "CORS reflects an arbitrary origin", T, "FAIL" if (acao == origin or (acao == "*" and acac.lower() == "true")) else "PASS", f"ACAO='{acao}' ACAC='{acac}'", severity="High")
    for p in (opts.get("paths") or DEFAULT_PATHS)[:25]:
        url = up.urljoin(base if base.endswith("/") else base + "/", p.lstrip("/"))
        try:
            rr = await gh.req("GET", url, follow=1)
        except GuardError as ex:
            S.add("live", "GW-WEB-014", f"Path {p}", T, "ERROR", str(ex)); continue
        loc = rr.headers.get("location", "")
        ctrl = "GW-CFG-004" if re.search(r"(?i)servertools|internaltools|debug", p) else "GW-WEB-014"
        if rr.status_code in (401, 403, 404) or (300 <= rr.status_code < 400 and LOGIN_RE.search(loc)) or (rr.status_code == 200 and LOGIN_RE.search(str(rr.url))):
            S.add("live", ctrl, f"Unauthenticated access to {p}", T, "PASS", f"{rr.status_code} {('-> ' + loc[:80]) if loc else ''}")
        elif rr.status_code == 200:
            S.add("live", ctrl, f"Unauthenticated access to {p}", T, "FAIL", f"200 without authentication ({len(rr.content)} bytes): candidate exposure, verify manually", severity="High")
        else:
            S.add("live", ctrl, f"Unauthenticated access to {p}", T, "INFO", f"{rr.status_code} {loc[:80]}")


def parse_matrix(text):
    out = []
    for line in (text or "").splitlines():
        parts = [x.strip() for x in line.split(",")]
        if len(parts) >= 3 and parts[2].lower() in ("allow", "deny"):
            out.append({"persona": parts[0], "path": parts[1], "expect": parts[2].lower(), "marker": parts[3] if len(parts) > 3 else ""})
    return out


async def authed_review(g: Guard, gh: GH, S: Sink, sess, opts, pw):
    label = sess["label"]; T = g.host; base = g.e["url"]
    state = security.unseal(sess["state_enc"])
    S.log(f"[{label}] authenticated review: bounded crawl (max {opts['max_pages']} pages, depth {opts['depth']})")
    browser = await pw.chromium.launch(headless=True)
    ctx = await browser.new_context(storage_state=state, viewport={"width": 1280, "height": 800})

    async def route(rt):
        rq = rt.request
        try:
            if rq.url.startswith(("data:", "blob:")): return await rt.continue_()
            if not g.allowed(rq.url): return await rt.abort()
            if rq.resource_type in ("document", "xhr", "fetch"): await g.gate("browser", rq.method, rq.url)
            await rt.continue_()
        except GuardError:
            await rt.abort(); raise
        except Exception:  # noqa: BLE001
            try: await rt.abort()
            except Exception: pass  # noqa: BLE001
    await ctx.route("**/*", route)
    page = await ctx.new_page(); page.set_default_timeout(30000)
    excl = re.compile(opts["exclude"]) if opts.get("exclude") else None
    seen, queue, pages = set(), [(base, 0)] + [(up.urljoin(base, s), 0) for s in opts.get("seeds", [])], []
    agg = defaultdict(list); gw = set(); expired = False
    try:
        while queue and len(pages) < opts["max_pages"]:
            url, depth = queue.pop(0)
            key = url.split("#")[0]
            if key in seen or not g.allowed(url): continue
            seen.add(key)
            try:
                resp = await page.goto(url, wait_until="domcontentloaded")
            except GuardError: raise
            except Exception as ex:  # noqa: BLE001
                agg["nav_error"].append(f"{url}: {str(ex)[:80]}"); continue
            final = page.url
            if host_port(final)[0] != T or (LOGIN_RE.search(final) and not LOGIN_RE.search(url)):
                expired = True; break
            await page.wait_for_timeout(400)
            hd = {k.lower(): v for k, v in (resp.headers if resp else {}).items()}
            html = (await page.content())[:400000]
            pages.append(final)
            u = final
            for h, label_ in (("x-content-type-options", "X-Content-Type-Options"), ("strict-transport-security", "Strict-Transport-Security")):
                if h not in hd: agg["hdr:" + label_].append(u)
            if "content-security-policy" not in hd: agg["hdr:Content-Security-Policy"].append(u)
            if "x-frame-options" not in hd and "frame-ancestors" not in hd.get("content-security-policy", ""): agg["hdr:Framing protection"].append(u)
            if "no-store" not in hd.get("cache-control", "").lower(): agg["cache"].append(u)
            if TRACE_RE.search(html): agg["trace"].append(u)
            if re.search(r"(?i)jsessionid=|[?&](sid|session|token)=", u + " ".join(re.findall(r'href="([^"]+)"', html)[:200])): agg["urlsess"].append(u)
            for c in re.findall(r"<!--(.*?)-->", html, re.S)[:50]:
                if re.search(r"(?i)(password|passwd|secret|todo|fixme|internal|\b10\.\d+\.\d+\.\d+|\bv?\d+\.\d+\.\d+)", c): agg["comment"].append(f"{u}: {c.strip()[:80]}")
            for m in GW_RE.finditer(html[:200000]):
                if m.group(2): gw.add(f"{m.group(1)} {m.group(2)}")
            forms = await page.eval_on_selector_all("form", "els=>els.map(f=>({a:f.action,m:(f.method||'get').toLowerCase(),i:[...f.querySelectorAll('input')].map(i=>({n:i.name||'',t:i.type,ac:i.autocomplete||''}))}))")
            for f in forms:
                if f["m"] == "post" and not any(CSRF_RE.search(i["n"]) and i["t"] == "hidden" for i in f["i"]): agg["csrf"].append(f"{u} -> {f['a'][:60]}")
                if f["a"].startswith("http://"): agg["formhttp"].append(f"{u} -> {f['a']}")
                for i in f["i"]:
                    if i["t"] == "password" and i["ac"] not in ("off", "new-password", "one-time-code"): agg["pwauto"].append(u)
            scripts = await page.eval_on_selector_all("script[src]", "els=>els.map(e=>({s:e.src,i:!!e.integrity}))")
            for sc in scripts:
                if host_port(sc["s"])[0] != T and not sc["i"]: agg["sri"].append(f"{host_port(sc['s'])[0]}")
                if sc["s"].startswith("http://") and base.startswith("https"): agg["mixed"].append(sc["s"][:80])
            st = await page.evaluate("()=>({l:Object.entries(localStorage).map(e=>[e[0],String(e[1]).slice(0,400)]),s:Object.entries(sessionStorage).map(e=>[e[0],String(e[1]).slice(0,400)])})")
            for store, items in (("localStorage", st["l"]), ("sessionStorage", st["s"])):
                for k, v in items:
                    if JWT_RE.match(v) or re.search(r"(?i)(token|secret|password)", k): agg["tokstore"].append(f"{store}:{k}")
            if depth < opts["depth"]:
                links = await page.eval_on_selector_all("a[href]", "els=>els.map(e=>e.href)")
                for l in links:
                    l = l.split("#")[0]
                    if l.startswith(("http://", "https://")) and g.allowed(l) and l not in seen and not SKIP_LINK.search(l) and not (excl and excl.search(l)):
                        queue.append((l, depth + 1))
            S.log(f"[{label}] page {len(pages)}: {final[:100]}", min(10 + int(60 * len(pages) / opts['max_pages']), 70))
        S.add("live", "GW-WEB-014", f"[{label}] Authenticated crawl coverage", T, "INFO" if pages else "ERROR", f"{len(pages)} page(s) reviewed; {len(queue)} more discovered but not visited. Guidewire UIs often navigate by script, so coverage by links is limited: add seed paths for important screens.")
        if expired:
            S.add("live", "GW-AUT-001", f"[{label}] Captured session was not accepted", T, "ERROR", "The saved session redirected to login. Re-authenticate and run again.", severity="")
        def listed(k, n=5): return "; ".join(agg[k][:n]) + (f" (+{len(agg[k]) - n} more)" if len(agg[k]) > n else "")
        for k, nm in (("hdr:Strict-Transport-Security", "Strict-Transport-Security"), ("hdr:X-Content-Type-Options", "X-Content-Type-Options"), ("hdr:Content-Security-Policy", "Content-Security-Policy"), ("hdr:Framing protection", "Framing protection")):
            if pages: S.add("live", "GW-WEB-008", f"[{label}] {nm} on authenticated pages", T, "FAIL" if agg[k] else "PASS", f"Missing on {len(agg[k])} of {len(pages)} pages: {listed(k)}" if agg[k] else f"Present on all {len(pages)} pages", severity="Medium")
        if pages: S.add("live", "GW-WEB-009", f"[{label}] Cache-Control no-store on authenticated pages", T, "FAIL" if agg["cache"] else "PASS", f"Not set on {len(agg['cache'])} of {len(pages)}: {listed('cache')}" if agg["cache"] else "Set on all pages", severity="Medium")
        S.add("live", "GW-WEB-010", f"[{label}] Stack traces or internals in pages", T, "FAIL" if agg["trace"] else "PASS", listed("trace") or "None found in crawled pages", severity="Medium")
        S.add("live", "GW-WEB-004", f"[{label}] Session identifiers in URLs", T, "FAIL" if agg["urlsess"] else "PASS", listed("urlsess") or "None found", severity="High")
        S.add("live", "GW-WEB-007", f"[{label}] POST forms without an anti-CSRF token field (candidate)", T, "FAIL" if agg["csrf"] else "PASS", (listed("csrf") + ". Guidewire may protect requests another way: confirm manually.") if agg["csrf"] else "All POST forms carry a token-like hidden field", severity="Medium")
        S.add("live", "GW-WEB-011", f"[{label}] Forms posting to plain HTTP", T, "FAIL" if agg["formhttp"] else "PASS", listed("formhttp") or "None found", severity="High")
        S.add("live", "GW-WEB-023", f"[{label}] Password fields allow autocomplete", T, "INFO" if agg["pwauto"] else "PASS", listed("pwauto") or "None found", severity="Low")
        S.add("live", "GW-WEB-025", f"[{label}] External scripts without Subresource Integrity", T, "FAIL" if (agg["sri"] or agg["mixed"]) else "PASS", f"External: {sorted(set(agg['sri']))[:5]}; mixed content: {agg['mixed'][:3]}" if (agg["sri"] or agg["mixed"]) else "No external scripts without SRI", severity="Medium")
        S.add("live", "GW-WEB-024", f"[{label}] Tokens kept in browser storage", T, "FAIL" if agg["tokstore"] else "PASS", listed("tokstore") or "No token-like values in localStorage / sessionStorage", severity="Medium")
        if agg["comment"]: S.add("live", "GW-WEB-010", f"[{label}] Revealing HTML comments", T, "INFO", listed("comment"), severity="Low")
        S.add("live", "GW-SCP-001", f"[{label}] Product and release strings seen in pages", T, "INFO", ", ".join(sorted(gw)) or "None seen. Record release from the About page or Server Tools.")
        cookies = [c for c in await ctx.cookies() if g.host.endswith(c["domain"].lstrip("."))]
        weak = []
        for c in cookies:
            csrfish = re.search(r"(?i)xsrf|csrf", c["name"])
            if not c["secure"] and base.startswith("https"): weak.append(f"{c['name']}: no Secure")
            if not c["httpOnly"] and not csrfish: weak.append(f"{c['name']}: no HttpOnly")
            if c.get("sameSite") in (None, "None") and not csrfish: weak.append(f"{c['name']}: SameSite=None")
        S.add("live", "GW-WEB-004", f"[{label}] Session cookie flags", T, "FAIL" if weak else "PASS", "; ".join(weak) if weak else f"{len(cookies)} cookie(s) with Secure/HttpOnly/SameSite set", severity="Medium")
        # access matrix
        for m in [x for x in parse_matrix(opts.get("matrix")) if x["persona"] == label]:
            url = up.urljoin(base if base.endswith("/") else base + "/", m["path"].lstrip("/"))
            r = await page.goto(url, wait_until="domcontentloaded"); status = r.status if r else 0
            try: body = (await page.inner_text("body"))[:5000]
            except Exception: body = ""  # noqa: BLE001
            red = bool(LOGIN_RE.search(page.url)) and not LOGIN_RE.search(url)
            denied = status in (401, 403, 404) or red or (m["marker"] and m["marker"].lower() in body.lower())
            if m["expect"] == "deny":
                S.add("live", "GW-AZN-015", f"Access matrix: {label} -> {m['path']} (expect deny)", T, "PASS" if denied else "FAIL", f"status {status}, final URL {page.url[:80]}" + ("" if denied else ". Candidate: confirm manually, proof of concept only."), severity="High")
            else:
                ok = status < 400 and not red and (not m["marker"] or m["marker"].lower() in body.lower())
                S.add("live", "GW-AZN-015", f"Access matrix: {label} -> {m['path']} (expect allow)", T, "PASS" if ok else "FAIL", f"status {status}, final URL {page.url[:80]}", severity="Medium")
        # logout replay (ends this captured session)
        if opts.get("logout") and opts["logout"].get("label") in (label, "*"):
            lo = opts["logout"]; old = {c["name"]: c["value"] for c in cookies}
            try:
                await page.goto(base, wait_until="domcontentloaded")
                if lo.get("selector"): await page.click(lo["selector"])
                elif lo.get("url"): await page.goto(up.urljoin(base, lo["url"].lstrip("/")), wait_until="domcontentloaded")
                await page.wait_for_load_state("load")
                rr = await gh.req("GET", up.urljoin(base if base.endswith("/") else base + "/", (lo.get("protected") or "").lstrip("/")), cookies=old, follow=0)
                loc = rr.headers.get("location", "")
                dead = rr.status_code in (401, 403) or (300 <= rr.status_code < 400 and LOGIN_RE.search(loc))
                S.add("live", "GW-WEB-005", f"[{label}] Old session cookie rejected after logout", T, "PASS" if dead else "FAIL", f"replay -> {rr.status_code} {loc[:60]}", severity="High")
                db.x("DELETE FROM auth_sessions WHERE id=?", (sess["id"],))
                S.log(f"[{label}] logout test ended this captured session")
            except Exception as ex:  # noqa: BLE001
                S.add("live", "GW-WEB-005", f"[{label}] Logout test", T, "ERROR", str(ex)[:200])
        else:
            S.add("live", "GW-WEB-005", f"[{label}] Logout invalidates the server session", T, "MANUAL", "Logout test not requested for this session")
    finally:
        await browser.close()


async def run(scan_id, eid, opts, user):
    S = Sink(eid, scan_id)
    g = Guard(eid)
    gh = GH(g)
    try:
        g.check_ready()
        o = {"max_pages": min(int(opts.get("max_pages", 30)), 200), "depth": min(int(opts.get("depth", 2)), 4), "exclude": opts.get("exclude", ""),
             "seeds": [s.strip() for s in (opts.get("seeds") or "").splitlines() if s.strip()], "matrix": opts.get("matrix", ""), "logout": opts.get("logout"),
             "paths": [s.strip() for s in (opts.get("paths") or "").splitlines() if s.strip()]}
        if opts.get("anon", True):
            await anon_checks(g, gh, S, o)
        S.log("Anonymous checks done", 25)
        sessions = db.q("SELECT * FROM auth_sessions WHERE engagement_id=?", (eid,))
        if opts.get("authed", True) and sessions:
            async with async_playwright() as pw:
                for s in sessions:
                    await authed_review(g, gh, S, db.d(s), o, pw)
        elif opts.get("authed", True):
            S.add("live", "GW-AUT-001", "Authenticated review", g.host, "MANUAL", "No captured login session. Use the Authentication tab first.")
        S.log("Live review complete", 90)
        return S.n
    finally:
        await gh.close()

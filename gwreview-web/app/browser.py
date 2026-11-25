"""Interactive login in a server-side Chromium shown inside the web app (CDP screencast), then session capture.

The person completes Okta (password, MFA push / TOTP / SMS) in the live view. When the browser is back on the target host,
the session (cookies + local storage) is encrypted and stored. No credentials pass through the tool's own code.
"""
import asyncio
import base64
import re
import time

from playwright.async_api import async_playwright

from . import db, security, settings
from .guard import Guard, GuardError, host_port

VIEW_W, VIEW_H = 1280, 800
LOGIN_RE = re.compile(r"(?i)(login|signin|sign-in|sso|saml|oauth2?|authorize|/auth/|logon|mfa|okta)")


class AuthSession:
    def __init__(self, guard: Guard, label, user):
        self.g, self.label, self.user = guard, label, user
        self.pw = self.browser = self.ctx = self.page = self.cdp = None
        self.subscribers = set()
        self.idp = None
        self.visited_idp = False
        self.msgs = []
        self.closed = False

    def note(self, m):
        self.msgs.append(f"{time.strftime('%H:%M:%S')} {m}")
        self.msgs = self.msgs[-50:]

    async def start(self):
        self.g.check_ready()
        self.pw = await async_playwright().start()
        self.browser = await self.pw.chromium.launch(headless=not settings.HEADED)
        self.ctx = await self.browser.new_context(viewport={"width": VIEW_W, "height": VIEW_H}, ignore_https_errors=False)
        await self.ctx.route("**/*", self._route)
        self.ctx.on("page", lambda p: asyncio.create_task(self._attach(p)))
        page = await self.ctx.new_page()
        await self._attach(page)
        await page.goto(self.g.e["url"], wait_until="domcontentloaded")

    async def _route(self, route):
        """Every request is fetched with redirects disabled so each hop is checked against scope (Chromium does not
        re-route redirects that were continued). An off-scope redirect from an in-scope host is treated as the IdP hop."""
        req = route.request
        try:
            url = req.url
            if url.startswith(("data:", "blob:", "about:")):
                return await route.continue_()
            h = host_port(url)[0]
            if not self.g.allowed(url, browser=True):
                if self.visited_idp and req.resource_type != "document" and h.endswith(settings.IDP_ASSET_HOSTS) and req.method in ("GET", "POST", "OPTIONS"):
                    return await route.continue_()  # Okta widget assets / CAPTCHA, only after the IdP was reached via an in-scope redirect
                self.note(f"Blocked request to {h} (not in scope)")
                return await route.abort()
            if h != self.g.host:
                if not self.idp:
                    self.idp = h
                    self.note(f"Identity provider reached: {h}" + (" (Okta)" if h.endswith(settings.OKTA_HOSTS) else ""))
                self.visited_idp = True
                if req.resource_type == "document":
                    await self.g.gate("auth-idp", req.method, url, count=False)
            elif req.resource_type in ("document", "xhr", "fetch"):
                await self.g.gate("auth", req.method, url)
            import html
            import urllib.parse as up
            resp = await route.fetch(max_redirects=0)
            hops = 0
            while 300 <= resp.status < 400 and resp.headers.get("location"):
                nxt = up.urljoin(url, resp.headers["location"])
                if not self.g.allowed(nxt, browser=True):
                    if req.resource_type == "document" and self.g.approve_idp(nxt):
                        self.note(f"Redirect to identity provider {host_port(nxt)[0]} approved (from in-scope host)")
                    else:
                        self.note(f"Blocked redirect to {host_port(nxt)[0]} (not in scope)")
                        return await route.abort()
                if req.resource_type == "document":
                    # Chromium follows fulfilled redirects internally without routing them, so hand the next hop back to the
                    # browser as a navigation; it then passes through this guard like any other request.
                    page = f'<!doctype html><meta http-equiv="refresh" content="0;url={html.escape(nxt, quote=True)}"><a href="{html.escape(nxt, quote=True)}">Continue</a>'
                    hdrs = {k: v for k, v in resp.headers.items() if k.lower() == "set-cookie"}
                    return await route.fulfill(status=200, body=page, content_type="text/html", headers=hdrs)
                hops += 1
                if hops > 5:
                    self.note("Blocked: too many redirects"); return await route.abort()
                url = nxt
                await self.g.gate("auth", "GET", url)
                resp = await self.ctx.request.get(url, max_redirects=0)
            await route.fulfill(response=resp)
        except GuardError as e:
            self.note(f"Halted: {e}")
            await route.abort()
        except Exception:  # noqa: BLE001
            try: await route.abort()
            except Exception: pass  # noqa: BLE001

    async def _attach(self, page):
        self.page = page
        if self.cdp:
            try: await self.cdp.send("Page.stopScreencast")
            except Exception: pass  # noqa: BLE001
        self.cdp = await self.ctx.new_cdp_session(page)
        self.cdp.on("Page.screencastFrame", lambda f: asyncio.create_task(self._frame(f)))
        await self.cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 55, "maxWidth": VIEW_W, "maxHeight": VIEW_H, "everyNthFrame": 1})

    async def _frame(self, f):
        try:
            await self.cdp.send("Page.screencastFrameAck", {"sessionId": f["sessionId"]})
        except Exception:  # noqa: BLE001
            return
        data = f["data"]
        for ws in list(self.subscribers):
            try: await ws.send_json({"t": "frame", "d": data})
            except Exception: self.subscribers.discard(ws)  # noqa: BLE001

    def status(self):
        url = self.page.url if self.page else ""
        h = host_port(url)[0] if url else ""
        back = h == self.g.host and not LOGIN_RE.search(url)
        return {"url": url, "idp": self.idp, "okta": bool(self.idp and self.idp.endswith(settings.OKTA_HOSTS)),
                "on_target": h == self.g.host, "looks_complete": bool(back and self.visited_idp), "msgs": self.msgs[-12:]}

    async def input(self, ev):
        p = self.page
        t = ev.get("t")
        x, y = float(ev.get("x", 0)), float(ev.get("y", 0))
        if t == "move": await p.mouse.move(x, y)
        elif t == "click": await p.mouse.click(x, y, button=ev.get("button", "left"), click_count=int(ev.get("n", 1)))
        elif t == "wheel": await p.mouse.wheel(float(ev.get("dx", 0)), float(ev.get("dy", 0)))
        elif t == "type": await p.keyboard.insert_text(ev["text"]) if ev.get("paste") else await p.keyboard.type(ev["text"])
        elif t == "key": await p.keyboard.press(ev["key"])

    async def capture(self):
        s = self.status()
        if not s["on_target"]:
            raise GuardError("The browser is not back on the target yet. Finish the login first.")
        state = await self.ctx.storage_state()
        sid = db.x("INSERT INTO auth_sessions(engagement_id,label,state_enc,idp,final_url,captured_by,captured) VALUES(?,?,?,?,?,?,?)",
                   (self.g.eid, self.label, security.seal(state), self.idp, s["url"][:500], self.user, time.time()))
        db.audit(self.user, "auth_captured", self.g.eid, f"label={self.label} idp={self.idp}")
        await self.close()
        return sid

    async def close(self):
        if self.closed: return
        self.closed = True
        for ws in list(self.subscribers):
            try: await ws.send_json({"t": "closed"})
            except Exception: pass  # noqa: BLE001
        try:
            if self.browser: await self.browser.close()
            if self.pw: await self.pw.stop()
        except Exception: pass  # noqa: BLE001


class AuthManager:
    def __init__(self): self.sessions = {}

    async def start(self, guard, label, user):
        old = self.sessions.pop(guard.eid, None)
        if old: await old.close()
        s = AuthSession(guard, label, user)
        await s.start()
        self.sessions[guard.eid] = s
        return s

    def get(self, eid): return self.sessions.get(eid)

    async def cancel(self, eid):
        s = self.sessions.pop(eid, None)
        if s: await s.close()


MANAGER = AuthManager()

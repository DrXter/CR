"""Scope and rules-of-engagement guard, bound to one engagement. Every request to a target passes through here.

Enforced: approval reference, approved window, in-scope host only, SSRF protection (no private addresses unless enabled),
rate limit, request budget, kill switch, audit trail. IdP hosts (Okta etc.) are reachable by the login browser only.
"""
import asyncio
import datetime as dt
import ipaddress
import json
import socket
import time
import urllib.parse as up

from . import db, settings


class GuardError(Exception):
    pass


def host_port(url):
    p = up.urlsplit(url)
    return (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80)


def is_private(host):
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)]
        except OSError:
            return False
    return any(i.is_private or i.is_loopback or i.is_link_local or i.is_reserved or i.is_multicast or i.is_unspecified for i in ips)


def validate_target_url(url):
    p = up.urlsplit(url)
    if p.scheme not in ("https", "http") or not p.hostname:
        raise GuardError("Enter a full URL starting with https://")
    if p.scheme == "http" and not settings.ALLOW_HTTP:
        raise GuardError("Plain http targets are refused (set GWR_ALLOW_HTTP=1 for a lab).")
    if p.username or p.password:
        raise GuardError("Credentials in the URL are not allowed.")
    if is_private(p.hostname) and not settings.ALLOW_PRIVATE:
        raise GuardError("Target resolves to a private or loopback address. Set GWR_ALLOW_PRIVATE_TARGETS=1 for internal targets.")
    return p


class Guard:
    def __init__(self, eid):
        self.eid = eid
        self._lock = asyncio.Lock()
        self._last = 0.0
        self.approved_idps = set()
        self.reload()

    def reload(self):
        r = db.q("SELECT * FROM engagements WHERE id=?", (self.eid,), one=True)
        if not r:
            raise GuardError("Engagement not found")
        self.e = db.d(r)
        self.host = self.e["host"]
        self.idp_cfg = {h.lower() for h in json.loads(self.e["idp_hosts"] or "[]")}

    # -- readiness
    def check_ready(self):
        self.reload()
        e = self.e
        if e["status"] != "active":
            raise GuardError(f"Engagement is {e['status']}.")
        if e["stop_flag"]:
            raise GuardError("Kill switch is on: testing halted.")
        if not (e["approval_ref"] or "").strip():
            raise GuardError("Approval reference is missing.")
        if not e["roe_by"]:
            raise GuardError("Rules of engagement have not been attested.")
        self._window()

    def _window(self):
        e = self.e
        try:
            s, en = dt.datetime.fromisoformat(e["window_start"]), dt.datetime.fromisoformat(e["window_end"])
        except (TypeError, ValueError):
            raise GuardError("Approved window is not set.")
        now = dt.datetime.now(dt.timezone.utc)
        if s.tzinfo is None: s = s.replace(tzinfo=dt.timezone.utc)
        if en.tzinfo is None: en = en.replace(tzinfo=dt.timezone.utc)
        if not (s <= now <= en):
            raise GuardError(f"Outside the approved window ({s.isoformat()} to {en.isoformat()}).")

    # -- per request
    def allowed(self, url, nav_from_target=False, browser=False):
        h, _ = host_port(url)
        if h == self.host:
            return True
        if browser and (h in self.idp_cfg or h in self.approved_idps or h.endswith(settings.OKTA_HOSTS)):
            if is_private(h) and not settings.ALLOW_PRIVATE and h not in self.idp_cfg:
                return False
            return True
        return False

    def approve_idp(self, url):
        h, _ = host_port(url)
        if url.startswith("http://") and not settings.ALLOW_HTTP:
            return False
        if is_private(h) and not settings.ALLOW_PRIVATE:
            return False
        self.approved_idps.add(h)
        return True

    async def gate(self, kind, method, url, count=True):
        """Check readiness, enforce rate and budget, then write the audit row."""
        async with self._lock:
            self.check_ready()
            if count:
                gap = time.monotonic() - self._last
                if gap < self.e["interval"]:
                    await asyncio.sleep(self.e["interval"] - gap)
                self._last = time.monotonic()
                if self.e["requests_made"] >= self.e["max_requests"]:
                    raise GuardError(f"Request budget of {self.e['max_requests']} reached.")
                db.x("UPDATE engagements SET requests_made=requests_made+1 WHERE id=?", (self.eid,))
            db.x("INSERT INTO traffic(engagement_id,ts,kind,method,url) VALUES(?,?,?,?,?)", (self.eid, time.time(), kind, method, url[:500]))

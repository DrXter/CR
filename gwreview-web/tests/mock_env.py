"""Mock Guidewire-like target (127.0.0.1:9101) and a separate-host mock Okta-style IdP with an MFA step (localhost:9102)."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

TARGET, IDP = 9101, 9102
SESSIONS = set()


class Target(BaseHTTPRequestHandler):
    server_version = "Apache-Coyote/1.1"
    def log_message(self, *a): pass
    def _send(self, code, body="", ctype="text/html", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers(); self.wfile.write(body.encode())
    def sess(self):
        c = self.headers.get("Cookie", "")
        return any(f"JSESSIONID={s}" in c for s in SESSIONS)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/callback":
            SESSIONS.add("abc123")
            return self._send(302, "", headers={"Location": "/home", "Set-Cookie": "JSESSIONID=abc123; Path=/"})
        if u.path in ("/", "/home", "/admin/Users", "/pc/PolicyCenter.do"):
            if not self.sess():
                return self._send(302, "", headers={"Location": f"http://localhost:{IDP}/authorize?rt=/home"})
            if u.path == "/admin/Users":
                return self._send(200, "<h1>Users administration</h1><a href='/home'>home</a>")
            return self._send(200, "<h1>Welcome underwriter</h1><a href='/admin/Users'>Admin</a><a href='/pc/PolicyCenter.do'>PC</a>")
        if u.path == "/logout":
            return self._send(302, "", headers={"Location": "/", "Set-Cookie": "JSESSIONID=; Path=/; Max-Age=0"})  # server-side session NOT invalidated
        if u.path == "/ServerTools":
            return self._send(200, "<h1>Server Tools</h1>")
        if u.path == "/missing":
            return self._send(500, "java.lang.NullPointerException at com.guidewire.pl.Foo(Foo.java:10) Apache Tomcat/9.0.1")
        return self._send(404, "Not found")
    def do_OPTIONS(self): self._send(200, "", headers={"Allow": "GET, POST, OPTIONS, TRACE"})


class Idp(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body="", headers=None):
        self.send_response(code); self.send_header("Content-Type", "text/html")
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(body.encode()))); self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/authorize":
            return self._send(200, "<title>Mock Okta</title><h1>Sign in</h1><form method=post action='/signin'><input id=u name=u placeholder=user><input id=p name=p type=password><button id=go>Sign in</button></form>")
        if u.path == "/mfa":
            return self._send(200, "<title>Mock Okta MFA</title><h1>Enter code</h1><form method=post action='/verify'><input id=c name=c><button id=v>Verify</button></form>")
        self._send(404, "nf")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); f = parse_qs(self.rfile.read(n).decode())
        if self.path == "/signin":
            if f.get("u") == ["tester"] and f.get("p") == ["pw"]: return self._send(302, "", {"Location": "/mfa"})
            return self._send(401, "bad")
        if self.path == "/verify":
            if f.get("c") == ["123456"]: return self._send(302, "", {"Location": f"http://127.0.0.1:{TARGET}/callback"})
            return self._send(401, "bad code")


def start():
    for port, h in ((TARGET, Target), (IDP, Idp)):
        s = ThreadingHTTPServer(("127.0.0.1", port), h); threading.Thread(target=s.serve_forever, daemon=True).start()


if __name__ == "__main__":
    start(); threading.Event().wait()

"""Tool-level authentication, roles, login throttling and session-at-rest encryption."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from fastapi import Depends, HTTPException, Request

from . import db
from .settings import FERNET, SECRET_KEY, SESSION_HOURS

ROLES = {"viewer": 1, "reviewer": 2, "admin": 3}
_fail = {}   # username/ip -> (count, locked_until)


def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def check_pw(pw, stored):
    try:
        s, h = stored.split("$")
        return hmac.compare_digest(hash_pw(pw, base64.b64decode(s)), stored)
    except Exception:  # noqa: BLE001
        return False


def make_token(username):
    exp = int(time.time()) + SESSION_HOURS * 3600
    body = f"{username}|{exp}"
    sig = hmac.new(SECRET_KEY, body.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{body}|{sig}".encode()).decode()


def read_token(tok):
    try:
        raw = base64.urlsafe_b64decode(tok.encode()).decode()
        body, sig = raw.rsplit("|", 1)
        if not hmac.compare_digest(hmac.new(SECRET_KEY, body.encode(), hashlib.sha256).hexdigest(), sig):
            return None
        username, exp = body.split("|")
        return username if int(exp) > time.time() else None
    except Exception:  # noqa: BLE001
        return None


def throttle_check(key):
    c, until = _fail.get(key, (0, 0))
    if until > time.time():
        raise HTTPException(429, "Too many failed logins. Try again in a few minutes.")


def throttle_fail(key):
    c, until = _fail.get(key, (0, 0))
    c += 1
    _fail[key] = (c, time.time() + 300 if c >= 5 else 0)


def throttle_ok(key):
    _fail.pop(key, None)


def bootstrap_admin():
    if db.q("SELECT 1 FROM users LIMIT 1"):
        return None
    pw = os.environ.get("GWR_ADMIN_PASSWORD") or secrets.token_urlsafe(14)
    db.x("INSERT INTO users(username,pw_hash,role,created) VALUES(?,?,?,?)", ("admin", hash_pw(pw), "admin", time.time()))
    db.audit("system", "bootstrap_admin")
    return pw


def current_user(request: Request):
    tok = request.cookies.get("gwr_session")
    name = read_token(tok) if tok else None
    row = db.q("SELECT * FROM users WHERE username=? AND active=1", (name,), one=True) if name else None
    if not row:
        raise HTTPException(401, "Not signed in")
    if request.method in ("POST", "PATCH", "PUT", "DELETE") and request.headers.get("x-requested-by") != "gwreview":
        raise HTTPException(403, "Missing X-Requested-By header")
    return db.d(row)


def need(role):
    def dep(user=Depends(current_user)):
        if ROLES[user["role"]] < ROLES[role]:
            raise HTTPException(403, f"Requires role {role}")
        return user
    return dep


def seal(obj):
    return FERNET.encrypt(json.dumps(obj).encode())


def unseal(blob):
    return json.loads(FERNET.decrypt(blob))

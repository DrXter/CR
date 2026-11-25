import json
import sqlite3
import threading
import time
from .settings import DB_PATH

_lock = threading.RLock()
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT, role TEXT, active INTEGER DEFAULT 1, created REAL);
CREATE TABLE IF NOT EXISTS engagements(id INTEGER PRIMARY KEY, name TEXT, url TEXT, host TEXT, approval_ref TEXT, window_start TEXT, window_end TEXT,
  interval REAL, max_requests INTEGER, status TEXT DEFAULT 'active', stop_flag INTEGER DEFAULT 0, requests_made INTEGER DEFAULT 0,
  idp_hosts TEXT DEFAULT '[]', roe_by TEXT, roe_at REAL, created_by TEXT, created REAL);
CREATE TABLE IF NOT EXISTS auth_sessions(id INTEGER PRIMARY KEY, engagement_id INTEGER, label TEXT, state_enc BLOB, idp TEXT, final_url TEXT, captured_by TEXT, captured REAL);
CREATE TABLE IF NOT EXISTS uploads(id INTEGER PRIMARY KEY, engagement_id INTEGER, kind TEXT, filename TEXT, size INTEGER, sha256 TEXT, path TEXT, uploaded_by TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, engagement_id INTEGER, kind TEXT, status TEXT, progress INTEGER DEFAULT 0, options TEXT, started REAL, finished REAL, log TEXT DEFAULT '', summary TEXT, created_by TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, engagement_id INTEGER, scan_id INTEGER, source TEXT, control TEXT, check_name TEXT, target TEXT, status TEXT,
  severity TEXT, observed TEXT, evidence TEXT, ts REAL, triage TEXT DEFAULT 'Unreviewed', triage_note TEXT DEFAULT '', triaged_by TEXT);
CREATE TABLE IF NOT EXISTS traffic(id INTEGER PRIMARY KEY, engagement_id INTEGER, ts REAL, kind TEXT, method TEXT, url TEXT, status INTEGER);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, user TEXT, action TEXT, engagement_id INTEGER, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_find ON findings(engagement_id, source);
CREATE INDEX IF NOT EXISTS ix_traffic ON traffic(engagement_id);
"""

def conn():
    c = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

_c = conn()
with _lock:
    _c.executescript(SCHEMA); _c.commit()

def q(sql, args=(), one=False):
    with _lock:
        cur = _c.execute(sql, args)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows

def x(sql, args=()):
    with _lock:
        cur = _c.execute(sql, args); _c.commit()
        return cur.lastrowid

def many(sql, rows):
    with _lock:
        _c.executemany(sql, rows); _c.commit()

def audit(user, action, eid=None, detail=""):
    x("INSERT INTO audit(ts,user,action,engagement_id,detail) VALUES(?,?,?,?,?)", (time.time(), user, action, eid, str(detail)[:1000]))

def d(row):
    return dict(row) if row is not None else None

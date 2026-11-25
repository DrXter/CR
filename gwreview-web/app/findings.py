import time
from . import db


class Sink:
    """Collects findings for one scan, writes progress and log lines."""
    def __init__(self, eid, scan_id):
        self.eid, self.sid = eid, scan_id
        self.n = 0

    def add(self, source, control, check, target, status, observed, evidence="", severity=""):
        db.x("INSERT INTO findings(engagement_id,scan_id,source,control,check_name,target,status,severity,observed,evidence,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
             (self.eid, self.sid, source, control, check[:300], target, status, severity, str(observed)[:1500], str(evidence)[:500], time.time()))
        self.n += 1

    def log(self, msg, progress=None):
        row = db.q("SELECT log FROM scans WHERE id=?", (self.sid,), one=True)
        txt = ((row["log"] if row else "") + f"{time.strftime('%H:%M:%S')} {msg}\n")[-20000:]
        if progress is None:
            db.x("UPDATE scans SET log=? WHERE id=?", (txt, self.sid))
        else:
            db.x("UPDATE scans SET log=?, progress=? WHERE id=?", (txt, progress, self.sid))

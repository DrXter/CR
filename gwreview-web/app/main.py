import asyncio
import datetime as dt
import hashlib
import json
import pathlib
import shutil
import time

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import cfgcheck, db, report, security, settings, srcscan, webscan
from .browser import MANAGER
from .findings import Sink
from .guard import Guard, GuardError, validate_target_url

STATIC = pathlib.Path(__file__).parent / "static"
app = FastAPI(title="gwreview", docs_url=None, redoc_url=None, openapi_url=None)
TASKS = {}
_boot_pw = security.bootstrap_admin()
if _boot_pw:
    print(f"\n*** First start: sign in as 'admin' with password: {_boot_pw}  (set GWR_ADMIN_PASSWORD to choose your own) ***\n", flush=True)


@app.middleware("http")
async def headers(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path.startswith("/api") and request.headers.get("x-requested-by") != "gwreview":
        return JSONResponse({"detail": "Missing X-Requested-By header"}, status_code=403)
    r = await call_next(request)
    r.headers["X-Content-Type-Options"] = "nosniff"; r.headers["X-Frame-Options"] = "DENY"; r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.url.path.startswith("/api"): r.headers["Cache-Control"] = "no-store"
    return r


def edir(eid):
    p = settings.DATA_DIR / "engagements" / str(eid); p.mkdir(parents=True, exist_ok=True); return p


def get_eng(eid):
    e = db.q("SELECT * FROM engagements WHERE id=?", (eid,), one=True)
    if not e: raise HTTPException(404, "Engagement not found")
    return db.d(e)


def live_eng(eid):
    e = get_eng(eid)
    if e["status"] == "destroyed": raise HTTPException(410, "Engagement data was destroyed")
    return e


# ------------------------------------------------------------------ session
class Login(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(b: Login, request: Request, resp: Response):
    key = b.username.lower() + "|" + (request.client.host if request.client else "")
    security.throttle_check(key)
    u = db.q("SELECT * FROM users WHERE username=? AND active=1", (b.username,), one=True)
    if not u or not security.check_pw(b.password, u["pw_hash"]):
        security.throttle_fail(key); db.audit(b.username, "login_failed"); raise HTTPException(401, "Wrong username or password")
    security.throttle_ok(key)
    resp.set_cookie("gwr_session", security.make_token(u["username"]), httponly=True, samesite="strict", secure=settings.COOKIE_SECURE, max_age=settings.SESSION_HOURS * 3600)
    db.audit(u["username"], "login")
    return {"username": u["username"], "role": u["role"]}


@app.post("/api/logout")
def logout(resp: Response, user=Depends(security.current_user)):
    resp.delete_cookie("gwr_session"); db.audit(user["username"], "logout"); return {"ok": True}


@app.get("/api/me")
def me(user=Depends(security.current_user)):
    return {"username": user["username"], "role": user["role"]}


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "reviewer"


@app.get("/api/users")
def users(user=Depends(security.need("admin"))):
    return [{"id": r["id"], "username": r["username"], "role": r["role"], "active": r["active"]} for r in db.q("SELECT * FROM users ORDER BY id")]


@app.post("/api/users")
def add_user(b: NewUser, user=Depends(security.need("admin"))):
    if b.role not in security.ROLES: raise HTTPException(400, "Bad role")
    if len(b.password) < 12: raise HTTPException(400, "Password must be at least 12 characters")
    if db.q("SELECT 1 FROM users WHERE username=?", (b.username,)): raise HTTPException(409, "User exists")
    db.x("INSERT INTO users(username,pw_hash,role,created) VALUES(?,?,?,?)", (b.username, security.hash_pw(b.password), b.role, time.time()))
    db.audit(user["username"], "user_created", None, f"{b.username} {b.role}"); return {"ok": True}


class UserPatch(BaseModel):
    role: str | None = None
    active: int | None = None
    password: str | None = None


@app.patch("/api/users/{uid}")
def patch_user(uid: int, b: UserPatch, user=Depends(security.need("admin"))):
    if b.role: db.x("UPDATE users SET role=? WHERE id=?", (b.role, uid))
    if b.active is not None: db.x("UPDATE users SET active=? WHERE id=?", (b.active, uid))
    if b.password:
        if len(b.password) < 12: raise HTTPException(400, "Password must be at least 12 characters")
        db.x("UPDATE users SET pw_hash=? WHERE id=?", (security.hash_pw(b.password), uid))
    db.audit(user["username"], "user_updated", None, f"id={uid}"); return {"ok": True}


# ------------------------------------------------------------------ engagements
class NewEng(BaseModel):
    url: str
    name: str = ""
    approval_ref: str
    window_start: str
    window_end: str
    interval: float = 1.0
    max_requests: int = 400
    idp_hosts: list[str] = []
    roe_attested: bool = False


@app.post("/api/engagements")
def create_eng(b: NewEng, user=Depends(security.need("reviewer"))):
    try:
        p = validate_target_url(b.url.strip())
    except GuardError as e:
        raise HTTPException(400, str(e))
    if not b.approval_ref.strip(): raise HTTPException(400, "Approval reference is required")
    if not b.roe_attested: raise HTTPException(400, "Attest that the Rules of Engagement have been agreed")
    if b.interval < settings.HARD_MIN_INTERVAL: raise HTTPException(400, f"Interval must be at least {settings.HARD_MIN_INTERVAL}s")
    if b.max_requests > settings.HARD_MAX_REQUESTS: raise HTTPException(400, f"Request budget must be at most {settings.HARD_MAX_REQUESTS}")
    try:
        s, en = dt.datetime.fromisoformat(b.window_start), dt.datetime.fromisoformat(b.window_end)
        if s.tzinfo is None or en.tzinfo is None: raise ValueError
        if en <= s: raise HTTPException(400, "Window end must be after start")
    except ValueError:
        raise HTTPException(400, "Window needs start and end with a timezone")
    eid = db.x("INSERT INTO engagements(name,url,host,approval_ref,window_start,window_end,interval,max_requests,idp_hosts,roe_by,roe_at,created_by,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (b.name or p.hostname, b.url.strip(), p.hostname.lower(), b.approval_ref.strip(), b.window_start, b.window_end, b.interval, b.max_requests,
                json.dumps([h.lower() for h in b.idp_hosts]), user["username"], time.time(), user["username"], time.time()))
    edir(eid); db.audit(user["username"], "engagement_created", eid, f"{b.url} ref={b.approval_ref}")
    return {"id": eid}


@app.get("/api/engagements")
def list_eng(user=Depends(security.current_user)):
    return [{k: r[k] for k in ("id", "name", "url", "status", "approval_ref", "window_start", "window_end", "requests_made", "stop_flag")} for r in db.q("SELECT * FROM engagements ORDER BY id DESC")]


@app.get("/api/engagements/{eid}")
def eng_detail(eid: int, user=Depends(security.current_user)):
    e = get_eng(eid)
    e.pop("idp_hosts", None)
    e["sessions"] = [{"id": r["id"], "label": r["label"], "idp": r["idp"], "captured": r["captured"], "by": r["captured_by"]} for r in db.q("SELECT * FROM auth_sessions WHERE engagement_id=?", (eid,))]
    e["uploads"] = [{"id": r["id"], "kind": r["kind"], "filename": r["filename"], "size": r["size"], "sha256": r["sha256"], "ts": r["ts"]} for r in db.q("SELECT * FROM uploads WHERE engagement_id=? ORDER BY id DESC", (eid,))]
    e["scans"] = [{k: r[k] for k in ("id", "kind", "status", "progress", "started", "finished")} for r in db.q("SELECT * FROM scans WHERE engagement_id=? ORDER BY id DESC LIMIT 20", (eid,))]
    c = db.q("SELECT status, COUNT(*) n FROM findings WHERE engagement_id=? GROUP BY status", (eid,))
    e["counts"] = {r["status"]: r["n"] for r in c}
    return e


@app.post("/api/engagements/{eid}/stop")
async def stop(eid: int, user=Depends(security.need("reviewer"))):
    get_eng(eid); db.x("UPDATE engagements SET stop_flag=1 WHERE id=?", (eid,))
    await MANAGER.cancel(eid)
    for sid, t in list(TASKS.items()):
        if t["eid"] == eid: t["task"].cancel()
    db.audit(user["username"], "kill_switch_on", eid); return {"ok": True}


@app.post("/api/engagements/{eid}/resume")
def resume(eid: int, user=Depends(security.need("admin"))):
    get_eng(eid); db.x("UPDATE engagements SET stop_flag=0 WHERE id=?", (eid,)); db.audit(user["username"], "kill_switch_off", eid); return {"ok": True}


@app.post("/api/engagements/{eid}/destroy")
async def destroy(eid: int, user=Depends(security.need("admin"))):
    e = get_eng(eid)
    await stop(eid, user)
    counts = {t: db.q(f"SELECT COUNT(*) n FROM {t} WHERE engagement_id=?", (eid,), one=True)["n"] for t in ("findings", "auth_sessions", "uploads", "scans", "traffic")}
    shutil.rmtree(edir(eid), ignore_errors=True)
    for t in counts: db.x(f"DELETE FROM {t} WHERE engagement_id=?", (eid,))
    db.x("UPDATE engagements SET status='destroyed' WHERE id=?", (eid,))
    db.audit(user["username"], "data_destroyed", eid, json.dumps(counts))
    return {"engagement": e["name"], "destroyed_at": dt.datetime.now(dt.timezone.utc).isoformat(), "by": user["username"], "removed": counts,
            "note": "Findings, sessions, uploads, scan logs and traffic records removed. Keep only the delivered report, as the Guidewire rules require."}


# ------------------------------------------------------------------ authentication (browser)
class AuthStart(BaseModel):
    label: str = "user1"


@app.post("/api/engagements/{eid}/auth/start")
async def auth_start(eid: int, b: AuthStart, user=Depends(security.need("reviewer"))):
    live_eng(eid)
    try:
        g = Guard(eid); g.check_ready()
        s = await MANAGER.start(g, b.label.strip()[:40] or "user1", user["username"])
    except GuardError as e:
        raise HTTPException(409, str(e))
    db.audit(user["username"], "auth_flow_started", eid, b.label)
    return {"ok": True}


@app.get("/api/engagements/{eid}/auth/status")
def auth_status(eid: int, user=Depends(security.current_user)):
    s = MANAGER.get(eid)
    return s.status() if s else {"active": False}


@app.post("/api/engagements/{eid}/auth/capture")
async def auth_capture(eid: int, user=Depends(security.need("reviewer"))):
    s = MANAGER.get(eid)
    if not s: raise HTTPException(409, "No login in progress")
    try:
        sid = await s.capture()
    except GuardError as e:
        raise HTTPException(409, str(e))
    MANAGER.sessions.pop(eid, None)
    return {"id": sid}


@app.post("/api/engagements/{eid}/auth/cancel")
async def auth_cancel(eid: int, user=Depends(security.need("reviewer"))):
    await MANAGER.cancel(eid); return {"ok": True}


@app.delete("/api/engagements/{eid}/auth/{sid}")
def auth_delete(eid: int, sid: int, user=Depends(security.need("reviewer"))):
    db.x("DELETE FROM auth_sessions WHERE id=? AND engagement_id=?", (sid, eid)); db.audit(user["username"], "auth_session_deleted", eid, sid); return {"ok": True}


@app.websocket("/ws/auth/{eid}")
async def ws_auth(ws: WebSocket, eid: int):
    origin = ws.headers.get("origin", "")
    if origin and origin.split("://")[-1] != ws.headers.get("host", ""):
        await ws.close(code=4403); return
    try:
        name = security.read_token(ws.cookies.get("gwr_session", ""))
        u = db.q("SELECT * FROM users WHERE username=? AND active=1", (name,), one=True) if name else None
        if not u or security.ROLES[u["role"]] < 2: raise HTTPException(401)
    except HTTPException:
        await ws.close(code=4401); return
    s = MANAGER.get(eid)
    if not s: await ws.close(code=4404); return
    await ws.accept(); s.subscribers.add(ws)
    try:
        while True:
            ev = await ws.receive_json()
            try: await s.input(ev)
            except Exception: pass  # noqa: BLE001
    except WebSocketDisconnect:
        pass
    finally:
        s.subscribers.discard(ws)


# ------------------------------------------------------------------ uploads
@app.post("/api/engagements/{eid}/uploads")
async def upload(eid: int, kind: str, file: UploadFile = File(...), user=Depends(security.need("reviewer"))):
    live_eng(eid)
    if kind not in ("source", "config"): raise HTTPException(400, "kind must be source or config")
    d = edir(eid) / "uploads"; d.mkdir(exist_ok=True)
    safe = "".join(c for c in (file.filename or "upload") if c.isalnum() or c in "._-")[:80] or "upload"
    path = d / f"{int(time.time())}_{safe}"
    h = hashlib.sha256(); size = 0; limit = settings.MAX_UPLOAD_MB * 1024 * 1024
    with open(path, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                out.close(); path.unlink(missing_ok=True); raise HTTPException(413, f"Upload larger than {settings.MAX_UPLOAD_MB} MB")
            h.update(chunk); out.write(chunk)
    uid = db.x("INSERT INTO uploads(engagement_id,kind,filename,size,sha256,path,uploaded_by,ts) VALUES(?,?,?,?,?,?,?,?)", (eid, kind, safe, size, h.hexdigest(), str(path), user["username"], time.time()))
    db.audit(user["username"], "upload", eid, f"{kind} {safe} {size}B sha256={h.hexdigest()[:16]}")
    return {"id": uid, "sha256": h.hexdigest(), "size": size}


# ------------------------------------------------------------------ scans
class ScanReq(BaseModel):
    kind: str
    options: dict = {}


async def run_scan(sid, eid, kind, opts, user):
    S = Sink(eid, sid)
    try:
        if kind == "config":
            n = await webscan.run(sid, eid, opts, user)
            up = db.q("SELECT * FROM uploads WHERE engagement_id=? AND kind='config' ORDER BY id DESC LIMIT 1", (eid,), one=True)
            if up:
                S.log("Checking uploaded configuration exports", 92)
                dest = edir(eid) / "config_extracted"; shutil.rmtree(dest, ignore_errors=True)
                await asyncio.to_thread(srcscan.safe_extract, up["path"], dest)
                await asyncio.to_thread(cfgcheck.run, dest, S, {"session_timeout_minutes": int(opts.get("session_timeout", 30))})
            else:
                S.add("config", "GW-CFG-008", "Configuration exports", "config exports", "MANUAL", "No configuration export uploaded. Upload config.xml, server.xml, web.xml and start scripts for the file-based checks.")
            summary = {"findings": S.n}
        else:
            up = db.q("SELECT * FROM uploads WHERE engagement_id=? AND kind='source' ORDER BY id DESC LIMIT 1", (eid,), one=True)
            if not up: raise ValueError("Upload a source archive first")
            S.log("Extracting archive safely", 5)
            dest = edir(eid) / "source_extracted"; shutil.rmtree(dest, ignore_errors=True)
            files, total = await asyncio.to_thread(srcscan.safe_extract, up["path"], dest)
            S.log(f"Extracted {files} files ({total // 1024} KB)", 10)
            summary = await asyncio.to_thread(srcscan.scan, dest, S, opts, edir(eid) / "src_out")
            summary["findings"] = S.n
        db.x("UPDATE scans SET status='done', progress=100, finished=?, summary=? WHERE id=?", (time.time(), json.dumps(summary), sid))
        S.log("Finished")
    except asyncio.CancelledError:
        db.x("UPDATE scans SET status='stopped', finished=? WHERE id=?", (time.time(), sid)); S.log("Stopped (kill switch)")
    except GuardError as e:
        db.x("UPDATE scans SET status='halted', finished=? WHERE id=?", (time.time(), sid)); S.log(f"Halted by guard: {e}")
    except Exception as e:  # noqa: BLE001
        db.x("UPDATE scans SET status='failed', finished=? WHERE id=?", (time.time(), sid)); S.log(f"Failed: {type(e).__name__}: {str(e)[:300]}")
    finally:
        TASKS.pop(sid, None)
        db.audit(user, f"scan_{kind}_finished", eid, f"scan {sid}")


@app.post("/api/engagements/{eid}/scans")
async def start_scan(eid: int, b: ScanReq, user=Depends(security.need("reviewer"))):
    live_eng(eid)
    if b.kind not in ("config", "source"): raise HTTPException(400, "kind must be config or source")
    if any(t["eid"] == eid for t in TASKS.values()): raise HTTPException(409, "A scan is already running for this engagement")
    if b.kind == "config":
        try: Guard(eid).check_ready()
        except GuardError as e: raise HTTPException(409, str(e))
    sid = db.x("INSERT INTO scans(engagement_id,kind,status,options,started,created_by) VALUES(?,?,?,?,?,?)", (eid, b.kind, "running", json.dumps(b.options)[:4000], time.time(), user["username"]))
    TASKS[sid] = {"eid": eid, "task": asyncio.create_task(run_scan(sid, eid, b.kind, b.options, user["username"]))}
    db.audit(user["username"], f"scan_{b.kind}_started", eid, f"scan {sid}")
    return {"id": sid}


@app.get("/api/scans/{sid}")
def scan_get(sid: int, user=Depends(security.current_user)):
    r = db.q("SELECT * FROM scans WHERE id=?", (sid,), one=True)
    if not r: raise HTTPException(404)
    d = db.d(r); d["summary"] = json.loads(d["summary"]) if d["summary"] else None; d.pop("options", None)
    return d


# ------------------------------------------------------------------ findings and reports
@app.get("/api/engagements/{eid}/findings")
def findings(eid: int, source: str = "", status: str = "", triage: str = "", q: str = "", user=Depends(security.current_user)):
    sql, args = "SELECT * FROM findings WHERE engagement_id=?", [eid]
    for col, v in (("source", source), ("status", status), ("triage", triage)):
        if v: sql += f" AND {col}=?"; args.append(v)
    if q: sql += " AND (check_name LIKE ? OR observed LIKE ? OR control LIKE ?)"; args += [f"%{q}%"] * 3
    return [dict(r) for r in db.q(sql + " ORDER BY CASE status WHEN 'FAIL' THEN 0 WHEN 'CANDIDATE' THEN 1 WHEN 'ERROR' THEN 2 WHEN 'MANUAL' THEN 3 ELSE 4 END, control, id LIMIT 3000", tuple(args))]


class Triage(BaseModel):
    triage: str
    note: str = ""


@app.patch("/api/findings/{fid}")
def triage(fid: int, b: Triage, user=Depends(security.need("reviewer"))):
    if b.triage not in ("Unreviewed", "Confirmed", "False positive", "Accepted risk", "Needs retest"): raise HTTPException(400, "Bad triage value")
    r = db.q("SELECT engagement_id FROM findings WHERE id=?", (fid,), one=True)
    if not r: raise HTTPException(404)
    db.x("UPDATE findings SET triage=?, triage_note=?, triaged_by=? WHERE id=?", (b.triage, b.note[:500], user["username"], fid))
    db.audit(user["username"], "triage", r["engagement_id"], f"finding {fid} -> {b.triage}"); return {"ok": True}


@app.get("/api/engagements/{eid}/report.xlsx")
def rep_x(eid: int, user=Depends(security.current_user)):
    get_eng(eid); db.audit(user["username"], "report_xlsx", eid)
    return Response(report.xlsx(eid), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment; filename=gwreview_{eid}.xlsx"})


@app.get("/api/engagements/{eid}/report.html")
def rep_h(eid: int, user=Depends(security.current_user)):
    get_eng(eid); db.audit(user["username"], "report_html", eid)
    return HTMLResponse(report.html_report(eid), headers={"Content-Disposition": f"attachment; filename=gwreview_{eid}.html"})


@app.get("/api/engagements/{eid}/sbom.json")
def sbom(eid: int, user=Depends(security.current_user)):
    p = edir(eid) / "src_out" / "sbom.json"
    if not p.exists(): raise HTTPException(404, "Run a source scan first")
    return FileResponse(p, media_type="application/json", filename=f"sbom_{eid}.json")


@app.post("/api/engagements/{eid}/tracker")
async def tracker_update(eid: int, file: UploadFile = File(...), user=Depends(security.need("reviewer"))):
    get_eng(eid)
    data = await file.read()
    try: out, n = report.tracker(eid, data)
    except Exception as e: raise HTTPException(400, f"Could not read the tracker: {e}")
    db.audit(user["username"], "tracker_updated", eid, f"{n} controls")
    return Response(out, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": "attachment; filename=tracker_gwreview.xlsx", "X-Controls-Updated": str(n)})


@app.get("/api/engagements/{eid}/audit")
def audit_log(eid: int, user=Depends(security.current_user)):
    a = [dict(r) for r in db.q("SELECT ts,user,action,detail FROM audit WHERE engagement_id=? ORDER BY id DESC LIMIT 500", (eid,))]
    t = db.q("SELECT COUNT(*) n FROM traffic WHERE engagement_id=?", (eid,), one=True)["n"]
    return {"audit": a, "traffic_count": t}


@app.get("/api/engagements/{eid}/traffic")
def traffic(eid: int, user=Depends(security.current_user)):
    return [dict(r) for r in db.q("SELECT ts,kind,method,url,status FROM traffic WHERE engagement_id=? ORDER BY id DESC LIMIT 1000", (eid,))]


@app.get("/api/health")
def health(): return {"ok": True}


@app.get("/")
def index(): return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")

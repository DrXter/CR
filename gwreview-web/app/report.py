import html
import io
import json
import time
from collections import Counter, defaultdict

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill

from . import db

COL = {"PASS": "C6EFCE", "FAIL": "FFC7CE", "INFO": "DDEBF7", "MANUAL": "FFEB9C", "ERROR": "F4B084", "CANDIDATE": "FFE699"}


def findings(eid):
    return [dict(r) for r in db.q("SELECT * FROM findings WHERE engagement_id=? ORDER BY control, source, id", (eid,))]


def eng(eid):
    return db.d(db.q("SELECT * FROM engagements WHERE id=?", (eid,), one=True))


def tstr(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)) if t else ""


def xlsx(eid):
    e, rows = eng(eid), findings(eid)
    wb = Workbook(); ws = wb.active; ws.title = "Summary"
    ws.append(["gwreview report"]); ws["A1"].font = Font(bold=True, size=14)
    ws.append(["Automated checks collect evidence. A reviewer decides the final result. FAIL / CANDIDATE mean 'needs attention', not a confirmed finding."])
    for k, v in (("Engagement", e["name"]), ("Target", e["url"]), ("Approval reference", e["approval_ref"]), ("Window", f"{e['window_start']} to {e['window_end']}"),
                 ("RoE attested by", e["roe_by"]), ("Requests sent to target", e["requests_made"])):
        ws.append([k, v])
    ws.append([])
    c = Counter(r["status"] for r in rows)
    for k in ("PASS", "FAIL", "CANDIDATE", "INFO", "MANUAL", "ERROR"): ws.append([k, c.get(k, 0)])
    t = Counter(r["triage"] for r in rows if r["status"] in ("FAIL", "CANDIDATE"))
    ws.append([]); ws.append(["Triage of FAIL / CANDIDATE"]); ws.cell(ws.max_row, 1).font = Font(bold=True)
    for k, v in t.items(): ws.append([k, v])
    ws.column_dimensions["A"].width = 28; ws.column_dimensions["B"].width = 70
    f = wb.create_sheet("Findings")
    hdr = ["Control ID", "Source", "Target", "Check", "Status", "Severity hint", "Observed", "Evidence", "Triage", "Reviewer note", "Reviewer", "Time (UTC)"]
    f.append(hdr)
    for c_ in f[1]: c_.font = Font(bold=True, color="FFFFFF"); c_.fill = PatternFill("solid", fgColor="000000")
    for r in rows:
        f.append([r["control"], r["source"], r["target"], r["check_name"], r["status"], r["severity"], r["observed"], r["evidence"], r["triage"], r["triage_note"], r["triaged_by"] or "", tstr(r["ts"])])
        if r["status"] in COL: f.cell(f.max_row, 5).fill = PatternFill("solid", fgColor=COL[r["status"]])
    for col, w in zip("ABCDEFGHIJKL", (12, 8, 16, 46, 11, 10, 80, 30, 14, 30, 12, 20)): f.column_dimensions[col].width = w
    for row in f.iter_rows(min_row=2):
        for c_ in row: c_.alignment = Alignment(wrap_text=True, vertical="top")
    f.freeze_panes = "A2"; f.auto_filter.ref = f"A1:L{f.max_row}"
    a = wb.create_sheet("Audit")
    a.append(["Time (UTC)", "User", "Action", "Detail"])
    for r in db.q("SELECT * FROM audit WHERE engagement_id=? ORDER BY id", (eid,)): a.append([tstr(r["ts"]), r["user"], r["action"], r["detail"]])
    for col, w in zip("ABCD", (20, 14, 22, 100)): a.column_dimensions[col].width = w
    b = io.BytesIO(); wb.save(b); return b.getvalue()


def html_report(eid):
    e, rows = eng(eid), findings(eid)
    c = Counter(r["status"] for r in rows)
    by = defaultdict(list)
    for r in rows:
        if r["status"] in ("FAIL", "CANDIDATE", "ERROR"): by[r["control"]].append(r)
    def esc(x): return html.escape(str(x or ""))
    out = [f"""<!doctype html><meta charset=utf-8><title>gwreview report</title>
<style>body{{font:14px Arial,sans-serif;margin:32px;color:#111}}h1{{border-bottom:4px solid #86BC25;padding-bottom:6px}}table{{border-collapse:collapse;width:100%;margin:12px 0}}
td,th{{border:1px solid #bbb;padding:5px 7px;vertical-align:top;font-size:12px}}th{{background:#000;color:#fff;text-align:left}}.FAIL{{background:#FFC7CE}}.CANDIDATE{{background:#FFE699}}.ERROR{{background:#F4B084}}
.note{{color:#555;font-style:italic}}</style>
<h1>Guidewire configuration and source review</h1>
<p class=note>Automated checks collect evidence. FAIL and CANDIDATE mean 'needs attention'; a reviewer confirms each one. Triage status is shown for every row.</p>
<table><tr><th>Engagement</th><td>{esc(e['name'])}</td></tr><tr><th>Target</th><td>{esc(e['url'])}</td></tr><tr><th>Approval reference</th><td>{esc(e['approval_ref'])}</td></tr>
<tr><th>Approved window</th><td>{esc(e['window_start'])} to {esc(e['window_end'])}</td></tr><tr><th>RoE attested by</th><td>{esc(e['roe_by'])}</td></tr>
<tr><th>Requests sent to target</th><td>{e['requests_made']}</td></tr></table>
<h2>Results</h2><table><tr>{''.join(f'<th>{k}</th>' for k in ('PASS','FAIL','CANDIDATE','INFO','MANUAL','ERROR'))}</tr><tr>{''.join(f'<td>{c.get(k,0)}</td>' for k in ('PASS','FAIL','CANDIDATE','INFO','MANUAL','ERROR'))}</tr></table>
<h2>Items needing attention, by control</h2>"""]
    for ctrl in sorted(by):
        out.append(f"<h3>{esc(ctrl)}</h3><table><tr><th>Status</th><th>Check</th><th>Observed</th><th>Triage</th><th>Reviewer note</th></tr>")
        for r in by[ctrl][:200]:
            out.append(f"<tr class={r['status']}><td>{r['status']}</td><td>{esc(r['check_name'])}</td><td>{esc(r['observed'])}</td><td>{esc(r['triage'])}</td><td>{esc(r['triage_note'])}</td></tr>")
        out.append("</table>")
    out.append("<h2>Limits</h2><ul><li>Source analysis is pattern based, not data-flow. Gosu and PCF have no built-in tool support.</li><li>Live checks are low-rate, read-only GET navigation inside the approved window. No brute force, fuzzing or load was used.</li><li>Controls not listed were not covered by automation: document review, business logic and segregation of duties remain manual.</li></ul>")
    return "".join(out)


def tracker(eid, data):
    """Return a COPY of the uploaded tracker with observed values. Never sets Compliant / Non-Compliant."""
    wb = load_workbook(io.BytesIO(data)); m = wb["Master Checklist"]
    idx = {m.cell(r, 1).value: r for r in range(5, m.max_row + 1)}
    by = defaultdict(list)
    for r in findings(eid):
        if r["triage"] != "False positive": by[r["control"]].append(r)
    n = 0
    for cid, items in by.items():
        r = idx.get(cid)
        if not r: continue
        parts = [f"[{x['status']}] {x['observed'][:130]}" for x in items[:5]]
        m.cell(r, 13).value = ("AUTO " + " | ".join(parts) + (f" (+{len(items) - 5} more)" if len(items) > 5 else ""))[:1500]
        m.cell(r, 14).value = "gwreview report"
        if m.cell(r, 12).value in (None, "Not Started"): m.cell(r, 12).value = "In Progress"
        n += 1
    b = io.BytesIO(); wb.save(b); return b.getvalue(), n

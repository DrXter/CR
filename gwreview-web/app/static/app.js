"use strict";
const $app = document.getElementById("app");
const S = { user: null, engs: [], eid: null, eng: null, tab: "Quick Audit", ws: null, pollers: [] };

// ---------- helpers (all text goes through textContent: target data is untrusted)
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, ""); else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
async function api(path, opts = {}) {
  const o = { credentials: "same-origin", headers: { "X-Requested-By": "gwreview" }, ...opts };
  if (opts.json) { o.method = o.method || "POST"; o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(opts.json); }
  const r = await fetch(path, o);
  if (r.status === 401 && path !== "/api/login") { S.user = null; render(); throw new Error("Signed out"); }
  if (!r.ok) { let m = r.statusText; try { m = (await r.json()).detail || m; } catch (e) {} throw new Error(m); }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r;
}
const fmt = t => t ? new Date(t * 1000).toLocaleString() : "";
function pill(s) { return h("span", { class: "pill " + s }, s); }
function stopPollers() { S.pollers.forEach(clearInterval); S.pollers = []; }
function poll(fn, ms) { S.pollers.push(setInterval(fn, ms)); }
function toLocalISO(v) { // datetime-local value -> ISO with the browser's UTC offset
  if (!v) return ""; const d = new Date(v); const off = -d.getTimezoneOffset(); const sg = off >= 0 ? "+" : "-";
  const p = n => String(Math.abs(n)).padStart(2, "0");
  return v + ":00" + sg + p(Math.floor(Math.abs(off) / 60)) + ":" + p(Math.abs(off) % 60);
}
function download(path, name) {
  api(path).then(r => r.blob()).then(b => { const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = name; a.click(); URL.revokeObjectURL(a.href); }).catch(e => alert(e.message));
}

// ---------- shell
async function boot() {
  try { S.user = await api("/api/me"); await loadEngs(); } catch (e) { S.user = null; }
  render();
}
async function loadEngs() {
  S.engs = await api("/api/engagements");
  if (S.eid && !S.engs.find(e => e.id === S.eid)) S.eid = null;
  if (!S.eid && S.engs.length) S.eid = S.engs[0].id;
  S.eng = S.eid ? await api("/api/engagements/" + S.eid) : null;
}
function render() {
  stopPollers(); closeWs();
  $app.replaceChildren(S.user ? shell() : loginView());
  if (S.user) tabs[S.tab] && tabs[S.tab]();
}
function loginView() {
  const u = h("input", { autocomplete: "username" }), p = h("input", { type: "password", autocomplete: "current-password" }), er = h("div", { class: "err" });
  const go = async () => { try { S.user = await api("/api/login", { json: { username: u.value, password: p.value } }); await loadEngs(); render(); } catch (e) { er.textContent = e.message; } };
  p.addEventListener("keydown", e => e.key === "Enter" && go());
  return h("div", { class: "login card" }, h("h2", {}, "gwreview"), h("div", { class: "hint" }, "Guidewire configuration and source review workbench"),
    h("label", {}, "Username"), u, h("label", {}, "Password"), p, er, h("p", {}, h("button", { class: "b", onclick: go }, "Sign in")));
}
const TABS = ["Quick Audit", "Engagement", "Authentication", "Config Review", "Source Review", "Findings", "Reports & Audit"];
function shell() {
  const sel = h("select", { onchange: async e => { S.eid = +e.target.value || null; S.eng = S.eid ? await api("/api/engagements/" + S.eid) : null; render(); } },
    h("option", { value: "" }, "New engagement..."), S.engs.map(e => h("option", { value: e.id, selected: e.id === S.eid }, `#${e.id} ${e.name}${e.status !== "active" ? " (" + e.status + ")" : ""}`)));
  const stop = S.eng && S.eng.status === "active" ? h("button", { class: "stop", onclick: async () => { if (confirm("Kill switch: stop all testing for this engagement now?")) { await api(`/api/engagements/${S.eid}/stop`, { method: "POST" }); await refreshEng(); render(); } } }, "STOP TESTING") : null;
  const tl = [...TABS]; if (S.user.role === "admin") tl.push("Admin");
  return h("div", {}, h("div", { class: "top" }, h("div", { class: "brand" }, "gw", h("span", {}, "review")), sel, h("div", { class: "sp" }),
    S.eng && S.eng.stop_flag ? h("span", { class: "tag" }, "KILL SWITCH ON") : null, stop, h("span", {}, `${S.user.username} (${S.user.role})`),
    h("button", { class: "s", onclick: async () => { await api("/api/logout", { method: "POST" }); S.user = null; render(); } }, "Sign out")),
    h("div", { class: "nav" }, tl.map(t => h("button", { class: t === S.tab ? "on" : "", onclick: () => { S.tab = t; render(); } }, t))),
    h("main", { id: "main" }));
}
async function refreshEng() { await loadEngs(); }
function main() { return document.getElementById("main"); }
function needEng(m) { if (!S.eng) { m.append(h("div", { class: "card" }, "Create or select an engagement first (Engagement tab).")); return false; } if (S.eng.status === "destroyed") { m.append(h("div", { class: "card" }, "This engagement's data was destroyed.")); return false; } return true; }

// ---------- findings table
function findingsTable(host, params, editable = true) {
  const qs = new URLSearchParams(params);
  const f = { status: h("select", {}, ["", "FAIL", "CANDIDATE", "ERROR", "MANUAL", "PASS", "INFO"].map(v => h("option", { value: v }, v || "All statuses"))),
    triage: h("select", {}, ["", "Unreviewed", "Confirmed", "False positive", "Accepted risk", "Needs retest"].map(v => h("option", { value: v }, v || "All triage"))),
    q: h("input", { placeholder: "Search check, observed, control" }) };
  const body = h("div", {});
  const load = async () => {
    const p = new URLSearchParams(qs); for (const [k, e] of Object.entries(f)) if (e.value) p.set(k, e.value);
    const rows = await api(`/api/engagements/${S.eid}/findings?` + p);
    const t = h("table", {}, h("tr", {}, ["Control", "Status", "Check", "Observed", "Triage", "Note"].map(x => h("th", {}, x))));
    for (const r of rows) {
      const tri = h("select", {}, ["Unreviewed", "Confirmed", "False positive", "Accepted risk", "Needs retest"].map(v => h("option", { value: v, selected: v === r.triage }, v)));
      const note = h("input", { value: r.triage_note || "", placeholder: "note" });
      const save = async () => { try { await api("/api/findings/" + r.id, { method: "PATCH", json: { triage: tri.value, note: note.value } }); } catch (e) { alert(e.message); } };
      tri.addEventListener("change", save); note.addEventListener("change", save);
      t.append(h("tr", {}, h("td", {}, r.control), h("td", {}, pill(r.status), r.severity ? h("div", { class: "hint" }, r.severity) : null), h("td", {}, r.check_name), h("td", {}, r.observed),
        h("td", {}, editable ? tri : r.triage), h("td", {}, editable ? note : r.triage_note)));
    }
    body.replaceChildren(h("div", { class: "hint" }, `${rows.length} row(s)${rows.length >= 3000 ? " (limit reached: filter to narrow)" : ""}`), t);
  };
  Object.values(f).forEach(e => e.addEventListener(e.tagName === "INPUT" ? "change" : "change", load));
  host.append(h("div", { class: "tools" }, f.status, f.triage, f.q, h("button", { class: "s", onclick: load }, "Refresh")), body);
  load();
  return load;
}

// ---------- scan runner widget
function scanPanel(kind, getOptions) {
  const bar = h("div", {}, h("div", { class: "bar" }, h("div", { id: "pb" })));
  const log = h("pre", { class: "log" }, ""), msg = h("div", { class: "err" });
  const btn = h("button", { class: "b" }, "Run scan");
  let timer = null;
  const watch = sid => {
    clearInterval(timer);
    timer = setInterval(async () => {
      const s = await api("/api/scans/" + sid); log.textContent = s.log; log.scrollTop = log.scrollHeight;
      bar.firstChild.firstChild.style.width = s.progress + "%";
      if (s.status !== "running") { clearInterval(timer); btn.disabled = false; msg.className = s.status === "done" ? "ok" : "err"; msg.textContent = "Scan " + s.status + (s.summary ? ": " + JSON.stringify(s.summary) : ""); await refreshEng(); if (panel.onDone) panel.onDone(); }
    }, 1200);
    S.pollers.push(timer);
  };
  btn.addEventListener("click", async () => {
    msg.textContent = ""; btn.disabled = true;
    try { const r = await api(`/api/engagements/${S.eid}/scans`, { json: { kind, options: getOptions() } }); watch(r.id); } catch (e) { msg.className = "err"; msg.textContent = e.message; btn.disabled = false; }
  });
  const running = (S.eng.scans || []).find(s => s.kind === kind && s.status === "running"); if (running) { btn.disabled = true; watch(running.id); }
  const panel = h("div", {}, btn, h("div", { class: "hint" }, ""), bar, log, msg);
  panel.run = () => { if (!btn.disabled) btn.click(); };
  return panel;
}

// ---------- tabs
const tabs = {
  async "Quick Audit"() {
    const m = main();
    if (!S.eng || S.eng.status === "destroyed") {
      const url = h("input", { placeholder: "https://pc-yourcompany.guidewire.net", autocomplete: "off" }), ref = h("input", { placeholder: "Guidewire approval reference" }), ack = h("input", { type: "checkbox" }), er = h("div", { class: "err" });
      const go = async () => {
        er.textContent = "";
        const n = new Date(), e9 = new Date(n.getTime() + 9 * 864e5), pad = x => String(x).padStart(2, "0"), lt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        try { const r = await api("/api/engagements", { json: { url: url.value, name: "", approval_ref: ref.value, window_start: toLocalISO(lt(new Date(n.getTime() - 60000))), window_end: toLocalISO(lt(e9)), interval: 1, max_requests: 400, idp_hosts: [], roe_attested: ack.checked } }); S.eid = r.id; await loadEngs(); render(); } catch (x) { er.textContent = x.message; }
      };
      url.addEventListener("keydown", e => e.key === "Enter" && go());
      m.append(h("div", { class: "card" }, h("h2", {}, "Audit an application"), h("div", { class: "hint" }, "Step 1 of 3: enter the application URL. Then sign in (password or Okta) and run the audit."),
        h("label", {}, "Application URL"), url, h("label", {}, "Guidewire approval reference"), ref,
        h("div", { class: "hint" }, "Testing window defaults to now through 9 days, one request per second, budget 400. Change these in the Engagement tab."),
        h("label", { class: "chk" }, ack, "Rules of Engagement are agreed, this URL is in the approved plan, no production data, backup taken."), er, h("p", {}, h("button", { class: "b", onclick: go }, "Continue"))));
      return;
    }
    const e = S.eng, nS = e.sessions.length;
    m.append(h("div", { class: "card" }, h("h2", {}, "Target: " + e.url), h("div", { class: "hint" }, `Approval ${e.approval_ref}. ${e.requests_made} of ${e.max_requests} requests used.`),
      h("button", { class: "s", onclick: () => { S.eid = null; S.eng = null; render(); } }, "Audit a different application")));
    const mst = h("input", { type: "number", value: "30" }), ext = h("input", { type: "checkbox", checked: true }), upS = h("input", { type: "file", accept: ".zip,.tar,.gz,.tgz" }), upC = h("input", { type: "file" }), msgS = h("div", { class: "hint" }), msgC = h("div", { class: "hint" });
    const upload = (inp, kind, out) => async () => { if (!inp.files[0]) return; out.textContent = "Uploading..."; const fd = new FormData(); fd.append("file", inp.files[0]); try { const r = await api(`/api/engagements/${S.eid}/uploads?kind=${kind}`, { method: "POST", body: fd }); out.textContent = `Uploaded, sha256 ${r.sha256.slice(0, 12)}`; } catch (x) { out.textContent = x.message; } };
    const cfgPanel = scanPanel("config", () => ({ anon: true, authed: S.eng.sessions.length > 0, max_pages: 30, depth: 2, seeds: "", paths: "", matrix: "", session_timeout: +mst.value, logout: null }));
    const srcPanel = scanPanel("source", () => ({ external: ext.checked }));
    const res = h("div", { class: "card" }, h("h2", {}, "Results"));
    const refresh = () => { res.replaceChildren(h("h2", {}, "Results"), h("div", { class: "tools" }, h("button", { class: "b", onclick: () => download(`/api/engagements/${S.eid}/report.xlsx`, `gwreview_${S.eid}.xlsx`) }, "Excel report"), h("button", { class: "s", onclick: () => download(`/api/engagements/${S.eid}/report.html`, `gwreview_${S.eid}.html`) }, "HTML report"))); findingsTable(res, {}, true); };
    cfgPanel.onDone = refresh; srcPanel.onDone = refresh;

    // step 2: sign in, in a separate browser tab
    const label = h("input", { value: "user1", placeholder: "Persona, e.g. underwriter" }), auto = h("input", { type: "checkbox", checked: true }), st = h("div", { class: "hint" }), er = h("div", { class: "err" }), sess = h("div", {});
    const drawS = () => sess.replaceChildren(S.eng.sessions.length ? h("table", {}, h("tr", {}, ["Login", "Via", "Captured", ""].map(x => h("th", {}, x))), ...S.eng.sessions.map(s => h("tr", {}, h("td", {}, s.label), h("td", {}, s.idp || "password"), h("td", {}, fmt(s.captured)),
      h("td", {}, h("button", { class: "s", onclick: async () => { await api(`/api/engagements/${S.eid}/auth/${s.id}`, { method: "DELETE" }); await refreshEng(); render(); } }, "Delete"))))) : h("div", { class: "hint" }, "No login captured yet."));
    drawS();
    const signin = h("button", { class: "b" }, "Sign in (opens a new tab)");
    signin.addEventListener("click", async () => {
      er.textContent = ""; const before = S.eng.sessions.length;
      const w = window.open("about:blank", "_blank");              // open synchronously so the pop-up is not blocked
      try { await api(`/api/engagements/${S.eid}/auth/start`, { json: { label: label.value } }); } catch (x) { er.textContent = x.message; if (w) w.close(); return; }
      const link = `/static/auth.html?eid=${S.eid}`;
      if (w) w.location = link; else st.replaceChildren("Your browser blocked the new tab. ", h("a", { href: link, target: "_blank" }, "Open the sign-in tab"));
      signin.disabled = true; if (w) st.textContent = "Finish signing in (Okta, MFA) in the other tab. This page continues by itself.";
      const iv = setInterval(async () => {
        try {
          await refreshEng();
          if (S.eng.sessions.length > before) { clearInterval(iv); drawS(); signin.disabled = false; st.className = "ok"; st.textContent = "Signed in. Session captured."; if (auto.checked) { st.textContent += " Starting the audit..."; cfgPanel.run(); } return; }
          const s = await api(`/api/engagements/${S.eid}/auth/status`);
          if (s.active === false) { clearInterval(iv); signin.disabled = false; st.className = "hint"; st.textContent = "Sign-in was cancelled or closed."; }
          else st.textContent = (s.okta ? "Okta detected. " : s.idp ? `Identity provider ${s.idp}. ` : "") + "Waiting for you to finish in the other tab...";
        } catch (x) { /* keep waiting */ }
      }, 1500);
      S.pollers.push(iv);
    });
    m.append(h("div", { class: "card" }, h("h2", {}, "Step 2 of 3: sign in (if the application has a login)"),
      h("div", { class: "hint" }, "A new browser tab shows the application's login screen. Sign in with password or Okta and complete MFA there. When you are back on the application the session is captured and this page carries on. Hardware security keys (FIDO2) need a headed server browser."),
      h("div", { class: "row" }, h("div", {}, h("label", {}, "Name this login"), label)), h("label", { class: "chk" }, auto, "Start the audit automatically after sign-in"),
      h("div", { class: "tools" }, signin, h("span", { class: "hint" }, "No login needed? Skip straight to step 3.")), st, er, sess));

    m.append(h("div", { class: "card" }, h("h2", {}, "Step 3 of 3: run the configuration audit"),
      h("div", { class: "hint" }, "Checks TLS, security headers, banners, error pages, HTTP methods, CORS, exposed Guidewire tool paths, cookies, tokens, session handling and a bounded read-only crawl. Uses every captured login plus anonymous checks."),
      h("div", { class: "row" }, h("div", {}, h("label", {}, "Session timeout policy (minutes)"), mst)),
      h("h3", {}, "Optional: configuration exports (zip of config.xml, server.xml, web.xml...)"), h("div", { class: "tools" }, upC, h("button", { class: "s", onclick: upload(upC, "config", msgC) }, "Upload")), msgC, cfgPanel),
      h("div", { class: "card" }, h("h2", {}, "Source code audit"), h("div", { class: "hint" }, "Upload the code as zip, tar or tar.gz, then run. Nothing is executed or built."),
        h("div", { class: "tools" }, upS, h("button", { class: "s", onclick: upload(upS, "source", msgS) }, "Upload")), msgS, h("label", { class: "chk" }, ext, "Also run gitleaks, semgrep and osv-scanner if installed"), srcPanel), res);
    refresh();
  },

  async Engagement() {
    const m = main();
    if (S.eng && S.eng.status !== "destroyed") {
      const e = S.eng; const used = Math.round(100 * e.requests_made / (e.max_requests || 1));
      m.append(h("div", { class: "card" }, h("h2", {}, e.name), h("div", {}, e.url),
        h("div", { class: "stats" }, ...["FAIL", "CANDIDATE", "ERROR", "MANUAL", "PASS", "INFO"].map(k => h("div", { class: "stat" }, h("b", {}, e.counts[k] || 0), pill(k)))),
        h("table", {}, ...[["Approval reference", e.approval_ref], ["Approved window", `${e.window_start}  to  ${e.window_end}`], ["Requests sent / budget", `${e.requests_made} / ${e.max_requests} (${used}%) at one per ${e.interval}s`],
          ["RoE attested by", e.roe_by], ["Captured logins", e.sessions.map(s => s.label + (s.idp ? ` (${s.idp})` : "")).join(", ") || "none yet"], ["Uploads", e.uploads.map(u => `${u.kind}: ${u.filename}`).join(", ") || "none yet"]].map(([a, b]) => h("tr", {}, h("th", {}, a), h("td", {}, b)))),
        h("p", {}, h("button", { class: "s", onclick: () => { S.eid = null; S.eng = null; render(); } }, "New engagement"))));
      return;
    }
    const url = h("input", { placeholder: "https://pc-example.guidewire.net", autocomplete: "off" });
    const name = h("input", { placeholder: "Optional name" }), ref = h("input", { placeholder: "Guidewire approval reference" });
    const now = new Date(); const pad = n => String(n).padStart(2, "0"); const lt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const ws = h("input", { type: "datetime-local", value: lt(now) }), we = h("input", { type: "datetime-local", value: lt(new Date(now.getTime() + 9 * 864e5)) });
    const iv = h("input", { type: "number", value: "1", min: "0.5", step: "0.5" }), mx = h("input", { type: "number", value: "400", max: "2000" });
    const idp = h("input", { placeholder: "Only if not Okta, e.g. login.example.com (comma separated)" }), ack = h("input", { type: "checkbox" }), er = h("div", { class: "err" });
    const go = async () => {
      er.textContent = "";
      try {
        const r = await api("/api/engagements", { json: { url: url.value, name: name.value, approval_ref: ref.value, window_start: toLocalISO(ws.value), window_end: toLocalISO(we.value), interval: +iv.value, max_requests: +mx.value, idp_hosts: idp.value.split(",").map(s => s.trim()).filter(Boolean), roe_attested: ack.checked } });
        S.eid = r.id; await loadEngs(); S.tab = "Authentication"; render();
      } catch (e) { er.textContent = e.message; }
    };
    m.append(h("div", { class: "card" }, h("h2", {}, "Start a review"), h("label", {}, "Target URL"), url,
      h("h3", {}, "Authorisation (required before any live request)"),
      h("div", { class: "hint" }, "Guidewire allows testing only the plan it approved, on the approved URLs, inside the approved window. The tool enforces this on every request."),
      h("div", { class: "row" }, h("div", {}, h("label", {}, "Approval reference"), ref), h("div", {}, h("label", {}, "Engagement name"), name)),
      h("div", { class: "row" }, h("div", {}, h("label", {}, "Window start (your time)"), ws), h("div", {}, h("label", {}, "Window end (your time)"), we),
        h("div", {}, h("label", {}, "Seconds between requests (min 0.5)"), iv), h("div", {}, h("label", {}, "Request budget (max 2000)"), mx)),
      h("label", {}, "Extra identity-provider hosts (Okta hosts are recognised automatically)"), idp,
      h("label", { class: "chk" }, ack, "I confirm the Rules of Engagement are agreed, testing is limited to this URL, no production data is in the environment and a backup exists."),
      er, h("p", {}, h("button", { class: "b", onclick: go }, "Create engagement"))));
  },

  async Authentication() {
    const m = main(); if (!needEng(m)) return;
    const label = h("input", { value: "user1", placeholder: "Persona label, e.g. underwriter" });
    const status = h("div", { class: "hint" }), msgs = h("pre", { class: "log" }), er = h("div", { class: "err" });
    const canvas = h("canvas", { class: "view", width: 1280, height: 800, tabindex: "0" });
    const holder = h("div", { class: "card", id: "viewcard" });
    const cap = h("button", { class: "b", disabled: true }, "Capture session"), can = h("button", { class: "s", disabled: true }, "Cancel");
    const startBtn = h("button", { class: "b" }, "Open login in a new browser session");
    const ctx = canvas.getContext("2d");
    const sessList = h("div", {});
    const drawSessions = () => sessList.replaceChildren(h("table", {}, h("tr", {}, ["Label", "IdP", "Captured", "By", ""].map(x => h("th", {}, x))),
      ...S.eng.sessions.map(s => h("tr", {}, h("td", {}, s.label), h("td", {}, s.idp || ""), h("td", {}, fmt(s.captured)), h("td", {}, s.by),
        h("td", {}, h("button", { class: "s", onclick: async () => { await api(`/api/engagements/${S.eid}/auth/${s.id}`, { method: "DELETE" }); await refreshEng(); render(); } }, "Delete"))))));
    drawSessions();
    const connect = () => {
      closeWs();
      const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/auth/" + S.eid); S.ws = ws;
      ws.onmessage = ev => { const d = JSON.parse(ev.data); if (d.t === "frame") { const im = new Image(); im.onload = () => ctx.drawImage(im, 0, 0, 1280, 800); im.src = "data:image/jpeg;base64," + d.d; } else if (d.t === "closed") { ctx.clearRect(0, 0, 1280, 800); } };
      const send = o => ws.readyState === 1 && ws.send(JSON.stringify(o));
      const pos = e => { const r = canvas.getBoundingClientRect(); return { x: (e.clientX - r.left) * 1280 / r.width, y: (e.clientY - r.top) * 800 / r.height }; };
      let lastMove = 0;
      canvas.onmousemove = e => { const n = Date.now(); if (n - lastMove > 80) { lastMove = n; send({ t: "move", ...pos(e) }); } };
      canvas.onmousedown = e => { canvas.focus(); e.preventDefault(); send({ t: "click", ...pos(e), button: e.button === 2 ? "right" : "left", n: e.detail || 1 }); };
      canvas.oncontextmenu = e => e.preventDefault();
      canvas.onwheel = e => { e.preventDefault(); send({ t: "wheel", x: 0, y: 0, dx: e.deltaX, dy: e.deltaY }); };
      canvas.onkeydown = e => {
        if (e.ctrlKey || e.metaKey) return;
        e.preventDefault();
        if (e.key.length === 1) send({ t: "type", text: e.key }); else send({ t: "key", key: e.key });
      };
      canvas.onpaste = e => { e.preventDefault(); const tx = e.clipboardData.getData("text"); if (tx) send({ t: "type", text: tx, paste: true }); };
    };
    startBtn.addEventListener("click", async () => {
      er.textContent = ""; startBtn.disabled = true;
      try { await api(`/api/engagements/${S.eid}/auth/start`, { json: { label: label.value } }); connect(); cap.disabled = can.disabled = false; canvas.focus(); watch(); } catch (e) { er.textContent = e.message; startBtn.disabled = false; }
    });
    cap.addEventListener("click", async () => { try { await api(`/api/engagements/${S.eid}/auth/capture`, { method: "POST" }); await refreshEng(); render(); } catch (e) { er.textContent = e.message; } });
    can.addEventListener("click", async () => { await api(`/api/engagements/${S.eid}/auth/cancel`, { method: "POST" }); closeWs(); startBtn.disabled = false; cap.disabled = can.disabled = true; ctx.clearRect(0, 0, 1280, 800); });
    const watch = () => poll(async () => {
      const s = await api(`/api/engagements/${S.eid}/auth/status`);
      if (s.active === false) { status.textContent = "No login in progress."; return; }
      status.replaceChildren(h("span", {}, `Page: ${s.url}  `), s.okta ? h("span", { class: "tag" }, "Okta detected") : (s.idp ? h("span", { class: "tag" }, "IdP: " + s.idp) : null), " ", s.looks_complete ? h("span", { class: "ok" }, "Back on the target after sign-in: click Capture session.") : null);
      cap.disabled = !s.on_target; msgs.textContent = (s.msgs || []).join("\n");
    }, 1000);
    m.append(h("div", { class: "card" }, h("h2", {}, "Sign in through your identity provider"),
      h("div", { class: "hint" }, "A controlled browser opens the target below. Complete Okta sign-in and MFA (push, authenticator code, SMS) in the live view. When you are back on the application, capture the session. Your password and MFA codes go to Okta, never into this tool's code or database."),
      h("div", { class: "warn" }, "Hardware security keys (FIDO2) cannot pass through the remote view. For those, run the server on your own computer with GWR_HEADED=1 so a real browser window opens."),
      h("div", { class: "row" }, h("div", {}, h("label", {}, "Persona label"), label)), h("div", { class: "tools" }, startBtn, cap, can), er, status),
      h("div", { class: "card" }, canvas, h("div", { class: "hint" }, "Click the view, then type. Paste with Ctrl+V."), msgs),
      h("div", { class: "card" }, h("h2", {}, "Captured sessions"), h("div", { class: "hint" }, "Stored encrypted. Delete them at close-out."), sessList));
  },

  async "Config Review"() {
    const m = main(); if (!needEng(m)) return;
    const o = { anon: h("input", { type: "checkbox", checked: true }), authed: h("input", { type: "checkbox", checked: true }), pages: h("input", { type: "number", value: "30", min: "1", max: "200" }), depth: h("input", { type: "number", value: "2", min: "0", max: "4" }),
      seeds: h("textarea", { placeholder: "/pc/PolicyCenter.do\n/some/screen" }), excl: h("input", { placeholder: "Regex of URLs to skip" }),
      paths: h("textarea", { placeholder: "Leave empty for the default list (Server Tools, .git, actuator, swagger...)" }), matrix: h("textarea", { placeholder: "underwriter, /admin/Users, deny\nunderwriter, /home, allow, Welcome" }),
      lo: h("input", { type: "checkbox" }), loLabel: h("input", { placeholder: "Persona label" }), loSel: h("input", { placeholder: "Logout button CSS selector (or use URL)" }), loUrl: h("input", { placeholder: "Logout URL path" }), loProt: h("input", { placeholder: "Protected path to replay, e.g. /home" }), st: h("input", { type: "number", value: "30" }) };
    const up = h("input", { type: "file" }), upMsg = h("div", { class: "hint" });
    const upBtn = h("button", { class: "s", onclick: async () => { if (!up.files[0]) return; const fd = new FormData(); fd.append("file", up.files[0]); try { const r = await api(`/api/engagements/${S.eid}/uploads?kind=config`, { method: "POST", body: fd }); upMsg.textContent = "Uploaded. sha256 " + r.sha256.slice(0, 16); } catch (e) { upMsg.textContent = e.message; } } }, "Upload exports");
    const panel = scanPanel("config", () => ({ anon: o.anon.checked, authed: o.authed.checked, max_pages: +o.pages.value, depth: +o.depth.value, seeds: o.seeds.value, exclude: o.excl.value, paths: o.paths.value, matrix: o.matrix.value, session_timeout: +o.st.value,
      logout: o.lo.checked ? { label: o.loLabel.value || "*", selector: o.loSel.value, url: o.loUrl.value, protected: o.loProt.value } : null }));
    const resHost = h("div", { class: "card" }, h("h2", {}, "Results"));
    m.append(h("div", { class: "card" }, h("h2", {}, "Configuration review of the live application"),
      h("div", { class: "hint" }, "Low-rate and read-only: GET navigation, one request per interval, bounded crawl. No brute force, fuzzing, injection or load."),
      h("label", { class: "chk" }, o.anon, "Anonymous checks: TLS, headers, banner, error page, methods, CORS, exposed paths"), h("label", { class: "chk" }, o.authed, `Authenticated review using the ${S.eng.sessions.length} captured session(s)`),
      h("div", { class: "row" }, h("div", {}, h("label", {}, "Max pages per session"), o.pages), h("div", {}, h("label", {}, "Crawl depth"), o.depth), h("div", {}, h("label", {}, "Session timeout policy (minutes)"), o.st)),
      h("div", { class: "row" }, h("div", {}, h("label", {}, "Seed paths (one per line)"), o.seeds), h("div", {}, h("label", {}, "Unauthenticated paths to check (one per line)"), o.paths), h("div", {}, h("label", {}, "Access matrix: persona, path, allow|deny, optional text marker"), o.matrix)),
      h("label", {}, "Skip URLs matching"), o.excl,
      h("label", { class: "chk" }, o.lo, "Logout replay test"), h("div", { class: "warn" }, "The logout test ends that captured session, so run it last or on its own capture."),
      h("div", { class: "row" }, o.loLabel, o.loSel, o.loUrl, o.loProt),
      h("h3", {}, "Configuration exports (optional, enables the file-based checks)"), h("div", { class: "hint" }, "Zip of config.xml, server.xml, web.xml, context.xml, database-config.xml and JVM start scripts, secrets removed."), h("div", { class: "tools" }, up, upBtn), upMsg,
      h("h3", {}, "Run"), panel), resHost);
    panel.onDone = () => { resHost.replaceChildren(h("h2", {}, "Results")); findingsTable(resHost, { source: "" }, true); };
    findingsTable(resHost, {}, true);
  },

  async "Source Review"() {
    const m = main(); if (!needEng(m)) return;
    const up = h("input", { type: "file", accept: ".zip,.tar,.gz,.tgz" }), upMsg = h("div", { class: "hint" }), ext = h("input", { type: "checkbox", checked: true });
    const upBtn = h("button", { class: "s", onclick: async () => { if (!up.files[0]) return; upMsg.textContent = "Uploading..."; const fd = new FormData(); fd.append("file", up.files[0]); try { const r = await api(`/api/engagements/${S.eid}/uploads?kind=source`, { method: "POST", body: fd }); upMsg.textContent = `Uploaded ${Math.round(r.size / 1024)} KB, sha256 ${r.sha256.slice(0, 16)}`; await refreshEng(); } catch (e) { upMsg.textContent = e.message; } } }, "Upload archive");
    const panel = scanPanel("source", () => ({ external: ext.checked }));
    const resHost = h("div", { class: "card" }, h("h2", {}, "Results"));
    const last = (S.eng.uploads || []).find(u => u.kind === "source");
    m.append(h("div", { class: "card" }, h("h2", {}, "Source code review"),
      h("div", { class: "hint" }, "Upload the customer-layer code (zip, tar, tar.gz). The archive is unpacked with path, symlink and size checks and analysed as text. Nothing is executed or built."),
      h("div", { class: "tools" }, up, upBtn), upMsg, last ? h("div", { class: "hint" }, `Latest upload: ${last.filename}, sha256 ${last.sha256.slice(0, 16)}`) : null,
      h("label", { class: "chk" }, ext, "Also run gitleaks, semgrep and osv-scanner when installed on the server"),
      h("div", { class: "hint" }, "Built in: 24 code-pattern rules (servlets, direct JDBC, string SQL, dynamic code, command execution, deserialisation, XXE, crypto, TLS trust, PCF/WSI permission gaps), secret detection with entropy, dependency and SBOM analysis."),
      panel, h("p", {}, h("button", { class: "s", onclick: () => download(`/api/engagements/${S.eid}/sbom.json`, "sbom.json") }, "Download SBOM (CycloneDX)"))), resHost);
    panel.onDone = () => { resHost.replaceChildren(h("h2", {}, "Results")); findingsTable(resHost, { source: "source" }, true); };
    findingsTable(resHost, { source: "source" }, true);
  },

  async Findings() {
    const m = main(); if (!needEng(m)) return;
    const host = h("div", { class: "card" }, h("h2", {}, "All findings"), h("div", { class: "hint" }, "Automation collects evidence; you decide. Mark each FAIL or CANDIDATE as Confirmed, False positive, Accepted risk or Needs retest."));
    m.append(host); findingsTable(host, {}, true);
  },

  async "Reports & Audit"() {
    const m = main(); if (!needEng(m)) return;
    const f = h("input", { type: "file", accept: ".xlsx" }), msg = h("div", { class: "hint" });
    const trk = h("button", { class: "s", onclick: async () => { if (!f.files[0]) return; const fd = new FormData(); fd.append("file", f.files[0]); try { const r = await api(`/api/engagements/${S.eid}/tracker`, { method: "POST", body: fd }); const b = await r.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = "tracker_gwreview.xlsx"; a.click(); msg.textContent = `Tracker copy downloaded: ${r.headers.get("X-Controls-Updated")} controls updated. Status stays In Progress: you decide Compliant or Non-Compliant.`; } catch (e) { msg.textContent = e.message; } } }, "Update my tracker (download copy)");
    const aud = h("div", {});
    api(`/api/engagements/${S.eid}/audit`).then(a => aud.replaceChildren(h("div", { class: "hint" }, `${a.traffic_count} request(s) sent to the target (full list below).`), h("table", {}, h("tr", {}, ["Time", "User", "Action", "Detail"].map(x => h("th", {}, x))), ...a.audit.map(r => h("tr", {}, h("td", {}, fmt(r.ts)), h("td", {}, r.user), h("td", {}, r.action), h("td", {}, r.detail))))));
    const trf = h("div", {});
    const showT = async () => { const t = await api(`/api/engagements/${S.eid}/traffic`); trf.replaceChildren(h("table", {}, h("tr", {}, ["Time", "Kind", "Method", "URL", "Status"].map(x => h("th", {}, x))), ...t.map(r => h("tr", {}, h("td", {}, fmt(r.ts)), h("td", {}, r.kind), h("td", {}, r.method), h("td", {}, r.url), h("td", {}, r.status || ""))))); };
    const destroy = h("button", { class: "stop", onclick: async () => { const n = prompt(`Download your report first. Type the engagement name to destroy all findings, sessions, uploads and logs:\n${S.eng.name}`); if (n !== S.eng.name) return; try { const c = await api(`/api/engagements/${S.eid}/destroy`, { method: "POST" }); alert("Destroyed.\n" + JSON.stringify(c, null, 1)); await loadEngs(); render(); } catch (e) { alert(e.message); } } }, "Destroy engagement data");
    m.append(h("div", { class: "card" }, h("h2", {}, "Reports"),
      h("div", { class: "tools" }, h("button", { class: "b", onclick: () => download(`/api/engagements/${S.eid}/report.xlsx`, `gwreview_${S.eid}.xlsx`) }, "Excel report"), h("button", { class: "s", onclick: () => download(`/api/engagements/${S.eid}/report.html`, `gwreview_${S.eid}.html`) }, "HTML report (print to PDF)"),
        h("button", { class: "s", onclick: () => download(`/api/engagements/${S.eid}/sbom.json`, "sbom.json") }, "SBOM")),
      h("h3", {}, "Write observations into your review tracker"), h("div", { class: "tools" }, f, trk), msg),
      h("div", { class: "card" }, h("h2", {}, "Audit trail"), aud, h("p", {}, h("button", { class: "s", onclick: showT }, "Show request log")), trf),
      S.user.role === "admin" ? h("div", { class: "card" }, h("h2", {}, "Close-out"), h("div", { class: "hint" }, "Guidewire's rules require all findings, results and code snippets to be destroyed after the test, except the report."), h("div", { class: "tools" }, destroy,
        S.eng.stop_flag ? h("button", { class: "s", onclick: async () => { await api(`/api/engagements/${S.eid}/resume`, { method: "POST" }); await refreshEng(); render(); } }, "Release kill switch") : null)) : null);
  },

  async Admin() {
    const m = main(); const list = h("div", {}), er = h("div", { class: "err" });
    const load = async () => { const us = await api("/api/users"); list.replaceChildren(h("table", {}, h("tr", {}, ["User", "Role", "Active", ""].map(x => h("th", {}, x))), ...us.map(u => h("tr", {}, h("td", {}, u.username),
      h("td", {}, h("select", { onchange: async e => { await api("/api/users/" + u.id, { method: "PATCH", json: { role: e.target.value } }); } }, ["viewer", "reviewer", "admin"].map(r => h("option", { value: r, selected: r === u.role }, r)))),
      h("td", {}, u.active ? "yes" : "no"), h("td", {}, h("button", { class: "s", onclick: async () => { await api("/api/users/" + u.id, { method: "PATCH", json: { active: u.active ? 0 : 1 } }); load(); } }, u.active ? "Disable" : "Enable")))))); };
    const nu = h("input", { placeholder: "username" }), np = h("input", { type: "password", placeholder: "password, 12+ characters" }), nr = h("select", {}, ["reviewer", "viewer", "admin"].map(r => h("option", { value: r }, r)));
    m.append(h("div", { class: "card" }, h("h2", {}, "Users and roles"), h("div", { class: "hint" }, "viewer: read only. reviewer: run reviews, upload, triage. admin: users, release kill switch, destroy data."), list,
      h("h3", {}, "Add user"), h("div", { class: "row" }, nu, np, nr), er, h("p", {}, h("button", { class: "b", onclick: async () => { er.textContent = ""; try { await api("/api/users", { json: { username: nu.value, password: np.value, role: nr.value } }); nu.value = np.value = ""; load(); } catch (e) { er.textContent = e.message; } } }, "Add user"))));
    load();
  }
};
function closeWs() { if (S.ws) { try { S.ws.close(); } catch (e) {} S.ws = null; } }
boot();

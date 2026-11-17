"use strict";
const eid = new URLSearchParams(location.search).get("eid");
const $ = id => document.getElementById(id);
const canvas = $("v"), ctx = canvas.getContext("2d");
const H = { "X-Requested-By": "gwreview" };
let ws = null, done = false, okCount = 0;
async function api(p, o = {}) { const r = await fetch(p, { credentials: "same-origin", headers: H, ...o }); if (!r.ok) { let m = r.statusText; try { m = (await r.json()).detail || m; } catch (e) {} throw new Error(m); } return r.json(); }
function connect() {
  ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/auth/" + eid);
  ws.onmessage = ev => { const d = JSON.parse(ev.data); if (d.t === "frame") { const im = new Image(); im.onload = () => ctx.drawImage(im, 0, 0, 1280, 800); im.src = "data:image/jpeg;base64," + d.d; } else if (d.t === "closed") ctx.clearRect(0, 0, 1280, 800); };
  const send = o => ws.readyState === 1 && ws.send(JSON.stringify(o));
  const pos = e => { const r = canvas.getBoundingClientRect(); return { x: (e.clientX - r.left) * 1280 / r.width, y: (e.clientY - r.top) * 800 / r.height }; };
  let last = 0;
  canvas.onmousemove = e => { const n = Date.now(); if (n - last > 80) { last = n; send({ t: "move", ...pos(e) }); } };
  canvas.onmousedown = e => { canvas.focus(); e.preventDefault(); send({ t: "click", ...pos(e), button: e.button === 2 ? "right" : "left", n: e.detail || 1 }); };
  canvas.oncontextmenu = e => e.preventDefault();
  canvas.onwheel = e => { e.preventDefault(); send({ t: "wheel", x: 0, y: 0, dx: e.deltaX, dy: e.deltaY }); };
  canvas.onkeydown = e => { if (e.ctrlKey || e.metaKey) return; e.preventDefault(); if (e.key.length === 1) send({ t: "type", text: e.key }); else send({ t: "key", key: e.key }); };
  canvas.onpaste = e => { e.preventDefault(); const t = e.clipboardData.getData("text"); if (t) send({ t: "type", text: t, paste: true }); };
}
async function capture(auto) {
  if (done) return; done = true;
  try { await api(`/api/engagements/${eid}/auth/capture`, { method: "POST" }); $("msg").textContent = "Session captured. You can close this tab; the audit continues in the other tab."; $("msg").className = "ok"; $("cap").disabled = true; ctx.clearRect(0, 0, 1280, 800); if (ws) ws.close(); setTimeout(() => window.close(), 1500); }
  catch (e) { done = false; $("msg").className = "err"; $("msg").textContent = (auto ? "Auto-capture waiting: " : "") + e.message; }
}
async function tick() {
  if (done) return;
  try {
    const s = await api(`/api/engagements/${eid}/auth/status`);
    if (s.active === false) { $("st").textContent = "No login in progress. Start it from the audit page."; return; }
    $("st").textContent = (s.okta ? "Okta detected. " : s.idp ? `IdP ${s.idp}. ` : "") + s.url;
    $("cap").disabled = !s.on_target;
    okCount = s.looks_complete ? okCount + 1 : 0;
    if (okCount >= 2) capture(true);   // back on the app after an identity-provider hop: capture automatically
  } catch (e) { $("st").textContent = e.message; }
}
$("cap").addEventListener("click", () => capture(false));
$("can").addEventListener("click", async () => { try { await api(`/api/engagements/${eid}/auth/cancel`, { method: "POST" }); } catch (e) {} if (ws) ws.close(); window.close(); });
connect(); canvas.focus(); setInterval(tick, 1000);

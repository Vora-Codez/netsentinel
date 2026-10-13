"use strict";
/* NetSentinel web UI. No frameworks, no CDN (it works on an offline network).
   SECURITY: every dynamic value goes through esc() before it touches innerHTML, because scanned
   banners, DNS names and packet text are attacker-controlled. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const RANK = { viewer: 1, analyst: 2, admin: 3 };
const VIEWS = ["overview", "alerts", "traffic", "scanner", "devices", "settings", "users", "audit", "help"];

const S = {
  view: "overview", status: null, user: null, csrf: "", sev: "all", expanded: new Set(), alertSig: "",
  pktSince: 0, packets: [], paused: false, selPkt: null, tab: "packets", pktFilter: "", ifaces: null,
  scanJob: null, scanTimer: null, failures: 0, settingsDirty: false, poll: null, roles: {},
};
const can = role => S.user && RANK[S.user.role] >= RANK[role];

/* ---------- helpers ---------- */
async function api(path, { method = "GET", body, anon } = {}) {
  const opt = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET") {
    opt.headers["Content-Type"] = "application/json";
    opt.headers[anon ? "X-NS-Client" : "X-NS-Token"] = anon ? "1" : S.csrf;
    opt.body = JSON.stringify(body || {});
  }
  let res;
  try { res = await fetch(path, opt); }
  catch (e) { if (++S.failures >= 3) $("#conn-banner").hidden = false; throw e; }
  S.failures = 0; $("#conn-banner").hidden = true;
  let data = null; try { data = await res.json(); } catch (e) { /* not json */ }
  if (res.status === 401 && !anon && S.user) { endSession(); }
  if (!res.ok) throw Object.assign(new Error((data && data.error) || res.statusText), { data, status: res.status });
  return data;
}
function toast(msg, err) {
  const t = document.createElement("div"); t.className = "toast" + (err ? " err" : ""); t.textContent = msg;
  $("#toasts").append(t); setTimeout(() => t.remove(), err ? 6000 : 3500);
}
const fail = e => { if (e.status !== 401) toast(e.message || "Something went wrong.", true); };
const fmtNum = n => Number(n || 0).toLocaleString();
function fmtBytes(n) {
  n = Number(n || 0); if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"]; let i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < 3);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}
function clock(v, ms) {
  const d = typeof v === "number" ? new Date(v * 1000) : new Date(v); if (isNaN(d)) return "";
  const t = d.toLocaleTimeString([], { hour12: false });
  return ms ? t + "." + String(d.getMilliseconds()).padStart(3, "0") : t;
}
function ago(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now"; if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago"; return new Date(iso).toLocaleDateString();
}
const sevBadge = s => `<span class="badge ${esc(s)}">${esc(s)}</span>`;
const emptyMsg = (el, msg) => { el.textContent = msg || ""; };
/* The CSP forbids inline style="" attributes, so widths are applied through the DOM instead. */
const applyBars = root => $$("i[data-w]", root).forEach(i => { i.style.width = i.dataset.w + "%"; });

/* ---------- sign-in / first-run setup ---------- */
async function boot() {
  let s;
  try { s = await api("/api/session"); } catch (e) { return setTimeout(boot, 2000); }
  S.roles = s.roles || {};
  if (s.user) { S.user = s.user; S.csrf = s.csrf; return enterApp(); }
  showGate(s.setup_required);
}
function showGate(setup) {
  clearInterval(S.poll); S.poll = null;
  $("#app").hidden = true; $("#gate").hidden = false;
  $("#gate").dataset.mode = setup ? "setup" : "login";
  $("#gate-title").textContent = setup ? "Create the administrator" : "Sign in";
  $("#gate-sub").textContent = setup ? "This is the first run. Make the account that will manage NetSentinel." : "Sign in to continue.";
  $("#gate-code-row").hidden = !setup; $("#gate-pass-hint").hidden = !setup;
  $("#gate-submit").textContent = setup ? "Create account" : "Sign in";
  $("#gate-pass").autocomplete = setup ? "new-password" : "current-password";
  $("#gate-error").hidden = true; $("#gate-pass").value = "";
  (setup ? $("#gate-code") : $("#gate-user")).focus();
}
$("#gate-form").addEventListener("submit", async e => {
  e.preventDefault();
  const setup = $("#gate").dataset.mode === "setup", err = $("#gate-error"), btn = $("#gate-submit");
  err.hidden = true; btn.disabled = true;
  try {
    await api(setup ? "/api/setup" : "/api/login", { method: "POST", anon: true,
      body: { username: $("#gate-user").value, password: $("#gate-pass").value, code: $("#gate-code").value } });
    $("#gate-pass").value = ""; await boot();
  } catch (er) { err.hidden = false; err.textContent = er.message; }
  btn.disabled = false;
});
function endSession() {
  S.user = null; S.csrf = ""; S.status = null; S.expanded.clear(); S.alertSig = ""; S.ifaces = null;
  resetPackets(); boot();
}
$("#btn-logout").addEventListener("click", async () => { try { await api("/api/logout", { method: "POST" }); } catch (e) { /* ignore */ } endSession(); });

function enterApp() {
  $("#gate").hidden = true; $("#app").hidden = false;
  $("#who-name").textContent = S.user.username;
  const rb = $("#who-role"); rb.textContent = S.user.role; rb.className = "badge " + S.user.role;
  $$(".admin-only").forEach(el => el.hidden = !can("admin"));
  $("#app").classList.toggle("ro", !can("analyst"));
  $("#ro-banner").hidden = can("analyst");
  $("#help-roles").innerHTML = Object.entries(S.roles).map(([r, t]) => `<p><span class="badge ${esc(r)}">${esc(r)}</span> ${esc(t)}</p>`).join("");
  const hash = location.hash.slice(1);
  show(VIEWS.includes(hash) && (!["users", "audit"].includes(hash) || can("admin")) ? hash : "overview");
  clearInterval(S.poll); S.poll = setInterval(() => { if (!document.hidden) refresh(); }, 2000);
}

/* ---------- navigation ---------- */
function show(view) {
  S.view = view;
  $$(".view").forEach(v => v.hidden = v.id !== "view-" + view);
  $$(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === view));
  history.replaceState(null, "", "#" + view);
  if (view === "settings") { S.settingsDirty = false; loadSettings(); }
  if (view === "help") loadGlossary();
  if (view === "traffic") initTraffic();
  if (view === "scanner") initScanner();
  if (view === "users") loadUsers();
  refresh();
}
document.addEventListener("click", e => {
  const nav = e.target.closest(".nav-item"); if (nav) return show(nav.dataset.view);
  const a = e.target.closest("[data-action]"); if (!a) return;
  if (a.dataset.action === "goto") show(a.dataset.view); else if (a.dataset.action === "open-demo") openDemo();
});

/* ---------- polling ---------- */
async function refresh() {
  if (!S.user) return;
  try {
    S.status = await api("/api/status"); paintChrome();
    const v = S.view;
    if (v === "overview") await loadOverview(); else if (v === "alerts") await loadAlerts();
    else if (v === "traffic") await loadTraffic(); else if (v === "devices") await loadDevices();
    else if (v === "audit") await loadAudit();
    else if (v === "scanner") { initScanner(); if (S.status.scan_active && !S.scanTimer) followScan(S.status.scan_active.id); }
  } catch (e) { /* banner / sign-in handle it */ }
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
function paintChrome() {
  const st = S.status, cap = st.capture;
  $("#side-version").textContent = "Version " + st.version;
  const dot = $("#nav-capture-dot"); dot.className = "dot" + (cap.state === "running" ? " on" : cap.state === "error" ? " err" : "");
  dot.title = cap.state === "running" ? "Capturing live traffic" : "Capture is off";
  const n = (st.alerts || {}).open || 0, pill = $("#nav-alert-count"); pill.hidden = n === 0; pill.textContent = n > 99 ? "99+" : n;
  $("#data-dir").textContent = st.data_dir;
}

/* ---------- overview ---------- */
function sparkline(series) {
  const w = 300, h = 60, vals = series.map(p => p.packets), max = Math.max(1, ...vals);
  const pts = vals.map((v, i) => [(i / (vals.length - 1)) * w, h - 4 - (v / max) * (h - 10)]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><path d="${line} L${w} ${h} L0 ${h} Z" fill="currentColor" opacity=".13"/><path d="${line}" fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/></svg>`;
}
function barRows(rows, labelFn, valFn, fmt) {
  const max = Math.max(1, ...rows.map(valFn));
  return rows.map(r => `<div class="bar-row"><code>${esc(labelFn(r))}</code><div class="track"><i data-w="${(valFn(r) / max * 100).toFixed(0)}"></i></div><span class="num muted">${esc(fmt(valFn(r)))}</span></div>`).join("");
}
async function loadOverview() {
  const d = await api("/api/overview"), h = d.health;
  $("#hero").className = "hero " + h.level; $("#hero-title").textContent = h.headline; $("#hero-detail").textContent = h.detail;
  const open = d.alerts.open;
  $("#hero-actions").innerHTML = open ? `<button data-action="goto" data-view="alerts">Review ${open} alert${open === 1 ? "" : "s"}</button>` : "";
  $("#spark").innerHTML = sparkline(d.series);
  const recent = d.series.slice(-5).reduce((a, p) => a + p.packets, 0) / 5;
  $("#spark-label").textContent = `Traffic, last 60 seconds (${recent.toFixed(recent < 10 ? 1 : 0)} packets/sec)`;
  $("#quickstart").hidden = !(d.traffic.packets === 0 && d.alerts.total === 0 && !d.last_scan);
  $("#facts").innerHTML = [[fmtNum(d.traffic.packets), "packets seen"], [fmtNum(open), "alerts to review"], [fmtNum(d.devices), "devices known"],
    [d.last_scan ? fmtNum(d.last_scan.open_count) : "none yet", "open ports in last scan"]].map(([v, l]) => `<div><dt>${esc(l)}</dt><dd>${esc(v)}</dd></div>`).join("");
  $("#ov-alerts").innerHTML = d.latest.length ? d.latest.map(a => `<div class="mini-alert" data-action="goto" data-view="alerts">${sevBadge(a.severity)}
    <div><strong>${esc(a.title)}</strong><span class="muted">${esc(a.src_ip)} &rarr; ${esc(a.dst_ip)} &middot; ${esc(ago(a.timestamp))}${a.source === "simulation" ? " &middot; demo" : ""}</span></div></div>`).join("")
    : `<p class="muted">Nothing needs attention right now.</p>`;
  $("#ov-talkers").innerHTML = d.talkers.length ? barRows(d.talkers, r => r.ip, r => r.bytes, fmtBytes) : `<p class="muted">No traffic seen yet.</p>`;
  $("#ov-protos").innerHTML = d.traffic.protocols.length ? barRows(d.traffic.protocols, r => r.proto, r => r.packets, fmtNum) : `<p class="muted">No traffic seen yet.</p>`;
  applyBars($("#view-overview"));
}

/* ---------- alerts ---------- */
function alertCard(a) {
  const open = S.expanded.has(a.id);
  const mitre = a.mitre_id && a.mitre_id !== "-" ? `<a href="https://attack.mitre.org/techniques/${esc(a.mitre_id.replace(".", "/"))}/" target="_blank" rel="noopener noreferrer">${esc(a.mitre_id)}</a>` : "";
  return `<article class="alert-card ${esc(a.severity)}${a.reviewed ? " reviewed" : ""}">
    <div class="alert-head" data-toggle="${a.id}" tabindex="0" role="button" aria-expanded="${open}"><div><h3>${esc(a.title)}</h3>
      <div class="alert-meta"><code>${esc(a.src_ip)} &rarr; ${esc(a.dst_ip)}</code><span>${esc(ago(a.last_seen))}</span>${a.count > 1 ? `<span class="count">seen ${a.count} times</span>` : ""}${mitre}</div></div>
      <div class="row">${a.source === "simulation" ? `<span class="badge demo">demo</span>` : ""}${sevBadge(a.severity)}</div></div>
    ${open ? `<div class="alert-body"><div><h4>What we saw</h4><p>${esc(a.description)}</p></div><div><h4>What it might mean</h4><p>${esc(a.meaning)}</p></div><div><h4>What to do</h4><p>${esc(a.action)}</p></div>
      <div class="actions">${can("analyst") ? `<button class="ghost" data-review="${a.id}" data-to="${a.reviewed ? 0 : 1}">${a.reviewed ? "Mark as not reviewed" : "Mark as reviewed"}</button>` : ""}
      <small class="muted">${esc(a.rule_name)} &middot; first seen ${esc(clock(a.timestamp))}</small></div></div>` : ""}</article>`;
}
async function loadAlerts() {
  const demo = $("#alert-demo").checked, status = $("#alert-status").value;
  $("#lnk-csv").href = "/api/export/alerts.csv" + (demo ? "?demo=1" : ""); $("#lnk-report").href = "/api/export/report.md" + (demo ? "?demo=1" : "");
  const d = await api(`/api/alerts?limit=300&severity=${S.sev}&status=${status}&source=${demo ? "all" : "live"}`);
  const sig = JSON.stringify(d.alerts.map(a => [a.id, a.count, a.reviewed])) + [...S.expanded].join(); if (sig === S.alertSig) return; S.alertSig = sig;
  $("#alert-list").innerHTML = d.alerts.length ? d.alerts.map(alertCard).join("")
    : `<div class="empty panel">${status === "open" ? "No alerts need your attention. " : "No alerts match. "}Try the demo to see what NetSentinel can catch.</div>`;
}
function toggleAlert(id) { S.expanded.has(id) ? S.expanded.delete(id) : S.expanded.add(id); S.alertSig = ""; loadAlerts(); }
$("#alert-list").addEventListener("click", async e => {
  const rv = e.target.closest("[data-review]");
  if (rv) { try { await api(`/api/alerts/${rv.dataset.review}/review`, { method: "POST", body: { reviewed: rv.dataset.to === "1" } }); S.alertSig = ""; refresh(); } catch (er) { fail(er); } return; }
  const t = e.target.closest("[data-toggle]"); if (t && !e.target.closest("a")) toggleAlert(Number(t.dataset.toggle));
});
$("#alert-list").addEventListener("keydown", e => { const t = e.target.closest("[data-toggle]"); if (t && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggleAlert(Number(t.dataset.toggle)); } });
$("#alert-sev").addEventListener("click", e => { const b = e.target.closest("button"); if (!b) return; $$("#alert-sev button").forEach(x => x.classList.toggle("active", x === b)); S.sev = b.dataset.sev; S.alertSig = ""; loadAlerts(); });
for (const id of ["#alert-status", "#alert-demo"]) $(id).addEventListener("change", () => { S.alertSig = ""; loadAlerts(); });
$("#btn-review-all").addEventListener("click", async () => { try { const r = await api("/api/alerts/review_all", { method: "POST" }); toast(`Marked ${r.reviewed} alert(s) as reviewed.`); S.alertSig = ""; refresh(); } catch (e) { fail(e); } });

/* ---------- live traffic ---------- */
async function initTraffic() {
  if (S.ifaces) return;
  try {
    S.ifaces = await api("/api/interfaces");
    $("#cap-iface").innerHTML = `<option value="">Default network adapter</option>` + S.ifaces.interfaces.map(i => `<option value="${esc(i.id)}"${i.id === S.ifaces.selected ? " selected" : ""}>${esc(i.name)}${i.ip ? " (" + esc(i.ip) + ")" : ""}</option>`).join("");
  } catch (e) { /* ignore */ }
}
function captureNotice() {
  const cap = S.status.capabilities, c = S.status.capture, n = $("#cap-notice"); let msg = "";
  if (c.state === "error" && c.error) msg = c.error;
  else if (!cap.scapy) msg = "Live capture isn't installed on this server (the Scapy library is missing). The demo and scanner still work.";
  else if (cap.npcap === false) msg = "The server needs Npcap (a free packet-capture driver) before it can listen to traffic.";
  else if (!cap.admin && c.state !== "running") msg = "The server doesn't have packet-capture permission. Run it as root/Administrator, or in Docker with NET_RAW and NET_ADMIN.";
  n.hidden = !msg; n.textContent = msg;
}
async function loadTraffic() {
  const c = S.status.capture, run = c.state === "running";
  $("#cap-dot").className = "dot" + (run ? " on" : c.state === "error" ? " err" : "");
  $("#cap-title").textContent = run ? "Capturing live traffic" : "Capture is off";
  $("#cap-sub").textContent = run ? `${fmtNum(c.live_packets)} packets so far` : "Demo traffic still appears here.";
  $("#btn-capture").textContent = run ? "Stop capture" : "Start capture"; $("#cap-iface").disabled = run; captureNotice();
  if (S.tab === "flows") return loadFlows();
  if (S.paused) return;
  const d = await api(`/api/packets?since_id=${S.pktSince}&limit=300&q=${encodeURIComponent(S.pktFilter)}`);
  if (d.packets.length) { S.packets = S.packets.concat(d.packets).slice(-400); S.pktSince = Math.max(S.pktSince, ...d.packets.map(p => p.id)); }
  renderPackets(d.packets.length > 0);
}
function renderPackets(changed) {
  if (!S.packets.length) { emptyMsg($("#pkt-empty"), S.pktFilter ? "No packets match this filter." : "No packets yet. Start a capture for live traffic, or try the demo from the sidebar."); $("#pkt-body").innerHTML = ""; return; }
  if (!changed) return; emptyMsg($("#pkt-empty"), "");
  const wrap = $("#pkt-wrap"), stick = wrap.scrollTop + wrap.clientHeight >= wrap.scrollHeight - 40;
  $("#pkt-body").innerHTML = S.packets.map(p => `<tr data-id="${p.id}" class="${p.source === "simulation" ? "demo " : ""}${p.id === S.selPkt ? "sel" : ""}"><td>${esc(clock(p.ts, true))}</td><td>${esc(p.src)}${p.sport ? ":" + esc(p.sport) : ""}</td><td>${esc(p.dst)}${p.dport ? ":" + esc(p.dport) : ""}</td><td class="proto proto-${esc(String(p.proto).toLowerCase())}">${esc(p.proto)}</td><td class="num">${esc(fmtNum(p.length))}</td><td>${esc(p.info)}</td></tr>`).join("");
  if (stick) wrap.scrollTop = wrap.scrollHeight;
}
function resetPackets() { S.packets = []; S.pktSince = 0; S.selPkt = null; $("#pkt-detail").hidden = true; $("#pkt-body").innerHTML = ""; }
$("#pkt-body").addEventListener("click", async e => {
  const tr = e.target.closest("tr"); if (!tr) return; const id = Number(tr.dataset.id); S.selPkt = id;
  $$("#pkt-body tr").forEach(r => r.classList.toggle("sel", r === tr));
  try {
    const p = await api("/api/packets/" + id), box = $("#pkt-detail"); box.hidden = false;
    box.innerHTML = `<h3>Packet details <button class="link" id="btn-close-detail">Close</button></h3><dl><dt>Time</dt><dd>${esc(clock(p.ts, true))}</dd><dt>From</dt><dd>${esc(p.src)}${p.sport ? ":" + esc(p.sport) : ""}</dd><dt>To</dt><dd>${esc(p.dst)}${p.dport ? ":" + esc(p.dport) : ""}</dd><dt>Protocol</dt><dd>${esc(p.proto)}</dd><dt>Size</dt><dd>${esc(fmtNum(p.length))} bytes</dd>${p.flags ? `<dt>TCP flags</dt><dd>${esc(p.flags)}</dd>` : ""}<dt>Summary</dt><dd>${esc(p.info)}</dd>${p.source === "simulation" ? `<dt>Origin</dt><dd>Demo (simulated)</dd>` : ""}</dl>
      ${p.hex.length ? `<h3>Data</h3><div class="hex">${p.hex.map(r => esc(r.offset + "  " + r.hex.padEnd(47) + "  " + r.ascii)).join("\n")}</div>` : `<p class="muted small">No payload captured for this packet.</p>`}`;
  } catch (er) { fail(er); }
});
$("#pkt-detail").addEventListener("click", e => { if (e.target.id === "btn-close-detail") { $("#pkt-detail").hidden = true; S.selPkt = null; renderPackets(true); } });
let filterTimer; $("#pkt-filter").addEventListener("input", e => { clearTimeout(filterTimer); filterTimer = setTimeout(() => { S.pktFilter = e.target.value.trim(); resetPackets(); $("#lnk-pkts").href = "/api/export/packets.csv?q=" + encodeURIComponent(S.pktFilter); loadTraffic(); }, 250); });
$("#btn-pause").addEventListener("click", e => { S.paused = !S.paused; e.target.textContent = S.paused ? "Resume" : "Pause"; if (!S.paused) loadTraffic(); });
$("#btn-clear-pkts").addEventListener("click", async () => { try { await api("/api/capture/clear", { method: "POST" }); resetPackets(); renderPackets(false); } catch (e) { fail(e); } });
$("#traffic-tabs").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return; S.tab = b.dataset.tab; $$("#traffic-tabs button").forEach(x => x.classList.toggle("active", x === b));
  $("#pkt-wrap").hidden = S.tab !== "packets"; $("#flow-wrap").hidden = S.tab !== "flows"; $("#pkt-detail").hidden = S.tab !== "packets" || !S.selPkt; loadTraffic();
});
async function loadFlows() {
  const d = await api("/api/flows?limit=200&sort=bytes"); emptyMsg($("#flow-empty"), d.flows.length ? "" : "No conversations yet.");
  $("#flow-body").innerHTML = d.flows.map(f => `<tr><td class="mono">${esc(f.src)}</td><td class="mono">${esc(f.dst)}</td><td>${esc(f.dport ?? "")}</td><td>${esc(f.proto)}${f.source === "simulation" ? ` <span class="badge demo">demo</span>` : ""}</td><td class="num">${fmtNum(f.packets)}</td><td class="num">${fmtBytes(f.bytes)}</td><td>${esc(clock(f.last))}</td></tr>`).join("");
}
$("#btn-capture").addEventListener("click", async e => {
  const btn = e.target; btn.disabled = true;
  try { if (S.status.capture.state === "running") await api("/api/capture/stop", { method: "POST" }); else { await api("/api/capture/start", { method: "POST", body: { iface: $("#cap-iface").value } }); toast("Capturing. Packets will appear below."); } }
  catch (er) { fail(er); }
  btn.disabled = false; refresh();
});

/* ---------- scanner ---------- */
function initScanner() {
  const st = S.status; if (!st || $("#scan-presets").children.length) return;
  const presets = Object.entries(st.presets).map(([k, v]) => `<label><input type="radio" name="preset" value="${esc(k)}"${k === "quick" ? " checked" : ""}> <span>${esc(v.name)}</span></label>`);
  presets.push(`<label><input type="radio" name="preset" value="custom"> <span>Pick my own ports</span></label>`);
  $("#scan-presets").innerHTML = presets.join("");
  if (st.local_subnet) $("#btn-my-net").hidden = false;
  if (!can("analyst")) { $("#scan-form").classList.add("ro"); $("#btn-scan").hidden = true; }
  $("#scan-target-help").textContent = can("admin") ? "One device, a range, or a whole network (up to 1,024 devices). As an administrator you may also scan outside addresses." : "One device, a range, or a whole network on your private address space (up to 1,024 devices).";
  loadScanHistory();
}
$("#scan-presets").addEventListener("change", () => { $("#scan-ports").hidden = $('input[name="preset"]:checked').value !== "custom"; });
$("#btn-my-net").addEventListener("click", () => { $("#scan-target").value = S.status.local_subnet; });
$("#btn-scan").addEventListener("click", async () => {
  const err = $("#scan-error"); err.hidden = true;
  if (!$("#scan-consent").checked) { err.hidden = false; err.textContent = "Tick the box to confirm you have permission to scan this target."; return; }
  try {
    const job = await api("/api/scan/start", { method: "POST", body: { targets: $("#scan-target").value, preset: $('input[name="preset"]:checked').value, ports: $("#scan-ports").value, confirm: true } });
    $("#scan-results").innerHTML = ""; followScan(job.id);
  } catch (e) { err.hidden = false; err.textContent = e.message; }
});
$("#btn-scan-cancel").addEventListener("click", async () => { if (S.scanJob) try { await api(`/api/scan/${S.scanJob}/cancel`, { method: "POST" }); } catch (e) { fail(e); } });
function followScan(id) {
  S.scanJob = id; clearInterval(S.scanTimer);
  const poll = async () => {
    let j; try { j = await api("/api/scan/" + id); } catch (e) { clearInterval(S.scanTimer); S.scanTimer = null; return; }
    const running = j.status === "running" || j.status === "queued";
    $("#btn-scan").disabled = running; $("#btn-scan-cancel").hidden = !running || !can("analyst"); $("#scan-progress").hidden = !running;
    $("#scan-bar").style.width = Math.round(j.progress * 100) + "%";
    $("#scan-phase").textContent = `${j.phase || "Starting"}... ${fmtNum(j.done)} of ${fmtNum(j.total)}${j.open_count ? ` - ${j.open_count} open so far` : ""}`;
    if (!running) { clearInterval(S.scanTimer); S.scanTimer = null; renderScan(j); loadScanHistory(); if (j.status === "error") { $("#scan-error").hidden = false; $("#scan-error").textContent = j.error; } }
  };
  S.scanTimer = setInterval(poll, 700); poll();
}
const RISK_RANK = { high: 3, medium: 2, low: 1, info: 0, unknown: 0 };
function renderScan(j, title) {
  const results = j.results || [], hosts = j.hosts || [...new Set(results.map(r => r.host))];
  const attention = results.filter(r => RISK_RANK[r.risk] >= 2).length, byHost = {}; results.forEach(r => (byHost[r.host] = byHost[r.host] || []).push(r));
  let html = `<p class="summary-line">${title ? esc(title) + ": " : ""}Found <strong>${hosts.length}</strong> device${hosts.length === 1 ? "" : "s"} up and <strong>${results.length}</strong> open port${results.length === 1 ? "" : "s"}${attention ? `, <strong>${attention}</strong> worth a closer look` : ""}. ${j.status === "cancelled" ? "<em>(Scan was cancelled, so results are partial.)</em>" : ""} <a href="/api/export/report.md" download>Download report</a></p>`;
  if (!hosts.length) html += `<div class="empty panel">No devices answered. Check the address, or the device may be blocking probes.</div>`;
  for (const host of hosts) {
    const rows = (byHost[host] || []).sort((a, b) => RISK_RANK[b.risk] - RISK_RANK[a.risk] || a.port - b.port), worst = rows.length ? rows[0].risk : "";
    html += `<section class="host-card"><header><strong>${esc(host)}</strong><span class="muted">${rows.length} open port${rows.length === 1 ? "" : "s"}</span>${RISK_RANK[worst] >= 1 ? sevBadge(worst) : ""}</header>`;
    html += rows.length ? `<table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Details</th></tr></thead><tbody>${rows.map(r => `<tr><td class="mono">${esc(r.port)}/tcp</td><td>${esc(r.service)}</td><td><span class="badge ${esc(r.risk)}">${esc(r.risk === "unknown" ? "unrated" : r.risk)}</span></td><td>${r.banner ? `<code>${esc(r.banner)}</code>` : ""}<div class="advice">${esc(r.advice)}</div></td></tr>`).join("")}</tbody></table>` : `<div class="empty">Up, with no open ports among those scanned.</div>`;
    html += `</section>`;
  }
  $("#scan-results").innerHTML = html;
}
async function loadScanHistory() {
  try {
    const d = await api("/api/scan/history"); $("#scan-history-panel").hidden = !d.runs.length;
    $("#scan-history").innerHTML = d.runs.map(r => `<div class="history-row"><div><strong>${esc(r.targets)}</strong><div class="muted small">${esc(new Date(r.started).toLocaleString())} &middot; ${esc(r.hosts_up)} up &middot; ${esc(r.open_count)} open &middot; ${esc(r.status)}</div></div><button class="ghost" data-run="${esc(r.id)}" data-label="${esc(r.targets)}">View</button></div>`).join("");
  } catch (e) { /* ignore */ }
}
$("#scan-history").addEventListener("click", async e => {
  const b = e.target.closest("[data-run]"); if (!b) return;
  try { const d = await api("/api/scan/history/" + b.dataset.run); renderScan({ results: d.results, status: "done" }, b.dataset.label); window.scrollTo({ top: 0, behavior: "smooth" }); } catch (er) { fail(er); }
});

/* ---------- devices ---------- */
async function loadDevices() {
  const d = await api("/api/devices"); emptyMsg($("#dev-empty"), d.devices.length ? "" : "No devices yet. Run a network scan, or start live capture to learn devices from ARP traffic.");
  $("#dev-body").innerHTML = d.devices.map(v => `<tr><td class="mono">${esc(v.ip)}</td><td class="mono">${esc(v.mac || "unknown")}</td><td>${esc(v.via === "arp" ? "Live capture (ARP)" : "Port scan")}${v.source === "simulation" ? ` <span class="badge demo">demo</span>` : ""}</td><td>${esc(clock(v.first_seen))}</td><td>${esc(ago(new Date(v.last_seen * 1000).toISOString()))}</td><td>${v.previous_macs.length ? `<span class="badge high">Hardware address changed</span>` : ""}</td></tr>`).join("");
}

/* ---------- settings ---------- */
const SCHEMA = [
  ["How sensitive should detection be?", [
    ["port_scan_threshold", "Port scan: ports tried", "Alert when one device tries this many different ports on another device within the time window."],
    ["port_scan_window", "Port scan: time window (seconds)", ""],
    ["sweep_threshold", "Network sweep: devices probed", "Alert when one device checks the same port on this many devices. Higher = fewer false alarms."],
    ["sweep_threshold_web", "Network sweep for web/DNS ports", "Ports like 80 and 443 are busy on every network, so they get a higher limit."],
    ["beacon_min_hits", "Beaconing: repeats needed", "How many evenly spaced connections to one outside address before it looks like malware phoning home."],
    ["beacon_jitter_pct", "Beaconing: timing variation allowed (%)", "Lower = only very robotic patterns count."],
    ["exfil_mb", "Large upload: megabytes", "Alert when this much data goes from your network to one outside address within a minute."],
    ["syn_flood_threshold", "Connection flood: requests in 5 seconds", ""],
    ["alert_cooldown", "Merge repeat alerts for (seconds)", "Identical alerts within this time are combined into one, with a counter."]]],
  ["Extra checks", [
    ["cleartext_alerts", "Warn about unencrypted services", "Telnet, FTP, POP3 and IMAP send passwords in plain text.", "check"],
    ["new_device_alerts", "Warn when a new device appears", "Based on ARP traffic during live capture.", "check"]]],
  ["Lists", [
    ["blacklist", "Blocked addresses", "One per line: address, then an optional reason. Any traffic to or from these raises a high alert.", "lines"],
    ["malicious_ports", "Suspicious ports", "One per line: port, then what it's known for. Connecting to these raises a high alert.", "lines"]]],
  ["Scanner", [
    ["scan_timeout", "Wait per port (seconds)", "Raise on slow or distant networks.", "float"],
    ["scan_workers", "Simultaneous probes", "More is faster but can overwhelm small routers."]]],
  ["Logging", [["log_packets_jsonl", "Also write every captured packet to a log file", "Off by default because it grows fast.", "check"]]],
];
async function loadSettings() {
  if (S.settingsDirty) return;
  const cfg = await api("/api/settings"), form = $("#settings-form"), ro = !can("admin");
  $("#settings-ro").hidden = !ro;
  form.innerHTML = SCHEMA.map(([title, items]) => `<fieldset ${ro ? "disabled" : ""}><legend>${esc(title)}</legend>${items.map(([key, label, help, type]) => {
    const v = cfg[key], id = "set-" + key;
    if (type === "check") return `<div class="setting"><label for="${id}">${esc(label)}</label><input type="checkbox" id="${id}" data-key="${key}" ${v ? "checked" : ""}><small>${esc(help)}</small></div>`;
    if (type === "lines") return `<div class="setting wide"><label for="${id}">${esc(label)}</label><small>${esc(help)}</small><textarea id="${id}" data-key="${key}" data-type="lines" rows="4">${esc(Object.entries(v).map(([k, w]) => w ? `${k}  ${w}` : k).join("\n"))}</textarea></div>`;
    return `<div class="setting"><label for="${id}">${esc(label)}</label><input type="number" id="${id}" data-key="${key}" value="${esc(v)}" step="${type === "float" ? "0.1" : "1"}">${help ? `<small>${esc(help)}</small>` : ""}</div>`;
  }).join("")}</fieldset>`).join("");
}
$("#settings-form").addEventListener("input", () => { S.settingsDirty = true; $("#settings-msg").textContent = "Unsaved changes"; });
function collectSettings() {
  const out = {};
  $$("#settings-form [data-key]").forEach(el => {
    const k = el.dataset.key;
    if (el.type === "checkbox") out[k] = el.checked;
    else if (el.dataset.type === "lines") { out[k] = {}; el.value.split("\n").forEach(line => { const m = line.trim().match(/^(\S+)\s*(.*)$/); if (m) out[k][m[1]] = m[2]; }); }
    else out[k] = Number(el.value);
  });
  return out;
}
$("#btn-save-settings").addEventListener("click", async () => { try { await api("/api/settings", { method: "POST", body: collectSettings() }); S.settingsDirty = false; $("#settings-msg").textContent = ""; toast("Settings saved."); await loadSettings(); } catch (e) { fail(e); } });
$("#btn-reset-settings").addEventListener("click", async () => { if (!confirm("Restore every setting to its default?")) return; try { await api("/api/settings/reset", { method: "POST" }); S.settingsDirty = false; $("#settings-msg").textContent = ""; toast("Defaults restored."); await loadSettings(); } catch (e) { fail(e); } });

/* ---------- users (admin) ---------- */
async function loadUsers() {
  try {
    const d = await api("/api/users");
    $("#nu-role").innerHTML = Object.keys(d.roles).map(r => `<option value="${esc(r)}"${r === "viewer" ? " selected" : ""}>${esc(r)}</option>`).join("");
    $("#role-help").innerHTML = Object.entries(d.roles).map(([r, t]) => `<div><dt>${esc(r)}</dt><dd>${esc(t)}</dd></div>`).join("");
    $("#user-body").innerHTML = d.users.map(u => {
      const me = u.username === S.user.username;
      return `<tr><td><strong>${esc(u.username)}</strong>${me ? ` <span class="muted">(you)</span>` : ""}</td>
        <td>${me ? `<span class="badge ${esc(u.role)}">${esc(u.role)}</span>` : `<select data-role="${u.id}" aria-label="Role for ${esc(u.username)}">${Object.keys(d.roles).map(r => `<option${r === u.role ? " selected" : ""}>${esc(r)}</option>`).join("")}</select>`}</td>
        <td>${u.last_login ? esc(ago(u.last_login)) : "never"}</td><td>${u.disabled ? `<span class="badge high">disabled</span>` : `<span class="badge low">active</span>`}</td>
        <td class="row">${me ? "" : `<button class="ghost small" data-disable="${u.id}" data-to="${u.disabled ? 0 : 1}">${u.disabled ? "Enable" : "Disable"}</button><button class="ghost small" data-resetpw="${u.id}" data-name="${esc(u.username)}">Reset password</button><button class="ghost small" data-del="${u.id}" data-name="${esc(u.username)}">Delete</button>`}</td></tr>`;
    }).join("");
  } catch (e) { fail(e); }
}
$("#user-form").addEventListener("submit", async e => {
  e.preventDefault(); const err = $("#user-error"); err.hidden = true;
  try { await api("/api/users", { method: "POST", body: { username: $("#nu-name").value, password: $("#nu-pass").value, role: $("#nu-role").value } }); $("#user-form").reset(); toast("User added."); loadUsers(); }
  catch (er) { err.hidden = false; err.textContent = er.message; }
});
$("#user-body").addEventListener("change", async e => { const s = e.target.closest("[data-role]"); if (!s) return; try { await api("/api/users/" + s.dataset.role, { method: "POST", body: { role: s.value } }); toast("Role updated. They've been signed out."); } catch (er) { fail(er); } loadUsers(); });
$("#user-body").addEventListener("click", async e => {
  const b = e.target.closest("button"); if (!b) return;
  try {
    if (b.dataset.disable) await api("/api/users/" + b.dataset.disable, { method: "POST", body: { disabled: b.dataset.to === "1" } });
    else if (b.dataset.resetpw) { const pw = prompt(`New temporary password for ${b.dataset.name} (at least 10 characters):`); if (!pw) return; await api("/api/users/" + b.dataset.resetpw, { method: "POST", body: { password: pw } }); toast("Password changed."); }
    else if (b.dataset.del) { if (!confirm(`Delete ${b.dataset.name}? This can't be undone.`)) return; await api(`/api/users/${b.dataset.del}/delete`, { method: "POST" }); }
  } catch (er) { fail(er); }
  loadUsers();
});

/* ---------- audit (admin) ---------- */
async function loadAudit() {
  const d = await api("/api/audit?limit=300"); emptyMsg($("#audit-empty"), d.events.length ? "" : "Nothing recorded yet.");
  $("#audit-body").innerHTML = d.events.map(v => `<tr><td class="mono">${esc(new Date(v.ts).toLocaleString())}</td><td>${esc(v.username || "-")}</td><td><span class="badge ${/fail|denied|refused/.test(v.action) ? "high" : ""}">${esc(v.action.replace(/_/g, " "))}</span></td><td>${esc(v.detail)}</td><td class="mono">${esc(v.ip)}</td></tr>`).join("");
}

/* ---------- account ---------- */
$("#btn-account").addEventListener("click", () => { $("#pw-error").hidden = true; $("#pw-form").reset(); $("#pw-dialog").showModal(); });
$("#pw-cancel").addEventListener("click", () => $("#pw-dialog").close());
$("#pw-form").addEventListener("submit", async e => {
  e.preventDefault();
  try { await api("/api/account/password", { method: "POST", body: { current: $("#pw-current").value, new: $("#pw-new").value } }); $("#pw-dialog").close(); toast("Password changed. Please sign in again."); endSession(); }
  catch (er) { $("#pw-error").hidden = false; $("#pw-error").textContent = er.message; }
});

/* ---------- help ---------- */
async function loadGlossary() {
  if ($("#glossary").children.length) return;
  try { const d = await api("/api/glossary"); $("#glossary").innerHTML = d.terms.map(([t, m]) => `<details><summary>${esc(t)}</summary><p>${esc(m)}</p></details>`).join(""); } catch (e) { /* ignore */ }
}

/* ---------- demo dialog ---------- */
function openDemo() {
  const sc = (S.status && S.status.scenarios) || {};
  $("#demo-list").innerHTML = Object.entries(sc).map(([k, v]) => `<div class="demo-item"><div><strong>${esc(v.name)}</strong><p>${esc(v.desc)}</p></div><button data-scenario="${esc(k)}" class="needs-analyst">Run</button></div>`).join("");
  $("#demo-dialog").showModal();
}
$("#btn-demo").addEventListener("click", openDemo);
$("#demo-list").addEventListener("click", async e => {
  const b = e.target.closest("[data-scenario]"); if (!b) return;
  try { await api("/api/simulate", { method: "POST", body: { scenario: b.dataset.scenario } }); $("#demo-dialog").close(); toast("Demo running. Watch the Overview and Alerts."); S.alertSig = ""; show("overview"); } catch (er) { fail(er); }
});
$("#btn-demo-clear").addEventListener("click", async () => {
  if (!confirm("Remove all demo alerts, packets and devices?")) return;
  try { await api("/api/simulate/clear", { method: "POST" }); resetPackets(); S.alertSig = ""; toast("Demo data removed."); refresh(); } catch (e) { fail(e); }
});

boot();

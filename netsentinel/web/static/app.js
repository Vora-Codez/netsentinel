"use strict";
/* NetSentinel web UI. No frameworks, no CDN (it works on an offline network).
   SECURITY: every dynamic value goes through esc() before it touches innerHTML, because scanned
   banners, DNS names and packet text are attacker-controlled. The CSP forbids inline styles and
   scripts, so widths are set through the DOM and every handler is attached here. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const icon = (name, cls = "") => `<svg class="ic ${cls}"><use href="#i-${name}"/></svg>`;
const RANK = { viewer: 1, analyst: 2, admin: 3 };
const VIEWS = ["overview", "alerts", "traffic", "scanner", "devices", "learn", "account", "settings", "users", "audit"];
const TITLES = { overview: "Overview", alerts: "Alerts", traffic: "Live traffic", scanner: "Port scanner", devices: "Devices", learn: "Learn",
  account: "Account & security", settings: "Settings", users: "Users", audit: "Audit log" };

const S = {
  view: "overview", status: null, user: null, csrf: "", sev: "all", expanded: new Set(), alertSig: "",
  pktSince: 0, packets: [], paused: false, selPkt: null, tab: "packets", pktFilter: "", ifaces: null,
  scanJob: null, scanTimer: null, failures: 0, settingsDirty: false, poll: null, roles: {}, minPw: 12,
  learn: null, ltab: "start", glossCat: "All", gateMode: "login", otpRecovery: false, lastInput: Date.now(),
};
const can = role => S.user && RANK[S.user.role] >= RANK[role];

/* Any keyboard/mouse use counts as activity. The dashboard's own 2-second refresh does not, so an
   unattended browser still gets signed out after the idle limit. */
for (const ev of ["pointerdown", "keydown", "wheel", "touchstart"]) addEventListener(ev, () => { S.lastInput = Date.now(); }, { passive: true });

/* ---------- helpers ---------- */
async function api(path, { method = "GET", body, anon, bg } = {}) {
  const opt = { method, headers: {}, credentials: "same-origin" };
  if (bg && Date.now() - S.lastInput > 60000) opt.headers["X-NS-Background"] = "1";
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
  if (res.status === 401 && !anon && S.user) endSession(data && data.error);
  if (res.status === 403 && data && data.code === "password_change_required" && S.user) showGate("newpw");
  if (!res.ok) throw Object.assign(new Error((data && data.error) || res.statusText), { data, status: res.status });
  return data;
}
function toast(msg, kind) {
  const t = document.createElement("div"); t.className = "toast" + (kind === true || kind === "err" ? " err" : kind === "warn" ? " warn" : ""); t.textContent = msg;
  $("#toasts").append(t); setTimeout(() => t.remove(), kind ? 7000 : 3800);
}
const fail = e => { if (e.status !== 401 && !(e.data && e.data.code === "password_change_required")) toast(e.message || "Something went wrong.", true); };
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
function ago(v) {
  const t = typeof v === "number" ? v * 1000 : new Date(v).getTime(); if (!t || isNaN(t)) return "";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return "just now"; if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago"; if (s < 86400 * 7) return Math.floor(s / 86400) + " days ago";
  return new Date(t).toLocaleDateString();
}
const when = v => { const d = new Date(typeof v === "number" ? v * 1000 : v); return isNaN(d) ? "" : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" }); };
const sevBadge = s => `<span class="badge ${esc(s)}">${esc(s)}</span>`;
const emptyMsg = (el, msg) => { el.textContent = msg || ""; };
const applyBars = root => $$("i[data-w]", root).forEach(i => { i.style.width = i.dataset.w + "%"; });
function download(name, text) {
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" })); a.download = name;
  document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

/* ---------- theme ---------- */
function isDark() {
  const t = document.documentElement.dataset.theme;
  return t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
}
function paintThemeButton() { $("#btn-theme use").setAttribute("href", isDark() ? "#i-sun" : "#i-moon"); }
$("#btn-theme").addEventListener("click", () => {
  const next = isDark() ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("ns-theme", next); } catch (e) { /* private window */ }
  paintThemeButton();
});
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", paintThemeButton);
paintThemeButton();

/* ---------- password strength (a guide; the server enforces the real rules) ---------- */
function strength(pw, user) {
  if (!pw) return { score: 0, text: `At least ${S.minPw} characters. A few random words works well.` };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/\d/.test(pw)) pool += 10; if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(Math.max(pool, 2)), hint = "";
  if (new Set(pw.toLowerCase()).size < 5) { bits = Math.min(bits, 20); hint = "Too many repeated characters."; }
  if (user && user.length >= 3 && pw.toLowerCase().includes(user.toLowerCase())) { bits = Math.min(bits, 25); hint = "Don't include your username."; }
  if (/^(password|passw0rd|qwerty|letmein|welcome|admin|netsentinel|iloveyou|changeme)$/i.test(pw.replace(/[^a-z]/gi, ""))) { bits = Math.min(bits, 20); hint = "A common word plus numbers is easy to guess."; }
  if (pw.length < S.minPw) return { score: 1, text: `${S.minPw - pw.length} more character${S.minPw - pw.length === 1 ? "" : "s"} needed.` };
  const score = bits < 50 ? 1 : bits < 65 ? 2 : bits < 80 ? 3 : 4;
  return { score, text: hint || ["", "Weak: add more words or characters.", "Fair. Longer is stronger.", "Good password.", "Strong password."][score] };
}
function bindMeter(input, meter, label, userFn) {
  const upd = () => { const r = strength(input.value, userFn ? userFn() : ""); meter.className = "meter s" + (input.value ? r.score : 0); label.textContent = r.text; };
  input.addEventListener("input", upd); upd(); return upd;
}
const gateMeter = bindMeter($("#gate-new"), $("#gate-meter"), $("#gate-meter-text"), () => S.gateMode === "setup" ? $("#gate-user").value : (S.user && S.user.username));
const acctMeter = bindMeter($("#acct-pw-new"), $("#acct-meter"), $("#acct-meter-text"), () => S.user && S.user.username);

/* ---------- sign-in, setup, two-factor, forced password change ---------- */
async function boot(message) {
  let s;
  try { s = await api("/api/session"); } catch (e) { return setTimeout(() => boot(message), 2000); }
  S.roles = s.roles || {}; S.minPw = s.min_password || 12;
  if (s.user) {
    S.user = s.user; S.csrf = s.csrf;
    if (s.user.must_change_pw) return showGate("newpw");
    return enterApp();
  }
  if (s.pending_2fa) return showGate("2fa");
  showGate(s.setup_required ? "setup" : "login", message || s.signed_out_message);
}
const GATE = {
  setup: { title: "Create the administrator", sub: "This is the first run. Make the account that will manage NetSentinel.", submit: "Create account", icon: "key",
    rows: ["code", "user", "new", "confirm"], newLabel: "Password" },
  login: { title: "Welcome back", sub: "Sign in to NetSentinel.", submit: "Sign in", icon: "shield", rows: ["user", "pass"] },
  "2fa": { title: "Two-factor sign-in", sub: "Open your authenticator app and type the 6-digit code for NetSentinel.", submit: "Verify", icon: "phone", rows: ["otp"] },
  newpw: { title: "Choose a new password", sub: "Your administrator set a temporary password. Pick one only you know before continuing.", submit: "Save and continue", icon: "key",
    rows: ["pass", "new", "confirm"], passLabel: "Temporary password", newLabel: "New password" },
};
function showGate(mode, info) {
  clearInterval(S.poll); S.poll = null; S.gateMode = mode; S.otpRecovery = false;
  const g = GATE[mode];
  $("#app").hidden = true; $("#gate").hidden = false; $("#gate").dataset.mode = mode;
  $("#gate-title").textContent = g.title; $("#gate-sub").textContent = g.sub; $("#gate-submit").textContent = g.submit;
  $("#gate-icon use").setAttribute("href", "#i-" + g.icon);
  for (const r of ["code", "user", "pass", "new", "confirm", "otp"]) $(`#gate-${r}-row`).hidden = !g.rows.includes(r);
  $("#gate-pass-label").textContent = g.passLabel || "Password"; $("#gate-new-label").textContent = g.newLabel || "New password";
  $("#gate-pass").autocomplete = mode === "login" ? "current-password" : "current-password";
  $("#gate-otp-toggle").hidden = mode !== "2fa"; $("#gate-back").hidden = !["2fa", "newpw"].includes(mode);
  $("#gate-back").textContent = mode === "newpw" ? "Sign out" : "Start over";
  $("#gate-otp-label").textContent = "Code from your authenticator app"; $("#gate-otp-toggle").textContent = "Use a recovery code instead";
  $("#gate-otp").inputMode = "numeric"; $("#gate-otp").placeholder = "123 456";
  $("#gate-info").hidden = !info; $("#gate-info").textContent = info || "";
  $("#gate-error").hidden = true;
  for (const id of ["#gate-pass", "#gate-new", "#gate-confirm", "#gate-otp"]) $(id).value = "";
  gateMeter();
  const first = { setup: "#gate-code", login: "#gate-user", "2fa": "#gate-otp", newpw: "#gate-pass" }[mode];
  setTimeout(() => $(first).focus(), 30);
}
$("#gate-otp-toggle").addEventListener("click", () => {
  S.otpRecovery = !S.otpRecovery;
  $("#gate-otp-label").textContent = S.otpRecovery ? "One of your recovery codes" : "Code from your authenticator app";
  $("#gate-otp-toggle").textContent = S.otpRecovery ? "Use my authenticator app instead" : "Use a recovery code instead";
  $("#gate-otp").inputMode = S.otpRecovery ? "text" : "numeric"; $("#gate-otp").placeholder = S.otpRecovery ? "xxxxx-xxxxx" : "123 456";
  $("#gate-otp").value = ""; $("#gate-otp").focus();
});
$("#gate-back").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST", anon: S.gateMode === "2fa" }); } catch (e) { /* ignore */ }
  S.user = null; S.csrf = ""; boot();
});
$("#gate-form").addEventListener("submit", async e => {
  e.preventDefault();
  const mode = S.gateMode, err = $("#gate-error"), btn = $("#gate-submit");
  const showErr = m => { err.hidden = false; err.textContent = m; };
  err.hidden = true;
  if ((mode === "setup" || mode === "newpw") && $("#gate-new").value !== $("#gate-confirm").value) return showErr("The two passwords don't match.");
  btn.disabled = true;
  try {
    if (mode === "setup") {
      await api("/api/setup", { method: "POST", anon: true, body: { code: $("#gate-code").value, username: $("#gate-user").value, password: $("#gate-new").value } });
      await boot();
    } else if (mode === "login") {
      const r = await api("/api/login", { method: "POST", anon: true, body: { username: $("#gate-user").value, password: $("#gate-pass").value } });
      $("#gate-pass").value = "";
      if (r.second_factor) showGate("2fa"); else { S.welcome = r; await boot(); }
    } else if (mode === "2fa") {
      try {
        const r = await api("/api/login/2fa", { method: "POST", anon: true, body: { code: $("#gate-otp").value } });
        S.welcome = r; await boot();
      } catch (er) {
        if (er.data && er.data.restart) { showGate("login", er.message); } else { $("#gate-otp").value = ""; showErr(er.message); }
      }
    } else if (mode === "newpw") {
      await api("/api/account/password", { method: "POST", body: { current: $("#gate-pass").value, new: $("#gate-new").value } });
      toast("Password saved."); await boot();
    }
  } catch (er) { showErr(er.message); }
  btn.disabled = false;
});
function endSession(message) {
  S.user = null; S.csrf = ""; S.status = null; S.expanded.clear(); S.alertSig = ""; S.ifaces = null; S.learn = null;
  closeDialogs(); resetPackets(); boot(message);
}
function closeDialogs() { $$("dialog[open]").forEach(d => d.close()); $("#user-menu").hidden = true; }
$("#btn-logout").addEventListener("click", async () => { try { await api("/api/logout", { method: "POST" }); } catch (e) { /* ignore */ } endSession(); });

function enterApp() {
  $("#gate").hidden = true; $("#app").hidden = false;
  $("#who-name").textContent = S.user.username; $("#who-role").textContent = S.user.role; $("#who-avatar").textContent = S.user.username.slice(0, 1);
  $$(".admin-only").forEach(el => el.hidden = !can("admin"));
  $("#app").classList.toggle("ro", !can("analyst"));
  $("#ro-banner").hidden = can("analyst");
  $("#help-roles").innerHTML = Object.entries(S.roles).map(([r, t]) => `<p><span class="badge ${esc(r)}">${esc(r)}</span> ${esc(t)}</p>`).join("");
  $("#ov-nudge").hidden = !!S.user.totp_enabled;
  if (S.welcome) {
    const w = S.welcome; S.welcome = null;
    if (w.used_recovery) toast(`You signed in with a recovery code. ${w.recovery_left} left. Make new ones from Account & security if you're running low.`, "warn");
    else if (w.previous && w.previous.at) toast(`Welcome back. Your last sign-in was ${ago(w.previous.at)} from ${w.previous.ip || "an unknown address"}.`);
  }
  loadLearn();
  route(location.hash.slice(1));
  clearInterval(S.poll); S.poll = setInterval(() => { if (!document.hidden) refresh(); }, 2000);
}

/* ---------- navigation ---------- */
function route(hash) {
  const [view, ...rest] = (hash || "").split("/");
  const ok = VIEWS.includes(view) && (!["users", "audit"].includes(view) || can("admin"));
  show(ok ? view : "overview", rest);
}
function show(view, args = []) {
  S.view = view;
  $$(".view").forEach(v => v.hidden = v.id !== "view-" + view);
  $$(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === view));
  $("#topbar-title").textContent = TITLES[view] || "";
  $("#user-menu").hidden = true;
  history.replaceState(null, "", "#" + [view, ...args].join("/"));
  if (view === "settings") { S.settingsDirty = false; loadSettings(); }
  if (view === "learn") openLearn(args[0] || S.ltab, args[1]);
  if (view === "traffic") initTraffic();
  if (view === "scanner") initScanner();
  if (view === "users") loadUsers();
  if (view === "account") loadAccount();
  window.scrollTo({ top: 0 });
  refresh();
}
document.addEventListener("click", e => {
  const nav = e.target.closest(".nav-item"); if (nav) return show(nav.dataset.view);
  if (!e.target.closest(".user-menu")) $("#user-menu").hidden = true;
  const a = e.target.closest("[data-action]"); if (!a) return;
  const act = a.dataset.action;
  if (act === "goto") show(a.dataset.view);
  else if (act === "open-demo") openDemo();
  else if (act === "learn-tech") { e.stopPropagation(); show("learn", ["attack", a.dataset.tid]); }
  else if (act === "learn-rule") show("learn", ["rules", a.dataset.rule]);
});
$("#btn-user").addEventListener("click", () => { const m = $("#user-menu"); m.hidden = !m.hidden; $("#btn-user").setAttribute("aria-expanded", String(!m.hidden)); });
addEventListener("keydown", e => { if (e.key === "Escape") $("#user-menu").hidden = true; });

/* ---------- polling ---------- */
async function refresh() {
  if (!S.user) return;
  try {
    S.status = await api("/api/status", { bg: true }); paintChrome();
    const v = S.view;
    if (v === "overview") await loadOverview(); else if (v === "alerts") await loadAlerts();
    else if (v === "traffic") await loadTraffic(); else if (v === "devices") await loadDevices();
    else if (v === "audit") await loadAudit();
    else if (v === "scanner") { initScanner(); if (S.status.scan_active && !S.scanTimer) followScan(S.status.scan_active.id); }
  } catch (e) { /* banner / sign-in handle it */ }
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
function paintChrome() {
  const st = S.status, cap = st.capture, run = cap.state === "running";
  $("#side-version").textContent = "NetSentinel " + st.version;
  const dot = $("#nav-capture-dot"); dot.className = "dot" + (run ? " on" : cap.state === "error" ? " err" : "");
  dot.title = run ? "Capturing live traffic" : "Capture is off";
  const chip = $("#chip-capture"); chip.querySelector(".dot").className = "dot" + (run ? " on" : cap.state === "error" ? " err" : "");
  chip.querySelector("span").textContent = run ? "Capturing" : cap.state === "error" ? "Capture error" : "Capture off";
  $("#chip-demo").hidden = !(st.simulator && st.simulator.running);
  const n = (st.alerts || {}).open || 0, pill = $("#nav-alert-count"); pill.hidden = n === 0; pill.textContent = n > 99 ? "99+" : n;
  $("#data-dir").textContent = st.data_dir;
}

/* ---------- overview ---------- */
function sparkline(series) {
  const w = 300, h = 60, vals = series.map(p => p.packets), max = Math.max(1, ...vals);
  const pts = vals.map((v, i) => [(i / Math.max(1, vals.length - 1)) * w, h - 4 - (v / max) * (h - 10)]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><path d="${line} L${w} ${h} L0 ${h} Z" fill="currentColor" opacity=".14"/><path d="${line}" fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/></svg>`;
}
function barRows(rows, labelFn, valFn, fmt) {
  const max = Math.max(1, ...rows.map(valFn));
  return rows.map(r => `<div class="bar-row"><code>${esc(labelFn(r))}</code><div class="track"><i data-w="${(valFn(r) / max * 100).toFixed(0)}"></i></div><span class="num muted">${esc(fmt(valFn(r)))}</span></div>`).join("");
}
const stat = (ic, cls, value, label) => `<div class="stat"><span class="s-ic ${cls}">${icon(ic)}</span><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`;
async function loadOverview() {
  const d = await api("/api/overview", { bg: true }), h = d.health;
  $("#hero").className = "hero " + h.level; $("#hero-title").textContent = h.headline; $("#hero-detail").textContent = h.detail;
  $("#hero-icon use").setAttribute("href", h.level === "ok" ? "#i-shield-check" : h.level === "demo" ? "#i-play" : "#i-shield-alert");
  const open = d.alerts.open;
  $("#hero-actions").innerHTML = open ? `<button data-action="goto" data-view="alerts">Review ${open} alert${open === 1 ? "" : "s"}</button>` : "";
  $("#spark").innerHTML = sparkline(d.series);
  const recent = d.series.slice(-5).reduce((a, p) => a + p.packets, 0) / 5;
  $("#spark-label").textContent = `Traffic, last 60 seconds (${recent.toFixed(recent < 10 ? 1 : 0)} packets/sec)`;
  $("#quickstart").hidden = !(d.traffic.packets === 0 && d.alerts.total === 0 && !d.last_scan);
  $("#facts").innerHTML = stat("packet", "", fmtNum(d.traffic.packets), "packets seen") + stat("bell", open ? "warn" : "ok", fmtNum(open), "alerts to review")
    + stat("devices", "purple", fmtNum(d.devices), "devices known") + stat("door", "", d.last_scan ? fmtNum(d.last_scan.open_count) : "none yet", "open ports in last scan");
  $("#ov-alerts").innerHTML = d.latest.length ? d.latest.map(a => `<div class="mini-alert" data-action="goto" data-view="alerts"><span class="sev-dot ${esc(a.severity)}" title="${esc(a.severity)}"></span>
    <div><strong>${esc(a.title)}</strong><span class="muted">${esc(a.src_ip)} &rarr; ${esc(a.dst_ip)} &middot; ${esc(ago(a.timestamp))}${a.source === "simulation" ? " &middot; demo" : ""}${a.mitre_id && a.mitre_id !== "-" ? " &middot; " + esc(a.mitre_id) : ""}</span></div></div>`).join("")
    : `<p class="muted">Nothing needs attention right now.</p>`;
  $("#ov-talkers").innerHTML = d.talkers.length ? barRows(d.talkers, r => r.ip, r => r.bytes, fmtBytes) : `<p class="muted">No traffic seen yet.</p>`;
  $("#ov-protos").innerHTML = d.traffic.protocols.length ? barRows(d.traffic.protocols, r => r.proto, r => r.packets, fmtNum) : `<p class="muted">No traffic seen yet.</p>`;
  applyBars($("#view-overview"));
}

/* ---------- alerts ---------- */
const techName = id => { const t = S.learn && S.learn.techniques.find(x => x.id === id); return t ? t.name : ""; };
function techTag(id) {
  if (!id || id === "-") return "";
  const name = techName(id);
  return `<button class="tag-btn" data-action="learn-tech" data-tid="${esc(id)}" title="Read about ${esc(id)} in Learn">${esc(id)}${name ? ` <span class="tname">${esc(name)}</span>` : ""}</button>`;
}
function alertCard(a) {
  const open = S.expanded.has(a.id), t = S.learn && S.learn.techniques.find(x => x.id === a.mitre_id);
  return `<article class="alert-card ${esc(a.severity)}${a.reviewed ? " reviewed" : ""}">
    <div class="alert-head" data-toggle="${a.id}" tabindex="0" role="button" aria-expanded="${open}"><div><h3>${esc(a.title)}</h3>
      <div class="alert-meta"><code>${esc(a.src_ip)} &rarr; ${esc(a.dst_ip)}</code><span>${esc(ago(a.last_seen))}</span>${a.count > 1 ? `<span class="count">seen ${a.count} times</span>` : ""}${techTag(a.mitre_id)}</div></div>
      <div class="row">${a.source === "simulation" ? `<span class="badge demo">demo</span>` : ""}${sevBadge(a.severity)}</div></div>
    ${open ? `<div class="alert-body"><div><h4>What we saw</h4><p>${esc(a.description)}</p></div><div><h4>What it might mean</h4><p>${esc(a.meaning)}</p></div><div><h4>What to do</h4><p>${esc(a.action)}</p></div>
      ${t ? `<div class="alert-technique">${icon("target")}<div><strong>MITRE ATT&amp;CK ${esc(t.id)}: ${esc(t.name)}</strong> <span class="muted small">(${esc(t.tactics.join(", "))})</span><p>${esc(t.summary)}</p>
        <div class="row"><button class="link" data-action="learn-tech" data-tid="${esc(t.id)}">Read more in Learn</button><a class="small" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer">attack.mitre.org ${icon("external")}</a></div></div></div>` : ""}
      <div class="actions">${can("analyst") ? `<button class="ghost small" data-review="${a.id}" data-to="${a.reviewed ? 0 : 1}">${icon("check")}${a.reviewed ? "Mark as not reviewed" : "Mark as reviewed"}</button>` : ""}
      <button class="link" data-action="learn-rule" data-rule="${esc(a.rule_id)}">When does this alert fire?</button>
      <small class="muted">${esc(a.rule_name)} &middot; first seen ${esc(clock(a.timestamp))}</small></div></div>` : ""}</article>`;
}
async function loadAlerts() {
  const demo = $("#alert-demo").checked, status = $("#alert-status").value;
  $("#lnk-csv").href = "/api/export/alerts.csv" + (demo ? "?demo=1" : ""); $("#lnk-report").href = "/api/export/report.md" + (demo ? "?demo=1" : "");
  const d = await api(`/api/alerts?limit=300&severity=${S.sev}&status=${status}&source=${demo ? "all" : "live"}`, { bg: true });
  const sig = JSON.stringify(d.alerts.map(a => [a.id, a.count, a.reviewed])) + [...S.expanded].join() + (S.learn ? "L" : ""); if (sig === S.alertSig) return; S.alertSig = sig;
  $("#alert-list").innerHTML = d.alerts.length ? d.alerts.map(alertCard).join("")
    : `<div class="empty panel">${status === "open" ? "No alerts need your attention. " : "No alerts match. "}Try the demo to see what NetSentinel can catch.</div>`;
}
function toggleAlert(id) { S.expanded.has(id) ? S.expanded.delete(id) : S.expanded.add(id); S.alertSig = ""; loadAlerts(); }
$("#alert-list").addEventListener("click", async e => {
  const rv = e.target.closest("[data-review]");
  if (rv) { try { await api(`/api/alerts/${rv.dataset.review}/review`, { method: "POST", body: { reviewed: rv.dataset.to === "1" } }); S.alertSig = ""; refresh(); } catch (er) { fail(er); } return; }
  const t = e.target.closest("[data-toggle]"); if (t && !e.target.closest("a, button")) toggleAlert(Number(t.dataset.toggle));
});
$("#alert-list").addEventListener("keydown", e => { const t = e.target.closest("[data-toggle]"); if (t && e.target === t && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggleAlert(Number(t.dataset.toggle)); } });
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
  const d = await api(`/api/packets?since_id=${S.pktSince}&limit=300&q=${encodeURIComponent(S.pktFilter)}`, { bg: true });
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
  const d = await api("/api/flows?limit=200&sort=bytes", { bg: true }); emptyMsg($("#flow-empty"), d.flows.length ? "" : "No conversations yet.");
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
    let j; try { j = await api("/api/scan/" + id, { bg: true }); } catch (e) { clearInterval(S.scanTimer); S.scanTimer = null; return; }
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
    html += `<section class="host-card"><header>${icon("laptop")}<strong>${esc(host)}</strong><span class="muted">${rows.length} open port${rows.length === 1 ? "" : "s"}</span>${RISK_RANK[worst] >= 1 ? sevBadge(worst) : ""}</header>`;
    html += rows.length ? `<table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Details</th></tr></thead><tbody>${rows.map(r => `<tr><td class="mono">${esc(r.port)}/tcp</td><td>${esc(r.service)}</td><td><span class="badge ${esc(r.risk)}">${esc(r.risk === "unknown" ? "unrated" : r.risk)}</span></td><td>${r.banner ? `<code>${esc(r.banner)}</code>` : ""}<div class="advice">${esc(r.advice)}</div></td></tr>`).join("")}</tbody></table>` : `<div class="empty">Up, with no open ports among those scanned.</div>`;
    html += `</section>`;
  }
  $("#scan-results").innerHTML = html;
}
async function loadScanHistory() {
  try {
    const d = await api("/api/scan/history"); $("#scan-history-panel").hidden = !d.runs.length;
    $("#scan-history").innerHTML = d.runs.map(r => `<div class="history-row"><div><strong>${esc(r.targets)}</strong><div class="muted small">${esc(when(r.started))} &middot; ${esc(r.hosts_up)} up &middot; ${esc(r.open_count)} open &middot; ${esc(r.status)}</div></div><button class="ghost small" data-run="${esc(r.id)}" data-label="${esc(r.targets)}">View</button></div>`).join("");
  } catch (e) { /* ignore */ }
}
$("#scan-history").addEventListener("click", async e => {
  const b = e.target.closest("[data-run]"); if (!b) return;
  try { const d = await api("/api/scan/history/" + b.dataset.run); renderScan({ results: d.results, status: "done" }, b.dataset.label); window.scrollTo({ top: 0, behavior: "smooth" }); } catch (er) { fail(er); }
});

/* ---------- devices ---------- */
async function loadDevices() {
  const d = await api("/api/devices", { bg: true }); emptyMsg($("#dev-empty"), d.devices.length ? "" : "No devices yet. Run a network scan, or start live capture to learn devices from ARP traffic.");
  $("#dev-body").innerHTML = d.devices.map(v => `<tr><td class="mono">${esc(v.ip)}</td><td class="mono">${esc(v.mac || "unknown")}</td><td>${esc(v.via === "arp" ? "Live capture (ARP)" : "Port scan")}${v.source === "simulation" ? ` <span class="badge demo">demo</span>` : ""}</td><td>${esc(clock(v.first_seen))}</td><td>${esc(ago(v.last_seen))}</td><td>${v.previous_macs.length ? `<span class="badge high">Hardware address changed</span>` : ""}</td></tr>`).join("");
}

/* ---------- learn ---------- */
async function loadLearn() {
  try { S.learn = await api("/api/learn"); S.alertSig = ""; if (S.view === "learn") openLearn(S.ltab); } catch (e) { /* ignore */ }
}
function openLearn(tab, focus) {
  if (!["start", "attack", "rules", "glossary"].includes(tab)) tab = "start";
  S.ltab = tab;
  $$("#learn-tabs button").forEach(b => b.classList.toggle("active", b.dataset.ltab === tab));
  $$(".learn-pane").forEach(p => p.hidden = p.id !== "learn-" + tab);
  if (!S.learn) return;
  if (tab === "attack") renderAttack(); else if (tab === "rules") renderRules(); else if (tab === "glossary") renderGlossary();
  if (focus) setTimeout(() => {
    const el = document.getElementById((tab === "attack" ? "tech-" : "rule-") + focus);
    if (el) { el.scrollIntoView({ behavior: "smooth", block: "start" }); el.classList.add("flash"); setTimeout(() => el.classList.remove("flash"), 1800); }
  }, 60);
}
$("#learn-tabs").addEventListener("click", e => { const b = e.target.closest("button"); if (b) show("learn", [b.dataset.ltab]); });
function renderAttack() {
  const L = S.learn, A = L.attack, box = $("#learn-attack");
  if (box.dataset.ready) return; box.dataset.ready = "1";
  const ruleName = id => (L.rules.find(r => r.id === id) || {}).name || id;
  box.innerHTML = `
    <div class="panel attack-hero"><div><h2>${icon("target", "h-ic")}What is MITRE ATT&amp;CK?</h2>${A.intro.map((p, i) => `<p class="${i === 0 ? "lead" : ""}">${esc(p)}</p>`).join("")}
      <p><a href="${esc(A.url)}" target="_blank" rel="noopener noreferrer">Visit attack.mitre.org ${icon("external")}</a></p></div>
      <div class="id-anatomy"><p class="eyebrow">How to read an ID</p><div class="id-big"><span class="a">T1557</span>.<span class="b">002</span></div>
        <div class="legend"><span><b class="a">T1557</b> Technique: Adversary-in-the-Middle</span><span><b class="b">.002</b> Sub-technique: ARP Cache Poisoning</span><span><b>TA0006</b> Tactic IDs start with TA (this one is Credential Access)</span></div></div></div>
    <div class="panel"><h2>The 14 tactics: an attack from start to finish</h2><p class="muted">Read left to right, top to bottom. Highlighted tactics are ones NetSentinel's rules can spot on the network.</p>
      <div class="tactics">${A.tactics.map(t => `<div class="tactic${t.covered ? " covered" : ""}"><small>${esc(t.id)}</small><strong>${esc(t.name)}</strong><p>${esc(t.text)}</p></div>`).join("")}</div>
      <div class="legend-row"><span><i></i>Watched by NetSentinel</span><span>Most tactics happen on the computers themselves; watching those needs endpoint tools, which NetSentinel isn't.</span></div></div>
    <div class="panel"><h2>Why security teams use it</h2><div class="uses">${A.how_to_use.map(u => `<div><strong>${esc(u.title)}</strong><p>${esc(u.text)}</p></div>`).join("")}</div>
      <div class="notice info">${esc(A.in_netsentinel)}</div></div>
    <h2>Techniques NetSentinel recognises</h2>
    ${L.techniques.map(t => `<div class="panel tech" id="tech-${esc(t.id)}"><div class="tech-head"><span class="tech-id">${esc(t.id)}</span><h3>${esc(t.name)}</h3>${t.tactics.map(x => `<span class="badge accent">${esc(x)}</span>`).join("")}<span class="spacer"></span>
        <a class="btn ghost small" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer">Official page ${icon("external")}</a></div>
      <p>${esc(t.summary)}</p>
      ${t.subs.length ? `<div class="subs">Sub-techniques: ${t.subs.map(s => `<a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer"><code>${esc(s.id)}</code> ${esc(s.name)}</a>`).join(" ")}</div>` : ""}
      <div class="tech-grid"><div><h4>What it looks like on the network</h4><p>${esc(t.looks_like)}</p>
        <h4>NetSentinel rules</h4><div class="row">${t.rules.length ? t.rules.map(r => `<button class="ghost small" data-action="learn-rule" data-rule="${esc(r)}">${esc(ruleName(r))}</button>`).join("") : (t.related_rule ? `<span class="muted small">Related: </span><button class="ghost small" data-action="learn-rule" data-rule="${esc(t.related_rule)}">${esc(ruleName(t.related_rule))}</button>` : `<span class="muted small">No rule uses this ID today.</span>`)}</div></div>
        <div><h4>How to defend</h4><ul>${t.defend.map(d => `<li>${esc(d)}</li>`).join("")}</ul></div></div></div>`).join("")}`;
}
function renderRules() {
  const L = S.learn, box = $("#learn-rules");
  box.innerHTML = `<p class="muted">These are the exact conditions, using your current settings. Identical alerts within ${esc(L.cooldown)} seconds are merged into one, with a counter. Administrators can tune the numbers in Settings.</p>
    <div class="rule-grid">${L.rules.map(r => `<div class="card rule-card" id="rule-${esc(r.id)}"><div class="rc-head"><h3>${esc(r.name)}</h3><div class="row">${techTag(r.mitre)}${sevBadge(r.severity)}</div></div>
      <p>${esc(r.title)}.</p>
      <div class="trigger"><h4>Fires when</h4>${esc(r.trigger)}</div>
      <div><h4>How it's counted</h4><p>${esc(r.method)}</p></div>
      <details><summary>What it means and what to do</summary><p>${esc(r.meaning)}</p><p>${esc(r.action)}</p></details></div>`).join("")}</div>`;
}
function renderGlossary() {
  const L = S.learn, q = $("#gloss-search").value.trim().toLowerCase();
  $("#gloss-cats").innerHTML = ["All", ...L.categories].map(c => `<button class="${c === S.glossCat ? "active" : ""}" data-cat="${esc(c)}">${esc(c)}</button>`).join("");
  const hl = s => { const e = esc(s); if (!q) return e; const i = e.toLowerCase().indexOf(esc(q)); return i < 0 ? e : e.slice(0, i) + "<mark>" + e.slice(i, i + esc(q).length) + "</mark>" + e.slice(i + esc(q).length); };
  const items = L.glossary.filter(g => (S.glossCat === "All" || g.cat === S.glossCat) && (!q || (g.term + " " + g.text).toLowerCase().includes(q)));
  $("#glossary").innerHTML = items.map(g => `<div class="gloss"><small>${esc(g.cat)}</small><strong>${hl(g.term)}</strong><p>${hl(g.text)}</p></div>`).join("");
  emptyMsg($("#gloss-empty"), items.length ? "" : "No terms match. Try a shorter word.");
}
$("#gloss-cats").addEventListener("click", e => { const b = e.target.closest("[data-cat]"); if (!b) return; S.glossCat = b.dataset.cat; renderGlossary(); });
$("#gloss-search").addEventListener("input", () => renderGlossary());

/* ---------- account & security ---------- */
const EVENT_TEXT = { login: "Signed in", login_failed: "Failed sign-in", "2fa_failed": "Wrong two-factor code", logout: "Signed out", password_changed: "Password changed",
  "2fa_enabled": "Two-factor turned on", "2fa_disabled": "Two-factor turned off", recovery_codes_regenerated: "New recovery codes", session_revoked: "Session ended",
  sessions_revoked: "Other sessions ended", signed_out_idle: "Signed out (inactive)" };
async function loadAccount() {
  let d; try { d = await api("/api/account"); } catch (e) { return fail(e); }
  const u = d.user; S.user.totp_enabled = u.totp_enabled; $("#ov-nudge").hidden = !!u.totp_enabled;
  $("#acct-pw-user").value = u.username;
  const checks = [u.totp_enabled, !u.must_change_pw, d.sessions.length <= 3], score = checks.filter(Boolean).length + 1;
  $("#acct-profile").innerHTML = `<span class="avatar">${esc(u.username.slice(0, 1))}</span><div><h2>${esc(u.username)} <span class="badge ${esc(u.role)}">${esc(u.role)}</span></h2>
      <p>${u.last_login ? `Last sign-in ${esc(ago(u.last_login))} from ${esc(u.last_login_ip || "unknown")}` : "First sign-in"}${u.pw_changed ? ` &middot; password set ${esc(ago(u.pw_changed))}` : ""}</p></div>
    <div class="score"><strong>${u.totp_enabled ? "Well protected" : "Add two-factor for full protection"}</strong><div class="meter s${score}"><i></i><i></i><i></i><i></i></div></div>`;
  const left = u.recovery_left;
  $("#acct-2fa").innerHTML = `<h2>${icon("phone", "h-ic")}Two-factor sign-in</h2>
    <div class="tfa-state${u.totp_enabled ? " on" : ""}">${icon(u.totp_enabled ? "shield-check" : "shield-alert", "big-ic")}<div><strong>${u.totp_enabled ? "On" : "Off"}</strong>
      <p>${u.totp_enabled ? "After your password you'll enter a 6-digit code from your authenticator app." : "Right now your password is the only thing protecting this account. Turn on two-factor so a stolen password isn't enough."}</p></div></div>
    ${u.totp_enabled ? `<p class="small ${left <= 3 ? "notice warn" : "muted"}">${left} of 10 recovery codes left.${left <= 3 ? " Make new ones soon." : ""}</p>
      <div class="row"><button class="ghost" id="btn-new-codes">New recovery codes</button><button class="danger-ghost" id="btn-2fa-off">Turn off</button></div>`
      : `<div class="row"><button id="btn-2fa-on">${icon("shield-check")}Turn on two-factor</button></div>`}`;
  const others = d.sessions.filter(s => !s.current).length;
  $("#btn-revoke-others").hidden = !others;
  $("#acct-session-note").textContent = `Sessions end after ${d.idle_minutes} minutes without activity, and after ${d.max_hours} hours at most.`;
  $("#acct-sessions").innerHTML = d.sessions.map(s => `<div class="session-row${s.current ? " current" : ""}">${icon(/iPhone|Android|iPad/.test(s.device) ? "phone" : "laptop")}
    <div><strong>${esc(s.device)}</strong> ${s.current ? `<span class="badge accent">This browser</span>` : ""}<br><small>${esc(s.ip || "unknown address")} &middot; signed in ${esc(when(s.created))} &middot; active ${esc(ago(s.last_seen))}</small></div>
    ${s.current ? "" : `<button class="ghost small" data-revoke="${esc(s.id)}">Sign out</button>`}</div>`).join("");
  $("#acct-activity").innerHTML = d.activity.length ? d.activity.map(v => `<tr><td class="mono">${esc(when(v.ts))}</td><td><span class="badge ${/fail|idle/.test(v.action) ? "high" : ""}">${esc(EVENT_TEXT[v.action] || v.action.replace(/_/g, " "))}</span></td><td>${esc(v.detail)}</td><td class="mono">${esc(v.ip)}</td></tr>`).join("")
    : `<tr><td colspan="4" class="muted">Nothing yet.</td></tr>`;
}
$("#acct-sessions").addEventListener("click", async e => {
  const b = e.target.closest("[data-revoke]"); if (!b) return;
  try { await api(`/api/account/sessions/${b.dataset.revoke}/revoke`, { method: "POST" }); toast("That session was signed out."); loadAccount(); } catch (er) { fail(er); }
});
$("#btn-revoke-others").addEventListener("click", async () => {
  try { const r = await api("/api/account/sessions/revoke-others", { method: "POST" }); toast(`Signed out ${r.revoked} other session(s).`); loadAccount(); } catch (e) { fail(e); }
});
$("#acct-pw-form").addEventListener("submit", async e => {
  e.preventDefault(); const err = $("#acct-pw-error"); err.hidden = true;
  if ($("#acct-pw-new").value !== $("#acct-pw-confirm").value) { err.hidden = false; err.textContent = "The two new passwords don't match."; return; }
  try {
    await api("/api/account/password", { method: "POST", body: { current: $("#acct-pw-current").value, new: $("#acct-pw-new").value } });
    $("#acct-pw-form").reset(); acctMeter(); toast("Password changed. Your other sessions were signed out."); loadAccount();
  } catch (er) { err.hidden = false; err.textContent = er.message; }
});
function codesHtml(codes) {
  return `<p>Save these recovery codes somewhere safe, like a password manager or a printed sheet. Each one lets you sign in once if you lose your phone. <strong>They won't be shown again.</strong></p>
    <ol>${codes.map(c => `<li>${esc(c)}</li>`).join("")}</ol>
    <div class="row"><button class="ghost small" type="button" data-copy-codes>${icon("copy")}Copy</button><button class="ghost small" type="button" data-dl-codes>${icon("download")}Download .txt</button></div>`;
}
function wireCodes(box, codes) {
  box.innerHTML = codesHtml(codes);
  box.querySelector("[data-copy-codes]").addEventListener("click", async () => { try { await navigator.clipboard.writeText(codes.join("\n")); toast("Copied."); } catch (e) { toast("Copy isn't allowed here. Use Download instead.", true); } });
  box.querySelector("[data-dl-codes]").addEventListener("click", () => download("netsentinel-recovery-codes.txt",
    `NetSentinel recovery codes for ${S.user.username}\nEach code works once. Keep them private.\n\n${codes.join("\n")}\n`));
}
/* two-factor setup wizard */
function tfaStep(n) {
  [1, 2, 3].forEach(i => { $("#tfa-step" + i).hidden = i !== n; });
  $$("#tfa-steps span").forEach((s, i) => { s.className = i + 1 === n ? "active" : i + 1 < n ? "done" : ""; });
}
document.addEventListener("click", async e => {
  if (e.target.closest("#btn-2fa-on")) {
    try {
      const r = await api("/api/account/2fa/setup", { method: "POST" });
      $("#tfa-qr").src = r.qr; $("#tfa-secret").textContent = r.secret; $("#tfa-code").value = ""; $("#tfa-pass").value = ""; $("#tfa-error").hidden = true;
      tfaStep(1); $("#tfa-dialog").showModal();
    } catch (er) { fail(er); }
  } else if (e.target.closest("#btn-2fa-off")) {
    await ask({ title: "Turn off two-factor sign-in?", text: "Your account will be protected by your password alone. Enter your password and a current code from your app (or a recovery code).",
      ok: "Turn off", danger: true, fields: [{ id: "password", label: "Password", type: "password", ac: "current-password" }, { id: "code", label: "Code from your app or a recovery code", ac: "one-time-code" }],
      submit: async v => { await api("/api/account/2fa/disable", { method: "POST", body: v }); toast("Two-factor sign-in is off."); loadAccount(); } });
  } else if (e.target.closest("#btn-new-codes")) {
    await ask({ title: "Make new recovery codes?", text: "Your old codes will stop working. Enter your password to continue.", ok: "Make new codes",
      fields: [{ id: "password", label: "Password", type: "password", ac: "current-password" }],
      submit: async v => { const r = await api("/api/account/2fa/recovery", { method: "POST", body: v }); wireCodes($("#codes-list"), r.recovery_codes); setTimeout(() => $("#codes-dialog").showModal(), 50); } });
  }
});
$("#tfa-next").addEventListener("click", () => { tfaStep(2); $("#tfa-code").focus(); });
$("#tfa-back").addEventListener("click", () => tfaStep(1));
$("#tfa-close").addEventListener("click", () => { $("#tfa-dialog").close(); loadAccount(); });
$("#tfa-step2").addEventListener("submit", async e => {
  e.preventDefault(); const err = $("#tfa-error"); err.hidden = true;
  try {
    const r = await api("/api/account/2fa/enable", { method: "POST", body: { code: $("#tfa-code").value, password: $("#tfa-pass").value } });
    wireCodes($("#tfa-codes"), r.recovery_codes); tfaStep(3);
  } catch (er) { err.hidden = false; err.textContent = er.message; }
});
$("#tfa-done").addEventListener("click", () => { $("#tfa-dialog").close(); toast("Two-factor sign-in is on."); loadAccount(); });
$("#codes-done").addEventListener("click", () => { $("#codes-dialog").close(); loadAccount(); });

/* A small form dialog. `submit` runs the action; if it throws, the error shows and the dialog stays open. */
function ask({ title, text = "", fields = [], ok = "Confirm", danger = false, submit }) {
  return new Promise(resolve => {
    const dlg = $("#ask-dialog"), form = $("#ask-form"), err = $("#ask-error");
    $("#ask-title").textContent = title; $("#ask-text").textContent = text; $("#ask-text").hidden = !text;
    $("#ask-ok").textContent = ok; $("#ask-ok").className = danger ? "danger" : ""; err.hidden = true;
    $("#ask-fields").innerHTML = fields.map(f => `<label class="field"><span>${esc(f.label)}</span><input data-f="${esc(f.id)}" type="${f.type === "password" ? "password" : "text"}" autocomplete="${esc(f.ac || "off")}" spellcheck="false" required>${f.hint ? `<small class="muted">${esc(f.hint)}</small>` : ""}</label>`).join("");
    const done = val => { form.onsubmit = null; $("#ask-cancel").onclick = null; dlg.onclose = null; if (dlg.open) dlg.close(); resolve(val); };
    form.onsubmit = async e => {
      e.preventDefault(); err.hidden = true; $("#ask-ok").disabled = true;
      const vals = {}; $$("[data-f]", form).forEach(i => { vals[i.dataset.f] = i.value; });
      try { const r = submit ? await submit(vals) : vals; $("#ask-ok").disabled = false; done(r === undefined ? true : r); }
      catch (er) { $("#ask-ok").disabled = false; if (er.status === 401) return done(null); err.hidden = false; err.textContent = er.message; }
    };
    $("#ask-cancel").onclick = () => done(null);
    dlg.onclose = () => resolve(null);
    dlg.showModal(); const first = $("[data-f]", form); if (first) first.focus();
  });
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
  ["Accounts and sign-in", [
    ["session_idle_minutes", "Sign people out after this many idle minutes", "Applies to everyone. Between 5 minutes and 24 hours. A dashboard left open on its own doesn't count as activity."]]],
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
$("#btn-save-settings").addEventListener("click", async () => { try { await api("/api/settings", { method: "POST", body: collectSettings() }); S.settingsDirty = false; $("#settings-msg").textContent = ""; toast("Settings saved."); await loadSettings(); loadLearn(); } catch (e) { fail(e); } });
$("#btn-reset-settings").addEventListener("click", async () => {
  if (!(await ask({ title: "Restore every setting to its default?", ok: "Restore defaults" }))) return;
  try { await api("/api/settings/reset", { method: "POST" }); S.settingsDirty = false; $("#settings-msg").textContent = ""; toast("Defaults restored."); await loadSettings(); loadLearn(); } catch (e) { fail(e); }
});

/* ---------- users (admin) ---------- */
async function loadUsers() {
  try {
    const d = await api("/api/users"), s = d.summary;
    $("#nu-role").innerHTML = Object.keys(d.roles).map(r => `<option value="${esc(r)}"${r === "viewer" ? " selected" : ""}>${esc(r)}</option>`).join("");
    $("#role-help").innerHTML = Object.entries(d.roles).map(([r, t]) => `<div><dt>${esc(r)}</dt><dd>${esc(t)}</dd></div>`).join("");
    $("#user-summary").innerHTML = stat("users", "", `${s.active}`, "active accounts")
      + stat("shield-check", s.with_2fa === s.active ? "ok" : "warn", `${s.with_2fa} of ${s.active}`, "use two-factor sign-in")
      + (s.admins_without_2fa.length ? stat("shield-alert", "warn", `${s.admins_without_2fa.length}`, `admin${s.admins_without_2fa.length === 1 ? "" : "s"} without two-factor: ${s.admins_without_2fa.join(", ")}`)
        : stat("key", "ok", "All admins", "protected with two-factor"));
    $("#user-body").innerHTML = d.users.map(u => {
      const me = u.username === S.user.username;
      return `<tr><td><strong>${esc(u.username)}</strong>${me ? ` <span class="muted">(you)</span>` : ""}${u.must_change_pw ? `<br><small class="muted">must choose a new password</small>` : ""}</td>
        <td>${me ? `<span class="badge ${esc(u.role)}">${esc(u.role)}</span>` : `<select data-role="${u.id}" aria-label="Role for ${esc(u.username)}">${Object.keys(d.roles).map(r => `<option${r === u.role ? " selected" : ""}>${esc(r)}</option>`).join("")}</select>`}</td>
        <td>${u.totp_enabled ? `<span class="badge on">${icon("shield-check")}On</span>` : `<span class="badge">Off</span>`}</td>
        <td>${u.last_login ? `${esc(ago(u.last_login))}<br><small class="muted">${esc(u.last_login_ip || "")}${u.sessions ? ` &middot; ${u.sessions} active session${u.sessions === 1 ? "" : "s"}` : ""}</small>` : "never"}</td>
        <td>${u.disabled ? `<span class="badge high">disabled</span>` : `<span class="badge low">active</span>`}</td>
        <td><div class="actions-cell">${me ? `<button class="ghost small" data-action="goto" data-view="account">Manage my account</button>` : `
          <button class="ghost small" data-resetpw="${u.id}" data-name="${esc(u.username)}">Reset password</button>
          ${u.totp_enabled ? `<button class="ghost small" data-reset2fa="${u.id}" data-name="${esc(u.username)}">Reset two-factor</button>` : ""}
          ${u.sessions ? `<button class="ghost small" data-signout="${u.id}" data-name="${esc(u.username)}">Sign out</button>` : ""}
          <button class="ghost small" data-disable="${u.id}" data-to="${u.disabled ? 0 : 1}">${u.disabled ? "Enable" : "Disable"}</button>
          <button class="danger-ghost small" data-del="${u.id}" data-name="${esc(u.username)}">Delete</button>`}</div></td></tr>`;
    }).join("");
  } catch (e) { fail(e); }
}
$("#user-form").addEventListener("submit", async e => {
  e.preventDefault(); const err = $("#user-error"); err.hidden = true;
  try {
    await api("/api/users", { method: "POST", body: { username: $("#nu-name").value, password: $("#nu-pass").value, role: $("#nu-role").value, must_change: $("#nu-must").checked } });
    $("#user-form").reset(); $("#nu-must").checked = true; toast("User added."); loadUsers();
  } catch (er) { err.hidden = false; err.textContent = er.message; }
});
$("#user-body").addEventListener("change", async e => { const s = e.target.closest("[data-role]"); if (!s) return; try { await api("/api/users/" + s.dataset.role, { method: "POST", body: { role: s.value } }); toast("Role updated. They've been signed out."); } catch (er) { fail(er); } loadUsers(); });
$("#user-body").addEventListener("click", async e => {
  const b = e.target.closest("button"); if (!b || b.dataset.action) return; const name = b.dataset.name;
  try {
    if (b.dataset.disable) await api("/api/users/" + b.dataset.disable, { method: "POST", body: { disabled: b.dataset.to === "1" } });
    else if (b.dataset.resetpw) await ask({ title: `Reset ${name}'s password`, text: "They'll be signed out everywhere and asked to choose their own password at their next sign-in.", ok: "Reset password",
      fields: [{ id: "password", label: `Temporary password (at least ${S.minPw} characters)`, type: "password", ac: "new-password" }],
      submit: async v => { await api("/api/users/" + b.dataset.resetpw, { method: "POST", body: { password: v.password } }); toast(`Password reset. Give ${name} the temporary password privately.`); } });
    else if (b.dataset.reset2fa) await ask({ title: `Reset ${name}'s two-factor sign-in?`, text: "Use this if they lost their phone and their recovery codes. They'll sign in with just their password until they set it up again, and they'll be signed out now.", ok: "Reset two-factor", danger: true,
      submit: async () => { await api(`/api/users/${b.dataset.reset2fa}/reset-2fa`, { method: "POST" }); toast(`Two-factor reset for ${name}.`); } });
    else if (b.dataset.signout) { const r = await api(`/api/users/${b.dataset.signout}/signout`, { method: "POST" }); toast(`Signed ${name} out of ${r.revoked} session(s).`); }
    else if (b.dataset.del) await ask({ title: `Delete ${name}?`, text: "This can't be undone. Their audit history stays.", ok: "Delete user", danger: true,
      submit: async () => { await api(`/api/users/${b.dataset.del}/delete`, { method: "POST" }); toast(`${name} was deleted.`); } });
  } catch (er) { fail(er); }
  loadUsers();
});

/* ---------- audit (admin) ---------- */
async function loadAudit() {
  const d = await api("/api/audit?limit=300", { bg: true }); emptyMsg($("#audit-empty"), d.events.length ? "" : "Nothing recorded yet.");
  $("#audit-body").innerHTML = d.events.map(v => `<tr><td class="mono">${esc(when(v.ts))}</td><td>${esc(v.username || "-")}</td><td><span class="badge ${/fail|denied|refused|reset|deleted/.test(v.action) ? "high" : /2fa|password|session|signed/.test(v.action) ? "accent" : ""}">${esc(v.action.replace(/_/g, " "))}</span></td><td>${esc(v.detail)}</td><td class="mono">${esc(v.ip)}</td></tr>`).join("");
}

/* ---------- demo dialog ---------- */
function openDemo() {
  const sc = (S.status && S.status.scenarios) || {};
  $("#demo-list").innerHTML = Object.entries(sc).map(([k, v]) => `<div class="demo-item"><div><strong>${esc(v.name)}</strong><p>${esc(v.desc)}</p></div><button data-scenario="${esc(k)}" class="needs-analyst small">${icon("play")}Run</button></div>`).join("");
  $("#demo-dialog").showModal();
}
$("#btn-demo").addEventListener("click", openDemo);
$("#demo-list").addEventListener("click", async e => {
  const b = e.target.closest("[data-scenario]"); if (!b) return;
  try { await api("/api/simulate", { method: "POST", body: { scenario: b.dataset.scenario } }); $("#demo-dialog").close(); toast("Demo running. Watch the Overview and Alerts."); S.alertSig = ""; show("overview"); } catch (er) { fail(er); }
});
$("#btn-demo-clear").addEventListener("click", async () => {
  $("#demo-dialog").close();
  if (!(await ask({ title: "Remove all demo data?", text: "Demo alerts, packets and devices will be deleted. Real data isn't touched.", ok: "Remove demo data" }))) return;
  try { await api("/api/simulate/clear", { method: "POST" }); resetPackets(); S.alertSig = ""; toast("Demo data removed."); refresh(); } catch (e) { fail(e); }
});

boot();

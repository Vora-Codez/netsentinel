"""Optional end-to-end check in a real browser (needs: pip install playwright && playwright install chromium).
Usage: python tests/e2e_browser.py   (starts its own server on a temp data folder; refreshes docs/screenshots)"""
import os, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from netsentinel import mfa  # noqa: E402

SHOTS = ROOT / "docs" / "screenshots"
SHOTS.mkdir(parents=True, exist_ok=True)
for old in SHOTS.glob("*.png"):
    old.unlink()
PORT, PW, PW2 = 8791, "correct horse battery", "viewer picks own phrase"
env = dict(os.environ, NETSENTINEL_HOME=tempfile.mkdtemp(), NETSENTINEL_PORT=str(PORT), NETSENTINEL_SETUP_CODE="SETUP123")
srv = subprocess.Popen([sys.executable, "-m", "netsentinel", "serve"], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
for _ in range(50):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/ping"); break
    except Exception:
        time.sleep(0.2)
problems, base = [], f"http://127.0.0.1:{PORT}"
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: problems.append(msg)
def shot(page, name, top=True):
    page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")
    if top:
        page.evaluate("() => window.scrollTo(0, 0)")
    time.sleep(0.35)                                              # let the fade-in finish
    page.screenshot(path=SHOTS / f"{name}.png")
try:
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1440, "height": 900}, color_scheme="light")
        page = ctx.new_page()
        errors, expected = [], []
        def on_console(m):
            if m.type != "error": return
            if any(code in m.text for code in ("400", "401", "403")) and len(expected) < 5: expected.append(m.text); return   # deliberate wrong code / password
            errors.append(m.text)
        page.on("console", on_console)
        page.on("pageerror", lambda e: errors.append(str(e)))

        # ---- first run
        page.goto(base)
        page.wait_for_selector("#gate:not([hidden])")
        check("Create the administrator" in page.inner_text("#gate-title"), "first run shows setup screen")
        page.fill("#gate-code", "WRONG"); page.fill("#gate-user", "admin"); page.fill("#gate-new", PW); page.fill("#gate-confirm", PW)
        check("Strong" in page.inner_text("#gate-meter-text") or "Good" in page.inner_text("#gate-meter-text"), "password strength meter rates a passphrase")
        shot(page, "00-setup")
        page.click("#gate-submit"); page.wait_for_selector("#gate-error:not([hidden])")
        check("setup code is wrong" in page.inner_text("#gate-error"), "wrong setup code is refused")
        page.fill("#gate-code", "SETUP123"); page.click("#gate-submit")
        page.wait_for_selector("#app:not([hidden])")
        check(page.inner_text("#who-name") == "admin", "admin signed in after setup")
        page.wait_for_selector("#quickstart:not([hidden])")
        check(page.locator("#ov-nudge").is_visible(), "overview nudges the user to turn on two-factor")
        shot(page, "01-overview-empty")

        # ---- demo + overview + alerts
        page.click("#btn-demo"); page.wait_for_selector("#demo-dialog[open]")
        shot(page, "02-demo-picker")
        page.click('[data-scenario="all"]')
        page.wait_for_selector("#nav-alert-count:not([hidden])", timeout=30000)
        time.sleep(14)
        page.wait_for_selector("#hero.alert, #hero.demo", timeout=20000)
        check(page.evaluate("() => [...document.querySelectorAll('.bar-row i')].some(i => i.getBoundingClientRect().width > 4)"), "overview bars have width under the strict CSP")
        shot(page, "03-overview-demo")
        page.click('.nav-item[data-view="alerts"]'); page.wait_for_selector(".alert-card")
        page.click(".alert-card.high .alert-head >> nth=0"); page.wait_for_selector(".alert-body")
        check("what it might mean" in page.inner_text(".alert-body").lower(), "alert expands with plain-English explanation")
        check(page.locator(".alert-technique").count() >= 1, "expanded alert explains its MITRE ATT&CK technique")
        shot(page, "04-alerts")
        tid = page.locator(".alert-body .tag-btn, .alert-head .tag-btn").first.get_attribute("data-tid")
        page.locator(".alert-head .tag-btn").first.click()
        page.wait_for_selector("#learn-attack:not([hidden]) .tech")
        check(page.evaluate(f"() => location.hash") == f"#learn/attack/{tid}", f"technique tag opens Learn at {tid}")
        time.sleep(1.2)
        check(page.locator(f"#tech-{tid}").is_visible(), "the technique card is shown")

        # ---- learn
        page.click('#learn-tabs [data-ltab="attack"]'); page.wait_for_selector(".tactic")
        check(page.locator(".tactic").count() == 14 and page.locator(".tactic.covered").count() >= 4, "ATT&CK tab shows the 14 tactics with coverage")
        page.evaluate("() => window.scrollTo(0, 0)")
        shot(page, "05-learn-attack")
        page.click('#learn-tabs [data-ltab="rules"]'); page.wait_for_selector(".rule-card")
        check("15 or more" in page.inner_text("#rule-port_scan"), "rule cards show the live thresholds")
        shot(page, "06-learn-rules")
        page.click('#learn-tabs [data-ltab="glossary"]'); page.wait_for_selector(".gloss")
        total = page.locator(".gloss").count()
        page.fill("#gloss-search", "csrf"); time.sleep(0.3)
        check(0 < page.locator(".gloss").count() < total and page.locator(".gloss mark").count() > 0, "glossary search filters and highlights")
        page.fill("#gloss-search", ""); page.click('#gloss-cats [data-cat="Networking basics"]'); time.sleep(0.3)
        shot(page, "07-learn-glossary")

        # ---- traffic + scanner
        page.click('.nav-item[data-view="traffic"]'); page.wait_for_selector("#pkt-body tr"); page.click("#pkt-body tr >> nth=0"); page.wait_for_selector("#pkt-detail:not([hidden])")
        page.fill("#pkt-filter", "port:445"); time.sleep(2.5)
        check(all("445" in r for r in page.locator("#pkt-body tr").all_inner_texts()) or page.locator("#pkt-body tr").count() == 0, "packet filter works")
        page.fill("#pkt-filter", ""); time.sleep(1.5)
        shot(page, "08-traffic")
        page.click('.nav-item[data-view="scanner"]'); page.wait_for_selector("#scan-presets label")
        check(page.locator('input[name="preset"]:checked').get_attribute("value") == "quick", "scanner defaults to the Quick preset")
        page.fill("#scan-target", "127.0.0.1"); page.check("#scan-consent"); page.click("#btn-scan")
        page.wait_for_selector(".host-card", timeout=30000)
        shot(page, "09-scanner")

        # ---- account: turn on two-factor
        page.click('.nav-item[data-view="account"]'); page.wait_for_selector("#btn-2fa-on")
        page.click("#btn-2fa-on"); page.wait_for_selector("#tfa-dialog[open]")
        check(page.evaluate("() => document.querySelector('#tfa-qr').naturalWidth > 0"), "two-factor QR code renders")
        shot(page, "10-two-factor-setup", top=False)
        page.click(".secret summary"); secret = page.inner_text("#tfa-secret").replace(" ", "")
        page.click("#tfa-next"); page.fill("#tfa-code", "000000"); page.fill("#tfa-pass", PW); page.click("#tfa-step2 button[type=submit]")
        page.wait_for_selector("#tfa-error:not([hidden])")
        check("didn't match" in page.inner_text("#tfa-error"), "wrong enrolment code is refused")
        page.fill("#tfa-code", mfa.code_at(secret, mfa.current_step())); page.click("#tfa-step2 button[type=submit]")
        page.wait_for_selector("#tfa-step3:not([hidden])")
        check(page.locator("#tfa-codes li").count() == 10, "ten recovery codes are shown once")
        codes = page.locator("#tfa-codes li").all_inner_texts()
        page.click("#tfa-done"); page.wait_for_selector(".tfa-state.on")
        check(page.locator(".session-row.current").count() == 1, "account lists this browser as the current session")
        shot(page, "11-account")

        # ---- users + audit + settings
        page.click('.nav-item[data-view="users"]'); page.wait_for_selector("#user-body tr")
        page.fill("#nu-name", "viewer1"); page.fill("#nu-pass", PW); page.select_option("#nu-role", "viewer"); page.click("#user-form button[type=submit]")
        page.locator("#user-body tr").nth(1).wait_for()
        check("must choose a new password" in page.inner_text("#user-body"), "new user must pick their own password")
        shot(page, "12-users")
        page.click('.nav-item[data-view="audit"]'); page.wait_for_selector("#audit-body tr")
        body = page.inner_text("#audit-body").lower()
        check("user created" in body and "2fa enabled" in body, "audit log records the new user and two-factor change")
        shot(page, "13-audit")
        page.click('.nav-item[data-view="settings"]'); page.wait_for_selector("#settings-form fieldset")
        check(page.locator("#set-session_idle_minutes").count() == 1, "settings include the idle sign-out time")
        shot(page, "14-settings")

        # ---- sign out, sign in with two-factor (recovery code path too)
        page.click("#btn-user"); page.click("#btn-logout"); page.wait_for_selector("#gate:not([hidden])")
        check("Welcome back" in page.inner_text("#gate-title"), "sign out returns to sign-in")
        shot(page, "15-sign-in")
        page.fill("#gate-user", "admin"); page.fill("#gate-pass", PW); page.click("#gate-submit")
        page.wait_for_selector('#gate[data-mode="2fa"]')
        check(page.locator("#gate-otp").is_visible(), "password step leads to the code step")
        page.fill("#gate-otp", "000000"); page.click("#gate-submit"); page.wait_for_selector("#gate-error:not([hidden])")
        check("didn't work" in page.inner_text("#gate-error"), "wrong sign-in code is refused")
        shot(page, "16-two-factor-sign-in")
        page.click("#gate-otp-toggle"); page.fill("#gate-otp", codes[0]); page.click("#gate-submit")
        page.wait_for_selector("#app:not([hidden])")
        check("recovery code" in page.inner_text("#toasts"), "recovery-code sign-in warns how many are left")
        page.click("#btn-user"); page.click("#btn-logout"); page.wait_for_selector("#gate:not([hidden])")

        # ---- viewer: forced password change, then read-only UI
        page.fill("#gate-user", "viewer1"); page.fill("#gate-pass", PW); page.click("#gate-submit")
        page.wait_for_selector('#gate[data-mode="newpw"]')
        check("Choose a new password" in page.inner_text("#gate-title"), "admin-issued password must be changed first")
        page.fill("#gate-pass", PW); page.fill("#gate-new", PW2); page.fill("#gate-confirm", PW2); page.click("#gate-submit")
        page.wait_for_selector("#app:not([hidden])")
        check(page.locator('.nav-item[data-view="users"]').is_hidden(), "viewer doesn't see Users")
        check(page.locator("#ro-banner").is_visible(), "viewer sees read-only banner")
        check(page.locator("#btn-demo").is_hidden(), "viewer can't start the demo")
        page.click('.nav-item[data-view="settings"]'); page.wait_for_selector("#settings-form fieldset[disabled]")
        check(page.locator("#btn-save-settings").is_hidden(), "viewer can't save settings")

        # ---- dark theme + phone width
        page.click('.nav-item[data-view="overview"]'); page.click("#btn-theme"); time.sleep(0.6)
        check(page.evaluate("() => document.documentElement.dataset.theme") == "dark", "theme toggle switches to dark")
        shot(page, "17-overview-dark")
        page.click('.nav-item[data-view="learn"]'); page.click('#learn-tabs [data-ltab="attack"]'); page.wait_for_selector(".tactic")
        shot(page, "18-learn-dark")
        page.reload(); page.wait_for_selector("#app:not([hidden])")
        check(page.evaluate("() => document.documentElement.dataset.theme") == "dark", "theme choice survives a reload")
        page.set_viewport_size({"width": 390, "height": 820}); page.click('.nav-item[data-view="overview"]'); time.sleep(1)
        check(page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth + 1"), "no horizontal scroll at phone width")
        shot(page, "19-mobile")
        b.close()
    check(not errors, f"no unexpected browser console errors {errors[:3]}")
finally:
    srv.terminate()
print("\nRESULT:", "ALL PASSED" if not problems else f"{len(problems)} problem(s)")
sys.exit(1 if problems else 0)

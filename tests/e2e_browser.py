"""Optional end-to-end check in a real browser (needs: pip install playwright && playwright install chromium).
Usage: python tests/e2e_browser.py   (starts its own server on a temp data folder)"""
import os, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "docs" / "screenshots"
PORT, PW = 8791, "correct horse battery"
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
try:
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1360, "height": 860}, color_scheme="light")
        page = ctx.new_page()
        errors = []
        seen403 = []
        def on_console(m):
            if m.type != "error": return
            if "403" in m.text and not seen403: seen403.append(1); return      # the deliberate wrong-setup-code request
            errors.append(m.text)
        page.on("console", on_console)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(base)
        page.wait_for_selector("#gate:not([hidden])")
        check("Create the administrator" in page.inner_text("#gate-title"), "first run shows setup screen")
        page.screenshot(path=SHOTS / "00-setup.png")
        page.fill("#gate-code", "WRONG"); page.fill("#gate-user", "admin"); page.fill("#gate-pass", PW); page.click("#gate-submit")
        page.wait_for_selector("#gate-error:not([hidden])")
        check("setup code is wrong" in page.inner_text("#gate-error"), "wrong setup code is refused")
        page.fill("#gate-code", "SETUP123"); page.click("#gate-submit")
        page.wait_for_selector("#app:not([hidden])")
        check(page.inner_text("#who-name") == "admin", "admin signed in after setup")
        page.wait_for_selector("#quickstart:not([hidden])")
        page.screenshot(path=SHOTS / "01-overview-empty.png")
        page.click("#btn-demo"); page.wait_for_selector("#demo-dialog[open]")
        page.screenshot(path=SHOTS / "02-demo-picker.png")
        page.click('[data-scenario="all"]')
        page.wait_for_selector("#nav-alert-count:not([hidden])", timeout=30000)
        time.sleep(14)
        page.wait_for_selector("#hero.alert, #hero.demo", timeout=20000)
        check(page.evaluate("() => [...document.querySelectorAll('.bar-row i')].some(i => i.getBoundingClientRect().width > 4)"), "overview bars have width under the strict CSP")
        page.screenshot(path=SHOTS / "03-overview-demo.png")
        page.click('[data-view="alerts"]'); page.wait_for_selector(".alert-card")
        page.click(".alert-head >> nth=0"); page.wait_for_selector(".alert-body")
        check("What it might mean" in page.inner_text(".alert-body"), "alert expands with plain-English explanation")
        page.screenshot(path=SHOTS / "04-alerts.png")
        page.click('[data-view="traffic"]'); page.wait_for_selector("#pkt-body tr"); page.click("#pkt-body tr >> nth=0"); page.wait_for_selector("#pkt-detail:not([hidden])")
        page.fill("#pkt-filter", "port:445"); time.sleep(2.5)
        check(all("445" in r for r in page.locator("#pkt-body tr").all_inner_texts()) or page.locator("#pkt-body tr").count() == 0, "packet filter works")
        page.fill("#pkt-filter", ""); time.sleep(1.5)
        page.screenshot(path=SHOTS / "05-traffic.png")
        page.click('[data-view="scanner"]'); page.wait_for_selector("#scan-presets label")
        check(page.locator('input[name="preset"]:checked').get_attribute("value") == "quick", "scanner defaults to the Quick preset")
        page.fill("#scan-target", "127.0.0.1"); page.check("#scan-consent"); page.click("#btn-scan")
        page.wait_for_selector(".host-card", timeout=30000)
        page.screenshot(path=SHOTS / "06-scanner.png")
        page.click('[data-view="users"]'); page.wait_for_selector("#user-body tr")
        page.fill("#nu-name", "viewer1"); page.fill("#nu-pass", PW); page.select_option("#nu-role", "viewer"); page.click("#user-form button[type=submit]")
        page.locator("#user-body tr").nth(1).wait_for()
        page.screenshot(path=SHOTS / "07-users.png")
        page.click('[data-view="audit"]'); page.wait_for_selector("#audit-body tr")
        check("user created" in page.inner_text("#audit-body"), "audit log records the new user")
        page.screenshot(path=SHOTS / "08-audit.png")
        page.click('[data-view="settings"]'); page.wait_for_selector("#settings-form fieldset"); page.screenshot(path=SHOTS / "09-settings.png")
        page.click("#btn-logout"); page.wait_for_selector("#gate:not([hidden])")
        check("Sign in" in page.inner_text("#gate-title"), "sign out returns to sign-in")
        # viewer: read-only UI
        page.fill("#gate-user", "viewer1"); page.fill("#gate-pass", PW); page.click("#gate-submit"); page.wait_for_selector("#app:not([hidden])")
        check(page.locator('.nav-item[data-view="users"]').is_hidden(), "viewer doesn't see Users")
        check(page.locator("#ro-banner").is_visible(), "viewer sees read-only banner")
        check(page.locator("#btn-demo").is_hidden(), "viewer can't start the demo")
        page.click('[data-view="settings"]'); page.wait_for_selector("#settings-form fieldset[disabled]")
        check(page.locator("#btn-save-settings").is_hidden(), "viewer can't save settings")
        # narrow screen + dark mode
        page.set_viewport_size({"width": 390, "height": 800}); page.click('[data-view="overview"]'); time.sleep(1)
        check(page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth + 1"), "no horizontal scroll at phone width")
        page.screenshot(path=SHOTS / "10-mobile.png")
        b.close()
    check(not errors, f"no browser console errors {errors[:3]}")
finally:
    srv.terminate()
print("\nRESULT:", "ALL PASSED" if not problems else f"{len(problems)} problem(s)")
sys.exit(1 if problems else 0)

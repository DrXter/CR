import asyncio, os, subprocess, sys, tempfile, time, pathlib, httpx
sys.path.insert(0, "tests"); import mock_env
from playwright.async_api import async_playwright
ROOT = pathlib.Path(__file__).resolve().parent.parent; OUT = pathlib.Path(sys.argv[1])
d = tempfile.mkdtemp(); mock_env.start()
e = dict(os.environ, GWR_DATA_DIR=d, GWR_ADMIN_PASSWORD="Adm1n-Passw0rd-xyz", GWR_ALLOW_HTTP="1", GWR_ALLOW_PRIVATE_TARGETS="1", GWR_PORT="9110", GWR_HOST="127.0.0.1")
p = subprocess.Popen([sys.executable, "-m", "app"], cwd=ROOT, env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(60):
    try:
        if httpx.get("http://127.0.0.1:9110/api/health").status_code == 200: break
    except Exception: time.sleep(.5)
async def main():
    async with async_playwright() as pw:
        b = await pw.chromium.launch(); pg = await b.new_page(viewport={"width": 1300, "height": 900}); errs = []
        pg.on("pageerror", lambda x: errs.append(str(x))); pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
        await pg.goto("http://127.0.0.1:9110/"); await pg.fill("input >> nth=0", "admin"); await pg.fill("input[type=password]", "Adm1n-Passw0rd-xyz"); await pg.click("text=Sign in")
        await pg.click("button:has-text('Engagement')"); await pg.wait_for_selector("text=Start a review")
        await pg.fill("input[placeholder*='guidewire.net']", "http://127.0.0.1:9101"); await pg.fill("input[placeholder*='approval reference']", "GW-REF-UI")
        await pg.check("input[type=checkbox]"); await pg.screenshot(path=str(OUT / "ui_engagement.png")); await pg.click("text=Create engagement")
        await pg.wait_for_selector("text=Sign in through your identity provider")
        await pg.click("text=Open login in a new browser session"); await pg.wait_for_selector("text=Okta detected|Mock", timeout=15000) if False else await asyncio.sleep(4)
        # drive the live view: focus canvas, keyboard through the mock IdP
        c = pg.locator("canvas.view"); await c.click(position={"x": 5, "y": 5})
        await pg.keyboard.press("Tab"); await pg.keyboard.type("tester"); await pg.keyboard.press("Tab"); await pg.keyboard.type("pw"); await pg.keyboard.press("Enter"); await asyncio.sleep(2.5)
        await pg.keyboard.press("Tab"); await pg.keyboard.type("123456"); await pg.keyboard.press("Enter")
        await pg.wait_for_selector("text=Back on the target after sign-in", timeout=20000); await pg.screenshot(path=str(OUT / "ui_auth.png"))
        await pg.click("text=Capture session"); await pg.wait_for_selector("td:has-text('underwriter'), td:has-text('user1')", timeout=10000)
        await pg.click("button:has-text('Config Review')"); await pg.wait_for_selector("text=Configuration review of the live application"); await pg.screenshot(path=str(OUT / "ui_config.png"))
        await pg.click("button:has-text('Source Review')"); await pg.wait_for_selector("text=Source code review"); await pg.click("button:has-text('Admin')"); await pg.wait_for_selector("text=Users and roles")
        print("UI errors:", errs); await b.close()
try: asyncio.run(main())
finally: p.terminate()

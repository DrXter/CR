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
        b = await pw.chromium.launch(); pg = await b.new_page(viewport={"width": 1300, "height": 1000}); errs = []
        pg.on("pageerror", lambda x: errs.append(str(x)))
        await pg.goto("http://127.0.0.1:9110/"); await pg.fill("input >> nth=0", "admin"); await pg.fill("input[type=password]", "Adm1n-Passw0rd-xyz"); await pg.click("text=Sign in")
        await pg.wait_for_selector("text=Audit an application")
        await pg.fill("input[placeholder*='guidewire.net']", "http://127.0.0.1:9101"); await pg.fill("input[placeholder*='approval reference']", "GW-REF-Q"); await pg.check("input[type=checkbox]"); await pg.click("text=Continue")
        await pg.wait_for_selector("text=Step 2 of 3")
        async with pg.expect_popup() as pop: await pg.click("text=Sign in (opens a new tab)")
        pp = await pop.value; await pp.wait_for_selector("canvas#v"); await asyncio.sleep(4)
        await pp.locator("canvas#v").click(position={"x": 5, "y": 5})
        await pp.keyboard.press("Tab"); await pp.keyboard.type("tester"); await pp.keyboard.press("Tab"); await pp.keyboard.type("pw"); await pp.keyboard.press("Enter"); await asyncio.sleep(2.5)
        await pp.keyboard.press("Tab"); await pp.keyboard.type("123456"); await pp.keyboard.press("Enter")
        # no manual capture: the popup auto-captures, the main tab then starts the audit by itself
        await pg.wait_for_selector("text=Signed in. Session captured", timeout=40000)
        await pg.wait_for_selector("text=Scan done", timeout=120000)
        print("popup closed:", pp.is_closed())
        n = await pg.locator("table tr").count(); await pg.screenshot(path=str(OUT / "ui_quick.png"), full_page=True)
        print("rows:", n, "errors:", [e for e in errs]); await b.close()
try: asyncio.run(main())
finally: p.terminate()

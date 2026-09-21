#!/usr/bin/env python3
"""Take the documentation screenshots (docs/img/*.png) of a DENIS console filled with the
built-in demo data (a fictional company), with headless Chrome. Needs Google Chrome (or set CHROME).

    denis serve --db demo.db --insecure-no-auth --listen 127.0.0.1:8099 &
    python3 tools/screenshots.py http://127.0.0.1:8099       # loads the built-in demo data first
"""
import json, os, subprocess, sys, urllib.error, urllib.request

base = sys.argv[1].rstrip("/")
chrome = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
out = os.path.join(os.path.dirname(__file__), "..", "docs", "img")
os.makedirs(out, exist_ok=True)
def call(method, path):
    r = urllib.request.Request(base + path, method=method, headers={"X-Denis": "1"}, data=b"" if method != "GET" else None)
    try:
        return json.load(urllib.request.urlopen(r))
    except urllib.error.HTTPError as e:
        if e.code == 409:   # demo data already loaded
            return None
        raise
call("POST", "/api/demo")
assets = json.load(urllib.request.urlopen(base + "/api/assets"))
alerts = json.load(urllib.request.urlopen(base + "/api/alerts"))
by = {(a.get("display_name") or ""): a["id"] for a in assets}
alert = next(e for e in alerts if e["type"] == "ot_control_command")

shots = [
    ("devices", "#assets", 1280, 860), ("review-queue", "#review", 1280, 620), ("device-detail", f"#device/{by['Finance file server']}", 1280, 1100),
    ("edit-asset", f"#edit/{by['Reception printer']}", 1280, 1000), ("alerts", "#alerts", 1280, 760), ("alert-dialog", f"#alert/{alert['id']}", 1280, 760),
    ("findings", "#findings", 1280, 900), ("rules", "#rules", 1280, 1150), ("compliance", "#compliance", 1280, 1150),
    ("topology", "#topology", 1280, 820), ("ot", "#ot", 1280, 1000), ("trends", "#trends", 1280, 520), ("sites", "#agents", 1280, 460), ("icon-picker", f"#icons/{by['Reception printer']}", 1280, 1000), ("passkeys", "#passkeys", 1280, 640),
    ("alerting", "#alerting", 1280, 1000), ("users", "#users", 1280, 1750),
]
for name, frag, w, h in shots:
    path = os.path.join(out, name + ".png")
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--window-size={w},{h}", "--virtual-time-budget=7000",
                    "--force-device-scale-factor=1", f"--screenshot={path}", base + "/" + frag], check=True, capture_output=True)
    print(name, os.path.getsize(path) // 1024, "KB")

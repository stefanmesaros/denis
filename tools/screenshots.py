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
def put(path, body):
    r = urllib.request.Request(base + path, method="PUT", headers={"X-Denis": "1", "Content-Type": "application/json"}, data=json.dumps(body).encode())
    return json.load(urllib.request.urlopen(r))
assets = json.load(urllib.request.urlopen(base + "/api/assets"))
alerts = json.load(urllib.request.urlopen(base + "/api/alerts"))
by = {(a.get("display_name") or ""): a["id"] for a in assets}
alert = next(e for e in alerts if e["type"] == "ot_control_command")
# something for the Rules page to show: two OT command watches and an exception
put("/api/rules", {"ot_watches": [
    {"id": "s7stop", "name": "S7 CPU stop on the packaging line", "enabled": True, "proto": "s7", "writes": False, "controls": False, "commands": ["PLC stop"],
     "targets": [{"kind": "device", "value": str(by["PLC Line 1"])}], "allowed_senders": [{"kind": "device", "value": str(by["Engineering workstation"])}], "score": 90, "cooldown_minutes": 10},
    {"id": "modbuswr", "name": "Any Modbus write", "enabled": True, "proto": "modbus", "writes": True, "controls": False, "commands": [],
     "targets": [], "allowed_senders": [{"kind": "type", "value": "scada server"}], "score": 70, "cooldown_minutes": 30}],
    "exceptions": {"new_destination": [{"kind": "type", "value": "smart speaker"}, {"kind": "cidr", "value": "10.20.90.0/24"}]}})

shots = [
    ("devices", "#assets", 1280, 860), ("review-queue", "#review", 1280, 620), ("device-detail", f"#device/{by['Finance file server']}", 1280, 1100),
    ("edit-asset", f"#edit/{by['Reception printer']}", 1280, 1000), ("alerts", "#alerts", 1280, 760), ("alert-dialog", f"#alert/{alert['id']}", 1280, 760),
    ("findings", "#findings", 1280, 900), ("accepted-risks", "#findings", 1280, 2300), ("rules", "#rules", 1280, 1150), ("ot-watches", "#rules", 1280, 4200), ("compliance", "#compliance", 1280, 1150),
    ("topology", "#topology", 1280, 820), ("ot", "#ot", 1280, 1250), ("trends", "#trends", 1280, 520), ("sites", "#agents", 1280, 460), ("icon-picker", f"#icons/{by['Reception printer']}", 1280, 1000), ("account", "#account", 1280, 640),
    ("alerting", "#alerting", 1280, 1000), ("users", "#users", 1280, 620), ("settings", "#settings", 1280, 1120), ("audit", "#audit", 1280, 760),
]
for name, frag, w, h in shots:
    path = os.path.join(out, name + ".png")
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--window-size={w},{h}", "--virtual-time-budget=7000",
                    "--force-device-scale-factor=1", f"--screenshot={path}", base + "/" + frag], check=True, capture_output=True)
    # some parts sit far down a page: take the whole page and keep that part (macOS `sips`: height, width, offset from the top)
    crop = {"ot-watches": (600, 2360), "accepted-risks": (420, 1610)}.get(name)
    if crop:
        subprocess.run(["sips", "-c", str(crop[0]), "1280", "--cropOffset", str(crop[1]), "0", path], check=True, capture_output=True)
    print(name, os.path.getsize(path) // 1024, "KB")

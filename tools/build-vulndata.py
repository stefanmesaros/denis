#!/usr/bin/env python3
"""Build data/vulndata.json: the data DENIS ships for "past end of life" and "known exploited vulnerability" findings.

Sources (all public):
  * endoflife.date  (https://endoflife.date/api/<product>.json): support end dates per release cycle.
  * CISA Known Exploited Vulnerabilities catalog: which CVEs are being exploited now.
  * NVD (https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...): for each such CVE, the affected version ranges
    of a product that a service banner can name.

Needs curl. A CVE goes into the file only when NVD gives clean version ranges for one product (no "and running on ..." conditions),
because a claim needs version evidence. Run it by hand, read the result, commit it; DENIS never fetches CVE data by itself.

    python3 tools/build-vulndata.py            # writes data/vulndata.json
"""
import json, subprocess, sys, time, datetime, pathlib

# banner product key -> endoflife.date product (only where the project publishes support dates)
EOL_PRODUCTS = {
    "nginx": "nginx", "apache-http-server": "apache-http-server", "php": "php", "openssl": "openssl",
    "exim": "exim", "proftpd": "proftpd",
}
# KEV (vendorProject, product) -> (banner product key, NVD cpe "vendor:product")
KEV_PRODUCTS = {
    ("Apache", "HTTP Server"): ("apache-http-server", "apache:http_server"),
    ("PHP", "PHP"): ("php", "php:php"),
    ("PHP Group", "PHP"): ("php", "php:php"),
    ("Exim", "Exim"): ("exim", "exim:exim"),
    ("Exim", "Exim Internet Mailer"): ("exim", "exim:exim"),
    ("Exim", "Mail Transfer Agent (MTA)"): ("exim", "exim:exim"),
    ("OpenSSL", "OpenSSL"): ("openssl", "openssl:openssl"),
    ("Microsoft", "Internet Information Services (IIS)"): ("iis", "microsoft:internet_information_services"),
    ("ProFTPD", "ProFTPD"): ("proftpd", "proftpd:proftpd"),
    ("OpenBSD", "OpenSSH"): ("openssh", "openbsd:openssh"),
    ("F5", "nginx"): ("nginx", "f5:nginx"),
    ("Nginx", "nginx"): ("nginx", "f5:nginx"),
}
UA = {"User-Agent": "denis-vulndata-builder"}


def get(url):
    # curl, because it uses the system's certificate store on every platform (Python's may have none)
    out = subprocess.run(["curl", "-sS", "--fail", "-m", "90", "-H", "User-Agent: " + UA["User-Agent"], url], capture_output=True, check=True)
    return json.loads(out.stdout)


def ranges_for(cve_item, cpe_product):
    """Version ranges of `cpe_product` from an NVD CVE record, or None if the record is not a clean single-product one."""
    out = []
    for cfg in cve_item.get("configurations", []):
        nodes = cfg.get("nodes", [])
        if cfg.get("operator") == "AND" and len(nodes) > 1:
            return None  # "product X running on platform Y": a banner cannot say
        for node in nodes:
            if node.get("operator") == "AND" or node.get("negate"):
                return None
            for m in node.get("cpeMatch", []):
                parts = m["criteria"].split(":")
                if len(parts) < 6 or ":".join(parts[3:5]) != cpe_product or not m.get("vulnerable"):
                    continue
                version = parts[5]
                lo, lo_i = m.get("versionStartIncluding") or m.get("versionStartExcluding"), "versionStartIncluding" in m
                hi, hi_i = m.get("versionEndIncluding") or m.get("versionEndExcluding"), "versionEndIncluding" in m
                if version not in ("*", "-"):
                    out.append({"exact": version + (":" + parts[6] if len(parts) > 6 and parts[6] not in ("*", "-") else "")})
                elif lo or hi:
                    r = {}
                    if lo: r["from"], r["from_incl"] = lo, lo_i
                    if hi: r["to"], r["to_incl"] = hi, hi_i
                    out.append(r)
                # a bare product with no version at all says nothing about any version: ignored
    return out or None


def main():
    today = datetime.date.today().isoformat()
    eol = {}
    for key, product in EOL_PRODUCTS.items():
        cycles = get(f"https://endoflife.date/api/{product}.json")
        eol[key] = [{"cycle": c["cycle"], "eol": c["eol"], **({"latest": c["latest"]} if "latest" in c else {})} for c in cycles if "cycle" in c and "eol" in c]
        print(f"eol {key}: {len(eol[key])} cycles", file=sys.stderr)
        time.sleep(0.3)
    kev = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    entries = []
    skipped = []
    for v in kev["vulnerabilities"]:
        hit = KEV_PRODUCTS.get((v["vendorProject"], v["product"]))
        if not hit:
            continue
        key, cpe_product = hit
        time.sleep(6.5)  # NVD allows 5 requests per 30 seconds without a key
        item = get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={v['cveID']}")["vulnerabilities"][0]["cve"]
        rng = ranges_for(item, cpe_product)
        if not rng:
            skipped.append(v["cveID"])
            print(f"skip {v['cveID']} ({v['product']}): no clean version ranges", file=sys.stderr)
            continue
        entries.append({"cve": v["cveID"], "name": v["vulnerabilityName"], "added": v["dateAdded"], "product": key, "ranges": rng,
                        "ransomware": v.get("knownRansomwareCampaignUse") == "Known"})
        print(f"kev {v['cveID']} {key} {rng}", file=sys.stderr)
    entries.sort(key=lambda e: e["cve"])
    out = {
        "generated": today,
        "sources": {"eol": "https://endoflife.date", "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "ranges": "https://nvd.nist.gov"},
        "kev_catalog_version": kev.get("catalogVersion"),
        "eol": eol,
        "kev": entries,
        "skipped": skipped,
    }
    path = pathlib.Path(__file__).resolve().parent.parent / "data" / "vulndata.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"wrote {path} ({len(entries)} known-exploited entries, {sum(len(c) for c in eol.values())} support cycles)", file=sys.stderr)


if __name__ == "__main__":
    main()

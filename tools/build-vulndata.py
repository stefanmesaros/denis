#!/usr/bin/env python3
"""Build data/vulndata.json: the data DENIS ships for "past end of life", "known exploited
vulnerability" and "manufacturer has an ICS-CERT advisory" findings.

Sources (all public):
  * endoflife.date  (https://endoflife.date/api/<product>.json): support end dates per release cycle.
  * CISA Known Exploited Vulnerabilities catalog: which CVEs are being exploited now.
  * NVD (https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...): for each such CVE, the affected version ranges
    of a product that a service banner can name.
  * FIRST.org EPSS (https://api.first.org/data/v1/epss): a modelled probability of exploitation
    in the next 30 days, for each CVE above. Purely informational context; never changes a match.
  * CISA's ICS Advisories feed (https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml):
    vendor + CVE ids per advisory, for the "manufacturer has an open advisory" finding. Matched
    only by vendor name, never by version (an industrial device's firmware is not read passively).

Needs curl. A CVE goes into the file only when NVD gives clean version ranges for one product (no "and running on ..." conditions),
because a claim needs version evidence. Run it by hand, read the result, commit it; DENIS never fetches CVE data by itself.

    python3 tools/build-vulndata.py            # writes data/vulndata.json
"""
import html, json, re, subprocess, sys, time, datetime, pathlib
import xml.etree.ElementTree as ET

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


def get_raw(url):
    # curl, because it uses the system's certificate store on every platform (Python's may have none)
    out = subprocess.run(["curl", "-sS", "--fail", "-m", "90", "-H", "User-Agent: " + UA["User-Agent"], url], capture_output=True, check=True)
    return out.stdout.decode("utf-8")


def get(url):
    return json.loads(get_raw(url))


def ics_advisories(rss_xml):
    """CISA's ICS Advisories RSS: each item's description embeds a "csaf-table" HTML table of
    (CVSS summary, Vendor, Equipment, Vulnerability) rows -- the same one shown on the advisory
    page -- so this is read directly, without a per-advisory follow-up fetch."""
    root = ET.fromstring(rss_xml)
    out = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        desc = html.unescape(item.findtext("description") or "")
        advisory_id = link.rstrip("/").rsplit("/", 1)[-1].upper()
        if not advisory_id.startswith("ICSA-"):
            continue
        published = datetime.date.today().isoformat()
        try:
            published = datetime.datetime.strptime(pub[:25], "%a, %d %b %y %H:%M:%S").date().isoformat()
        except ValueError:
            pass
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", desc)))
        tables = re.findall(r'<div class="csaf-table">(.*?)</div>', desc, re.S)
        vendors = set()
        if tables:
            cells = [re.sub(r"<[^>]+>", "", c).strip() for c in re.findall(r"<td[^>]*>(.*?)</td>", tables[0], re.S)]
            if len(cells) % 4 == 0:
                vendors = {cells[i + 1] for i in range(0, len(cells), 4) if cells[i + 1]}
        if not vendors:
            continue  # no vendor to match against: cannot be used for the finding
        for vendor in sorted(vendors):
            out.append({"id": advisory_id, "title": title, "vendor": vendor, "published": published, "cves": cves})
    return out


def epss_scores(cves):
    """FIRST.org EPSS score per CVE, batched (the API accepts a comma-separated list)."""
    scores = {}
    cves = sorted(set(cves))
    for i in range(0, len(cves), 40):
        chunk = cves[i:i + 40]
        data = get(f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}")
        for row in data.get("data", []):
            try:
                scores[row["cve"]] = round(float(row["epss"]), 4)
            except (KeyError, ValueError):
                pass
        time.sleep(0.5)
    return scores


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

    epss = epss_scores(e["cve"] for e in entries)
    print(f"epss: {len(epss)} of {len(entries)} known-exploited CVEs scored", file=sys.stderr)

    ics_rss = get_raw("https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml")
    ics = ics_advisories(ics_rss)
    ics.sort(key=lambda a: (a["id"], a["vendor"]))
    print(f"ics: {len(ics)} (advisory, vendor) pairs from the current feed", file=sys.stderr)

    out = {
        "generated": today,
        "sources": {
            "eol": "https://endoflife.date", "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "ranges": "https://nvd.nist.gov", "epss": "https://www.first.org/epss/", "ics": "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94",
        },
        "kev_catalog_version": kev.get("catalogVersion"),
        "eol": eol,
        "kev": entries,
        "epss": epss,
        "ics": ics,
        "skipped": skipped,
    }
    path = pathlib.Path(__file__).resolve().parent.parent / "data" / "vulndata.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"wrote {path} ({len(entries)} known-exploited entries, {sum(len(c) for c in eol.values())} support cycles, {len(ics)} ICS advisory/vendor pairs)", file=sys.stderr)


if __name__ == "__main__":
    main()

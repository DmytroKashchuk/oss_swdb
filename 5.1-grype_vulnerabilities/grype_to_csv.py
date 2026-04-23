import json, csv, os, glob, re

VULN_DIR = "vulnerabilities"
OUTPUT = "vulnerabilities.csv"

FIELDS = [
    "project", "vuln_id", "cve", "severity", "risk_score",
    "epss", "epss_percentile",
    "cwe", "cvss_score", "cvss_vector", "description",
    "fix_state", "fix_versions",
    "pkg_name", "pkg_version", "pkg_type", "pkg_language", "purl",
    "data_source",
    "is_kev", "kev_date_added", "kev_due_date",
    "kev_ransomware", "kev_vendor", "kev_product",
]


def get_from_vuln_or_related(vuln, related, key):
    """Return the first non-empty list for `key`, checking vuln first then related."""
    items = vuln.get(key) or []
    if items:
        return items
    for r in related:
        items = r.get(key) or []
        if items:
            return items
    return []


rows = []
for f in sorted(glob.glob(os.path.join(VULN_DIR, "*.json"))):
    project = re.sub(r'[._]vulns\.json$', '', os.path.basename(f))
    data = json.load(open(f))

    for m in data.get("matches", []):
        vuln = m["vulnerability"]
        art = m["artifact"]
        fix = vuln.get("fix", {})
        related = m.get("relatedVulnerabilities", [])
        cve = next((r["id"] for r in related if r["id"].startswith("CVE-")), "")

        # EPSS
        epss_list = get_from_vuln_or_related(vuln, related, "epss")
        epss_val = epss_list[0].get("epss", "") if epss_list else ""
        epss_pct = epss_list[0].get("percentile", "") if epss_list else ""

        # CWE
        cwe_list = get_from_vuln_or_related(vuln, related, "cwes")
        cwes = "; ".join(sorted(set(c.get("cwe", "") for c in cwe_list if c.get("cwe"))))

        # CVSS
        cvss_list = get_from_vuln_or_related(vuln, related, "cvss")
        if cvss_list:
            cvss_score = cvss_list[0].get("metrics", {}).get("baseScore", "")
            cvss_vector = cvss_list[0].get("vector", "")
        else:
            cvss_score = ""
            cvss_vector = ""

        # KEV (CISA Known Exploited Vulnerabilities)
        kev_list = get_from_vuln_or_related(vuln, related, "knownExploited")
        is_kev = bool(kev_list)
        if is_kev:
            kev = kev_list[0]
            kev_date_added = kev.get("dateAdded", "")
            kev_due_date = kev.get("dueDate", "")
            kev_ransomware = kev.get("knownRansomwareCampaignUse", "")
            kev_vendor = kev.get("vendorProject", "")
            kev_product = kev.get("product", "")
        else:
            kev_date_added = ""
            kev_due_date = ""
            kev_ransomware = ""
            kev_vendor = ""
            kev_product = ""

        # risk (incorporates CVSS + EPSS + KEV)
        risk = vuln.get("risk", "")

        rows.append({
            "project": project,
            "vuln_id": vuln.get("id", ""),
            "cve": cve,
            "severity": vuln.get("severity", ""),
            "risk_score": risk,
            "epss": epss_val,
            "epss_percentile": epss_pct,
            "cwe": cwes,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "description": vuln.get("description", ""),
            "fix_state": fix.get("state", ""),
            "fix_versions": "; ".join(fix.get("versions", [])),
            "pkg_name": art.get("name", ""),
            "pkg_version": art.get("version", ""),
            "pkg_type": art.get("type", ""),
            "pkg_language": art.get("language", ""),
            "purl": art.get("purl", ""),
            "data_source": vuln.get("dataSource", ""),
            "is_kev": is_kev,
            "kev_date_added": kev_date_added,
            "kev_due_date": kev_due_date,
            "kev_ransomware": kev_ransomware,
            "kev_vendor": kev_vendor,
            "kev_product": kev_product,
        })

with open(OUTPUT, "w", newline="") as out:
    w = csv.DictWriter(out, fieldnames=FIELDS)
    w.writeheader()
    w.writerows(rows)

kev_count = sum(1 for r in rows if r["is_kev"])
ransomware_kev = sum(1 for r in rows if r["kev_ransomware"] == "Known")
print(f"Done. {len(rows)} vulnerabilities -> {OUTPUT}")
print(f"  KEV entries: {kev_count}")
print(f"  KEV with known ransomware use: {ransomware_kev}")
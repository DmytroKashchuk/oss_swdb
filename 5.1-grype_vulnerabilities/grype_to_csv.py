import json, csv, os, glob, re

VULN_DIR = "vulnerabilities"
OUTPUT = "vulnerabilities.csv"

FIELDS = ["project", "vuln_id", "cve", "severity", "risk_score", "epss", "epss_percentile",
          "cwe", "cvss_score", "cvss_vector", "description", "fix_state", "fix_versions",
          "pkg_name", "pkg_version", "pkg_type", "pkg_language", "purl", "data_source"]

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
        epss_list = vuln.get("epss") or []
        if not epss_list:
            for r in related:
                epss_list = r.get("epss") or []
                if epss_list: break
        epss_val = epss_list[0].get("epss", "") if epss_list else ""
        epss_pct = epss_list[0].get("percentile", "") if epss_list else ""

        # CWE
        cwe_list = vuln.get("cwes") or []
        if not cwe_list:
            for r in related:
                cwe_list = r.get("cwes") or []
                if cwe_list: break
        cwes = "; ".join(sorted(set(c.get("cwe", "") for c in cwe_list if c.get("cwe"))))

        # CVSS
        cvss_list = vuln.get("cvss") or []
        if not cvss_list:
            for r in related:
                cvss_list = r.get("cvss") or []
                if cvss_list: break
        cvss_score = cvss_list[0].get("metrics", {}).get("baseScore", "") if cvss_list else ""
        cvss_vector = cvss_list[0].get("vector", "") if cvss_list else ""

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
        })

with open(OUTPUT, "w", newline="") as out:
    w = csv.DictWriter(out, fieldnames=FIELDS)
    w.writeheader()
    w.writerows(rows)

print(f"Done. {len(rows)} vulnerabilities -> {OUTPUT}")
import pandas as pd
import subprocess, os, re

df = pd.read_csv("/Users/dmk6603/Documents/swdb_opensource/1-indentify_open_source/MAIN.csv")
SBOM_DIR = "/Users/dmk6603/Documents/swdb_opensource/5-generate_sbom/sboms"
VULN_DIR = "vulnerabilities"
os.makedirs(VULN_DIR, exist_ok=True)

def sanitize(s):
    return re.sub(r'[^\w\-]', '_', str(s).strip())

for i, row in df.iterrows():
    url = row.get("repo_url")
    if pd.isna(url) or str(url).strip() == "":
        continue

    name = f"{sanitize(row['VendorName'])}-{sanitize(row['Product'])}"
    sbom_file = os.path.join(SBOM_DIR, f"{name}.cdx.json")
    vuln_file = os.path.join(VULN_DIR, f"{name}.vulns.json")

    if not os.path.exists(sbom_file):
        print(f"[skip] {name} — SBOM not found")
        continue

    if os.path.exists(vuln_file):
        print(f"[skip] {name} — vulns already scanned")
        continue

    print(f"[grype] {name} -> {vuln_file}")
    subprocess.run(["grype", f"sbom:{sbom_file}", "-o", f"json={vuln_file}"])

print("Done.")
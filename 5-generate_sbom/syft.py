import pandas as pd
import subprocess, os, re

df = pd.read_csv("/Users/dmk6603/Documents/swdb_opensource/1-indentify_open_source/MAIN.csv")
CLONE_DIR = "/Users/dmk6603/Documents/cloned_repos_oss_swdb"
SBOM_DIR = "sboms"
os.makedirs(SBOM_DIR, exist_ok=True)

def sanitize(s):
    return re.sub(r'[^\w\-]', '_', str(s).strip())

for i, row in df.iterrows():
    url = row.get("repo_url")
    if pd.isna(url) or str(url).strip() == "":
        continue

    name = f"{sanitize(row['VendorName'])}-{sanitize(row['Product'])}"
    repo_path = os.path.join(CLONE_DIR, name)
    sbom_file = os.path.join(SBOM_DIR, f"{name}.cdx.json")

    if not os.path.exists(repo_path):
        print(f"[skip] {name} — repo not cloned")
        continue

    if os.path.exists(sbom_file):
        print(f"[skip] {name} — SBOM already exists")
        continue

    print(f"[sbom] {name} -> {sbom_file}")
    subprocess.run(["syft", repo_path, "-o", f"cyclonedx-json={sbom_file}"])

print("Done.")
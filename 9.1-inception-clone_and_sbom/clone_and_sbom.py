import pandas as pd
import subprocess
import os
import re
import shutil

CSV_PATH = "../9-inception/libraries_with_links.csv"
CLONE_DIR = "../../cloned_repos_oss_swdb_libs_of_libs"
SBOM_DIR = "sboms"

os.makedirs(CLONE_DIR, exist_ok=True)
os.makedirs(SBOM_DIR, exist_ok=True)

df = pd.read_csv(CSV_PATH)

def sanitize(s):
    return re.sub(r'[^\w\-]', '_', str(s).strip())

for i, row in df.iterrows():
    url = row.get("lib_github_url")
    if pd.isna(url) or str(url).strip() == "":
        continue

    name = f"{sanitize(row['project'])}--{sanitize(row['name'])}"
    repo_path = os.path.join(CLONE_DIR, name)
    sbom_file = os.path.join(SBOM_DIR, f"{name}.cdx.json")

    if os.path.exists(sbom_file):
        print(f"[skip] {name} — SBOM already exists")
        continue

    clone_url = str(url).strip().rstrip("/") + ".git"
    print(f"[clone] {clone_url} -> {repo_path}")

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, repo_path],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"[fail-clone] {name}: {e}")
        # Clean up partial clone if any
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path, ignore_errors=True)
        continue

    print(f"[sbom] {name} -> {sbom_file}")
    try:
        subprocess.run(
            ["syft", repo_path, "-o", f"cyclonedx-json={sbom_file}"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"[fail-sbom] {name}: {e}")
        # Keep the repo so you can investigate; skip delete
        continue

    # SBOM succeeded -> safe to delete the repo
    print(f"[clean] removing {repo_path}")
    shutil.rmtree(repo_path, ignore_errors=True)

print("Done.")
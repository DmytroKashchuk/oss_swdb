import pandas as pd
import subprocess, os, re

df = pd.read_csv("/Users/dmk6603/Documents/swdb_opensource/1-indentify_open_source/MAIN.csv")
CLONE_DIR = "/Users/dmk6603/Documents/cloned_repos_oss_swdb"
os.makedirs(CLONE_DIR, exist_ok=True)

def sanitize(s):
    return re.sub(r'[^\w\-]', '_', str(s).strip())

for i, row in df.iterrows():
    url = row.get("repo_url")
    if pd.isna(url) or str(url).strip() == "":
        continue

    name = f"{sanitize(row['VendorName'])}-{sanitize(row['Product'])}"
    dest = os.path.join(CLONE_DIR, name)

    if os.path.exists(dest):
        print(f"[skip] {name} already exists")
        continue

    print(f"[clone] {url} -> {dest}")
    subprocess.run(["git", "clone", "--depth", "1", str(url).rstrip("/") + ".git", dest])

print("Done.")
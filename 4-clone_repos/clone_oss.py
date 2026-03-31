import pandas as pd
import subprocess, os, re

df = pd.read_csv("/Users/dmk6603/Documents/swdb_opensource/1-indentify_open_source/MAIN.csv")
CLONE_DIR = "/Users/dmk6603/Documents/cloned_repos_oss_swdb"
os.makedirs(CLONE_DIR, exist_ok=True)

CUTOFF = "2023-01-01"  # ultimo commit PRIMA di questa data

def sanitize(s):
    return re.sub(r'[^\w\-]', '_', str(s).strip())

for i, row in df.iterrows():
    url = row.get("repo_url")
    if pd.isna(url) or str(url).strip() == "":
        continue

    name = f"{sanitize(row['VendorName'])}-{sanitize(row['Product'])}"
    dest = os.path.join(CLONE_DIR, name)

    if os.path.exists(dest):
        print(f"[skip] {name} già esistente")
        continue

    repo_url = str(url).rstrip("/") + ".git"
    print(f"[clone] {repo_url} -> {dest}")

    # Clone completo (serve la history per trovare il commit giusto)
    result = subprocess.run(["git", "clone", repo_url, dest], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [ERRORE clone] {result.stderr.strip()}")
        continue

    # Trova l'ultimo commit prima del 2023
    commit = subprocess.run(
        ["git", "log", "--before", CUTOFF, "--format=%H", "-1"],
        capture_output=True, text=True, cwd=dest
    )
    sha = commit.stdout.strip()

    if sha:
        subprocess.run(["git", "checkout", sha], cwd=dest, capture_output=True)
        print(f"  [ok] checkout a {sha[:12]} (ultimo commit prima del {CUTOFF})")
    else:
        print(f"  [warn] nessun commit trovato prima del {CUTOFF}")

print("Done.")
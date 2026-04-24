import json
import csv
import os
import glob

SBOM_DIR = "sboms"
OUTPUT = "dependencies.csv"


def get_prop(props, key):
    if not props:
        return ""
    for p in props:
        if p["name"] == key:
            return p["value"]
    return ""


def collect_dependency_refs(sbom):
    # Ritorna il set dei bom-ref che compaiono in qualche dependsOn.
    # Sono i nodi che qualcuno dichiara come propria dipendenza.
    dep_refs = set()
    
    for entry in sbom.get("dependencies", []):
        for dst in entry.get("dependsOn", []):
            dep_refs.add(dst)
    
    return dep_refs


rows = []

for f in sorted(glob.glob(os.path.join(SBOM_DIR, "*.cdx.json"))):
    project = os.path.basename(f).replace(".cdx.json", "")
    
    with open(f) as fp:
        data = json.load(fp)
    
    dep_refs = collect_dependency_refs(data)
    
    for c in data.get("components", []):
        bom_ref = c.get("bom-ref", "")
        
        # Salta i components che non sono dipendenze di nessuno
        # (root progetto + GitHub Actions e altri artefatti orfani)
        if bom_ref not in dep_refs:
            continue
        
        rows.append({
            "project": project,
            "name": c.get("name", ""),
            "group": c.get("group", ""),
            "version": c.get("version", ""),
            "type": c.get("type", ""),
            "purl": c.get("purl", ""),
            "cpe": c.get("cpe", ""),
            "language": get_prop(c.get("properties"), "syft:package:language"),
            "pkg_type": get_prop(c.get("properties"), "syft:package:type"),
            "path": get_prop(c.get("properties"), "syft:location:0:path"),
        })

# remove duplicated rows
rows = list({(r["project"], r["name"], r["version"]): r for r in rows}.values())


with open(OUTPUT, "w", newline="") as out:
    w = csv.DictWriter(out, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

print(f"Done. {len(rows)} dependencies -> {OUTPUT}")
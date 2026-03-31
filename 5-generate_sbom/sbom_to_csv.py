import json, csv, os, glob, re

SBOM_DIR = "sboms"
OUTPUT = "libraries.csv"

def get_prop(props, key):
    if not props:
        return ""
    for p in props:
        if p["name"] == key:
            return p["value"]
    return ""

rows = []
for f in sorted(glob.glob(os.path.join(SBOM_DIR, "*.cdx.json"))):
    project = os.path.basename(f).replace(".cdx.json", "")
    data = json.load(open(f))

    for c in data.get("components", []):
        rows.append({
            "project": project,
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "type": c.get("type", ""),
            "purl": c.get("purl", ""),
            "cpe": c.get("cpe", ""),
            "language": get_prop(c.get("properties"), "syft:package:language"),
            "pkg_type": get_prop(c.get("properties"), "syft:package:type"),
            "path": get_prop(c.get("properties"), "syft:location:0:path"),
        })

with open(OUTPUT, "w", newline="") as out:
    w = csv.DictWriter(out, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

print(f"Done. {len(rows)} components -> {OUTPUT}")
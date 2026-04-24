import csv
import os
import threading

import markdown
from flask import Flask, jsonify, render_template, request, send_file, abort
from markupsafe import Markup

app = Flask(__name__)

README_PATH = os.path.join(os.path.dirname(__file__), "README.md")

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "open_source_classification.csv")
MAIN_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "MAIN.csv")
UNIVERSE_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "swdb_universe_installs.csv")
GRYPE_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "MAIN_w_grype.csv")
LIBRARIES_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "libraries.csv")
LIBRARIES_VULNS_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "libraries_with_vulns.csv")
VULNS_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "vulnerabilities.csv")
LIBRARIES_LINKS_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "libraries_with_links.csv")
INCEPTION_LIBRARIES_PATH = os.path.join(os.path.dirname(__file__), "data", "inception_data", "libraries.csv")

DOWNLOAD_MAP = {
    "open_source": DATA_PATH,
    "main": MAIN_DATA_PATH,
    "universe": UNIVERSE_DATA_PATH,
    "grype": GRYPE_DATA_PATH,
    "libraries": LIBRARIES_DATA_PATH,
    "libraries_vulns": LIBRARIES_VULNS_DATA_PATH,
    "vulnerabilities": VULNS_DATA_PATH,
    "libraries_links": LIBRARIES_LINKS_DATA_PATH,
    "inception_libraries": INCEPTION_LIBRARIES_PATH,
}


@app.route("/download/<dataset>")
def download(dataset):
    path = DOWNLOAD_MAP.get(dataset)
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True)


def load_csv(path=None):
    with open(path or DATA_PATH, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@app.route("/")
def index():
    return render_template("open_source.html")


@app.route("/api/data")
def api_data():
    return jsonify(load_csv())


@app.route("/main")
def main_data():
    return render_template("main.html")


@app.route("/api/main")
def api_main():
    return jsonify(load_csv(MAIN_DATA_PATH))


@app.route("/universe")
def universe():
    return render_template("universe.html")


@app.route("/api/universe")
def api_universe():
    return jsonify(load_csv(UNIVERSE_DATA_PATH))


@app.route("/grype")
def grype():
    return render_template("grype.html")


@app.route("/api/grype")
def api_grype():
    return jsonify(load_csv(GRYPE_DATA_PATH))


@app.route("/libraries")
def libraries():
    return render_template("libraries.html")


@app.route("/api/libraries")
def api_libraries():
    return jsonify(load_csv(LIBRARIES_DATA_PATH))


@app.route("/libraries-vulns")
def libraries_vulns():
    return render_template("libraries_vulns.html")


@app.route("/api/libraries-vulns")
def api_libraries_vulns():
    rows = load_csv(LIBRARIES_VULNS_DATA_PATH)
    for r in rows:
        vendor, product, _lib = _split_project(r.get("project", ""))
        r["vendor"] = vendor
        r["product"] = product
    return jsonify(rows)


@app.route("/vulnerabilities")
def vulnerabilities():
    return render_template("vulnerabilities.html")


@app.route("/api/vulnerabilities")
def api_vulnerabilities():
    return jsonify(load_csv(VULNS_DATA_PATH))


@app.route("/libraries-links")
def libraries_links():
    return render_template("libraries_links.html")

@app.route("/edr")
def edr():
    return render_template("edr.html")


@app.route("/api/libraries-links")
def api_libraries_links():
    return jsonify(load_csv(LIBRARIES_LINKS_DATA_PATH))


@app.route("/readme")
def readme():
    with open(README_PATH, encoding="utf-8") as f:
        content = f.read()
    html = markdown.markdown(content, extensions=["tables", "fenced_code", "toc"])
    return render_template("readme.html", readme_html=Markup(html))


# ---------------------------------------------------------------------------
# Inception > Libraries (large CSV: ~1GB / ~4.5M rows)
# Strategy: build a one-time line-offset index for fast page seeks. For
# filtered queries, scan once and cache the matching offsets keyed by the
# filter signature. Tabulator drives this via remote pagination.
# ---------------------------------------------------------------------------

_INCEPTION_LOCK = threading.Lock()
_INCEPTION_STATE = {
    "ready": False,
    "building": False,
    "header": [],
    "offsets": [],          # byte offsets, one per data row
    "total": 0,
    "filter_cache": {},     # signature -> list of offsets (capped)
    "stats": {},            # unique counts (projects/vendors/products/libraries)
}
_INCEPTION_FILTER_CAP = 200_000  # cap matches per filter to keep memory bounded
_DERIVED_FIELDS = ("vendor", "product", "library")


def _split_project(project):
    """Split a project string of the form `VENDOR-Product--Library` into parts.

    Returns (vendor, product, library). Missing parts come back as empty strings.
    """
    if not project:
        return "", "", ""
    head, sep, library = project.partition("--")
    if not sep:
        # no '--' present: treat the whole thing as the head, no library
        head, library = project, ""
    vendor, dash, product = head.partition("-")
    if not dash:
        vendor, product = head, ""
    return vendor, product, library


def _build_inception_index():
    """Scan the file once to capture header, per-row offsets, and unique counts."""
    state = _INCEPTION_STATE
    with _INCEPTION_LOCK:
        if state["ready"] or state["building"]:
            return
        state["building"] = True
    try:
        offsets = []
        unique_projects = set()
        unique_vendors = set()
        unique_products = set()   # keyed as "vendor\x00product" to avoid collisions
        unique_libraries = set()  # by `name` column
        with open(INCEPTION_LIBRARIES_PATH, "rb") as f:
            header_line = f.readline()
            if not header_line:
                raise RuntimeError("inception libraries.csv is empty")
            header = next(csv.reader([header_line.decode("utf-8", "replace")]))
            proj_idx = header.index("project") if "project" in header else 0
            name_idx = header.index("name") if "name" in header else 1
            while True:
                pos = f.tell()
                line = f.readline()
                if not line:
                    break
                if not line.strip():
                    continue
                offsets.append(pos)
                try:
                    values = next(csv.reader([line.decode("utf-8", "replace")]))
                except StopIteration:
                    continue
                project = values[proj_idx] if proj_idx < len(values) else ""
                name = values[name_idx] if name_idx < len(values) else ""
                if project:
                    unique_projects.add(project)
                    vendor, product, _lib = _split_project(project)
                    if vendor:
                        unique_vendors.add(vendor)
                        unique_products.add(vendor + "\x00" + product)
                if name:
                    unique_libraries.add(name)
        with _INCEPTION_LOCK:
            state["header"] = header
            state["offsets"] = offsets
            state["total"] = len(offsets)
            state["stats"] = {
                "projects": len(unique_projects),
                "vendors": len(unique_vendors),
                "products": len(unique_products),
                "libraries": len(unique_libraries),
            }
            state["ready"] = True
    finally:
        with _INCEPTION_LOCK:
            state["building"] = False


def _ensure_inception_ready():
    if not _INCEPTION_STATE["ready"]:
        _build_inception_index()


def _read_rows_at_offsets(offsets):
    """Read parsed dict rows at the given byte offsets (in order)."""
    header = _INCEPTION_STATE["header"]
    proj_idx = header.index("project") if "project" in header else -1
    rows = []
    if not offsets:
        return rows
    with open(INCEPTION_LIBRARIES_PATH, "r", encoding="utf-8", newline="") as f:
        for off in offsets:
            f.seek(off)
            line = f.readline()
            if not line:
                continue
            try:
                values = next(csv.reader([line]))
            except StopIteration:
                continue
            row = {h: (values[i] if i < len(values) else "") for i, h in enumerate(header)}
            project = values[proj_idx] if 0 <= proj_idx < len(values) else ""
            vendor, product, library = _split_project(project)
            row["vendor"] = vendor
            row["product"] = product
            row["library"] = library
            rows.append(row)
    return rows


def _matches(values_lower, derived_lower, filters):
    """All-AND substring match.

    `filters` is a list of (kind, key, needle_lower) where kind is:
      - 'global': search across all real columns
      - 'col':    key is column index into `values_lower`
      - 'derived':key is one of 'vendor'/'product'/'library' (lookup in derived_lower)
    """
    for kind, key, needle in filters:
        if kind == "global":
            if not (any(needle in v for v in values_lower) or any(needle in v for v in derived_lower.values())):
                return False
        elif kind == "col":
            if key >= len(values_lower) or needle not in values_lower[key]:
                return False
        else:  # derived
            if needle not in derived_lower.get(key, ""):
                return False
    return True


def _filter_offsets(filters):
    """Scan the file applying filters; return (offsets, stats).

    `stats` is a dict of unique counts (projects/vendors/products/libraries)
    over the matched rows so the UI cards can reflect the current filter.
    """
    header = _INCEPTION_STATE["header"]
    field_index = {h.lower(): i for i, h in enumerate(header)}
    proj_idx = field_index.get("project", -1)
    name_idx = field_index.get("name", -1)
    parsed = []
    needs_derived = False
    for field, value in filters:
        needle = value.lower()
        if field in (None, "", "*"):
            parsed.append(("global", None, needle))
            needs_derived = True
            continue
        f_lower = field.lower()
        if f_lower in _DERIVED_FIELDS:
            parsed.append(("derived", f_lower, needle))
            needs_derived = True
            continue
        idx = field_index.get(f_lower)
        if idx is None:
            return [], {"projects": 0, "vendors": 0, "products": 0, "libraries": 0}
        parsed.append(("col", idx, needle))

    matches = []
    uniq_projects = set()
    uniq_vendors = set()
    uniq_products = set()
    uniq_libraries = set()
    cap = _INCEPTION_FILTER_CAP
    with open(INCEPTION_LIBRARIES_PATH, "r", encoding="utf-8", newline="") as f:
        f.readline()  # skip header
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            if not line.strip():
                continue
            try:
                values = next(csv.reader([line]))
            except StopIteration:
                continue
            values_lower = [v.lower() for v in values]
            project = values[proj_idx] if 0 <= proj_idx < len(values) else ""
            v, p, lib = _split_project(project)
            if needs_derived:
                derived_lower = {"vendor": v.lower(), "product": p.lower(), "library": lib.lower()}
            else:
                derived_lower = {}
            if _matches(values_lower, derived_lower, parsed):
                matches.append(pos)
                if project:
                    uniq_projects.add(project)
                    if v:
                        uniq_vendors.add(v)
                        uniq_products.add(v + "\x00" + p)
                if name_idx >= 0 and name_idx < len(values) and values[name_idx]:
                    uniq_libraries.add(values[name_idx])
                if len(matches) >= cap:
                    break
    stats = {
        "projects": len(uniq_projects),
        "vendors": len(uniq_vendors),
        "products": len(uniq_products),
        "libraries": len(uniq_libraries),
    }
    return matches, stats


def _parse_request_filters():
    """Read Tabulator-style ?filter[i][field]=&filter[i][value]= and ?q= globals."""
    filters = []
    q = (request.args.get("q") or "").strip()
    if q:
        filters.append((None, q))
    # Tabulator sends filter as form-encoded items
    for key, value in request.args.items():
        if not key.startswith("filter[") or not key.endswith("][value]"):
            continue
        if not value:
            continue
        # extract index
        try:
            idx = key[len("filter["):key.index("]")]
        except ValueError:
            continue
        field = request.args.get("filter[%s][field]" % idx, "")
        if field:
            filters.append((field, value.strip()))
    return filters


@app.route("/inception/libraries")
def inception_libraries():
    return render_template("inception_libraries.html")


@app.route("/api/inception/libraries/meta")
def api_inception_libraries_meta():
    _ensure_inception_ready()
    return jsonify({
        "header": _INCEPTION_STATE["header"],
        "total": _INCEPTION_STATE["total"],
        "stats": _INCEPTION_STATE["stats"],
        "filter_cap": _INCEPTION_FILTER_CAP,
    })


@app.route("/api/inception/libraries")
def api_inception_libraries():
    _ensure_inception_ready()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    try:
        size = int(request.args.get("size", 50))
    except ValueError:
        size = 50
    size = max(1, min(size, 500))

    filters = _parse_request_filters()
    state = _INCEPTION_STATE

    if not filters:
        offsets = state["offsets"]
        total = state["total"]
        truncated = False
        stats = state["stats"]
    else:
        sig = tuple(sorted((f or "", v) for f, v in filters))
        cache = state["filter_cache"]
        if sig in cache:
            offsets, stats = cache[sig]
        else:
            offsets, stats = _filter_offsets(filters)
            # Bound cache size to avoid leaks
            if len(cache) > 16:
                cache.pop(next(iter(cache)))
            cache[sig] = (offsets, stats)
        total = len(offsets)
        truncated = total >= _INCEPTION_FILTER_CAP

    last_page = max(1, (total + size - 1) // size)
    start = (page - 1) * size
    end = start + size
    rows = _read_rows_at_offsets(offsets[start:end])

    return jsonify({
        "data": rows,
        "last_page": last_page,
        "total": total,
        "truncated": truncated,
        "filter_cap": _INCEPTION_FILTER_CAP,
        "stats": stats,
        "filtered": bool(filters),
    })


# ---------------------------------------------------------------------------
# Inception > Graph (transitive dependency graph for libraries)
# Builds, on first request, an in-memory adjacency index from the same CSV:
#   - product_to_projs : (vendor_lc, product_lc) -> set(library_proj_lc)
#   - proj_to_deps     : library_proj_lc        -> set(name_lc)
#   - proj_set         : set of all library_proj_lc (used to know if a `name`
#                        is also itself a project that has its own deps)
#   - label            : id_lc -> display label (preserve original casing)
# Then a BFS expands a chosen root up to a depth + node cap.
# ---------------------------------------------------------------------------

_GRAPH_LOCK = threading.Lock()
_GRAPH_STATE = {
    "ready": False,
    "building": False,
    "product_to_projs": {},
    "proj_to_deps": {},
    "proj_set": set(),
    "label": {},
    "products": [],   # sorted list of "vendor / product" strings for autocomplete
    "projects": [],   # sorted list of library(proj) names for autocomplete
}


def _build_graph_index():
    state = _GRAPH_STATE
    with _GRAPH_LOCK:
        if state["ready"] or state["building"]:
            return
        state["building"] = True
    try:
        product_to_projs = {}
        proj_to_deps = {}
        label = {}
        with open(INCEPTION_LIBRARIES_PATH, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            header = next(reader)
            try:
                pi = header.index("project")
                ni = header.index("name")
            except ValueError:
                raise RuntimeError("inception libraries.csv missing project/name columns")
            for values in reader:
                if not values:
                    continue
                project = values[pi] if pi < len(values) else ""
                name = values[ni] if ni < len(values) else ""
                if not project:
                    continue
                vendor, product, library = _split_project(project)
                v_lc, p_lc, lib_lc = vendor.lower(), product.lower(), library.lower()
                name_lc = name.lower()
                if vendor and product:
                    label.setdefault("product:" + v_lc + "/" + p_lc, vendor + " / " + product)
                if library:
                    label.setdefault(lib_lc, library)
                    if vendor and product:
                        product_to_projs.setdefault((v_lc, p_lc), set()).add(lib_lc)
                if name:
                    label.setdefault(name_lc, name)
                    if library:
                        proj_to_deps.setdefault(lib_lc, set()).add(name_lc)
        proj_set = set(proj_to_deps.keys())
        products_sorted = sorted({label["product:" + k[0] + "/" + k[1]]
                                   for k in product_to_projs.keys()})
        projects_sorted = sorted({label[k] for k in proj_set})
        with _GRAPH_LOCK:
            state["product_to_projs"] = product_to_projs
            state["proj_to_deps"] = proj_to_deps
            state["proj_set"] = proj_set
            state["label"] = label
            state["products"] = products_sorted
            state["projects"] = projects_sorted
            state["ready"] = True
    finally:
        with _GRAPH_LOCK:
            state["building"] = False


def _ensure_graph_ready():
    if not _GRAPH_STATE["ready"]:
        _build_graph_index()


def _resolve_root(query, kind):
    """Pick starting node id(s) for the BFS.

    Returns list of (node_id, node_label, node_kind).
    `kind` is 'auto' | 'product' | 'library'.
    """
    state = _GRAPH_STATE
    q = (query or "").strip()
    if not q:
        return []
    q_lc = q.lower()
    roots = []
    if kind in ("auto", "product"):
        # exact "vendor / product"
        if "/" in q:
            v, _, p = q.partition("/")
            key = (v.strip().lower(), p.strip().lower())
            if key in state["product_to_projs"]:
                lab = state["label"].get("product:" + key[0] + "/" + key[1], q)
                roots.append(("product:" + key[0] + "/" + key[1], lab, "product"))
        # any product whose name == q (any vendor)
        for (v_lc, p_lc) in state["product_to_projs"].keys():
            if p_lc == q_lc:
                key = "product:" + v_lc + "/" + p_lc
                if not any(r[0] == key for r in roots):
                    roots.append((key, state["label"].get(key, q), "product"))
        if roots and kind == "product":
            return roots
    if kind in ("auto", "library"):
        if q_lc in state["proj_set"]:
            roots.append((q_lc, state["label"].get(q_lc, q), "library"))
        elif q_lc in state["label"]:
            # a known leaf name (not a project itself) - still a valid root
            roots.append((q_lc, state["label"].get(q_lc, q), "name"))
    return roots


def _expand_graph(roots, max_depth, max_nodes):
    state = _GRAPH_STATE
    nodes = {}    # id -> {id, label, kind, depth}
    edges = []
    truncated = False

    def add_node(nid, lab, kind, depth):
        if nid in nodes:
            return False
        nodes[nid] = {"id": nid, "label": lab, "kind": kind, "depth": depth}
        return True

    frontier = []
    for nid, lab, kind in roots:
        add_node(nid, lab, kind, 0)
        frontier.append((nid, kind, 0))

    while frontier:
        if len(nodes) >= max_nodes:
            truncated = True
            break
        nid, kind, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        # Determine outgoing children for this node
        children = []  # list of (child_id, child_label, child_kind)
        if kind == "product":
            _, _, key = nid.partition(":")
            v_lc, _, p_lc = key.partition("/")
            for lib_lc in state["product_to_projs"].get((v_lc, p_lc), ()):
                children.append((lib_lc, state["label"].get(lib_lc, lib_lc), "library"))
        elif kind in ("library", "name"):
            for dep_lc in state["proj_to_deps"].get(nid, ()):
                child_kind = "library" if dep_lc in state["proj_set"] else "name"
                children.append((dep_lc, state["label"].get(dep_lc, dep_lc), child_kind))

        for cid, clab, ckind in children:
            if len(nodes) >= max_nodes:
                truncated = True
                break
            is_new = add_node(cid, clab, ckind, depth + 1)
            edges.append({"source": nid, "target": cid})
            if is_new:
                frontier.append((cid, ckind, depth + 1))

    return list(nodes.values()), edges, truncated


@app.route("/inception/graph")
def inception_graph():
    return render_template("inception_graph.html")


@app.route("/api/inception/graph/meta")
def api_inception_graph_meta():
    _ensure_graph_ready()
    s = _GRAPH_STATE
    return jsonify({
        "products_sample": s["products"][:5000],
        "projects_sample": s["projects"][:5000],
        "products_total": len(s["products"]),
        "projects_total": len(s["projects"]),
    })


@app.route("/api/inception/graph")
def api_inception_graph():
    _ensure_graph_ready()
    query = request.args.get("q", "")
    kind = request.args.get("kind", "auto")
    # depth: 1..20 ; "0" or "max" means unlimited (we cap internally at 50)
    depth_raw = (request.args.get("depth") or "2").strip().lower()
    if depth_raw in ("0", "max", "unlimited", "all"):
        depth = 50
    else:
        try:
            depth = max(1, min(int(depth_raw), 20))
        except ValueError:
            depth = 2
    # max_nodes: 10..20000 ; "0" or "max" means unlimited (cap at 20000)
    cap_raw = (request.args.get("max_nodes") or "200").strip().lower()
    if cap_raw in ("0", "max", "unlimited", "all"):
        max_nodes = 20000
    else:
        try:
            max_nodes = max(10, min(int(cap_raw), 20000))
        except ValueError:
            max_nodes = 200

    roots = _resolve_root(query, kind)
    if not roots:
        return jsonify({"nodes": [], "edges": [], "truncated": False, "roots": [], "error": "No matching product or library found."})

    nodes, edges, truncated = _expand_graph(roots, depth, max_nodes)
    return jsonify({
        "nodes": nodes,
        "edges": edges,
        "truncated": truncated,
        "roots": [{"id": r[0], "label": r[1], "kind": r[2]} for r in roots],
        "depth": depth,
        "max_nodes": max_nodes,
    })


# run on port 8899 to avoid conflicts with other services
if __name__ == "__main__":
    app.run(debug=True, port=8899)
import csv
import os

import markdown
from flask import Flask, jsonify, render_template, send_file, abort
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

DOWNLOAD_MAP = {
    "open_source": DATA_PATH,
    "main": MAIN_DATA_PATH,
    "universe": UNIVERSE_DATA_PATH,
    "grype": GRYPE_DATA_PATH,
    "libraries": LIBRARIES_DATA_PATH,
    "libraries_vulns": LIBRARIES_VULNS_DATA_PATH,
    "vulnerabilities": VULNS_DATA_PATH,
    "libraries_links": LIBRARIES_LINKS_DATA_PATH,
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
    return jsonify(load_csv(LIBRARIES_VULNS_DATA_PATH))


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

# run on port 8899 to avoid conflicts with other services
if __name__ == "__main__":
    app.run(debug=True, port=8899)
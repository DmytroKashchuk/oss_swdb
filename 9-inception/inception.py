import pandas as pd
import requests, time, re, json, os

TOKEN = "ghp_YOUR_TOKEN_HERE"
HEADERS_GH = {"Authorization": f"token {TOKEN}"} if not TOKEN.startswith("ghp_YOUR") else {}

CACHE_FILE = "lib_url_cache.json"

libs = pd.read_csv("libraries.csv")
unique = libs[["name", "pkg_type", "purl"]].drop_duplicates(subset=["name", "pkg_type"])
print(f"Unique libraries to look up: {len(unique)}")

# load progress from previous run
cache = {}
if os.path.exists(CACHE_FILE):
    cache = {tuple(k): v for k, v in json.load(open(CACHE_FILE))}
    print(f"Loaded {len(cache)} cached results from {CACHE_FILE}")

def extract_gh(urls):
    if isinstance(urls, str): urls = [urls]
    for u in urls:
        m = re.search(r'https?://github\.com/([^/]+/[^/\s#?]+)', str(u))
        if m: return f"https://github.com/{m.group(1).rstrip('.git')}"
    return ""

def get_json(url, headers=None, timeout=30, retries=3):
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers or {}, timeout=timeout)
            return r.json() if r.status_code == 200 else None
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                return None

# --- npm ---
def lookup_npm(name, purl):
    d = get_json(f"https://registry.npmjs.org/{name}")
    if not d: return ""
    repo = d.get("repository", {})
    if isinstance(repo, dict):
        gh = extract_gh(repo.get("url", ""))
        if gh: return gh
    # fallback: homepage
    gh = extract_gh(d.get("homepage", ""))
    if gh: return gh
    # fallback: bugs URL
    bugs = d.get("bugs", {})
    if isinstance(bugs, dict):
        return extract_gh(bugs.get("url", ""))
    return ""

# --- pypi ---
def lookup_pypi(name, purl):
    d = get_json(f"https://pypi.org/pypi/{name}/json")
    if not d: return ""
    info = d.get("info", {})
    for key in ["Source", "Repository", "Source Code", "Homepage", "Code"]:
        gh = extract_gh((info.get("project_urls") or {}).get(key, ""))
        if gh: return gh
    return extract_gh(info.get("home_page", ""))

# --- rubygems ---
def lookup_gem(name, purl):
    d = get_json(f"https://rubygems.org/api/v1/gems/{name}.json")
    if not d: return ""
    for key in ["source_code_uri", "homepage_uri"]:
        gh = extract_gh(d.get(key, ""))
        if gh: return gh
    return ""

# --- composer/packagist ---
def lookup_composer(name, purl):
    m = re.match(r'pkg:composer/([^@]+)', str(purl))
    if not m: return ""
    d = get_json(f"https://repo.packagist.org/p2/{m.group(1)}.json")
    if not d: return ""
    pkgs = list(d.get("packages", {}).values())
    if pkgs and pkgs[0]:
        return extract_gh(pkgs[0][0].get("source", {}).get("url", ""))
    return ""

# --- crates.io ---
def lookup_crate(name, purl):
    d = get_json(f"https://crates.io/api/v1/crates/{name}", headers={"User-Agent": "research"})
    if not d: return ""
    return extract_gh(d.get("crate", {}).get("repository", ""))

# --- nuget ---
def lookup_nuget(name, purl):
    # try v3 registration
    for base in ["https://api.nuget.org/v3/registration5-gz-semver2", "https://api.nuget.org/v3/registration5-semver2"]:
        d = get_json(f"{base}/{name.lower()}/index.json")
        if d:
            items = d.get("items", [])
            if items:
                pages = items[-1].get("items", [])
                if pages:
                    cat = pages[-1].get("catalogEntry", {})
                    for key in ["projectUrl", "repository"]:
                        gh = extract_gh(str(cat.get(key, "")))
                        if gh: return gh
    return ""

# --- go module ---
def lookup_go(name, purl):
    m = re.match(r'pkg:golang/([^@]+)', str(purl))
    mod = m.group(1) if m else name
    # direct github.com path
    if "github.com/" in mod:
        parts = mod.split("/")
        idx = parts.index("github.com")
        if idx + 2 < len(parts):
            return f"https://github.com/{parts[idx+1]}/{parts[idx+2]}"
    # resolve vanity URL via go-import meta tag
    try:
        r = requests.get(f"https://{mod}?go-get=1", timeout=10, allow_redirects=True)
        m2 = re.search(r'<meta\s+name="go-import"\s+content="([^"]+)"', r.text)
        if m2:
            parts = m2.group(1).split()
            if len(parts) >= 3:
                return extract_gh(parts[2])
    except:
        pass
    # fallback: try pkg.go.dev source tab
    try:
        r = requests.get(f"https://pkg.go.dev/{mod}", timeout=10)
        gh = extract_gh(r.text)
        if gh: return gh
    except:
        pass
    return ""

# --- maven ---
def lookup_maven(name, purl):
    m = re.match(r'pkg:maven/([^/]+)/([^@]+)', str(purl))
    if not m: return ""
    group, artifact = m.group(1), m.group(2)
    # get latest version from maven central
    d = get_json(f"https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}&rows=1&wt=json")
    if d:
        docs = d.get("response", {}).get("docs", [])
        if docs:
            v = docs[0].get("latestVersion", docs[0].get("v", ""))
            if v:
                # fetch POM and parse scm/url
                group_path = group.replace(".", "/")
                pom_url = f"https://repo1.maven.org/maven2/{group_path}/{artifact}/{v}/{artifact}-{v}.pom"
                try:
                    r = requests.get(pom_url, timeout=10)
                    if r.status_code == 200:
                        # look for <scm><url>, <scm><connection>, or <url>
                        for pattern in [r'<scm>.*?<url>([^<]+)</url>', r'<scm>.*?<connection>([^<]+)</connection>', r'<url>([^<]+)</url>']:
                            match = re.search(pattern, r.text, re.DOTALL)
                            if match:
                                gh = extract_gh(match.group(1))
                                if gh: return gh
                except:
                    pass
    # fallback: guess from group ID if it contains github
    if "github" in group.lower():
        return extract_gh(group)
    # fallback: common pattern org.apache.X -> github.com/apache/X
    known_orgs = {
        "org.apache": "apache", "com.google": "google", "org.eclipse": "eclipse",
        "io.netty": "netty", "com.fasterxml": "FasterXML", "org.springframework": "spring-projects",
        "org.jetbrains": "JetBrains", "com.squareup": "square",
    }
    for prefix, org in known_orgs.items():
        if group.startswith(prefix):
            return f"https://github.com/{org}/{artifact}"
    return ""

# --- hex.pm (elixir/erlang) ---
def lookup_hex(name, purl):
    d = get_json(f"https://hex.pm/api/packages/{name}")
    if not d: return ""
    links = d.get("meta", {}).get("links", {})
    for key in ["GitHub", "Repository", "Source", "Homepage"]:
        gh = extract_gh(links.get(key, ""))
        if gh: return gh
    return ""

# --- dart pub.dev ---
def lookup_dart(name, purl):
    d = get_json(f"https://pub.dev/api/packages/{name}")
    if not d: return ""
    latest = d.get("latest", {}).get("pubspec", {})
    repo = latest.get("repository", "")
    if repo: return extract_gh(repo)
    return extract_gh(latest.get("homepage", ""))

# --- swift ---
def lookup_swift(name, purl):
    m = re.match(r'pkg:swift/([^@]+)', str(purl))
    if not m: return ""
    path = m.group(1)
    if "github.com" in path:
        return extract_gh(f"https://{path}")
    return ""

# --- github-action ---
def lookup_gh_action(name, purl):
    # actions are already github repos, e.g. actions/checkout
    m = re.match(r'pkg:githubactions/([^@]+)', str(purl))
    if m: return f"https://github.com/{m.group(1)}"
    if "/" in name and not name.startswith("."):
        return f"https://github.com/{name}"
    return ""

# --- jenkins-plugin ---
def lookup_jenkins(name, purl):
    d = get_json(f"https://plugins.jenkins.io/api/plugin/{name}")
    if not d: return ""
    return extract_gh(d.get("scm", ""))

# --- R-package (CRAN) ---
def lookup_r(name, purl):
    d = get_json(f"https://crandb.r-pkg.org/{name}")
    if not d: return ""
    for key in ["URL", "BugReports"]:
        gh = extract_gh(d.get(key, ""))
        if gh: return gh
    return ""

# --- luarocks ---
def lookup_lua(name, purl):
    d = get_json(f"https://luarocks.org/api/1/{name}")
    if not d: return ""
    return extract_gh(d.get("homepage", ""))

# --- conan ---
def lookup_conan(name, purl):
    # conan center doesn't have a simple API, try GitHub search
    if HEADERS_GH:
        d = get_json(f"https://api.github.com/search/repositories?q={name}+in:name&per_page=1", headers=HEADERS_GH)
        if d and d.get("items"):
            return d["items"][0].get("html_url", "")
    return ""

LOOKUP = {
    # syft names              # purl scheme aliases
    "npm":                      lookup_npm,
    "python":                   lookup_pypi,
    "pip":                      lookup_pypi,
    "pypi":                     lookup_pypi,
    "gem":                      lookup_gem,
    "php-composer":             lookup_composer,
    "composer":                 lookup_composer,
    "rust-crate":               lookup_crate,
    "cargo":                    lookup_crate,
    "dotnet":                   lookup_nuget,
    "nuget":                    lookup_nuget,
    "go-module":                lookup_go,
    "golang":                   lookup_go,
    "java-archive":             lookup_maven,
    "maven":                    lookup_maven,
    "hex":                      lookup_hex,
    "dart-pub":                 lookup_dart,
    "pub":                      lookup_dart,
    "swift":                    lookup_swift,
    "github-action":            lookup_gh_action,
    "github-action-workflow":   lookup_gh_action,
    "github":                   lookup_gh_action,
    "jenkins-plugin":           lookup_jenkins,
    "R-package":                lookup_r,
    "cran":                     lookup_r,
    "lua-rocks":                lookup_lua,
    "luarocks":                 lookup_lua,
    "erlang-otp":               lookup_hex,
    "otp":                      lookup_hex,
    "conan":                    lookup_conan,
    # skip: binary, deb, rpm, generic (OS-level / unidentifiable)
}

done = 0
for i, row in unique.iterrows():
    key = (row["name"], row["pkg_type"])
    if key in cache: continue

    pkg_type = str(row.get("pkg_type", ""))
    fn = LOOKUP.get(pkg_type)
    if not fn:
        cache[key] = ""
        continue

    done += 1
    print(f"[{len(cache)+1}/{len(unique)}] {pkg_type}: {row['name']}")
    try:
        cache[key] = fn(row["name"], row.get("purl", ""))
    except Exception as e:
        print(f"  error: {e}")
        cache[key] = ""
    time.sleep(0.3)

    # save progress every 500 lookups
    if done % 1000 == 0:
        json.dump([[list(k), v] for k, v in cache.items()], open(CACHE_FILE, "w"))
        print(f"  [saved {len(cache)} to {CACHE_FILE}]")

# final save
json.dump([[list(k), v] for k, v in cache.items()], open(CACHE_FILE, "w"))

libs["lib_github_url"] = libs.apply(lambda r: cache.get((r["name"], r["pkg_type"]), ""), axis=1)
libs.to_csv("libraries_with_links.csv", index=False)

found = sum(1 for v in cache.values() if v)
print(f"\nDone. Found GitHub URLs for {found}/{len(cache)} unique libraries.")

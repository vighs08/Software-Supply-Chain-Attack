
"""
SYNTHETIC sample data generator.

IMPORTANT - READ THIS BEFORE USING THE RESULTS
---------------------------------------------
Everything produced by this file is SIMULATED. It is NOT real package
data and NOT real attack data. It exists so that:

  1. the ML model can be trained and the pipeline can run end-to-end
     before real data collection exists, and
  2. tests can check that clearly normal and clearly suspicious inputs
     are handled differently.

The "normal" packages follow simple assumptions chosen by hand (for
example "releases every 2-12 weeks", "size grows a few percent per
release"). The "suspicious" scenarios are loosely INSPIRED by public
incidents (event-stream maintainer takeover, credential-stealing
typosquats, colors/faker sabotage, download inflation, tampered
artifacts), but they are simplified caricatures written by us.

Because we wrote both the normal data and the attacks, good scores on
this data only show that the code works as designed. They do NOT show
how well the system would detect real supply chain attacks. See
docs/ANOMALY_DETECTION.md for what real-world data is needed.

Every generated observation carries "synthetic": true.
"""

import random
from datetime import date, timedelta


DEPENDENCY_POOL = [
    "lodash", "chalk", "debug", "commander", "semver", "minimist", "yargs",
    "requests", "urllib3", "click", "pyyaml", "six", "attrs", "colorama",
    "express", "axios", "uuid", "moment", "rich", "typing-extensions",
]

NORMAL_HOSTS = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]

# Typical API call "stories" of harmless libraries.
NORMAL_API_PATTERNS = [
    ["fs.readFile", "JSON.parse", "path.join", "fs.writeFile"],
    ["os.path.join", "open_read", "json.loads", "logging.info"],
    ["path.resolve", "fs.readdir", "fs.readFile", "crypto.createHash"],
    ["hashlib.sha256", "open_read", "struct.unpack"],
    ["util.format", "console.log"],
    ["os.environ", "logging.basicConfig", "json.dumps"],
    ["fs.readFile", "zlib.inflate", "fs.writeFile"],
    ["https.get", "JSON.parse", "fs.writeFile"],   # e.g. a downloader library
]

# Build tools legitimately start compilers.
BUILD_API_PATTERN = ["fs.readFile", "child_process.spawn", "fs.writeFile"]

NORMAL_CODE_TEMPLATES = [
    """
def {name}(values):
    \"\"\"Return the cleaned list of values.\"\"\"
    result = []
    for value in values:
        if value is None:
            continue
        result.append(str(value).strip())
    return result
""",
    """
'use strict';
const path = require('path');

function {name}(options) {{
  const settings = Object.assign({{}}, options);
  if (!settings.root) {{
    settings.root = process.cwd();
  }}
  return path.resolve(settings.root, settings.file || 'index.js');
}}

module.exports = {name};
""",
    """
class {Name}:
    def __init__(self, limit=10):
        self.limit = limit
        self.items = []

    def add(self, item):
        if len(self.items) >= self.limit:
            self.items.pop(0)
        self.items.append(item)
""",
]


def _minified_code(rng):
    """Legitimately minified JS (long lines, no hidden payload)."""

    parts = [
        f"function {chr(97 + i)}(t,e){{return t+e*{rng.randint(1, 9)}}}"
        for i in range(rng.randint(30, 60))
    ]
    return ";".join(parts) + ";module.exports={a:a};"


def _normal_code(rng):
    if rng.random() < 0.1:
        return _minified_code(rng)

    template = rng.choice(NORMAL_CODE_TEMPLATES)
    name = rng.choice(["format_items", "loadConfig", "parseArgs", "Cache", "normalize"])
    return template.format(name=name, Name=name.capitalize())


def _release_history(rng, start, count, author, co_author, dependencies, install_script):
    releases = []
    day = start
    size = rng.randint(5_000, 400_000)
    usual_gap = rng.randint(14, 90)

    for index in range(count):
        releases.append({
            "version": f"1.{index}.0",
            "released_at": day.isoformat(),
            "size_bytes": size,
            "author": co_author if co_author and rng.random() < 0.4 else author,
            "dependencies": list(dependencies),
            "has_install_script": install_script,
        })
        day += timedelta(days=max(1, int(rng.gauss(usual_gap, usual_gap * 0.3))))
        size = int(size * rng.uniform(0.97, 1.12))

    return releases, day, size, usual_gap


def generate_normal_observation(rng, index):
    """One simulated, harmless package release."""

    ecosystem = rng.choice(["npm", "pypi"])
    author = f"maintainer{index}"
    co_author = f"comaintainer{index}" if rng.random() < 0.15 else None
    dependencies = rng.sample(DEPENDENCY_POOL, rng.randint(0, 5))
    is_build_tool = rng.random() < 0.08

    history, next_day, size, usual_gap = _release_history(
        rng,
        date(2024, 1, 1) + timedelta(days=rng.randint(0, 200)),
        rng.randint(5, 10),
        author,
        co_author,
        dependencies,
        is_build_tool,
    )

    # The current release: same behaviour, with small natural changes.
    current_author = author
    if co_author and rng.random() < 0.4:
        current_author = co_author
    elif rng.random() < 0.03:
        current_author = f"newhelper{index}"   # a genuine new maintainer

    current_dependencies = list(dependencies)
    if rng.random() < 0.2:
        current_dependencies.append(rng.choice(DEPENDENCY_POOL))

    if rng.random() < 0.05:
        size = int(size * rng.uniform(1.3, 1.9))   # a big but legitimate refactor

    # Downloads: steady with weekly noise, sometimes a gentle trend or a
    # small legitimate bump (e.g. mentioned in a blog post).
    base = rng.lognormvariate(8, 1.5)
    trend = rng.uniform(-0.01, 0.03)
    downloads = [
        max(0, int(base * (1 + trend) ** week * rng.uniform(0.85, 1.15)))
        for week in range(12)
    ]
    if rng.random() < 0.05:
        downloads[-1] = int(downloads[-1] * rng.uniform(1.5, 2.5))

    api_calls = list(BUILD_API_PATTERN if is_build_tool else rng.choice(NORMAL_API_PATTERNS))
    hosts = rng.sample(NORMAL_HOSTS, rng.randint(1, 2))
    if rng.random() < 0.1:
        hosts.append("github.com")

    # The previous release behaved the same way.
    history[-1]["api_calls"] = list(api_calls)
    history[-1]["network_hosts"] = list(hosts)

    file_accesses = [
        {"path": f"/tmp/build/{index}/index.js", "mode": "write"},
        {"path": f"/tmp/build/{index}/package.json", "mode": "read"},
    ]
    source_code = _normal_code(rng)

    # Rare but LEGITIMATE behaviour, so the model learns that these
    # features are not always zero. Isolation Forest cannot split on a
    # feature that never varies in its training data.
    if rng.random() < 0.04:
        # dotenv-style libraries read the project's .env file
        file_accesses.append({"path": f"/home/dev/project{index}/.env", "mode": "read"})
        api_calls = ["fs.readFile", "process.env"] + api_calls
    if rng.random() < 0.04:
        # libraries that call a documented web API or CDN
        hosts.append(rng.choice(["api.github.com", "cdn.jsdelivr.net", "unpkg.com"]))
    if rng.random() < 0.03:
        # legitimate base64 use, e.g. decoding an embedded icon
        source_code += "\nicon = base64.b64decode(ICON_DATA)\n"

    return {
        "synthetic": True,
        "scenario": "normal",
        "package_name": f"sample-lib-{index}",
        "version": f"1.{len(history)}.0",
        "ecosystem": ecosystem,
        "download_history": downloads,
        "release_history": history,
        "current_release": {
            "released_at": (next_day + timedelta(days=rng.randint(-3, 10))).isoformat(),
            "size_bytes": size,
            "author": current_author,
            "dependencies": current_dependencies,
            "has_install_script": is_build_tool,
        },
        "source_code": source_code,
        "behavior": {
            "network_connections": [{"host": host, "port": 443} for host in hosts],
            "file_accesses": file_accesses,
            "api_calls": api_calls,
        },
        "integrity": {
            "hash": "PASS", "signature": "PASS", "version": "PASS",
            "source": "TRUSTED", "attestation": "PASS",
            "reproducible_build": "PASS", "timestamp": "PASS",
        },
    }


# --------------------------------------------------
# Suspicious scenarios (simulated)
# --------------------------------------------------

def _obfuscated_payload(rng):
    blob = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(600))
    return (
        "var _0x3f2a=['\\x72\\x65\\x71\\x75\\x69\\x72\\x65\\x28\\x27'];"
        f"eval(Buffer.from('{blob}','base64').toString());"
        f"new Function(atob('{blob[:200]}'))();"
    )


def _attack_ip(rng):
    return f"{rng.randint(23, 200)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def scenario_maintainer_takeover(rng, index):
    """Inspired by event-stream (2018): a new maintainer adds a malicious dependency."""

    observation = generate_normal_observation(rng, index)
    current = observation["current_release"]
    current["author"] = f"newowner{index}"
    current["dependencies"] = current["dependencies"] + ["flatmap-stream-x"]
    current["has_install_script"] = True
    current["size_bytes"] = int(current["size_bytes"] * rng.uniform(3, 8))
    observation["source_code"] = _obfuscated_payload(rng)
    observation["behavior"]["network_connections"].append({"host": _attack_ip(rng), "port": 8080})
    observation["behavior"]["api_calls"] = ["fs.readFile", "process.env", "Buffer.from", "https.request"]
    observation["scenario"] = "maintainer_takeover"
    return observation


def scenario_credential_stealer(rng, index):
    """Typosquat-style package that steals credentials during install."""

    observation = generate_normal_observation(rng, index)
    observation["current_release"]["has_install_script"] = True
    observation["behavior"]["file_accesses"] += [
        {"path": "/home/dev/.ssh/id_rsa", "mode": "read"},
        {"path": "/home/dev/.npmrc", "mode": "read"},
        {"path": "/home/dev/.aws/credentials", "mode": "read"},
    ]
    observation["behavior"]["network_connections"].append(
        {"host": f"collect-{index}.example-exfil.net", "port": 443}
    )
    observation["behavior"]["api_calls"] = [
        "os.environ", "open_read", "base64.b64encode", "requests.post",
    ]
    observation["scenario"] = "credential_stealer"
    return observation


def scenario_dropper(rng, index):
    """Downloads a second-stage binary, runs it, and installs persistence."""

    observation = generate_normal_observation(rng, index)
    observation["source_code"] = _obfuscated_payload(rng)
    observation["behavior"]["network_connections"].append({"host": _attack_ip(rng), "port": 4444})
    observation["behavior"]["file_accesses"] += [
        {"path": "/home/dev/.bashrc", "mode": "write"},
        {"path": "C:\\Users\\dev\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\upd.exe", "mode": "write"},
    ]
    observation["behavior"]["api_calls"] = [
        "https.get", "fs.writeFile", "fs.chmod", "child_process.exec", "eval",
    ]
    observation["scenario"] = "dropper"
    return observation


def scenario_sabotage_burst(rng, index):
    """Inspired by colors/faker (2022): a burst of strange releases by the owner."""

    observation = generate_normal_observation(rng, index)
    history = observation["release_history"]
    last_day = date.fromisoformat(history[-1]["released_at"])

    # Three extra releases within a few days.
    for extra in range(3):
        release = dict(history[-1])
        release["version"] = f"9.9.{extra}"
        release["released_at"] = (last_day + timedelta(days=extra + 1)).isoformat()
        history.append(release)

    observation["current_release"]["released_at"] = (last_day + timedelta(days=4)).isoformat()
    observation["current_release"]["size_bytes"] = int(history[-1]["size_bytes"] * rng.uniform(0.05, 0.2))
    observation["behavior"]["api_calls"] = ["process.exit", "while_true_loop", "console.log"] * 3
    observation["scenario"] = "sabotage_burst"
    return observation


def scenario_download_inflation(rng, index):
    """Artificial download spike, e.g. to make a fake package look popular."""

    observation = generate_normal_observation(rng, index)
    downloads = observation["download_history"]
    downloads[-1] = int(max(downloads[:-1]) * rng.uniform(40, 200)) + 5000
    observation["scenario"] = "download_inflation"
    return observation


def scenario_tampered_artifact(rng, index):
    """Behaviour looks normal, but the artifact no longer matches its hash/signature."""

    observation = generate_normal_observation(rng, index)
    observation["integrity"].update({"hash": "FAIL", "signature": "FAIL", "attestation": "FAIL"})
    observation["scenario"] = "tampered_artifact"
    return observation


SUSPICIOUS_SCENARIOS = {
    "maintainer_takeover": scenario_maintainer_takeover,
    "credential_stealer": scenario_credential_stealer,
    "dropper": scenario_dropper,
    "sabotage_burst": scenario_sabotage_burst,
    "download_inflation": scenario_download_inflation,
    "tampered_artifact": scenario_tampered_artifact,
}


def generate_normal_dataset(count, seed=42):
    rng = random.Random(seed)
    return [generate_normal_observation(rng, index) for index in range(count)]


def generate_suspicious_dataset(per_scenario, seed=7):
    rng = random.Random(seed)
    data = []

    for name, make in SUSPICIOUS_SCENARIOS.items():
        for number in range(per_scenario):
            data.append(make(rng, 100_000 + len(data)))

    return data

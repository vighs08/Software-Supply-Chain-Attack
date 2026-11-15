
"""
Behaviour analysis: network communication, file access and API calls.

The input comes from the `behavior` section of an observation, i.e.
what a package actually DID while it was installed, built or run.

Where does this data come from?
  In a real deployment it would be collected by the Runtime Protection
  Layer / CI sandbox (eBPF, strace, Procmon, an HTTP proxy, ...).
  This prototype does not collect it yet: the sample data in
  `anomaly/sample_data.py` is SIMULATED.
"""

import ipaddress
import re


# --------------------------------------------------
# 1. Network communication
# --------------------------------------------------

# Hosts that a package installer normally talks to.
EXPECTED_HOSTS = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "repo.maven.apache.org",
    "proxy.golang.org",
    "crates.io",
    "static.crates.io",
}

NORMAL_PORTS = {80, 443}


def _is_raw_ip(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False

    # Connecting to localhost is normal (e.g. test servers).
    return not address.is_loopback


def analyze_network(connections):
    """Summarise network connections made by the package."""

    unexpected_hosts = sorted({
        connection["host"]
        for connection in connections
        if connection["host"] not in EXPECTED_HOSTS
        and connection["host"] not in ("localhost", "127.0.0.1", "::1")
    })

    raw_ip_hosts = sorted({
        connection["host"]
        for connection in connections
        if _is_raw_ip(connection["host"])
    })

    unusual_ports = sorted({
        connection["port"]
        for connection in connections
        if connection["port"] not in NORMAL_PORTS
        and connection["host"] not in ("localhost", "127.0.0.1", "::1")
    })

    return {
        "unexpected_hosts": unexpected_hosts,
        "raw_ip_hosts": raw_ip_hosts,
        "unusual_ports": unusual_ports,
    }


# --------------------------------------------------
# 2. File system access
# --------------------------------------------------

# Credential files in the user's home directory or the system. A normal
# library has no reason to read them.
SENSITIVE_PATH_PATTERNS = [
    r"/\.ssh/",
    r"/\.aws/credentials",
    r"/\.npmrc$",
    r"/\.pypirc$",
    r"/\.netrc$",
    r"/\.docker/config\.json$",
    r"/\.kube/config$",
    r"/\.git-credentials$",
    r"/etc/passwd$",
    r"/etc/shadow$",
    r"/login data$",          # Chrome saved passwords
    r"/cookies$",
    r"wallet",
]

# Locations used to survive a reboot (persistence) or alter the system.
SYSTEM_PATH_PATTERNS = [
    r"^/etc/",
    r"^/usr/",
    r"^/bin/",
    r"/\.bashrc$",
    r"/\.profile$",
    r"/\.zshrc$",
    r"crontab",
    r"^c:/windows/",
    r"/start menu/programs/startup/",
    r"/appdata/roaming/microsoft/windows/start menu/",
]

# Project secret files. Some libraries (e.g. dotenv) read these
# legitimately, so they are a weaker signal than credential files.
SECRET_CONFIG_PATTERNS = [
    r"(^|/)\.env(\.[a-z]+)?$",
]

_SENSITIVE_RE = [re.compile(pattern) for pattern in SENSITIVE_PATH_PATTERNS]
_SECRET_CONFIG_RE = [re.compile(pattern) for pattern in SECRET_CONFIG_PATTERNS]
_SYSTEM_RE = [re.compile(pattern) for pattern in SYSTEM_PATH_PATTERNS]


def analyze_files(file_accesses):
    """Summarise file reads/writes made by the package."""

    sensitive_reads = sorted({
        access["path"]
        for access in file_accesses
        if any(pattern.search(access["path"]) for pattern in _SENSITIVE_RE)
    })

    secret_config_reads = sorted({
        access["path"]
        for access in file_accesses
        if any(pattern.search(access["path"]) for pattern in _SECRET_CONFIG_RE)
    })

    system_writes = sorted({
        access["path"]
        for access in file_accesses
        if access["mode"] == "write"
        and any(pattern.search(access["path"]) for pattern in _SYSTEM_RE)
    })

    return {
        "sensitive_reads": sensitive_reads,
        "secret_config_reads": secret_config_reads,
        "system_writes": system_writes,
        "total_accesses": len(file_accesses),
    }


# --------------------------------------------------
# 3. API calls and API call sequences
# --------------------------------------------------

# Map raw API names (Node.js and Python) to simple categories.
# The order matters: the first matching category wins.
API_CATEGORIES = [
    ("dynamic_code", ("eval", "new function", "vm.runin", "compile(", "exec(")),
    ("process_exec", ("child_process", "subprocess", "os.system", "os.popen",
                      "spawn", "execsync", "execfile")),
    ("network", ("http.", "https.", "fetch", "socket", "requests.", "urllib",
                 "net.connect", "dns.")),
    ("encoding", ("base64", "atob", "btoa", "buffer.from", "b64encode",
                  "b64decode", "hexlify")),
    ("env_access", ("process.env", "os.environ", "os.getenv")),
    ("fs_write", ("writefile", "fs.write", "open_write", "appendfile",
                  "shutil.copy", "fs.chmod", "os.chmod")),
    ("fs_read", ("readfile", "fs.read", "open_read", "readdir", "os.listdir")),
    ("crypto", ("crypto.", "hashlib", "createhash", "cipher")),
]

# Categories that are dangerous on their own.
DANGEROUS_CATEGORIES = {"dynamic_code", "process_exec"}

# Ordered patterns that describe typical attack behaviour. Each pattern
# matches when its steps appear in this order (other calls may appear
# in between).
SUSPICIOUS_SEQUENCES = {
    "data_exfiltration": ("env_access", "encoding", "network"),
    "secret_file_exfiltration": ("fs_read", "encoding", "network"),
    "download_and_execute": ("network", "fs_write", "process_exec"),
    "remote_code_execution": ("network", "dynamic_code"),
}


def categorize_api_call(call):
    """Return the category name for one API call, or 'other'."""

    lowered = call.lower()

    # Python's built-in exec/eval are often logged without a module.
    if lowered in ("exec", "eval", "builtins.exec", "builtins.eval"):
        return "dynamic_code"

    for category, keywords in API_CATEGORIES:
        if any(keyword in lowered for keyword in keywords):
            return category

    return "other"


def _contains_in_order(sequence, steps):
    """True if `steps` appear in `sequence` in the same order."""

    position = 0

    for item in sequence:
        if item == steps[position]:
            position += 1
            if position == len(steps):
                return True

    return False


def category_bigrams(categories):
    """Pairs of consecutive categories, e.g. ('fs_read', 'network')."""

    return [
        (categories[index], categories[index + 1])
        for index in range(len(categories) - 1)
    ]


def analyze_api_calls(api_calls, known_bigrams=None):
    """
    Summarise API calls.

    known_bigrams: the set of category pairs seen in NORMAL training
    packages. A high share of never-seen pairs means the call sequence
    is unusual ("sequence analysis" in the project guide).
    """

    categories = [categorize_api_call(call) for call in api_calls]

    dangerous_calls = sorted({
        call for call, category in zip(api_calls, categories)
        if category in DANGEROUS_CATEGORIES
    })

    matched_sequences = [
        name for name, steps in SUSPICIOUS_SEQUENCES.items()
        if _contains_in_order(categories, steps)
    ]

    bigrams = category_bigrams(categories)

    if known_bigrams and bigrams:
        novel = [pair for pair in bigrams if pair not in known_bigrams]
        novel_ratio = len(novel) / len(bigrams)
    else:
        novel = []
        novel_ratio = 0.0

    return {
        "categories": categories,
        "dangerous_calls": dangerous_calls,
        "dangerous_call_count": sum(
            1 for category in categories if category in DANGEROUS_CATEGORIES
        ),
        "matched_sequences": matched_sequences,
        "novel_bigrams": sorted({f"{a}->{b}" for a, b in novel}),
        "novel_bigram_ratio": round(novel_ratio, 4),
    }

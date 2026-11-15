
"""
Data preparation: validate and clean one "package observation".

A package observation is everything we know about ONE release of ONE
package. It is a plain dictionary (or JSON object) like this:

{
  "package_name": "colourful-logger",
  "version": "2.4.0",
  "ecosystem": "npm",

  # Weekly download counts, oldest first. The LAST value is the
  # current week.
  "download_history": [1200, 1350, 1280, 1400],

  # Earlier releases, oldest first.
  "release_history": [
    {"version": "2.3.0", "released_at": "2026-01-10",
     "size_bytes": 48000, "author": "alice",
     "dependencies": ["chalk"], "has_install_script": false,
     "api_calls": ["fs.readFile"]}
  ],

  # The release being analysed.
  "current_release": {
    "released_at": "2026-02-11", "size_bytes": 51000,
    "author": "alice", "dependencies": ["chalk"],
    "has_install_script": false
  },

  # Optional: source code text (main file / install script).
  "source_code": "module.exports = ...",

  # Optional: behaviour observed while installing/building/running
  # the package (sandbox, eBPF, strace, proxy logs, ...).
  "behavior": {
    "network_connections": [{"host": "registry.npmjs.org", "port": 443}],
    "file_accesses": [{"path": "/tmp/build/x.js", "mode": "write"}],
    "api_calls": ["fs.readFile", "http.request"]
  },

  # Optional: results of the Integrity Verification Module.
  "integrity": {"hash": "PASS", "signature": "NOT_CHECKED", ...}
}

Only `package_name` and `version` are required. Missing optional
sections are filled with safe empty defaults so the rest of the
pipeline never has to check for None.
"""

from datetime import date, datetime


class InvalidObservation(ValueError):
    """Raised when the input data cannot be used for analysis."""


def _parse_date(value, field_name):
    """Accept 'YYYY-MM-DD', a full ISO timestamp, or None."""

    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        return value.date()

    if isinstance(value, date):
        return value

    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
        except ValueError:
            pass

    raise InvalidObservation(
        f"{field_name} must be an ISO date such as 2026-01-31"
    )


def _non_negative_number(value, field_name, default=0):
    if value is None:
        return default

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidObservation(f"{field_name} must be a number")

    if value < 0:
        raise InvalidObservation(f"{field_name} cannot be negative")

    return value


def _string_list(value, field_name):
    if value is None:
        return []

    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise InvalidObservation(f"{field_name} must be a list of strings")

    return [item.strip() for item in value if item.strip()]


def _prepare_release(release, field_name):
    if not isinstance(release, dict):
        raise InvalidObservation(f"{field_name} must be an object")

    return {
        "version": str(release.get("version", "")),
        "released_at": _parse_date(
            release.get("released_at"), f"{field_name}.released_at"
        ),
        "size_bytes": _non_negative_number(
            release.get("size_bytes"), f"{field_name}.size_bytes", None
        ),
        "author": str(release.get("author") or "").strip().lower(),
        "dependencies": sorted(set(_string_list(
            release.get("dependencies"), f"{field_name}.dependencies"
        ))),
        "has_install_script": bool(release.get("has_install_script", False)),
        "api_calls": _string_list(
            release.get("api_calls"), f"{field_name}.api_calls"
        ),
        "network_hosts": _string_list(
            release.get("network_hosts"), f"{field_name}.network_hosts"
        ),
    }


def _prepare_behavior(behavior):
    if behavior is None:
        behavior = {}

    if not isinstance(behavior, dict):
        raise InvalidObservation("behavior must be an object")

    connections = []
    for index, item in enumerate(behavior.get("network_connections") or []):
        if not isinstance(item, dict) or not isinstance(item.get("host"), str):
            raise InvalidObservation(
                f"behavior.network_connections[{index}] needs a 'host' string"
            )
        port = item.get("port", 443)
        if isinstance(port, bool) or not isinstance(port, int):
            raise InvalidObservation(
                f"behavior.network_connections[{index}].port must be an integer"
            )
        connections.append({"host": item["host"].strip().lower(), "port": port})

    file_accesses = []
    for index, item in enumerate(behavior.get("file_accesses") or []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise InvalidObservation(
                f"behavior.file_accesses[{index}] needs a 'path' string"
            )
        mode = str(item.get("mode", "read")).lower()
        if mode not in ("read", "write"):
            raise InvalidObservation(
                f"behavior.file_accesses[{index}].mode must be read or write"
            )
        # Normalise Windows paths so one set of rules works everywhere.
        file_accesses.append({
            "path": item["path"].replace("\\", "/").lower(),
            "mode": mode,
        })

    return {
        "network_connections": connections,
        "file_accesses": file_accesses,
        "api_calls": _string_list(behavior.get("api_calls"), "behavior.api_calls"),
    }


def prepare_observation(raw):
    """
    Validate one raw observation and return a cleaned copy.

    Raises InvalidObservation with a readable message when the input
    is not usable.
    """

    if not isinstance(raw, dict):
        raise InvalidObservation("Observation must be a JSON object")

    package_name = raw.get("package_name")
    version = raw.get("version")

    if not isinstance(package_name, str) or not package_name.strip():
        raise InvalidObservation("package_name is required")

    if not isinstance(version, str) or not version.strip():
        raise InvalidObservation("version is required")

    downloads = raw.get("download_history") or []
    if not isinstance(downloads, list):
        raise InvalidObservation("download_history must be a list of numbers")
    downloads = [
        _non_negative_number(value, "download_history[]") for value in downloads
    ]

    history = raw.get("release_history") or []
    if not isinstance(history, list):
        raise InvalidObservation("release_history must be a list")
    history = [
        _prepare_release(release, f"release_history[{index}]")
        for index, release in enumerate(history)
    ]

    # Make sure releases are ordered oldest -> newest when dates exist.
    if all(release["released_at"] for release in history):
        history.sort(key=lambda release: release["released_at"])

    current = _prepare_release(
        raw.get("current_release") or {}, "current_release"
    )
    current["version"] = version.strip()

    source_code = raw.get("source_code") or ""
    if not isinstance(source_code, str):
        raise InvalidObservation("source_code must be a string")

    integrity = raw.get("integrity")
    if integrity is not None and not isinstance(integrity, dict):
        raise InvalidObservation("integrity must be an object")

    return {
        "package_name": package_name.strip(),
        "version": version.strip(),
        "ecosystem": str(raw.get("ecosystem") or "unknown").strip().lower(),
        "synthetic": bool(raw.get("synthetic", False)),
        "download_history": downloads,
        "release_history": history,
        "current_release": current,
        "source_code": source_code,
        "behavior": _prepare_behavior(raw.get("behavior")),
        "integrity": integrity,
    }

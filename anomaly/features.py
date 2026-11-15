
"""
Feature extraction: turn one prepared observation into a list of
numbers that the ML model can understand.

An ML model cannot read JSON. It needs a fixed list of numbers
(a "feature vector"), always in the same order. FEATURE_NAMES defines
that order and FEATURE_DESCRIPTIONS explains every feature in plain
English (used to explain detections to the user).

Each feature maps to an "Analysis Factor" from the project guide:

  Download frequency & spikes      -> download_spike_score
  Code obfuscation & minification  -> code_entropy, max_line_length_log,
                                      long_line_ratio, obfuscation_indicators
  Network communication            -> unexpected_host_count,
                                      raw_ip_connections, unusual_port_count
  File system access               -> sensitive_file_reads, secret_config_reads,
                                      system_file_writes
  API calls & sequences            -> dangerous_api_calls, suspicious_sequences,
                                      novel_api_bigram_ratio
  Author behaviour                 -> new_author, author_changed
  Update frequency & size changes  -> size_change_log, release_interval_log,
                                      releases_last_7_days
  Package drift                    -> drift_score, new_dependency_count,
                                      install_script_added
"""

import math

from .behavior_analysis import (
    analyze_api_calls,
    analyze_files,
    analyze_network,
    categorize_api_call,
)
from .code_analysis import analyze_code
from .stat_methods import is_iqr_outlier, robust_z_score


FEATURE_DESCRIPTIONS = {
    "download_spike_score": "Robust (MAD) z-score of this week's downloads (log scale) compared with the package's history",
    "code_entropy": "Randomness of the source code characters (high = packed/encoded code)",
    "max_line_length_log": "Length of the longest source line (log10 scale)",
    "long_line_ratio": "Share of source lines longer than 500 characters",
    "obfuscation_indicators": "Number of obfuscation tricks found (eval, base64 decode, hex escapes, ...)",
    "unexpected_host_count": "Number of contacted hosts that are not normal package registries",
    "raw_ip_connections": "Number of connections to raw IP addresses instead of domain names",
    "unusual_port_count": "Number of distinct non-HTTP(S) ports contacted",
    "sensitive_file_reads": "Number of credential files accessed (.ssh, .aws, .npmrc, ...)",
    "secret_config_reads": "Number of project secret files (.env) accessed",
    "system_file_writes": "Number of writes to system or start-up locations",
    "dangerous_api_calls": "Number of process-execution or dynamic-code API calls",
    "suspicious_sequences": "Number of known attack-like API call sequences found",
    "novel_api_bigram_ratio": "Share of API call transitions never seen in normal packages",
    "size_change_log": "How much the package size changed since the previous release (|log2 ratio|)",
    "release_interval_log": "How different the time since the last release is from the usual interval (|log2 ratio|)",
    "releases_last_7_days": "Number of releases published in the 7 days before this one",
    "new_author": "1 if the publishing author never published this package before",
    "author_changed": "1 if the author differs from the previous release's author",
    "drift_score": "How much the package's capabilities changed since the previous release (0 = same, 1 = completely different)",
    "new_dependency_count": "Number of dependencies added in this release",
    "install_script_added": "1 if an install script appeared in this release",
}

FEATURE_NAMES = list(FEATURE_DESCRIPTIONS)


def _download_features(downloads):
    """Compare the latest week's downloads with earlier weeks."""

    if len(downloads) < 5:
        return 0.0, {"download_z": 0.0, "download_latest": None}

    *history, latest = downloads

    # Download counts grow and shrink by PERCENTAGES, so compare them on
    # a log scale: 1,000 -> 2,000 counts the same as 100 -> 200.
    score = robust_z_score(math.log1p(latest), [math.log1p(x) for x in history])

    # Cap extreme values so a single feature cannot dominate the model.
    score = max(-10.0, min(score, 50.0))

    usual = sorted(history)[len(history) // 2]  # median
    ratio = latest / usual if usual else float(latest > 0) * 100.0

    return score, {
        "download_z": round(score, 2),
        "download_latest": latest,
        "download_usual": usual,
        "download_ratio": round(ratio, 2),
    }


def _release_features(history, current):
    """Size changes, update frequency and author behaviour."""

    details = {}
    previous = history[-1] if history else None

    # ---- Size change (current size vs previous release) ----
    size_change_log = 0.0
    if previous and previous["size_bytes"] and current["size_bytes"]:
        size_change_log = abs(math.log2(current["size_bytes"] / previous["size_bytes"]))
        details["previous_size_bytes"] = previous["size_bytes"]
        details["current_size_bytes"] = current["size_bytes"]

        # Statistical check (IQR): compare this size change with the
        # package's own historical size changes.
        past_changes = [
            abs(math.log2(b["size_bytes"] / a["size_bytes"]))
            for a, b in zip(history, history[1:])
            if a["size_bytes"] and b["size_bytes"]
        ]
        details["size_change_iqr_outlier"] = is_iqr_outlier(size_change_log, past_changes)

    # ---- Update frequency ----
    release_interval_log = 0.0
    releases_last_7_days = 0
    dates = [release["released_at"] for release in history if release["released_at"]]

    if current["released_at"] and dates:
        days_since_last = max((current["released_at"] - dates[-1]).days, 0)
        intervals = [(b - a).days for a, b in zip(dates, dates[1:])]

        if intervals:
            usual = max(sorted(intervals)[len(intervals) // 2], 1)  # median
            release_interval_log = abs(math.log2(max(days_since_last, 0.5) / usual))
            details["usual_release_interval_days"] = usual

        details["days_since_last_release"] = days_since_last
        releases_last_7_days = sum(
            1 for day in dates if 0 <= (current["released_at"] - day).days <= 7
        )

    # ---- Author behaviour ----
    known_authors = {release["author"] for release in history if release["author"]}
    author = current["author"]
    new_author = 1 if author and known_authors and author not in known_authors else 0
    author_changed = 1 if author and previous and previous["author"] and author != previous["author"] else 0
    details["author"] = author
    details["previous_author"] = previous["author"] if previous else None

    return {
        "size_change_log": size_change_log,
        "release_interval_log": release_interval_log,
        "releases_last_7_days": releases_last_7_days,
        "new_author": new_author,
        "author_changed": author_changed,
    }, details


def _capabilities(release, api_calls, hosts):
    """
    Describe what a release can do as a set of labels, e.g.
    {'dep:chalk', 'api:fs_read', 'net:registry.npmjs.org'}.
    """

    labels = {f"dep:{name}" for name in release["dependencies"]}
    labels |= {f"api:{categorize_api_call(call)}" for call in api_calls}
    labels |= {f"net:{host}" for host in hosts}

    if release["has_install_script"]:
        labels.add("install_script")

    return labels


def _drift_features(history, current, behavior):
    """Package drift: compare this release's capabilities with the previous one."""

    if not history:
        return {"drift_score": 0.0, "new_dependency_count": 0, "install_script_added": 0}, {}

    previous = history[-1]

    before = _capabilities(previous, previous["api_calls"], previous["network_hosts"])
    after = _capabilities(
        current,
        behavior["api_calls"],
        [connection["host"] for connection in behavior["network_connections"]],
    )

    # If the previous release has no recorded behaviour, compare only
    # dependencies and install scripts to avoid a false drift signal.
    if not previous["api_calls"] and not previous["network_hosts"]:
        after = {label for label in after if not label.startswith(("api:", "net:"))}

    union = before | after
    drift = 1 - len(before & after) / len(union) if union else 0.0

    added_dependencies = sorted(set(current["dependencies"]) - set(previous["dependencies"]))

    return {
        "drift_score": round(drift, 4),
        "new_dependency_count": len(added_dependencies),
        "install_script_added": int(current["has_install_script"] and not previous["has_install_script"]),
    }, {
        "added_capabilities": sorted(after - before),
        "removed_capabilities": sorted(before - after),
        "added_dependencies": added_dependencies,
    }


def extract_features(observation, known_bigrams=None):
    """
    Build the feature vector for one PREPARED observation
    (see data_preparation.prepare_observation).

    Returns (features, details):
      features: {feature_name: number} in FEATURE_NAMES order
      details:  human-readable evidence used to explain the result
    """

    behavior = observation["behavior"]

    download_score, download_details = _download_features(observation["download_history"])
    code = analyze_code(observation["source_code"])
    network = analyze_network(behavior["network_connections"])
    files = analyze_files(behavior["file_accesses"])
    api = analyze_api_calls(behavior["api_calls"], known_bigrams)
    release_values, release_details = _release_features(
        observation["release_history"], observation["current_release"]
    )
    drift_values, drift_details = _drift_features(
        observation["release_history"], observation["current_release"], behavior
    )

    features = {
        "download_spike_score": download_score,
        "code_entropy": code["entropy"],
        "max_line_length_log": math.log10(1 + code["max_line_length"]),
        "long_line_ratio": code["long_line_ratio"],
        "obfuscation_indicators": code["obfuscation_indicators"],
        "unexpected_host_count": len(network["unexpected_hosts"]),
        "raw_ip_connections": len(network["raw_ip_hosts"]),
        "unusual_port_count": len(network["unusual_ports"]),
        "sensitive_file_reads": len(files["sensitive_reads"]),
        "secret_config_reads": len(files["secret_config_reads"]),
        "system_file_writes": len(files["system_writes"]),
        "dangerous_api_calls": api["dangerous_call_count"],
        "suspicious_sequences": len(api["matched_sequences"]),
        "novel_api_bigram_ratio": api["novel_bigram_ratio"],
        **release_values,
        **drift_values,
    }

    # Keep the guaranteed order and make every value a float.
    features = {name: float(features[name]) for name in FEATURE_NAMES}

    details = {
        "downloads": download_details,
        "code": code,
        "network": network,
        "files": files,
        "api": {key: value for key, value in api.items() if key != "categories"},
        "release": release_details,
        "drift": drift_details,
        "has_source_code": bool(observation["source_code"]),
        "has_behavior_data": bool(
            behavior["api_calls"] or behavior["network_connections"] or behavior["file_accesses"]
        ),
    }

    return features, details


def collect_known_bigrams(observations):
    """Learn which API category transitions occur in NORMAL packages."""

    known = set()

    for observation in observations:
        categories = [categorize_api_call(call) for call in observation["behavior"]["api_calls"]]
        known.update(zip(categories, categories[1:]))

    return known

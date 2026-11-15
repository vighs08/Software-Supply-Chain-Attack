"""
Stage 1 tests: statistics, code analysis, data preparation and
feature extraction.
"""

import pytest

from anomaly.behavior_analysis import analyze_api_calls, analyze_files, analyze_network
from anomaly.code_analysis import analyze_code, shannon_entropy
from anomaly.data_preparation import InvalidObservation, prepare_observation
from anomaly.features import FEATURE_NAMES, extract_features
from anomaly.stat_methods import is_iqr_outlier, robust_z_score, z_score


# ---------------- Statistics ----------------

def test_z_score_flags_large_value():
    history = [100, 102, 98, 101, 99]
    assert abs(z_score(100, history)) < 1
    assert z_score(200, history) > 10


def test_robust_z_score_ignores_single_old_outlier():
    # One old huge spike should not hide a new one.
    history = [100, 105, 95, 100, 5000, 102]
    assert robust_z_score(1000, history) > 10
    assert abs(robust_z_score(101, history)) < 1


def test_iqr_outlier():
    history = [0.05, 0.1, 0.08, 0.12, 0.07]
    assert is_iqr_outlier(3.0, history)
    assert not is_iqr_outlier(0.09, history)


def test_statistics_need_enough_history():
    assert z_score(10, [1]) == 0.0
    assert robust_z_score(10, [1, 2]) == 0.0
    assert not is_iqr_outlier(10, [1, 2])


# ---------------- Code analysis ----------------

NORMAL_CODE = """
function add(a, b) {
  return a + b;
}
module.exports = { add };
"""

OBFUSCATED_CODE = (
    "var _0x=['\x68\x74\x74\x70\x3a\x2f\x2f\x31'];"
    "eval(atob('" + "QUJDRGVmZ2hpams0NTY3OCsv" * 10 + "'));"
)


def test_normal_code_has_no_indicators():
    result = analyze_code(NORMAL_CODE)
    assert result["obfuscation_indicators"] == 0
    assert result["long_line_ratio"] == 0


def test_obfuscated_code_is_detected():
    result = analyze_code(OBFUSCATED_CODE)
    assert result["obfuscation_indicators"] >= 3
    assert "dynamic_eval" in result["matched_patterns"]
    assert "base64_decode" in result["matched_patterns"]


def test_entropy_of_random_text_is_higher():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("aZ9$kq2!Lm") > shannon_entropy("aaaabbbb")


# ---------------- Behaviour analysis ----------------

def test_network_analysis():
    result = analyze_network([
        {"host": "registry.npmjs.org", "port": 443},
        {"host": "45.33.12.9", "port": 4444},
        {"host": "localhost", "port": 8080},
    ])
    assert result["unexpected_hosts"] == ["45.33.12.9"]
    assert result["raw_ip_hosts"] == ["45.33.12.9"]
    assert result["unusual_ports"] == [4444]


def test_file_analysis():
    result = analyze_files([
        {"path": "/home/dev/.ssh/id_rsa", "mode": "read"},
        {"path": "/home/dev/.bashrc", "mode": "write"},
        {"path": "/tmp/build/out.js", "mode": "write"},
    ])
    assert result["sensitive_reads"] == ["/home/dev/.ssh/id_rsa"]
    assert result["system_writes"] == ["/home/dev/.bashrc"]


def test_api_sequence_detection():
    calls = ["process.env", "Buffer.from", "https.request"]
    result = analyze_api_calls(calls)
    assert "data_exfiltration" in result["matched_sequences"]

    normal = analyze_api_calls(["fs.readFile", "JSON.parse", "fs.writeFile"])
    assert normal["matched_sequences"] == []


def test_novel_bigram_ratio():
    known = {("fs_read", "other")}
    result = analyze_api_calls(["fs.readFile", "JSON.parse", "eval"], known)
    # fs_read->other is known, other->dynamic_code is new: 1 of 2.
    assert result["novel_bigram_ratio"] == 0.5


# ---------------- Data preparation ----------------

def test_prepare_requires_name_and_version():
    with pytest.raises(InvalidObservation):
        prepare_observation({"version": "1.0"})
    with pytest.raises(InvalidObservation):
        prepare_observation({"package_name": "x"})


def test_prepare_rejects_bad_types():
    with pytest.raises(InvalidObservation):
        prepare_observation({"package_name": "x", "version": "1", "download_history": "lots"})
    with pytest.raises(InvalidObservation):
        prepare_observation({"package_name": "x", "version": "1",
                             "current_release": {"released_at": "yesterday"}})


def test_prepare_fills_defaults():
    prepared = prepare_observation({"package_name": " demo ", "version": "1.0.0"})
    assert prepared["package_name"] == "demo"
    assert prepared["behavior"]["api_calls"] == []
    assert prepared["release_history"] == []


# ---------------- Feature extraction ----------------

def _observation(**overrides):
    base = {
        "package_name": "demo",
        "version": "1.4.0",
        "download_history": [1000, 1100, 950, 1050, 1000, 1020],
        "release_history": [
            {"version": "1.0.0", "released_at": "2025-11-01", "size_bytes": 9400, "author": "alice", "dependencies": ["a"]},
            {"version": "1.0.1", "released_at": "2025-12-01", "size_bytes": 9800, "author": "alice", "dependencies": ["a"]},
            {"version": "1.1.0", "released_at": "2026-01-01", "size_bytes": 10000, "author": "alice", "dependencies": ["a"]},
            {"version": "1.2.0", "released_at": "2026-02-01", "size_bytes": 10500, "author": "alice", "dependencies": ["a"]},
            {"version": "1.3.0", "released_at": "2026-03-01", "size_bytes": 11000, "author": "alice", "dependencies": ["a"]},
        ],
        "current_release": {"released_at": "2026-04-01", "size_bytes": 11200, "author": "alice", "dependencies": ["a"]},
        "source_code": NORMAL_CODE,
    }
    base.update(overrides)
    return prepare_observation(base)


def test_feature_vector_has_all_features_in_order():
    features, _ = extract_features(_observation())
    assert list(features) == FEATURE_NAMES
    assert all(isinstance(value, float) for value in features.values())


def test_normal_release_features_are_small():
    features, _ = extract_features(_observation())
    assert abs(features["download_spike_score"]) < 3
    assert features["new_author"] == 0
    assert features["size_change_log"] < 0.1
    assert features["drift_score"] == 0


def test_takeover_release_features():
    observation = _observation(
        download_history=[1000, 1100, 950, 1050, 1000, 90000],
        current_release={"released_at": "2026-03-02", "size_bytes": 95000,
                         "author": "mallory", "dependencies": ["a", "flatmap-stream"],
                         "has_install_script": True},
    )
    features, details = extract_features(observation)
    assert features["download_spike_score"] > 10
    assert features["new_author"] == 1
    assert features["author_changed"] == 1
    assert features["size_change_log"] > 3
    assert features["new_dependency_count"] == 1
    assert features["install_script_added"] == 1
    assert features["drift_score"] > 0
    assert details["release"]["size_change_iqr_outlier"] is True

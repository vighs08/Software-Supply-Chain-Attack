"""
Stage 2 tests: ML model, detector and integrity integration.

All data used here is SYNTHETIC (see anomaly/sample_data.py).
"""

import json
from pathlib import Path

import pytest

from anomaly.data_preparation import InvalidObservation
from anomaly.integrity_signals import integrity_findings, normalize_integrity
from anomaly.model import AnomalyModel, ModelNotTrainedError
from anomaly.sample_data import (
    SUSPICIOUS_SCENARIOS,
    generate_normal_dataset,
    generate_suspicious_dataset,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLES = PROJECT_ROOT / "data" / "samples"


def _load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


# ---------------- Model ----------------

def test_model_save_and_load(trained_model, tmp_path):
    path = trained_model.save(tmp_path / "model.joblib")
    loaded = AnomalyModel.load(path)
    assert loaded.metadata["data_source"] == "synthetic-test"
    assert loaded.feature_names == trained_model.feature_names


def test_missing_model_gives_clear_error(tmp_path):
    with pytest.raises(ModelNotTrainedError, match="python -m anomaly.train_model"):
        AnomalyModel.load(tmp_path / "missing.joblib")


def test_training_needs_enough_data():
    with pytest.raises(ValueError):
        AnomalyModel().fit(generate_normal_dataset(10), data_source="synthetic")


def test_suspicious_packages_score_more_unusual(detector):
    normal = [detector.analyze(x)["ml"]["anomaly_percentile"] for x in generate_normal_dataset(60, seed=500)]
    attacks = [
        detector.analyze(x)["ml"]["anomaly_percentile"]
        for x in generate_suspicious_dataset(5, seed=501)
        if x["scenario"] in ("maintainer_takeover", "dropper", "credential_stealer")
    ]
    assert sorted(attacks)[len(attacks) // 2] > 0.95
    assert sorted(normal)[len(normal) // 2] < 0.8


# ---------------- Detector: normal data ----------------

def test_normal_sample_file_is_normal(detector):
    result = detector.analyze(_load("normal_package.json"))
    assert result["verdict"] == "NORMAL"
    assert result["severity"] is None
    assert result["findings"] == []
    assert result["input_is_synthetic"] is True


def test_false_positive_rate_on_synthetic_normal_data(detector):
    results = [detector.analyze(x) for x in generate_normal_dataset(200, seed=777)]
    flagged = sum(r["verdict"] == "SUSPICIOUS" for r in results)
    # Expect a low but non-zero rate: anomaly detection is never perfect.
    assert flagged / len(results) <= 0.05


# ---------------- Detector: suspicious data ----------------

EXPECTED_CODES = {
    "maintainer_takeover": {"CODE_OBFUSCATION", "SUSPICIOUS_NETWORK", "PACKAGE_DRIFT"},
    "credential_stealer": {"SENSITIVE_FILE_ACCESS", "SUSPICIOUS_API_SEQUENCE"},
    "dropper": {"SYSTEM_FILE_WRITE", "SUSPICIOUS_API_SEQUENCE", "SUSPICIOUS_NETWORK"},
    "sabotage_burst": {"RELEASE_BURST", "SIZE_CHANGE"},
    "download_inflation": {"DOWNLOAD_SPIKE"},
    "tampered_artifact": {"INTEGRITY_HASH_FAILED", "INTEGRITY_SIGNATURE_FAILED"},
}


@pytest.mark.parametrize("scenario", list(SUSPICIOUS_SCENARIOS))
def test_each_scenario_is_flagged_with_the_right_reasons(detector, scenario):
    samples = [x for x in generate_suspicious_dataset(3, seed=11) if x["scenario"] == scenario]
    for sample in samples:
        result = detector.analyze(sample)
        codes = {f["code"] for f in result["findings"]}
        assert result["verdict"] == "SUSPICIOUS", (scenario, result["summary"])
        assert EXPECTED_CODES[scenario] <= codes, (scenario, codes)


def test_credential_stealer_sample_file(detector):
    result = detector.analyze(_load("suspicious_credential_stealer.json"))
    assert result["verdict"] == "SUSPICIOUS"
    assert result["severity"] in ("High", "Critical")
    features = [r["feature"] for r in result["ml"]["top_unusual_features"]]
    assert "sensitive_file_reads" in features


def test_maintainer_takeover_sample_file_is_critical(detector):
    result = detector.analyze(_load("suspicious_maintainer_takeover.json"))
    assert result["severity"] == "Critical"
    assert result["risk_score"] >= 90
    assert any(f["code"] == "NEW_AUTHOR" for f in result["findings"])


def test_findings_are_sorted_most_severe_first(detector):
    result = detector.analyze(_load("suspicious_maintainer_takeover.json"))
    order = ["Critical", "High", "Medium", "Low"]
    ranks = [order.index(f["severity"]) for f in result["findings"]]
    assert ranks == sorted(ranks)


def test_invalid_input_raises(detector):
    with pytest.raises(InvalidObservation):
        detector.analyze({"package_name": "x"})


# ---------------- Integrity integration ----------------

def test_integrity_shapes_are_normalised():
    flat = {"hash": "PASS", "signature": "NOT_CHECKED", "source": "TRUSTED"}
    engine = {"hash_verification": {"status": "PASS"}, "signature_verification": {"status": "FAIL"}}
    db_row = {"hash_status": "FAIL", "attestation_status": "PASS"}

    assert normalize_integrity(flat)["signature"] == "NOT_CHECKED"
    assert normalize_integrity(engine)["signature"] == "FAIL"
    assert normalize_integrity(db_row)["hash"] == "FAIL"
    assert normalize_integrity(None)["hash"] == "NOT_PROVIDED"


def test_integrity_failures_become_findings():
    _, findings, risk, not_checked = integrity_findings(
        {"hash": "FAIL", "signature": "NOT_CHECKED", "source": "UNKNOWN", "version": "PASS"}
    )
    codes = {f["code"]: f["severity"] for f in findings}
    assert codes == {"INTEGRITY_HASH_FAILED": "Critical", "INTEGRITY_SOURCE_FAILED": "Medium"}
    assert "signature" in not_checked
    assert 0 < risk <= 1


def test_integrity_failure_alone_makes_package_suspicious(detector):
    sample = _load("normal_package.json")
    sample["integrity"]["hash"] = "FAIL"
    result = detector.analyze(sample)
    assert result["severity"] == "Critical"
    assert result["verdict"] == "SUSPICIOUS"


def test_real_integrity_engine_output_is_accepted(detector, monkeypatch):
    """Run the EXISTING verify_package() and feed its result to the detector."""

    from integrity.package_info import PackageInfo
    from integrity.verification_engine import verify_package

    # verify_package uses paths relative to the project folder.
    monkeypatch.chdir(PROJECT_ROOT)
    package = PackageInfo(
        name="test-package", version="1.0.0", ecosystem="python",
        file_path="samples/test_package.txt",
        expected_hash="a1bfdd904c055dfefe3f46804f992a65e2977b0203bc653ea2900640e1557b5b",
        expected_version="1.0.0", actual_version="1.0.0", source="pypi.org",
    )
    verification = verify_package(package)

    sample = _load("normal_package.json")
    sample["integrity"] = verification
    result = detector.analyze(sample)

    assert result["integrity"]["statuses"]["hash"] == "PASS"
    assert result["integrity"]["statuses"]["signature"] == "NOT_CHECKED"
    assert "signature" in result["integrity"]["not_checked"]

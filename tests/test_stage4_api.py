"""
Stage 4 tests: Flask API.

Uses the REAL Flask app from api.py with the Flask test client. The
database is replaced by InMemoryAlertRepository and the model by the
small test model, so these tests run without PostgreSQL.
"""

import json
from pathlib import Path

import pytest

from alerts.alert_service import AlertService
from alerts.email_notifier import EmailSettings
from api import app as flask_app
from database.alert_repository import InMemoryAlertRepository

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def _load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


@pytest.fixture
def client(detector):
    repo = InMemoryAlertRepository()
    flask_app.config.update(
        TESTING=True,
        ALERT_REPOSITORY=repo,
        ANOMALY_DETECTOR=detector,
        ALERT_SERVICE=AlertService(repo, EmailSettings(enabled=False)),
    )
    with flask_app.test_client() as test_client:
        test_client.repo = repo
        yield test_client
    for key in ("ALERT_REPOSITORY", "ANOMALY_DETECTOR", "ALERT_SERVICE"):
        flask_app.config.pop(key, None)


def test_existing_home_endpoint_still_works(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.get_json() == {"message": "SSCA-Defender API is running"}


def test_existing_verify_validation_still_works(client):
    response = client.post("/verify", json={"package": "x"})
    assert response.status_code == 400


def test_analyze_normal_package(client):
    response = client.post("/anomaly/analyze", json=_load("normal_package.json"))
    body = response.get_json()

    assert response.status_code == 200
    assert body["detection"]["verdict"] == "NORMAL"
    assert body["response"]["alert_action"] == "NO_ALERT"
    assert body["response"]["alert"] is None


def test_analyze_suspicious_package_creates_alert(client):
    response = client.post("/anomaly/analyze", json=_load("suspicious_maintainer_takeover.json"))
    body = response.get_json()

    assert response.status_code == 200
    assert body["detection"]["severity"] == "Critical"
    alert = body["response"]["alert"]
    assert body["response"]["alert_action"] == "CREATED"
    assert alert["status_label"] == "New"
    assert alert["needs_attention"] is True
    assert alert["email_status"] == "DISABLED"
    assert "fingerprint" not in alert
    assert isinstance(alert["detected_at"], str)     # datetime serialised


def test_analyze_rejects_bad_input(client):
    assert client.post("/anomaly/analyze", data="not json").status_code == 400
    response = client.post("/anomaly/analyze", json={"package_name": "x"})
    assert response.status_code == 400
    assert "version" in response.get_json()["error"]


def test_analyze_uses_stored_verification_results(client):
    # Simulate a row written earlier by POST /verify (save_audit_record).
    client.repo.verifications.append({
        "id": 42, "package_name": "tidy-config", "package_version": "2.5.0",
        "hash_status": "FAIL", "signature_status": "NOT_CHECKED", "source_status": "TRUSTED",
        "version_status": "PASS", "attestation_status": "PASS",
    })
    sample = _load("normal_package.json")
    del sample["integrity"]

    body = client.post("/anomaly/analyze", json=sample).get_json()

    assert body["detection"]["integrity"]["source"] == "verification_records#42"
    assert body["detection"]["severity"] == "Critical"
    assert any(f["code"] == "INTEGRITY_HASH_FAILED" for f in body["detection"]["findings"])


def test_model_info(client):
    body = client.get("/anomaly/model").get_json()
    assert body["model"]["algorithm"] == "IsolationForest"
    assert body["model"]["data_source"] == "synthetic-test"


def test_alert_listing_filters_and_triage(client):
    for name in ("suspicious_credential_stealer.json", "suspicious_maintainer_takeover.json"):
        client.post("/anomaly/analyze", json=_load(name))

    listing = client.get("/alerts").get_json()
    assert listing["count"] == 2
    assert listing["alerts"][0]["severity"] == "Critical"      # most severe first

    critical_id = listing["alerts"][0]["id"]
    other_id = listing["alerts"][1]["id"]

    # Review one alert in detail.
    detail = client.get(f"/alerts/{other_id}").get_json()
    assert detail["reasons"] and detail["recommendations"]
    assert detail["history"] == []

    # Triage: Under Review, then False Positive.
    response = client.patch(f"/alerts/{other_id}/status",
                            json={"status": "Under Review", "analyst": "vighnesh"})
    assert response.status_code == 200
    assert response.get_json()["status_label"] == "Under Review"

    response = client.patch(f"/alerts/{other_id}/status", json={"status": "False Positive"})
    assert response.status_code == 400                         # action_taken missing

    response = client.patch(f"/alerts/{other_id}/status",
                            json={"status": "False Positive", "action_taken": "Expected telemetry"})
    body = response.get_json()
    assert body["status"] == "FALSE_POSITIVE"
    assert body["needs_attention"] is False
    assert len(body["history"]) == 2

    # Only the critical alert still needs attention.
    open_alerts = client.get("/alerts?needs_attention=true").get_json()
    assert [a["id"] for a in open_alerts["alerts"]] == [critical_id]
    assert client.get("/alerts?status=false positive").get_json()["count"] == 1
    assert client.get("/alerts?severity=critical").get_json()["count"] == 1

    summary = client.get("/alerts/summary").get_json()
    assert summary["needs_attention"] == 1
    assert summary["by_status"] == {"NEW": 1, "FALSE_POSITIVE": 1}


def test_alert_api_errors(client):
    assert client.get("/alerts/999").status_code == 404
    assert client.patch("/alerts/999/status", json={"status": "Resolved", "action_taken": "x"}).status_code == 404
    assert client.patch("/alerts/1/status", json={}).status_code == 400
    assert client.get("/alerts?status=closed").status_code == 400
    assert client.get("/alerts?severity=extreme").status_code == 400
    assert client.get("/alerts?needs_attention=maybe").status_code == 400
    assert client.get("/alerts?limit=abc").status_code == 400


def test_database_unavailable_returns_503(detector, monkeypatch):
    """Without SSCA_DB_PASSWORD the PostgreSQL repository cannot connect."""

    monkeypatch.delenv("SSCA_DB_PASSWORD", raising=False)
    flask_app.config.update(TESTING=True, ANOMALY_DETECTOR=detector)
    for key in ("ALERT_REPOSITORY", "ALERT_SERVICE"):
        flask_app.config.pop(key, None)

    try:
        with flask_app.test_client() as test_client:
            assert test_client.get("/alerts").status_code == 503
            response = test_client.post("/anomaly/analyze", json=_load("suspicious_credential_stealer.json"))
            body = response.get_json()
            assert response.status_code == 503
            assert body["stored"] is False
            assert body["detection"]["verdict"] == "SUSPICIOUS"   # analysis still shown
    finally:
        for key in ("ALERT_REPOSITORY", "ANOMALY_DETECTOR", "ALERT_SERVICE"):
            flask_app.config.pop(key, None)


def test_unreachable_database_gives_clear_503(detector):
    """A PostgreSQL server that cannot be reached is reported as 503, not 500."""

    import socket

    import psycopg

    from database.alert_repository import DatabaseUnavailableError, PostgresAlertRepository

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]

    repo = PostgresAlertRepository(
        lambda: psycopg.connect(host="127.0.0.1", port=closed_port, dbname="x",
                                user="x", password="x", connect_timeout=3)
    )
    with pytest.raises(DatabaseUnavailableError):
        repo.list_alerts()

    flask_app.config.update(TESTING=True, ALERT_REPOSITORY=repo, ANOMALY_DETECTOR=detector)
    flask_app.config.pop("ALERT_SERVICE", None)
    try:
        with flask_app.test_client() as test_client:
            response = test_client.get("/alerts")
            assert response.status_code == 503
            assert "Database unavailable" in response.get_json()["error"]
    finally:
        for key in ("ALERT_REPOSITORY", "ANOMALY_DETECTOR", "ALERT_SERVICE"):
            flask_app.config.pop(key, None)


def test_bad_email_configuration_gives_clear_error(detector, monkeypatch):
    monkeypatch.setenv("SSCA_SMTP_PORT", "not-a-number")
    flask_app.config.update(TESTING=True, ALERT_REPOSITORY=InMemoryAlertRepository(),
                            ANOMALY_DETECTOR=detector)
    flask_app.config.pop("ALERT_SERVICE", None)
    try:
        with flask_app.test_client() as test_client:
            response = test_client.post("/anomaly/analyze", json=_load("suspicious_credential_stealer.json"))
            body = response.get_json()
            assert response.status_code == 500
            assert "SSCA_SMTP_PORT" in body["error"]
            assert body["detection"]["verdict"] == "SUSPICIOUS"
            assert body["stored"] is False
    finally:
        for key in ("ALERT_REPOSITORY", "ANOMALY_DETECTOR", "ALERT_SERVICE"):
            flask_app.config.pop(key, None)

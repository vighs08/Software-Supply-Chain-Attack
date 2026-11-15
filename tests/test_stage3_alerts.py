"""
Stage 3 tests: alert generation, duplicate suppression, email
notifications and triage management.

Email is tested against a REAL local SMTP server (aiosmtpd) started by
the test - no real credentials or mailboxes are used.
"""

import email
import json
import socket
from pathlib import Path

import pytest
from aiosmtpd.controller import Controller

from alerts.alert_service import AlertService, alert_fingerprint
from alerts.email_notifier import EmailSettings, build_alert_email, send_alert_email
from alerts.recommendations import recommend
from alerts.triage import TriageError, change_status, normalize_status
from database.alert_repository import InMemoryAlertRepository

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def _load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


# ---------------- Local SMTP test server ----------------

class _CollectingHandler:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append({
            "from": envelope.mail_from,
            "to": list(envelope.rcpt_tos),
            "message": email.message_from_bytes(envelope.content),
        })
        return "250 Message accepted for delivery"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def smtp_server():
    handler = _CollectingHandler()
    controller = Controller(handler, hostname="127.0.0.1", port=_free_port())
    controller.start()
    yield controller, handler
    controller.stop()


def _email_settings(port, **overrides):
    settings = EmailSettings(
        enabled=True, host="127.0.0.1", port=port, use_starttls=False,
        sender="ssca-defender@example.test", recipients=["security-team@example.test"],
        min_severity="High",
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


# ---------------- Alert generation ----------------

def test_normal_package_creates_no_alert(detector):
    repo = InMemoryAlertRepository()
    service = AlertService(repo, _email_settings(1, enabled=False))

    outcome = service.process_detection(detector.analyze(_load("normal_package.json")))

    assert outcome["alert_action"] == "NO_ALERT"
    assert len(repo.detections) == 1      # the analysis is still stored
    assert repo.alerts == []


def test_suspicious_package_creates_alert_and_sends_email(detector, smtp_server):
    controller, handler = smtp_server
    repo = InMemoryAlertRepository()
    service = AlertService(repo, _email_settings(controller.port))

    result = detector.analyze(_load("suspicious_maintainer_takeover.json"))
    outcome = service.process_detection(result)

    assert outcome["alert_action"] == "CREATED"
    alert = outcome["alert"]
    assert alert["status"] == "NEW"
    assert alert["severity"] == "Critical"
    assert alert["email_status"] == "SENT"
    assert alert["email_sent_at"] is not None
    assert alert["recommendations"]

    # The SMTP server really received one email with the key details.
    assert len(handler.messages) == 1
    received = handler.messages[0]
    assert received["to"] == ["security-team@example.test"]
    body = received["message"].get_payload()
    assert "stream-merge-utils" in received["message"]["Subject"]
    assert "Critical" in received["message"]["Subject"]
    for text in ("Version:        3.3.6", "Detected at:", "What was detected:",
                 "Recommended actions:", "Obfuscated code detected"):
        assert text in body


def test_duplicate_alert_is_suppressed(detector, smtp_server):
    controller, handler = smtp_server
    repo = InMemoryAlertRepository()
    service = AlertService(repo, _email_settings(controller.port))
    sample = _load("suspicious_maintainer_takeover.json")

    first = service.process_detection(detector.analyze(sample))
    second = service.process_detection(detector.analyze(sample))

    assert first["alert_action"] == "CREATED"
    assert second["alert_action"] == "DUPLICATE_SUPPRESSED"
    assert len(repo.alerts) == 1
    assert repo.alerts[0]["occurrence_count"] == 2
    assert len(handler.messages) == 1      # no second email
    assert len(repo.detections) == 2       # but both analyses are stored


def test_false_positive_suppresses_but_resolved_allows_new_alert(detector):
    repo = InMemoryAlertRepository()
    service = AlertService(repo, _email_settings(1, enabled=False))
    sample = _load("suspicious_credential_stealer.json")

    alert_id = service.process_detection(detector.analyze(sample))["alert"]["id"]
    change_status(repo, alert_id, "False Positive", action_taken="Known internal telemetry")
    assert service.process_detection(detector.analyze(sample))["alert_action"] == "DUPLICATE_SUPPRESSED"

    change_status(repo, alert_id, "Under Review")
    change_status(repo, alert_id, "Resolved", action_taken="Removed package, rotated keys")
    # The problem came back after being resolved: that deserves a new alert.
    assert service.process_detection(detector.analyze(sample))["alert_action"] == "CREATED"
    assert len(repo.alerts) == 2


def test_different_problem_gets_new_alert(detector):
    sample = _load("suspicious_credential_stealer.json")
    first = detector.analyze(sample)
    sample["integrity"]["hash"] = "FAIL"
    second = detector.analyze(sample)
    assert alert_fingerprint(first) != alert_fingerprint(second)


def test_medium_alert_does_not_email(detector, smtp_server):
    controller, handler = smtp_server
    repo = InMemoryAlertRepository()
    service = AlertService(repo, _email_settings(controller.port))

    sample = _load("normal_package.json")
    sample["integrity"]["source"] = "UNKNOWN"      # Medium integrity finding
    outcome = service.process_detection(detector.analyze(sample))

    assert outcome["alert"]["severity"] == "Medium"
    assert outcome["alert"]["email_status"] == "NOT_REQUIRED"
    assert handler.messages == []


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        AlertService(InMemoryAlertRepository(), EmailSettings(), alert_min_severity="Severe")


# ---------------- Email settings and failures ----------------

def test_email_disabled_or_unconfigured_is_recorded(detector):
    repo = InMemoryAlertRepository()
    result = detector.analyze(_load("suspicious_maintainer_takeover.json"))

    disabled = AlertService(repo, EmailSettings(enabled=False)).process_detection(result)
    assert disabled["alert"]["email_status"] == "DISABLED"

    status, detail = send_alert_email(disabled["alert"], EmailSettings(enabled=True))
    assert status == "DISABLED"
    assert "SSCA_SMTP_HOST" in detail and "SSCA_EMAIL_TO" in detail


def test_email_failure_is_recorded_not_raised(detector):
    repo = InMemoryAlertRepository()
    # Nothing listens on this port, so the connection is refused.
    service = AlertService(repo, _email_settings(_free_port(), timeout=3))
    outcome = service.process_detection(detector.analyze(_load("suspicious_maintainer_takeover.json")))

    assert outcome["alert_action"] == "CREATED"
    assert outcome["alert"]["email_status"] == "FAILED"
    assert outcome["alert"]["email_error"]


def test_settings_come_from_environment(monkeypatch):
    monkeypatch.setenv("SSCA_EMAIL_ENABLED", "true")
    monkeypatch.setenv("SSCA_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SSCA_SMTP_PORT", "2525")
    monkeypatch.setenv("SSCA_SMTP_PASSWORD", "not-a-real-secret")
    monkeypatch.setenv("SSCA_EMAIL_TO", "a@example.test, b@example.test")
    monkeypatch.setenv("SSCA_EMAIL_MIN_SEVERITY", "critical")

    settings = EmailSettings.from_env()

    assert settings.enabled and settings.port == 2525
    assert settings.recipients == ["a@example.test", "b@example.test"]
    assert settings.min_severity == "Critical"
    assert "not-a-real-secret" not in repr(settings)   # password never printed


def test_email_subject_cannot_be_injected():
    alert = {
        "id": 1, "package_name": "evil\r\nBcc: victim@example.test", "package_version": "1.0",
        "ecosystem": "npm", "severity": "High", "risk_score": 70, "summary": "x",
        "detected_at": "2026-01-01", "reasons": [], "recommendations": [],
    }
    message = build_alert_email(alert, _email_settings(25))
    assert "\n" not in message["Subject"]
    assert message["Bcc"] is None


# ---------------- Recommendations ----------------

def test_recommendations_are_ordered_and_unique():
    findings = [
        {"code": "SENSITIVE_FILE_ACCESS"}, {"code": "SENSITIVE_FILE_ACCESS"}, {"code": "NEW_AUTHOR"},
    ]
    actions = recommend(findings, "High")
    assert actions[0].startswith("Block the package version")
    assert len(actions) == len(set(actions))
    assert any("rotate SSH keys" in a for a in actions)


# ---------------- Triage ----------------

@pytest.fixture
def repo_with_alert(detector):
    repo = InMemoryAlertRepository()
    service = AlertService(repo, EmailSettings(enabled=False))
    alert = service.process_detection(detector.analyze(_load("suspicious_credential_stealer.json")))["alert"]
    return repo, alert["id"]


def test_status_names_are_normalised():
    assert normalize_status("Under Review") == "UNDER_REVIEW"
    assert normalize_status("false-positive") == "FALSE_POSITIVE"
    with pytest.raises(TriageError):
        normalize_status("Closed")


def test_full_triage_workflow(repo_with_alert):
    repo, alert_id = repo_with_alert

    alert = change_status(repo, alert_id, "Under Review", analyst="vighnesh", notes="Checking install logs")
    assert alert["status"] == "UNDER_REVIEW"
    assert alert["assigned_to"] == "vighnesh"

    alert = change_status(repo, alert_id, "Resolved", action_taken="Removed package; rotated SSH and AWS keys")
    assert alert["status"] == "RESOLVED"
    assert alert["action_taken"] == "Removed package; rotated SSH and AWS keys"
    assert alert["closed_at"] is not None

    history = alert["history"]
    assert [(h["old_status"], h["new_status"]) for h in history] == [
        ("NEW", "UNDER_REVIEW"), ("UNDER_REVIEW", "RESOLVED"),
    ]


def test_closing_requires_action_taken(repo_with_alert):
    repo, alert_id = repo_with_alert
    with pytest.raises(TriageError, match="action_taken is required"):
        change_status(repo, alert_id, "Resolved")


def test_invalid_transition_is_rejected(repo_with_alert):
    repo, alert_id = repo_with_alert
    change_status(repo, alert_id, "False Positive", action_taken="Expected behaviour")
    with pytest.raises(TriageError) as error:
        change_status(repo, alert_id, "Resolved", action_taken="x")
    assert error.value.http_status == 409


def test_unknown_alert(repo_with_alert):
    repo, _ = repo_with_alert
    with pytest.raises(TriageError) as error:
        change_status(repo, 999, "Under Review")
    assert error.value.http_status == 404


def test_needs_attention_tracking(detector):
    repo = InMemoryAlertRepository()
    service = AlertService(repo, EmailSettings(enabled=False))
    ids = [
        service.process_detection(detector.analyze(_load(name)))["alert"]["id"]
        for name in ("suspicious_credential_stealer.json", "suspicious_maintainer_takeover.json")
    ]
    change_status(repo, ids[0], "False Positive", action_taken="Known telemetry")

    open_alerts = repo.list_alerts(needs_attention=True)
    assert [a["id"] for a in open_alerts] == [ids[1]]
    assert repo.summary()["by_status"] == {"FALSE_POSITIVE": 1, "NEW": 1}
    assert repo.summary()["open_by_severity"] == {"Critical": 1}


# ---------------- Configuration checks (added in the integration stage) ----------------

def test_invalid_port_or_severity_gives_clear_error(monkeypatch):
    monkeypatch.setenv("SSCA_SMTP_PORT", "five-eight-seven")
    with pytest.raises(ValueError, match="SSCA_SMTP_PORT"):
        EmailSettings.from_env()

    monkeypatch.setenv("SSCA_SMTP_PORT", "587")
    monkeypatch.setenv("SSCA_EMAIL_MIN_SEVERITY", "severe")
    with pytest.raises(ValueError, match="SSCA_EMAIL_MIN_SEVERITY"):
        EmailSettings.from_env()


def test_smtp_check_logs_in_without_sending(smtp_server):
    from alerts.email_notifier import check_smtp_connection

    controller, handler = smtp_server
    status, detail = check_smtp_connection(_email_settings(controller.port))
    assert status == "OK", detail
    assert handler.messages == []          # nothing was sent

    status, detail = check_smtp_connection(_email_settings(_free_port(), timeout=3))
    assert status == "FAILED"

    status, detail = check_smtp_connection(EmailSettings(enabled=True))
    assert status == "DISABLED" and "SSCA_SMTP_HOST" in detail


def test_email_check_tool_send_test(smtp_server, monkeypatch, capsys, trained_model, tmp_path):
    """The command-line tool sends exactly one [TEST] email through the real pipeline."""

    from alerts import email_check
    from anomaly.detector import AnomalyDetector

    controller, handler = smtp_server
    for key, value in {
        "SSCA_EMAIL_ENABLED": "true", "SSCA_SMTP_HOST": "127.0.0.1",
        "SSCA_SMTP_PORT": str(controller.port), "SSCA_SMTP_STARTTLS": "false",
        "SSCA_EMAIL_FROM": "ssca@example.test", "SSCA_EMAIL_TO": "team@example.test",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(AnomalyDetector, "load", classmethod(lambda cls: cls(trained_model)))

    assert email_check.main([]) == 0
    assert handler.messages == []          # check mode sends nothing

    assert email_check.main(["--send-test"]) == 0
    assert len(handler.messages) == 1
    message = handler.messages[0]["message"]
    assert message["Subject"].startswith("[SSCA-Defender][TEST]")
    assert "TEST EMAIL using SYNTHETIC sample data" in message.get_payload()
    assert "Email status: SENT" in capsys.readouterr().out

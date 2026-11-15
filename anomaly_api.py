
"""
Flask API endpoints for the Anomaly Detection System, alerts and triage.

Registered in api.py as a Blueprint, so the existing /verify endpoint
is unchanged.

  POST  /anomaly/analyze          analyse one package observation
  GET   /anomaly/model            information about the trained model
  GET   /alerts                   list alerts (filters: status, severity,
                                  needs_attention, limit)
  GET   /alerts/summary           counts per status / open alerts per severity
  GET   /alerts/<id>              one alert with reasons, actions and history
  PATCH /alerts/<id>/status       change the triage status
"""

import json
from datetime import date, datetime

import psycopg
from flask import Blueprint, current_app, jsonify, request

from alerts.alert_service import AlertService
from alerts.triage import STATUS_LABELS, TriageError, change_status, normalize_status
from anomaly.data_preparation import InvalidObservation
from anomaly.detector import SEVERITY_ORDER, AnomalyDetector
from anomaly.model import DEFAULT_MODEL_PATH, ModelNotTrainedError
from database.alert_repository import DatabaseUnavailableError, PostgresAlertRepository


anomaly_bp = Blueprint("anomaly", __name__)

# Errors that mean "the database could not be used".
DATABASE_ERRORS = (psycopg.Error, DatabaseUnavailableError)


# --------------------------------------------------
# Helpers: create shared objects once per application
# --------------------------------------------------

def get_repository():
    if "ALERT_REPOSITORY" not in current_app.config:
        current_app.config["ALERT_REPOSITORY"] = PostgresAlertRepository()
    return current_app.config["ALERT_REPOSITORY"]


def get_detector():
    if "ANOMALY_DETECTOR" not in current_app.config:
        current_app.config["ANOMALY_DETECTOR"] = AnomalyDetector.load()
    return current_app.config["ANOMALY_DETECTOR"]


def get_alert_service():
    if "ALERT_SERVICE" not in current_app.config:
        current_app.config["ALERT_SERVICE"] = AlertService(get_repository())
    return current_app.config["ALERT_SERVICE"]


def to_json(value):
    """Convert database values (datetimes, ...) into JSON-friendly ones."""

    if isinstance(value, dict):
        return {key: to_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [to_json(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def present_alert(alert):
    """Add human-friendly labels to an alert before returning it."""

    if alert is None:
        return None
    alert = to_json(alert)
    alert.pop("fingerprint", None)
    alert["status_label"] = STATUS_LABELS.get(alert["status"], alert["status"])
    alert["needs_attention"] = alert["status"] in ("NEW", "UNDER_REVIEW")
    return alert


def database_unavailable(extra=None):
    current_app.logger.exception("Database operation failed")
    body = {
        "error": "Database unavailable. Check that PostgreSQL is running, "
                 "SSCA_DB_PASSWORD is set and the tables exist "
                 "(python -m database.init_anomaly_tables)."
    }
    body.update(extra or {})
    return jsonify(body), 503


# --------------------------------------------------
# Anomaly detection
# --------------------------------------------------

@anomaly_bp.route("/anomaly/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    try:
        detector = get_detector()
    except ModelNotTrainedError as exc:
        return jsonify({"error": str(exc)}), 503

    # Use integrity results stored by POST /verify when the request does
    # not include them.
    integrity_source = "request" if data.get("integrity") else "none"
    if not data.get("integrity") and isinstance(data.get("package_name"), str) \
            and isinstance(data.get("version"), str):
        try:
            stored = get_repository().get_latest_verification(data["package_name"], data["version"])
        except DATABASE_ERRORS:
            current_app.logger.warning("Could not look up stored verification results")
            stored = None
        if stored:
            data = dict(data, integrity=stored)
            integrity_source = f"verification_records#{stored.get('id')}"

    try:
        detection = detector.analyze(data)
    except InvalidObservation as exc:
        return jsonify({"error": str(exc)}), 400

    detection["integrity"]["source"] = integrity_source

    try:
        service = get_alert_service()
    except ValueError as exc:
        # e.g. SSCA_SMTP_PORT is not a number or a severity name is misspelled
        current_app.logger.error("Alert configuration error: %s", exc)
        return jsonify({
            "error": f"Alert configuration error: {exc}",
            "detection": to_json(detection),
            "stored": False,
        }), 500

    try:
        outcome = service.process_detection(detection)
    except DATABASE_ERRORS:
        # Still show the analysis, but make it clear nothing was stored.
        return database_unavailable({"detection": to_json(detection), "stored": False})

    outcome["alert"] = present_alert(outcome["alert"])
    return jsonify(to_json({"detection": detection, "response": outcome})), 200


@anomaly_bp.route("/anomaly/model", methods=["GET"])
def model_info():
    try:
        detector = get_detector()
    except ModelNotTrainedError as exc:
        return jsonify({"error": str(exc)}), 503

    report_path = DEFAULT_MODEL_PATH.with_name("training_report.json")
    report = None
    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report.pop("model", None)

    return jsonify({"model": detector.model.metadata, "evaluation": report}), 200


# --------------------------------------------------
# Alerts and triage
# --------------------------------------------------

@anomaly_bp.route("/alerts", methods=["GET"])
def list_alerts():
    status = request.args.get("status")
    severity = request.args.get("severity")
    needs_attention = request.args.get("needs_attention")

    try:
        if status:
            status = normalize_status(status)
    except TriageError as exc:
        return jsonify({"error": str(exc)}), 400

    if severity:
        severity = severity.strip().capitalize()
        if severity not in SEVERITY_ORDER:
            return jsonify({"error": "severity must be Low, Medium, High or Critical"}), 400

    if needs_attention is not None:
        if needs_attention.lower() not in ("true", "false"):
            return jsonify({"error": "needs_attention must be true or false"}), 400
        needs_attention = needs_attention.lower() == "true"

    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 500)
    except ValueError:
        return jsonify({"error": "limit must be a number"}), 400

    try:
        alerts = get_repository().list_alerts(status, severity, needs_attention, limit)
    except DATABASE_ERRORS:
        return database_unavailable()

    return jsonify({"count": len(alerts), "alerts": [present_alert(a) for a in alerts]}), 200


@anomaly_bp.route("/alerts/summary", methods=["GET"])
def alerts_summary():
    try:
        summary = get_repository().summary()
    except DATABASE_ERRORS:
        return database_unavailable()

    summary["needs_attention"] = sum(
        summary["by_status"].get(status, 0) for status in ("NEW", "UNDER_REVIEW")
    )
    return jsonify(summary), 200


@anomaly_bp.route("/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):
    try:
        alert = get_repository().get_alert(alert_id)
    except DATABASE_ERRORS:
        return database_unavailable()

    if alert is None:
        return jsonify({"error": f"Alert {alert_id} not found"}), 404

    return jsonify(present_alert(alert)), 200


@anomaly_bp.route("/alerts/<int:alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id):
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or "status" not in data:
        return jsonify({"error": "Request body must be a JSON object with a 'status' field"}), 400

    try:
        alert = change_status(
            get_repository(), alert_id, data["status"],
            action_taken=data.get("action_taken"),
            analyst=data.get("analyst"),
            notes=data.get("notes"),
        )
    except TriageError as exc:
        return jsonify({"error": str(exc)}), exc.http_status
    except DATABASE_ERRORS:
        return database_unavailable()

    return jsonify(present_alert(alert)), 200

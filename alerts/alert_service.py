
"""
Alert generation and response.

What happens after the detector has analysed a package:

  1. The detection result is saved (every analysis, normal or not).
  2. If the severity is high enough (default: Medium or above), an
     alert is needed.
  3. DUPLICATE CHECK: a "fingerprint" is built from the package, the
     version and the kinds of problems found. If an alert with the
     same fingerprint is still New, Under Review, or was marked False
     Positive, NO new alert and NO new email are created - only the
     occurrence counter of the existing alert goes up.
  4. Otherwise a new alert is stored with recommended actions.
  5. If the severity reaches the email threshold (default: High), an
     email is sent and the email result is stored with the alert.
"""

import hashlib
import os
from datetime import datetime, timezone

from anomaly.detector import SEVERITY_RANK

from .email_notifier import EmailSettings, send_alert_email
from .recommendations import recommend


def alert_fingerprint(result):
    """
    Identify "the same problem in the same package version".

    The ML finding is left out when other findings exist, because the
    ML score can move slightly after re-training while the underlying
    problem stays the same.
    """

    codes = sorted({f["code"] for f in result["findings"] if f["code"] != "ML_ANOMALY"})
    if not codes:
        codes = ["ML_ANOMALY"]

    text = "|".join([
        result["ecosystem"], result["package_name"].lower(), result["version"], *codes,
    ])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _meets(severity, minimum):
    return severity is not None and SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum]


class AlertService:
    def __init__(self, repository, email_settings=None, alert_min_severity=None, smtp_factory=None):
        self.repository = repository
        self.email_settings = email_settings or EmailSettings.from_env()
        self.alert_min_severity = (
            alert_min_severity
            or os.environ.get("SSCA_ALERT_MIN_SEVERITY", "Medium").strip().capitalize()
        )
        self.smtp_factory = smtp_factory   # only used by tests

        for value in (self.alert_min_severity, self.email_settings.min_severity):
            if value not in SEVERITY_RANK:
                raise ValueError(f"Unknown severity '{value}'. Use Low, Medium, High or Critical")

    def process_detection(self, result):
        """Store the detection and create/suppress/email an alert as needed."""

        detection_id = self.repository.save_detection(result)
        response = {"detection_id": detection_id, "alert_action": None, "alert": None, "email": None}

        # ---- 2. Is an alert needed? ----
        if not _meets(result["severity"], self.alert_min_severity):
            response["alert_action"] = "NO_ALERT"
            response["reason"] = (
                f"Severity {result['severity'] or 'None'} is below the alert "
                f"threshold ({self.alert_min_severity})"
            )
            return response

        # ---- 3. Duplicate check ----
        fingerprint = alert_fingerprint(result)
        existing = self.repository.find_suppressing_alert(fingerprint)

        if existing is not None:
            alert = self.repository.record_repeat(existing["id"])
            response.update({
                "alert_action": "DUPLICATE_SUPPRESSED",
                "alert": alert,
                "reason": (
                    f"Alert #{existing['id']} for the same problem already exists "
                    f"(status {existing['status']}); no new alert or email was sent"
                ),
            })
            return response

        # ---- 4. Create the alert ----
        alert = self.repository.create_alert({
            "fingerprint": fingerprint,
            "detection_id": detection_id,
            "package_name": result["package_name"],
            "package_version": result["version"],
            "ecosystem": result["ecosystem"],
            "severity": result["severity"],
            "risk_score": result["risk_score"],
            "summary": result["summary"],
            "reasons": result["findings"],
            "recommendations": recommend(result["findings"], result["severity"]),
            "detected_at": datetime.now(timezone.utc),
        })
        response["alert_action"] = "CREATED"

        # ---- 5. Email ----
        if _meets(result["severity"], self.email_settings.min_severity):
            status, error = send_alert_email(alert, self.email_settings, self.smtp_factory)
        else:
            status, error = "NOT_REQUIRED", (
                f"Severity below email threshold ({self.email_settings.min_severity})"
            )

        alert = self.repository.update_email_status(alert["id"], status, error)
        response["alert"] = alert
        response["email"] = {"status": status, "detail": error}
        return response

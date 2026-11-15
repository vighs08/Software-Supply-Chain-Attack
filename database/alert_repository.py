
"""
Storage for anomaly detections, security alerts and triage history.

Two implementations with the SAME methods:

  PostgresAlertRepository  - the real one. Uses the project's existing
                             PostgreSQL database and get_connection()
                             from database/audit_logger.py.

  InMemoryAlertRepository  - keeps everything in Python lists. Used by
                             the automated tests and the offline demo
                             when PostgreSQL is not available. Data is
                             lost when the program stops.

Alerts and history are returned as plain dictionaries.
"""

from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from database.audit_logger import get_connection


# Statuses that mean "an alert for this problem already exists, do not
# raise it again". RESOLVED is not included: if a resolved problem comes
# back, that is worth a new alert.
SUPPRESSING_STATUSES = ("NEW", "UNDER_REVIEW", "FALSE_POSITIVE")
OPEN_STATUSES = ("NEW", "UNDER_REVIEW")
CLOSED_STATUSES = ("RESOLVED", "FALSE_POSITIVE")


def _now():
    return datetime.now(timezone.utc)


class DatabaseUnavailableError(RuntimeError):
    """PostgreSQL is not configured or cannot be reached."""


# ==================================================
# PostgreSQL implementation
# ==================================================

class PostgresAlertRepository:
    def __init__(self, connection_factory=get_connection):
        self.connection_factory = connection_factory

    def _connect(self):
        try:
            conn = self.connection_factory()
        except KeyError as exc:
            # get_connection() reads os.environ["SSCA_DB_PASSWORD"].
            raise DatabaseUnavailableError(
                f"Environment variable {exc} is not set"
            ) from None
        except psycopg.OperationalError as exc:
            raise DatabaseUnavailableError(
                "Could not connect to PostgreSQL (is the service running "
                "and is the password correct?)"
            ) from exc

        conn.row_factory = dict_row
        return conn

    # ---- detections ----

    def save_detection(self, result):
        query = """
            INSERT INTO anomaly_detections (
                package_name, package_version, ecosystem, verdict, severity,
                risk_score, anomaly_percentile, ml_raw_score, findings,
                features, integrity_statuses, input_is_synthetic, model_trained_at
            )
            VALUES (
                %(package_name)s, %(version)s, %(ecosystem)s, %(verdict)s, %(severity)s,
                %(risk_score)s, %(percentile)s, %(raw_score)s, %(findings)s,
                %(features)s, %(integrity)s, %(synthetic)s, %(trained_at)s
            )
            RETURNING id;
        """
        params = {
            "package_name": result["package_name"],
            "version": result["version"],
            "ecosystem": result["ecosystem"],
            "verdict": result["verdict"],
            "severity": result["severity"],
            "risk_score": result["risk_score"],
            "percentile": result["ml"]["anomaly_percentile"],
            "raw_score": result["ml"]["raw_score"],
            "findings": Jsonb(result["findings"]),
            "features": Jsonb(result["features"]),
            "integrity": Jsonb(result["integrity"]["statuses"]),
            "synthetic": result["input_is_synthetic"],
            "trained_at": result["model"]["trained_at"],
        }

        with self._connect() as conn:
            return conn.execute(query, params).fetchone()["id"]

    # ---- alerts ----

    def find_suppressing_alert(self, fingerprint):
        query = """
            SELECT * FROM security_alerts
            WHERE fingerprint = %s AND status = ANY(%s)
            ORDER BY id DESC LIMIT 1;
        """
        with self._connect() as conn:
            return conn.execute(query, (fingerprint, list(SUPPRESSING_STATUSES))).fetchone()

    def create_alert(self, alert):
        query = """
            INSERT INTO security_alerts (
                fingerprint, detection_id, package_name, package_version, ecosystem,
                severity, risk_score, summary, reasons, recommendations, detected_at, last_seen_at
            )
            VALUES (
                %(fingerprint)s, %(detection_id)s, %(package_name)s, %(package_version)s,
                %(ecosystem)s, %(severity)s, %(risk_score)s, %(summary)s, %(reasons)s,
                %(recommendations)s, %(detected_at)s, %(detected_at)s
            )
            RETURNING *;
        """
        params = dict(alert)
        params["reasons"] = Jsonb(alert["reasons"])
        params["recommendations"] = Jsonb(alert["recommendations"])

        with self._connect() as conn:
            return conn.execute(query, params).fetchone()

    def record_repeat(self, alert_id):
        query = """
            UPDATE security_alerts
            SET occurrence_count = occurrence_count + 1, last_seen_at = NOW()
            WHERE id = %s
            RETURNING *;
        """
        with self._connect() as conn:
            return conn.execute(query, (alert_id,)).fetchone()

    def update_email_status(self, alert_id, status, error=None):
        query = """
            UPDATE security_alerts
            SET email_status = %s,
                email_error = %s,
                email_sent_at = CASE WHEN %s = 'SENT' THEN NOW() ELSE email_sent_at END
            WHERE id = %s
            RETURNING *;
        """
        with self._connect() as conn:
            return conn.execute(query, (status, error, status, alert_id)).fetchone()

    def list_alerts(self, status=None, severity=None, needs_attention=None, limit=100):
        conditions, params = [], []

        if status:
            conditions.append("status = %s")
            params.append(status)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if needs_attention is True:
            conditions.append("status = ANY(%s)")
            params.append(list(OPEN_STATUSES))
        elif needs_attention is False:
            conditions.append("status = ANY(%s)")
            params.append(list(CLOSED_STATUSES))

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        # Most severe first, then newest first.
        query = f"""
            SELECT * FROM security_alerts {where}
            ORDER BY CASE severity
                WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                WHEN 'Medium' THEN 2 ELSE 1 END DESC,
                detected_at DESC
            LIMIT %s;
        """
        params.append(limit)

        with self._connect() as conn:
            return conn.execute(query, params).fetchall()

    def get_alert(self, alert_id):
        with self._connect() as conn:
            alert = conn.execute(
                "SELECT * FROM security_alerts WHERE id = %s;", (alert_id,)
            ).fetchone()

            if alert is None:
                return None

            alert["history"] = conn.execute(
                "SELECT * FROM alert_triage_history WHERE alert_id = %s ORDER BY id;",
                (alert_id,),
            ).fetchall()

        return alert

    def update_status(self, alert_id, old_status, new_status, action_taken, analyst, notes):
        """Change the status and write a history row in ONE transaction."""

        update = """
            UPDATE security_alerts
            SET status = %(new)s,
                action_taken = COALESCE(%(action)s, action_taken),
                assigned_to = COALESCE(%(analyst)s, assigned_to),
                updated_at = NOW(),
                closed_at = CASE WHEN %(new)s IN ('RESOLVED', 'FALSE_POSITIVE')
                                 THEN NOW() ELSE NULL END
            WHERE id = %(id)s AND status = %(old)s
            RETURNING id;
        """
        history = """
            INSERT INTO alert_triage_history
                (alert_id, old_status, new_status, action_taken, analyst, notes)
            VALUES (%(id)s, %(old)s, %(new)s, %(action)s, %(analyst)s, %(notes)s);
        """
        params = {
            "id": alert_id, "old": old_status, "new": new_status,
            "action": action_taken, "analyst": analyst, "notes": notes,
        }

        with self._connect() as conn:
            updated = conn.execute(update, params).fetchone()
            if updated is None:
                # Someone else changed the status at the same time.
                return False
            conn.execute(history, params)

        return True

    def summary(self):
        with self._connect() as conn:
            by_status = conn.execute(
                "SELECT status, COUNT(*) AS count FROM security_alerts GROUP BY status;"
            ).fetchall()
            open_by_severity = conn.execute(
                "SELECT severity, COUNT(*) AS count FROM security_alerts "
                "WHERE status = ANY(%s) GROUP BY severity;",
                (list(OPEN_STATUSES),),
            ).fetchall()

        return {
            "by_status": {row["status"]: row["count"] for row in by_status},
            "open_by_severity": {row["severity"]: row["count"] for row in open_by_severity},
        }

    # ---- integration with the Integrity Verification Module ----

    def get_latest_verification(self, package_name, package_version):
        """Most recent row written by the existing save_audit_record()."""

        query = """
            SELECT * FROM verification_records
            WHERE package_name = %s AND package_version = %s
            ORDER BY id DESC LIMIT 1;
        """
        with self._connect() as conn:
            return conn.execute(query, (package_name, package_version)).fetchone()


# ==================================================
# In-memory implementation (tests / offline demo)
# ==================================================

class InMemoryAlertRepository:
    def __init__(self):
        self.detections = []
        self.alerts = []
        self.history = []
        self.verifications = []

    def save_detection(self, result):
        self.detections.append(dict(result))
        return len(self.detections)

    def find_suppressing_alert(self, fingerprint):
        matches = [
            alert for alert in self.alerts
            if alert["fingerprint"] == fingerprint and alert["status"] in SUPPRESSING_STATUSES
        ]
        return dict(matches[-1]) if matches else None

    def create_alert(self, alert):
        stored = dict(alert)
        stored.update({
            "id": len(self.alerts) + 1,
            "status": "NEW",
            "action_taken": None,
            "assigned_to": None,
            "occurrence_count": 1,
            "email_status": "PENDING",
            "email_error": None,
            "email_sent_at": None,
            "last_seen_at": alert["detected_at"],
            "updated_at": alert["detected_at"],
            "closed_at": None,
        })
        self.alerts.append(stored)
        return dict(stored)

    def _find(self, alert_id):
        return next((alert for alert in self.alerts if alert["id"] == alert_id), None)

    def record_repeat(self, alert_id):
        alert = self._find(alert_id)
        alert["occurrence_count"] += 1
        alert["last_seen_at"] = _now()
        return dict(alert)

    def update_email_status(self, alert_id, status, error=None):
        alert = self._find(alert_id)
        alert["email_status"] = status
        alert["email_error"] = error
        if status == "SENT":
            alert["email_sent_at"] = _now()
        return dict(alert)

    def list_alerts(self, status=None, severity=None, needs_attention=None, limit=100):
        rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        result = [
            alert for alert in self.alerts
            if (status is None or alert["status"] == status)
            and (severity is None or alert["severity"] == severity)
            and (needs_attention is None
                 or (alert["status"] in OPEN_STATUSES) == needs_attention)
        ]
        result.sort(key=lambda a: (rank[a["severity"]], a["detected_at"]), reverse=True)
        return [dict(alert) for alert in result[:limit]]

    def get_alert(self, alert_id):
        alert = self._find(alert_id)
        if alert is None:
            return None
        result = dict(alert)
        result["history"] = [dict(h) for h in self.history if h["alert_id"] == alert_id]
        return result

    def update_status(self, alert_id, old_status, new_status, action_taken, analyst, notes):
        alert = self._find(alert_id)
        if alert is None or alert["status"] != old_status:
            return False

        now = _now()
        alert["status"] = new_status
        alert["action_taken"] = action_taken or alert["action_taken"]
        alert["assigned_to"] = analyst or alert["assigned_to"]
        alert["updated_at"] = now
        alert["closed_at"] = now if new_status in CLOSED_STATUSES else None

        self.history.append({
            "id": len(self.history) + 1,
            "alert_id": alert_id,
            "old_status": old_status,
            "new_status": new_status,
            "action_taken": action_taken,
            "analyst": analyst,
            "notes": notes,
            "changed_at": now,
        })
        return True

    def summary(self):
        by_status, open_by_severity = {}, {}
        for alert in self.alerts:
            by_status[alert["status"]] = by_status.get(alert["status"], 0) + 1
            if alert["status"] in OPEN_STATUSES:
                open_by_severity[alert["severity"]] = open_by_severity.get(alert["severity"], 0) + 1
        return {"by_status": by_status, "open_by_severity": open_by_severity}

    def get_latest_verification(self, package_name, package_version):
        matches = [
            row for row in self.verifications
            if row["package_name"] == package_name and row["package_version"] == package_version
        ]
        return dict(matches[-1]) if matches else None


"""
Create the anomaly detection / alert / triage tables in PostgreSQL.

Usage (SSCA_DB_PASSWORD must be set):

    python -m database.init_anomaly_tables

Uses the existing connection settings from database/audit_logger.py,
so the tables are created in the same ssca_defender_db database as
verification_records. Existing tables and data are not touched
(CREATE TABLE IF NOT EXISTS).
"""

from pathlib import Path

from database.audit_logger import get_connection


SCHEMA_FILE = Path(__file__).resolve().parent / "anomaly_schema.sql"


def create_tables(connection_factory=get_connection):
    sql = SCHEMA_FILE.read_text(encoding="utf-8")

    with connection_factory() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql)


if __name__ == "__main__":
    create_tables()
    print("Anomaly detection tables are ready: "
          "anomaly_detections, security_alerts, alert_triage_history")

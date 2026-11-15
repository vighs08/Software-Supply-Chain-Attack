
"""
READ-ONLY check of the PostgreSQL connection.

    python -m database.check_connection

Uses the existing get_connection() from database/audit_logger.py and
reports:
  * whether the connection works (the password is never printed)
  * PostgreSQL version, database and user
  * which SSCA-Defender tables exist, and how many rows they contain
  * whether verification_records has the columns save_audit_record() needs

It only runs SELECT queries. Nothing is created, changed or deleted.
"""

import sys

import psycopg

from database.audit_logger import get_connection


EXISTING_TABLE = "verification_records"
NEW_TABLES = ["anomaly_detections", "security_alerts", "alert_triage_history"]

AUDIT_COLUMNS = {
    "package_name", "package_version", "ecosystem", "file_name", "sha256", "sha512",
    "hash_status", "signature_status", "source_status", "version_status",
    "attestation_status", "overall_status",
}


def main():
    try:
        conn = get_connection()
    except KeyError:
        print("NOT CONFIGURED: environment variable SSCA_DB_PASSWORD is not set.")
        return 1
    except psycopg.OperationalError as exc:
        # The message comes from the server/driver and never contains the password.
        print("CONNECTION FAILED:", str(exc).strip().splitlines()[0])
        return 1

    with conn:
        row = conn.execute("SELECT version(), current_database(), current_user").fetchone()
        print("Connection:      OK")
        print("Server:         ", row[0].split(",")[0])
        print("Database / user:", row[1], "/", row[2])

        existing = {
            name for (name,) in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            ).fetchall()
        }

        print("\nTables (public schema):")
        for table in [EXISTING_TABLE] + NEW_TABLES:
            if table in existing:
                # Table names come from the fixed list above, not from user input.
                count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                print(f"  {table:24s} exists, {count} row(s)")
            else:
                print(f"  {table:24s} MISSING")

        if EXISTING_TABLE in existing:
            columns = {
                name for (name,) in conn.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = %s",
                    (EXISTING_TABLE,),
                ).fetchall()
            }
            missing = sorted(AUDIT_COLUMNS - columns)
            print("\nverification_records columns needed by save_audit_record():",
                  "all present" if not missing else "MISSING " + ", ".join(missing))

        if not set(NEW_TABLES) <= existing:
            print("\nThe anomaly tables can be created with:  python -m database.init_anomaly_tables")

    return 0


if __name__ == "__main__":
    sys.exit(main())

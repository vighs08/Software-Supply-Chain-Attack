
import os
import psycopg


def get_connection():
    """Connect to the SSCA-Defender PostgreSQL database."""

    return psycopg.connect(
        host="localhost",
        port=5432,
        dbname="ssca_defender_db",
        user="postgres",
        password=os.environ["SSCA_DB_PASSWORD"]
    )


def save_audit_record(record):
    """Save one package verification result to the audit database."""

    query = """
        INSERT INTO verification_records (
            package_name,
            package_version,
            ecosystem,
            file_name,
            sha256,
            sha512,
            hash_status,
            signature_status,
            source_status,
            version_status,
            attestation_status,
            overall_status
        )
        VALUES (
            %(package_name)s,
            %(package_version)s,
            %(ecosystem)s,
            %(file_name)s,
            %(sha256)s,
            %(sha512)s,
            %(hash_status)s,
            %(signature_status)s,
            %(source_status)s,
            %(version_status)s,
            %(attestation_status)s,
            %(overall_status)s
        )
        RETURNING id;
    """

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, record)
            record_id = cursor.fetchone()[0]

    return record_id
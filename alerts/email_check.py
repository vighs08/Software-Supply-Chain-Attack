
"""
Check the email alert configuration (for example Gmail).

    python -m alerts.email_check
        Shows the email settings (passwords are never shown), connects to
        the SMTP server and logs in. NO email is sent.

    python -m alerts.email_check --send-test
        Sends ONE test alert email to SSCA_EMAIL_TO. The alert comes from
        the real detection pipeline (detector -> alert service -> email)
        using the SYNTHETIC sample data/samples/suspicious_maintainer_takeover.json.
        The alert is kept in memory only; nothing is written to PostgreSQL.
"""

import argparse
import json
import sys
from pathlib import Path

from alerts.alert_service import AlertService
from alerts.email_notifier import EmailSettings, check_smtp_connection
from anomaly.detector import SEVERITY_ORDER, AnomalyDetector
from database.alert_repository import InMemoryAlertRepository


SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "suspicious_maintainer_takeover.json"


def _mask(address):
    """you@gmail.com -> yo***@gmail.com"""

    name, _, domain = address.partition("@")
    return f"{name[:2]}***@{domain}" if domain else "***"


def show_settings(settings):
    print("Email settings (from environment variables):")
    print(f"  SSCA_EMAIL_ENABLED       {settings.enabled}")
    print(f"  SSCA_SMTP_HOST           {settings.host or '(not set)'}")
    print(f"  SSCA_SMTP_PORT           {settings.port}")
    print(f"  encryption               {'SSL' if settings.use_ssl else 'STARTTLS' if settings.use_starttls else 'NONE'}")
    print(f"  SSCA_SMTP_USERNAME       {_mask(settings.username) if settings.username else '(not set)'}")
    print(f"  SSCA_SMTP_PASSWORD       {'set (hidden)' if settings.password else '(not set)'}")
    print(f"  SSCA_EMAIL_FROM          {_mask(settings.sender) if settings.sender else '(not set)'}")
    print(f"  SSCA_EMAIL_TO            {', '.join(_mask(a) for a in settings.recipients) or '(not set)'}")
    emailed = SEVERITY_ORDER[SEVERITY_ORDER.index(settings.min_severity):]
    print(f"  SSCA_EMAIL_MIN_SEVERITY  {settings.min_severity}  (emails are sent for: {', '.join(emailed)})")

    if "gmail" in settings.host.lower():
        if settings.username and settings.sender and settings.username.lower() != settings.sender.lower():
            print("  WARNING: Gmail normally requires SSCA_EMAIL_FROM to be the same address as SSCA_SMTP_USERNAME.")
        if settings.password and len(settings.password.replace(" ", "")) != 16:
            print("  WARNING: a Gmail App Password has 16 letters. Your normal Gmail password will not work.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check SSCA-Defender email alerts")
    parser.add_argument("--send-test", action="store_true", help="send ONE real test alert email")
    args = parser.parse_args(argv)

    try:
        settings = EmailSettings.from_env()
    except ValueError as exc:
        print("CONFIGURATION ERROR:", exc)
        return 1

    show_settings(settings)

    print("\nConnecting and logging in (no email is sent)...")
    status, detail = check_smtp_connection(settings)
    print(f"  {status}: {detail}")
    if status != "OK":
        return 1

    if not args.send_test:
        print("\nLogin works. To send ONE test alert email, run:  python -m alerts.email_check --send-test")
        return 0

    if not settings.enabled:
        print("\nSSCA_EMAIL_ENABLED is not true - no email sent.")
        return 1

    # Real pipeline: detector -> alert service -> email. In-memory storage only.
    settings.subject_prefix = "[SSCA-Defender][TEST]"
    detector = AnomalyDetector.load()
    result = detector.analyze(json.loads(SAMPLE.read_text(encoding="utf-8")))
    result["summary"] = "TEST EMAIL using SYNTHETIC sample data - no action needed. " + result["summary"]

    outcome = AlertService(InMemoryAlertRepository(), settings).process_detection(result)
    alert = outcome["alert"]

    print(f"\nDetection: {result['verdict']} / {result['severity']}  -> alert action: {outcome['alert_action']}")
    print(f"Email status: {alert['email_status']}" + (f" ({alert['email_error']})" if alert["email_error"] else ""))
    return 0 if alert["email_status"] == "SENT" else 1


if __name__ == "__main__":
    sys.exit(main())

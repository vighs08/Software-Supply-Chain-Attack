
"""
Email alerts for suspicious package activity.

All settings come from ENVIRONMENT VARIABLES - nothing secret is stored
in the code:

  SSCA_EMAIL_ENABLED        "true" to send emails (default: false)
  SSCA_SMTP_HOST            e.g. smtp.gmail.com
  SSCA_SMTP_PORT            default 587
  SSCA_SMTP_USERNAME        optional (leave empty for no login)
  SSCA_SMTP_PASSWORD        optional - use an app password, never your real password
  SSCA_SMTP_STARTTLS        "true" (default) to upgrade the connection with STARTTLS
  SSCA_SMTP_SSL             "true" to use SMTP over SSL (port 465) instead
  SSCA_EMAIL_FROM           sender address
  SSCA_EMAIL_TO             recipients, comma separated
  SSCA_EMAIL_MIN_SEVERITY   lowest severity that is emailed (default: High)

This is only an ALERT notification channel. It is not an email
security gateway or phishing detector.
"""

import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class EmailSettings:
    enabled: bool = False
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = field(default="", repr=False)   # never printed
    use_starttls: bool = True
    use_ssl: bool = False
    sender: str = ""
    recipients: list = field(default_factory=list)
    min_severity: str = "High"
    timeout: int = 15
    subject_prefix: str = "[SSCA-Defender]"

    @classmethod
    def from_env(cls):
        port_text = os.environ.get("SSCA_SMTP_PORT", "").strip() or "587"
        if not port_text.isdigit():
            raise ValueError("SSCA_SMTP_PORT must be a whole number, for example 587")

        min_severity = os.environ.get("SSCA_EMAIL_MIN_SEVERITY", "").strip().capitalize() or "High"
        if min_severity not in ("Low", "Medium", "High", "Critical"):
            raise ValueError("SSCA_EMAIL_MIN_SEVERITY must be Low, Medium, High or Critical")

        return cls(
            enabled=_env_bool("SSCA_EMAIL_ENABLED"),
            host=os.environ.get("SSCA_SMTP_HOST", "").strip(),
            port=int(port_text),
            username=os.environ.get("SSCA_SMTP_USERNAME", "").strip(),
            password=os.environ.get("SSCA_SMTP_PASSWORD", ""),
            use_starttls=_env_bool("SSCA_SMTP_STARTTLS", True),
            use_ssl=_env_bool("SSCA_SMTP_SSL", False),
            sender=os.environ.get("SSCA_EMAIL_FROM", "").strip(),
            recipients=[
                address.strip()
                for address in os.environ.get("SSCA_EMAIL_TO", "").split(",")
                if address.strip()
            ],
            min_severity=min_severity,
        )

    def problems(self):
        """Return a list of missing settings (empty list = ready to send)."""

        missing = []
        if not self.host:
            missing.append("SSCA_SMTP_HOST")
        if not self.sender:
            missing.append("SSCA_EMAIL_FROM")
        if not self.recipients:
            missing.append("SSCA_EMAIL_TO")
        if self.username and not self.password:
            missing.append("SSCA_SMTP_PASSWORD")
        return missing


def _one_line(text):
    """Remove line breaks so user-supplied text cannot inject email headers."""

    return " ".join(str(text).split())


def _format_time(value):
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    return str(value)


def build_alert_email(alert, settings):
    """Create the email message for one alert."""

    package = f"{_one_line(alert['package_name'])} {_one_line(alert['package_version'])}"

    message = EmailMessage()
    message["Subject"] = (
        f"{settings.subject_prefix} {alert['severity']} alert #{alert['id']}: "
        f"suspicious activity in {package}"
    )
    message["From"] = settings.sender
    message["To"] = ", ".join(settings.recipients)

    reasons = "\n".join(
        f"  - [{reason['severity']}] {reason['title']}\n      {reason['evidence']}"
        for reason in alert["reasons"]
    )
    actions = "\n".join(
        f"  {number}. {action}"
        for number, action in enumerate(alert["recommendations"], start=1)
    )

    message.set_content(f"""SSCA-Defender detected suspicious package activity.

Alert ID:       {alert['id']}
Package:        {alert['package_name']}
Version:        {alert['package_version']}
Ecosystem:      {alert.get('ecosystem') or 'unknown'}
Severity:       {alert['severity']}
Risk score:     {alert['risk_score']} / 100
Detected at:    {_format_time(alert['detected_at'])}

Summary:
  {alert['summary']}

What was detected:
{reasons}

Recommended actions:
{actions}

Triage:
  This alert has status NEW. Review it and update its status
  (Under Review / Resolved / False Positive) through the SSCA-Defender API:
  PATCH /alerts/{alert['id']}/status

This message was generated automatically by the SSCA-Defender
Anomaly Detection System. Detections are based on statistical and
machine-learning analysis and must be confirmed by a person.
""")
    return message


def send_alert_email(alert, settings, smtp_factory=None):
    """
    Send the alert email.

    Returns (status, error):
      ("SENT", None)        email accepted by the SMTP server
      ("DISABLED", reason)  email turned off or not configured
      ("FAILED", reason)    sending was attempted but failed
    """

    if not settings.enabled:
        return "DISABLED", "Email alerts are disabled (SSCA_EMAIL_ENABLED is not true)"

    missing = settings.problems()
    if missing:
        return "DISABLED", "Missing email settings: " + ", ".join(missing)

    message = build_alert_email(alert, settings)

    try:
        with _open_connection(settings, smtp_factory) as server:
            server.send_message(message)

    except (OSError, smtplib.SMTPException) as exc:
        # The error is stored with the alert so the failure can be
        # investigated. SMTP errors contain the server response, not
        # the password.
        return "FAILED", f"{type(exc).__name__}: {exc}"

    return "SENT", None


def _open_connection(settings, smtp_factory=None):
    """Connect to the SMTP server, switch on encryption and log in."""

    if smtp_factory is not None:
        server = smtp_factory(settings.host, settings.port, timeout=settings.timeout)
    elif settings.use_ssl:
        server = smtplib.SMTP_SSL(
            settings.host, settings.port, timeout=settings.timeout,
            context=ssl.create_default_context(),
        )
    else:
        server = smtplib.SMTP(settings.host, settings.port, timeout=settings.timeout)

    try:
        if settings.use_starttls and not settings.use_ssl:
            server.starttls(context=ssl.create_default_context())
        if settings.username:
            server.login(settings.username, settings.password)
    except BaseException:
        server.close()
        raise

    return server


def check_smtp_connection(settings, smtp_factory=None):
    """
    Connect and log in to the SMTP server WITHOUT sending any email.

    Returns (status, detail):
      ("OK", ...)           connection, encryption and login worked
      ("DISABLED", reason)  settings are missing
      ("FAILED", reason)    the server could not be reached or login failed
    """

    missing = settings.problems()
    if missing:
        return "DISABLED", "Missing email settings: " + ", ".join(missing)

    try:
        with _open_connection(settings, smtp_factory):
            pass
    except (OSError, smtplib.SMTPException) as exc:
        return "FAILED", f"{type(exc).__name__}: {exc}"

    security = "SSL" if settings.use_ssl else ("STARTTLS" if settings.use_starttls else "no encryption")
    login = "logged in" if settings.username else "no login"
    return "OK", f"Connected to {settings.host}:{settings.port} ({security}, {login})"

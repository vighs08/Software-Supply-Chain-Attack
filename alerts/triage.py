
"""
Alert triage management.

Triage = deciding what to do with each alert. Every alert has a status:

    NEW            just created, nobody has looked at it yet
    UNDER_REVIEW   an analyst is investigating
    RESOLVED       a real problem that has been dealt with
    FALSE_POSITIVE not a real problem (the package is fine)

Allowed changes:

    NEW           -> UNDER_REVIEW, RESOLVED, FALSE_POSITIVE
    UNDER_REVIEW  -> RESOLVED, FALSE_POSITIVE
    RESOLVED      -> UNDER_REVIEW   (re-open)
    FALSE_POSITIVE-> UNDER_REVIEW   (re-open)

Closing an alert (RESOLVED / FALSE_POSITIVE) requires a short
description of the action taken, so there is always a record of what
was done. Every change is written to the triage history.

Alerts that are NEW or UNDER_REVIEW "need attention".
"""


STATUSES = ("NEW", "UNDER_REVIEW", "RESOLVED", "FALSE_POSITIVE")

STATUS_LABELS = {
    "NEW": "New",
    "UNDER_REVIEW": "Under Review",
    "RESOLVED": "Resolved",
    "FALSE_POSITIVE": "False Positive",
}

ALLOWED_TRANSITIONS = {
    "NEW": {"UNDER_REVIEW", "RESOLVED", "FALSE_POSITIVE"},
    "UNDER_REVIEW": {"RESOLVED", "FALSE_POSITIVE"},
    "RESOLVED": {"UNDER_REVIEW"},
    "FALSE_POSITIVE": {"UNDER_REVIEW"},
}

NEEDS_ACTION_TEXT = {"RESOLVED", "FALSE_POSITIVE"}

MAX_TEXT_LENGTH = 2000


class TriageError(ValueError):
    """A triage request that cannot be carried out (bad input or rule)."""

    def __init__(self, message, http_status=400):
        super().__init__(message)
        self.http_status = http_status


def normalize_status(value):
    """Accept 'Under Review', 'under_review', 'UNDER-REVIEW', ... ."""

    if not isinstance(value, str):
        raise TriageError("status must be a string")

    status = value.strip().upper().replace(" ", "_").replace("-", "_")

    if status not in STATUSES:
        raise TriageError(
            "status must be one of: " + ", ".join(STATUS_LABELS.values())
        )

    return status


def _clean_text(value, field_name):
    if value is None:
        return None
    if not isinstance(value, str):
        raise TriageError(f"{field_name} must be a string")
    value = value.strip()
    if len(value) > MAX_TEXT_LENGTH:
        raise TriageError(f"{field_name} is too long (max {MAX_TEXT_LENGTH} characters)")
    return value or None


def change_status(repository, alert_id, new_status, action_taken=None, analyst=None, notes=None):
    """Validate and apply a status change. Returns the updated alert."""

    new_status = normalize_status(new_status)
    action_taken = _clean_text(action_taken, "action_taken")
    analyst = _clean_text(analyst, "analyst")
    notes = _clean_text(notes, "notes")

    alert = repository.get_alert(alert_id)
    if alert is None:
        raise TriageError(f"Alert {alert_id} not found", http_status=404)

    old_status = alert["status"]

    if new_status == old_status:
        raise TriageError(f"Alert {alert_id} already has status {STATUS_LABELS[old_status]}")

    if new_status not in ALLOWED_TRANSITIONS[old_status]:
        allowed = ", ".join(STATUS_LABELS[s] for s in sorted(ALLOWED_TRANSITIONS[old_status]))
        raise TriageError(
            f"Cannot change status from {STATUS_LABELS[old_status]} to "
            f"{STATUS_LABELS[new_status]}. Allowed: {allowed}",
            http_status=409,
        )

    if new_status in NEEDS_ACTION_TEXT and not action_taken:
        raise TriageError(
            f"action_taken is required when marking an alert as {STATUS_LABELS[new_status]}"
        )

    changed = repository.update_status(alert_id, old_status, new_status, action_taken, analyst, notes)
    if not changed:
        raise TriageError(
            "The alert was changed by someone else at the same time. Reload and try again.",
            http_status=409,
        )

    return repository.get_alert(alert_id)

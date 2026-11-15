
"""
Bridge between the Integrity Verification Module and anomaly detection.

The integrity module answers "is this artifact the one we expected?"
(hash, signature, version, source, attestation, reproducible build,
timestamp). A failed integrity check is HARD EVIDENCE, not a
statistical guess, so it is NOT fed into the ML model. Instead every
failed check becomes a finding with a fixed severity, and it is
combined with the ML result by the detector.

This module accepts the integrity results in any of the three shapes
that already exist in the project, so the integrity code itself did not
need to change:

  1. The flat "checks" dict returned by POST /verify:
       {"hash": "PASS", "signature": "NOT_CHECKED", ...}
  2. The full dict returned by integrity.verification_engine.verify_package():
       {"hash_verification": {"status": "PASS"}, ...}
  3. A row of the PostgreSQL verification_records table:
       {"hash_status": "PASS", "signature_status": ..., ...}
"""


CHECKS = [
    "hash",
    "signature",
    "version",
    "source",
    "attestation",
    "reproducible_build",
    "timestamp",
]

# Key names used by verify_package().
_ENGINE_KEYS = {
    "hash": "hash_verification",
    "signature": "signature_verification",
    "version": "version_verification",
    "source": "source_verification",
    "attestation": "attestation_verification",
    "reproducible_build": "reproducible_build_verification",
    "timestamp": "timestamp_verification",
}

# What a FAILED check means and how serious it is.
FAILURE_RULES = {
    "hash": ("Critical", "Package hash does not match the trusted hash - the artifact may have been modified."),
    "signature": ("Critical", "Digital signature is invalid - the package may not come from the trusted publisher."),
    "attestation": ("High", "Build attestation does not match the artifact - provenance cannot be trusted."),
    "reproducible_build": ("High", "Independent builds produced different outputs - the build may have been tampered with."),
    "source": ("Medium", "Package comes from a source that is not on the trusted-source list."),
    "version": ("Medium", "Installed version differs from the expected version."),
    "timestamp": ("Medium", "Trusted timestamp could not be verified for this artifact."),
}

# Statuses that count as a positive (good) result.
GOOD_STATUSES = {"PASS", "TRUSTED", "VERIFIED"}
# Statuses that only mean "we do not know".
UNKNOWN_STATUSES = {"NOT_CHECKED", "NOT_PROVIDED", "SKIPPED", ""}

# Contribution of each failure to the 0..1 integrity risk value.
_RISK_WEIGHTS = {"Critical": 0.6, "High": 0.35, "Medium": 0.15}


def _status_from(value):
    if isinstance(value, dict):
        value = value.get("status")
    return str(value or "NOT_PROVIDED").strip().upper()


def normalize_integrity(integrity):
    """Return {check_name: STATUS} for all 7 checks."""

    if not integrity:
        return {check: "NOT_PROVIDED" for check in CHECKS}

    statuses = {}

    for check in CHECKS:
        if check in integrity:                       # shape 1
            value = integrity[check]
        elif _ENGINE_KEYS[check] in integrity:       # shape 2
            value = integrity[_ENGINE_KEYS[check]]
        elif f"{check}_status" in integrity:         # shape 3
            value = integrity[f"{check}_status"]
        else:
            value = None

        statuses[check] = _status_from(value)

    return statuses


def integrity_findings(integrity):
    """
    Convert integrity results into findings.

    Returns (statuses, findings, integrity_risk, not_checked)
      integrity_risk is a number from 0 (all fine) to 1 (very bad).
      not_checked lists checks that were skipped or not supplied.
    """

    statuses = normalize_integrity(integrity)
    findings = []
    risk = 0.0

    for check, status in statuses.items():
        if status in GOOD_STATUSES or status in UNKNOWN_STATUSES:
            continue

        # Any other value (FAIL, UNKNOWN source, ...) is a failure.
        severity, message = FAILURE_RULES[check]
        findings.append({
            "code": f"INTEGRITY_{check.upper()}_FAILED",
            "category": "integrity",
            "severity": severity,
            "title": f"Integrity check failed: {check.replace('_', ' ')}",
            "evidence": f"{message} (status: {status})",
        })
        risk += _RISK_WEIGHTS[severity]

    not_checked = [
        check for check, status in statuses.items()
        if status in UNKNOWN_STATUSES
    ]

    return statuses, findings, round(min(risk, 1.0), 4), not_checked

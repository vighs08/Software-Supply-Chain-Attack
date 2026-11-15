
"""
Mitigation recommendations: what should a developer DO about an alert?

Each finding code maps to a short list of practical actions. The final
list keeps the order (most severe findings first) and removes repeats.
"""


RECOMMENDATIONS = {
    "ML_ANOMALY": [
        "Review the 'most unusual features' listed in the alert and compare with the previous release.",
    ],
    "DOWNLOAD_SPIKE": [
        "Check whether the download spike has a legitimate reason (new release announcement, popular dependent).",
        "Watch for typosquatting or dependency-confusion packages with similar names.",
    ],
    "CODE_OBFUSCATION": [
        "Do not install or run this version until the obfuscated code has been decoded and reviewed.",
        "Compare the published package contents with the source repository.",
    ],
    "SUSPICIOUS_NETWORK": [
        "Block the contacted IP address(es) at the firewall / proxy.",
        "Check network logs of build machines for connections to the same address.",
    ],
    "UNEXPECTED_NETWORK": [
        "Confirm the contacted hosts are documented by the package; otherwise block them.",
    ],
    "SENSITIVE_FILE_ACCESS": [
        "Assume the accessed credentials are compromised: rotate SSH keys, cloud keys and registry tokens.",
        "Remove the package from all machines and CI runners where it was installed.",
    ],
    "SECRET_FILE_READ": [
        "Confirm the package is expected to read .env files; if not, rotate the secrets they contain.",
    ],
    "SYSTEM_FILE_WRITE": [
        "Inspect start-up files and shell profiles for persistence entries and remove them.",
        "Re-image affected build machines if persistence is confirmed.",
    ],
    "SUSPICIOUS_API_SEQUENCE": [
        "Run the package in an isolated sandbox and capture its full behaviour before trusting it.",
    ],
    "UNUSUAL_API_SEQUENCE": [
        "Review the new API call transitions in the package source.",
    ],
    "SIZE_CHANGE": [
        "Diff this release against the previous one to find what was added.",
    ],
    "RELEASE_BURST": [
        "Pin the last known-good version until the new releases are reviewed.",
    ],
    "UNUSUAL_RELEASE_TIMING": [
        "Check whether the package was revived after a long pause and who published the release.",
    ],
    "NEW_AUTHOR": [
        "Verify the new maintainer with the project's official channels (repository, announcements).",
    ],
    "PACKAGE_DRIFT": [
        "Review newly added dependencies and install scripts before upgrading.",
        "Pin the previous version in your lock file until the change is understood.",
    ],
    "INTEGRITY_HASH_FAILED": [
        "Do not use this artifact. Re-download it from the official registry and verify the hash again.",
        "Investigate the mirror, cache or proxy that served the modified file.",
    ],
    "INTEGRITY_SIGNATURE_FAILED": [
        "Do not use this artifact. Confirm the publisher's public key through an independent channel.",
    ],
    "INTEGRITY_ATTESTATION_FAILED": [
        "Treat the build provenance as untrusted; rebuild from verified source if possible.",
    ],
    "INTEGRITY_REPRODUCIBLE_BUILD_FAILED": [
        "Investigate the build environment for tampering; compare build logs of both builds.",
    ],
    "INTEGRITY_SOURCE_FAILED": [
        "Install the package only from a trusted registry.",
    ],
    "INTEGRITY_VERSION_FAILED": [
        "Pin the expected version in the lock file and reinstall.",
    ],
    "INTEGRITY_TIMESTAMP_FAILED": [
        "Request a new trusted timestamp or verify the artifact through another integrity check.",
    ],
}

SEVERITY_ACTIONS = {
    "Critical": "Block the package version in CI/CD immediately and start incident response.",
    "High": "Block the package version in CI/CD until an analyst has reviewed this alert.",
    "Medium": "Review this alert before the next release that includes this package version.",
    "Low": "Review when convenient; no immediate action required.",
}


def recommend(findings, severity):
    """Build an ordered, de-duplicated list of recommended actions."""

    actions = []

    if severity in SEVERITY_ACTIONS:
        actions.append(SEVERITY_ACTIONS[severity])

    for finding in findings:
        for action in RECOMMENDATIONS.get(finding["code"], []):
            if action not in actions:
                actions.append(action)

    return actions

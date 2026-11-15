
"""
The Anomaly Detector: combines three kinds of evidence into one result.

  1. ML evidence        - Isolation Forest anomaly percentile
                          ("how unusual is this package overall?")
  2. Behaviour evidence - explicit findings computed from the features
                          and statistical tests (z-score / MAD / IQR),
                          e.g. "reads ~/.ssh/id_rsa", "4x size increase"
  3. Integrity evidence - failed checks from the Integrity
                          Verification Module

This is a small "ensemble": no single signal decides alone, and every
alert can be explained in plain English.

Severity levels: Critical > High > Medium > Low.
"""

from datetime import datetime, timezone

from .data_preparation import prepare_observation
from .features import extract_features
from .integrity_signals import integrity_findings
from .model import DEFAULT_MODEL_PATH, AnomalyModel


SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER, start=1)}

# Anomaly percentile thresholds for the ML signal on its own.
ML_THRESHOLDS = [
    (0.999, "High"),
    (0.99, "Medium"),
    (0.97, "Low"),
]

# Base risk score per overall severity (0-100 scale).
RISK_BASE = {None: 0, "Low": 20, "Medium": 45, "High": 70, "Critical": 90}


def highest_severity(severities):
    severities = [s for s in severities if s]
    if not severities:
        return None
    return max(severities, key=SEVERITY_RANK.get)


def _finding(code, category, severity, title, evidence):
    return {
        "code": code,
        "category": category,
        "severity": severity,
        "title": title,
        "evidence": evidence,
    }


def behaviour_findings(features, details):
    """
    Turn feature values and evidence into readable findings.

    Returns (findings, notes). Notes are weak signals that are common in
    legitimate packages; they are shown to the analyst but do not raise
    the severity on their own (the ML model still sees them as features).
    """

    findings = []
    notes = []

    # ---- Download frequency ----
    # Both tests must agree: statistically unusual (MAD z-score) AND a
    # large real increase (ratio), so normal noise is not reported.
    z = features["download_spike_score"]
    ratio = details["downloads"].get("download_ratio") or 0
    if z >= 4 and ratio >= 3:
        findings.append(_finding(
            "DOWNLOAD_SPIKE", "downloads", "Medium" if ratio >= 10 else "Low",
            "Sudden spike in download count",
            f"Latest weekly downloads ({details['downloads']['download_latest']}) are "
            f"{ratio:.1f}x the usual level ({details['downloads']['download_usual']}); "
            f"robust z-score {z:.1f}.",
        ))

    # ---- Obfuscation / minification ----
    code = details["code"]
    if code["obfuscation_indicators"] >= 3 or (
        code["obfuscation_indicators"] >= 1 and code["entropy"] >= 5.5
    ):
        findings.append(_finding(
            "CODE_OBFUSCATION", "code", "High",
            "Obfuscated code detected",
            f"Found {code['obfuscation_indicators']} obfuscation indicators "
            f"({', '.join(code['matched_patterns'])}); entropy {code['entropy']}.",
        ))
    elif code["obfuscation_indicators"] >= 1:
        # One trick alone (e.g. decoding an embedded image) is often
        # legitimate; two different tricks are more worrying.
        findings.append(_finding(
            "CODE_OBFUSCATION", "code",
            "Medium" if code["obfuscation_indicators"] >= 2 else "Low",
            "Possible code obfuscation",
            f"Found {', '.join(code['matched_patterns'])} in the source code.",
        ))
    elif code["long_line_ratio"] > 0:
        notes.append(
            f"Minified source code (longest line {code['max_line_length']} characters). "
            "Harder to review; confirm the package normally ships minified files."
        )

    # ---- Network ----
    network = details["network"]
    files = details["files"]
    if network["raw_ip_hosts"]:
        findings.append(_finding(
            "SUSPICIOUS_NETWORK", "network", "High",
            "Connection to a raw IP address",
            f"Connected to {', '.join(network['raw_ip_hosts'])}"
            + (f" on unusual port(s) {network['unusual_ports']}" if network["unusual_ports"] else "")
            + ". Legitimate packages normally use registry domain names.",
        ))
    elif network["unexpected_hosts"]:
        # Medium when combined with secret access or a non-HTTPS port,
        # Low on its own (many libraries call documented web APIs).
        risky = files["sensitive_reads"] or files["secret_config_reads"] or network["unusual_ports"]
        findings.append(_finding(
            "UNEXPECTED_NETWORK", "network", "Medium" if risky else "Low",
            "Contacted unexpected hosts",
            f"Contacted {', '.join(network['unexpected_hosts'])}, which are not package registries"
            + (f", on port(s) {network['unusual_ports']}" if network["unusual_ports"] else "") + ".",
        ))

    # ---- File system ----
    if files["sensitive_reads"]:
        findings.append(_finding(
            "SENSITIVE_FILE_ACCESS", "filesystem", "High",
            "Access to credential or secret files",
            f"Accessed {', '.join(files['sensitive_reads'])}.",
        ))
    if files["secret_config_reads"]:
        findings.append(_finding(
            "SECRET_FILE_READ", "filesystem", "Low",
            "Project secret file read",
            f"Read {', '.join(files['secret_config_reads'])}. Normal for config "
            "libraries such as dotenv, suspicious for other packages.",
        ))
    if files["system_writes"]:
        findings.append(_finding(
            "SYSTEM_FILE_WRITE", "filesystem", "High",
            "Write to system or start-up location",
            f"Wrote to {', '.join(files['system_writes'])} (possible persistence).",
        ))

    # ---- API calls and sequences ----
    api = details["api"]
    if api["matched_sequences"]:
        findings.append(_finding(
            "SUSPICIOUS_API_SEQUENCE", "api_calls", "High",
            "Attack-like sequence of API calls",
            f"Matched pattern(s): {', '.join(api['matched_sequences'])}.",
        ))
    elif api["dangerous_calls"]:
        notes.append(
            f"Process execution / dynamic code APIs used: {', '.join(api['dangerous_calls'])}. "
            "Common for build tools, unusual for ordinary libraries."
        )
    if features["novel_api_bigram_ratio"] >= 0.5 and len(api["novel_bigrams"]) >= 2:
        findings.append(_finding(
            "UNUSUAL_API_SEQUENCE", "api_calls", "Low",
            "API call order never seen in normal packages",
            f"New transitions: {', '.join(api['novel_bigrams'][:5])}.",
        ))

    # ---- Size changes ----
    release = details["release"]
    if features["size_change_log"] >= 2:
        factor = release["current_size_bytes"] / release["previous_size_bytes"]
        findings.append(_finding(
            "SIZE_CHANGE", "release", "Medium",
            "Unexpected package size change",
            f"Size changed from {release['previous_size_bytes']} to "
            f"{release['current_size_bytes']} bytes ({factor:.2f}x).",
        ))
    elif features["size_change_log"] >= 1 and release.get("size_change_iqr_outlier"):
        findings.append(_finding(
            "SIZE_CHANGE", "release", "Low",
            "Size change larger than usual for this package",
            "The size change is an IQR outlier compared with earlier releases.",
        ))

    # ---- Update frequency ----
    if features["releases_last_7_days"] >= 3:
        findings.append(_finding(
            "RELEASE_BURST", "release", "Medium",
            "Unusual burst of releases",
            f"{int(features['releases_last_7_days'])} releases in the 7 days before this one.",
        ))
    elif features["release_interval_log"] >= 3 and "days_since_last_release" in release:
        findings.append(_finding(
            "UNUSUAL_RELEASE_TIMING", "release", "Low",
            "Unusual time since previous release",
            f"{release['days_since_last_release']} days since the last release; "
            f"the usual interval is about {release.get('usual_release_interval_days')} days.",
        ))

    # ---- Author behaviour ----
    if features["new_author"]:
        # Low on its own: projects do gain genuine new maintainers. It
        # becomes important when combined with other findings.
        findings.append(_finding(
            "NEW_AUTHOR", "author", "Low",
            "Release published by a new author",
            f"'{release['author']}' has never published this package before "
            f"(previous release by '{release['previous_author']}').",
        ))

    # ---- Package drift ----
    drift = details["drift"]
    drift_reasons = []
    if features["install_script_added"]:
        drift_reasons.append("an install script was added")
    if features["drift_score"] >= 0.5:
        drift_reasons.append(f"{features['drift_score']:.0%} of capabilities changed")
    if drift_reasons:
        added = ", ".join(drift.get("added_capabilities", [])[:6])
        findings.append(_finding(
            "PACKAGE_DRIFT", "drift", "Medium",
            "Package behaviour drifted from the previous release",
            "; ".join(drift_reasons).capitalize() + (f". New: {added}." if added else "."),
        ))

    return findings, notes


class AnomalyDetector:
    def __init__(self, model):
        self.model = model

    @classmethod
    def load(cls, path=DEFAULT_MODEL_PATH):
        return cls(AnomalyModel.load(path))

    def analyze(self, raw_observation):
        """
        Analyse one package observation and return an explainable result.

        Raises anomaly.data_preparation.InvalidObservation for bad input.
        """

        observation = prepare_observation(raw_observation)
        features, details = extract_features(observation, self.model.known_bigrams)

        # 1. ML evidence
        ml = self.model.score(features)
        ml_severity = next(
            (severity for threshold, severity in ML_THRESHOLDS
             if ml["anomaly_percentile"] >= threshold),
            None,
        )
        ml["severity"] = ml_severity
        ml["top_unusual_features"] = self.model.explain(features)

        findings = []
        if ml_severity:
            names = ", ".join(r["feature"] for r in ml["top_unusual_features"][:3]) or "combination of features"
            findings.append(_finding(
                "ML_ANOMALY", "machine_learning", ml_severity,
                "Machine learning model flagged unusual behaviour",
                f"More unusual than {ml['anomaly_percentile']:.1%} of normal training "
                f"packages. Most unusual: {names}.",
            ))

        # 2. Behaviour evidence
        behaviour, notes = behaviour_findings(features, details)
        findings += behaviour

        # 3. Integrity evidence
        statuses, integrity_list, integrity_risk, not_checked = integrity_findings(
            observation["integrity"]
        )
        findings += integrity_list

        severity = self._overall_severity(findings, ml_severity)
        findings.sort(key=lambda f: SEVERITY_RANK[f["severity"]], reverse=True)

        risk_score = RISK_BASE[severity] + round(10 * ml["anomaly_percentile"])
        if severity is None:
            risk_score = round(19 * ml["anomaly_percentile"])

        if severity in ("Medium", "High", "Critical"):
            verdict = "SUSPICIOUS"
        elif severity == "Low":
            verdict = "REVIEW"
        else:
            verdict = "NORMAL"

        return {
            "package_name": observation["package_name"],
            "version": observation["version"],
            "ecosystem": observation["ecosystem"],
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "verdict": verdict,
            "severity": severity,
            "risk_score": min(risk_score, 100),
            "summary": self._summary(verdict, severity, findings),
            "findings": findings,
            "notes": notes,
            "ml": ml,
            "integrity": {
                "statuses": statuses,
                "risk": integrity_risk,
                "not_checked": not_checked,
            },
            "features": {name: round(value, 4) for name, value in features.items()},
            "data_coverage": {
                "download_history": len(observation["download_history"]) >= 5,
                "release_history": bool(observation["release_history"]),
                "source_code": details["has_source_code"],
                "behavior": details["has_behavior_data"],
                "integrity": observation["integrity"] is not None,
            },
            "input_is_synthetic": observation["synthetic"],
            "model": {
                "algorithm": self.model.metadata.get("algorithm"),
                "trained_at": self.model.metadata.get("trained_at"),
                "training_data_source": self.model.metadata.get("data_source"),
            },
        }

    @staticmethod
    def _overall_severity(findings, ml_severity):
        severity = highest_severity(f["severity"] for f in findings)

        strong = [f for f in findings if SEVERITY_RANK[f["severity"]] >= SEVERITY_RANK["High"]]
        strong_behaviour = [f for f in strong if f["category"] not in ("machine_learning", "integrity")]

        # Escalate to Critical when independent strong signals agree.
        if len(strong) >= 3 or (ml_severity == "High" and strong_behaviour):
            severity = "Critical"

        return severity

    @staticmethod
    def _summary(verdict, severity, findings):
        if verdict == "NORMAL":
            return "No unusual behaviour detected."

        titles = [f["title"] for f in findings[:3]]
        more = len(findings) - len(titles)
        text = f"{severity} risk: " + "; ".join(titles)
        if more > 0:
            text += f" (+{more} more)"
        return text + "."

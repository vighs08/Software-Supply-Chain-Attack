# SSCA-Defender — Anomaly Detection System (ML)

This document explains the Anomaly Detection System module: what it does, how it works, how to run it, and what its limits are.

It covers **Component 2 (Anomaly Detection System)** of the project guide (`Software supply chain attack.html`), together with two additional features requested on top of the guide:

| Source | Feature |
|---|---|
| **Project guide (HTML), Component 2 / Core Features table** | ML anomaly detection, statistical anomaly detection (z-score, IQR, MAD), behavioural profiling, deviation from baselines, package drift detection |
| **Project guide (HTML), Component 6** (partially) | Email alerting and the mitigation-recommendation engine |
| **Additional requirement** (not in the HTML) | Email alert workflow with duplicate suppression, alert triage management (New / Under Review / Resolved / False Positive) |

---

## 1. How the pieces fit together

```text
 package observation (JSON)
            │
            ▼
 anomaly/data_preparation.py   validate + clean the input
            │
            ▼
 anomaly/features.py           22 numeric features
   ├─ code_analysis.py         obfuscation / minification
   ├─ behavior_analysis.py     network, files, API calls & sequences
   └─ stat_methods.py          z-score, MAD, IQR
            │
            ▼
 anomaly/detector.py  ◄── anomaly/model.py (Isolation Forest)
            │         ◄── anomaly/integrity_signals.py (Integrity Verification results)
            ▼
 detection result: verdict, severity, risk score, findings, explanation
            │
            ▼
 alerts/alert_service.py       store result → create alert or suppress duplicate
   ├─ alerts/recommendations.py recommended actions
   └─ alerts/email_notifier.py  email (SMTP)
            │
            ▼
 database/alert_repository.py  PostgreSQL (same database as verification_records)
            │
            ▼
 alerts/triage.py + anomaly_api.py   view and triage alerts via the Flask API
```

## 2. New files

| File | Purpose |
|---|---|
| `anomaly/data_preparation.py` | Checks that an input observation is valid and fills in safe defaults. Gives readable error messages. |
| `anomaly/stat_methods.py` | Statistical tests: classic z-score, robust z-score (median + MAD) and the IQR outlier rule. |
| `anomaly/code_analysis.py` | Measures obfuscation: character entropy, line lengths, `eval`, base64 decoding, hex escapes, long encoded strings. Reads the code and never runs it. |
| `anomaly/behavior_analysis.py` | Analyses network connections, file accesses and API calls, including ordered **API call sequences** such as "read secrets → encode → send over network". |
| `anomaly/features.py` | Turns one observation into 22 numbers, the input the ML model needs. |
| `anomaly/model.py` | The Isolation Forest model: training, scoring, explanation, save/load. |
| `anomaly/integrity_signals.py` | Converts Integrity Verification results into findings. |
| `anomaly/detector.py` | Combines ML, behaviour and integrity evidence into one explainable result. |
| `anomaly/sample_data.py` | **Synthetic** data generator: normal packages plus 6 simulated attack scenarios. |
| `anomaly/train_model.py` | Command-line training and evaluation script. |
| `alerts/recommendations.py` | Recommended actions for every kind of finding. |
| `alerts/email_notifier.py` | Builds and sends alert emails. All settings come from environment variables. |
| `alerts/alert_service.py` | Stores detections, creates alerts, suppresses duplicates, triggers email. |
| `alerts/triage.py` | Triage status workflow and its rules. |
| `alerts/email_check.py` | Command-line check of email settings and SMTP login; optional single test email. |
| `database/check_connection.py` | Read-only command-line check of the PostgreSQL connection and tables. |
| `database/anomaly_schema.sql` | PostgreSQL tables: `anomaly_detections`, `security_alerts`, `alert_triage_history`. |
| `database/init_anomaly_tables.py` | Creates those tables using the existing `get_connection()`. |
| `database/alert_repository.py` | Database access (PostgreSQL), plus an in-memory version for tests and the demo. |
| `anomaly_api.py` | Flask Blueprint with the new API endpoints. |
| `demo_anomaly.py` | Offline demo that needs no database or email. |
| `data/samples/*.json` | Three hand-written **synthetic** example inputs. |
| `tests/` | Automated tests (pytest). |
| `requirements.txt` | All Python dependencies. |

**Changes to existing files:**

- `api.py`: two lines added (import and register the Blueprint). `/verify` is unchanged.
- `.gitignore`: ignores the generated `models/` folder.
- `README.md`: updated documentation.

The integrity module (`integrity/`) and `database/audit_logger.py` were **not changed**.

## 3. The input: a "package observation"

One JSON object describes one release of one package. Only `package_name` and `version` are required. Every other section is optional, and analyses without data are simply skipped. The result's `data_coverage` field shows which sections were present.

```json
{
  "package_name": "tidy-config",
  "version": "2.5.0",
  "ecosystem": "npm",
  "download_history": [4100, 4350, 3980, 4200, 4420, 4690],
  "release_history": [
    {"version": "2.4.0", "released_at": "2025-12-01", "size_bytes": 42900,
     "author": "priya", "dependencies": ["chalk"], "has_install_script": false,
     "api_calls": ["fs.readFile"], "network_hosts": ["registry.npmjs.org"]}
  ],
  "current_release": {"released_at": "2026-01-14", "size_bytes": 44100,
     "author": "priya", "dependencies": ["chalk"], "has_install_script": false},
  "source_code": "module.exports = ...",
  "behavior": {
    "network_connections": [{"host": "registry.npmjs.org", "port": 443}],
    "file_accesses": [{"path": "/tmp/build/x/package.json", "mode": "read"}],
    "api_calls": ["path.resolve", "fs.readFile", "JSON.parse"]
  },
  "integrity": {"hash": "PASS", "signature": "NOT_CHECKED", "source": "TRUSTED"}
}
```

- `download_history`: weekly download counts, oldest first. The **last** number is the current week.
- `release_history`: earlier releases, oldest first. `api_calls` and `network_hosts` on the latest earlier release enable full drift detection.
- `behavior`: what the package did when installed or run, for example captured by a sandbox.
- `integrity`: optional. Any of the three result shapes from the integrity module is accepted (see section 6).

See the complete examples in `data/samples/`.

## 4. Coverage of the HTML "Analysis Factors"

| HTML analysis factor | Features | Statistical / rule check |
|---|---|---|
| Package download frequency patterns and spikes | `download_spike_score` | Robust z-score (MAD) on a log scale **and** at least 3× the usual level |
| Code obfuscation and minification detection | `code_entropy`, `max_line_length_log`, `long_line_ratio`, `obfuscation_indicators` | Count of obfuscation patterns plus entropy |
| Network communication patterns during build and runtime | `unexpected_host_count`, `raw_ip_connections`, `unusual_port_count` | Raw IPs, non-registry hosts, non-HTTP(S) ports |
| File system access patterns and modifications | `sensitive_file_reads`, `secret_config_reads`, `system_file_writes` | Credential files, `.env`, persistence locations |
| API call signatures and sequence analysis | `dangerous_api_calls`, `suspicious_sequences`, `novel_api_bigram_ratio` | Known attack sequences, plus API transitions never seen in normal training data |
| Author behavior and contribution patterns | `new_author`, `author_changed` | New publisher never seen before |
| Package update frequency and size changes | `size_change_log`, `release_interval_log`, `releases_last_7_days` | IQR outlier on size changes, release bursts, unusual gaps |
| Package drift detection (Core Features table) | `drift_score`, `new_dependency_count`, `install_script_added` | Jaccard distance between the previous and current release's capabilities |

## 5. How the ML model works

### Why Isolation Forest?

The HTML lists Isolation Forest, Autoencoders, Random Forest and XGBoost. I chose **Isolation Forest** as the starting algorithm:

- **No labelled attack data exists in this project.** Random Forest and XGBoost are *supervised*: they must be trained on many examples that are already labelled "attack" or "normal". We do not have a reliable labelled dataset of real attacks, and training them on attacks we invented ourselves would only teach them to recognise our own inventions.
- Isolation Forest is *unsupervised*. It only needs examples of **normal** packages and flags anything that does not fit.
- It is simple: no feature scaling, few settings, and it trains in seconds.
- Autoencoders (neural networks) would also work unsupervised, but they need more data and tuning and are harder to explain to a beginner. They are a good later comparison.

### The idea in one picture

Isolation Forest builds 200 random trees. Each tree keeps asking random questions such as *"is `sensitive_file_reads` greater than 0.7?"* until every package sits alone.

- A **normal** package resembles many others, so it needs **many** questions to be separated.
- An **unusual** package is different, so it is separated after **few** questions.

The average number of questions becomes the score.

### From score to something understandable

- **Anomaly percentile (0–1):** the share of normal training packages that look *more normal* than this one. `0.5` means average; `0.99` means more unusual than 99% of normal packages.
- **Most unusual features:** for each feature the model remembers the typical (median) training value. The explanation lists the features that are furthest from typical, for example `sensitive_file_reads: 2 vs typical 0`.

### Lesson learned during development

Isolation Forest **cannot use a feature that never changes in its training data**. In the first synthetic dataset, normal packages *never* read secret files. The model was therefore blind to `sensitive_file_reads`, and a credential stealer only scored at the 73rd percentile. Real normal packages do sometimes read `.env` (dotenv) or call web APIs. After that realistic variety was added to the normal data, the same attack scored above the 97th percentile.

This is why the detector does **not** rely on ML alone (section 6).

## 6. How the final decision is made

The detector combines three kinds of evidence:

1. **ML evidence.** The ML percentile alone gives at most: ≥ 0.97 → Low, ≥ 0.99 → Medium, ≥ 0.999 → High.
2. **Behaviour evidence.** Explicit findings with fixed severities, for example credential-file access (High), raw-IP connection (High), new author (Low). Weak signals that are common in legitimate packages (minified code alone, build tools spawning compilers) are reported as **notes** and do not raise the severity.
3. **Integrity evidence.** These are cryptographic facts, not statistics, so they are **not** fed to the ML model:

   | Failed check | Severity |
   |---|---|
   | hash, signature | Critical |
   | attestation, reproducible build | High |
   | source, version, timestamp | Medium |
   | `NOT_CHECKED` / not provided | No finding, but listed in `integrity.not_checked` |

**Overall severity** is the highest finding. It is escalated to **Critical** when three or more High findings agree, or when the ML says High *and* a High behaviour finding exists.

**Verdict:**

| Severity | Verdict |
|---|---|
| Medium / High / Critical | `SUSPICIOUS` |
| Low | `REVIEW` |
| none | `NORMAL` |

**Risk score (0–100):** a base value for the severity (Critical 90, High 70, Medium 45, Low 20) plus up to 10 points from the ML percentile.

### Integration with the Integrity Verification Module

The integrity results can reach the detector in three ways, and **all three already exist in the project**:

1. The `"checks"` object returned by `POST /verify`, pasted into `integrity`.
2. The full dict from `integrity.verification_engine.verify_package()`.
3. **Automatically:** when `POST /anomaly/analyze` is called *without* `integrity`, the API reads the newest row for that package and version from the existing `verification_records` table, which `/verify` writes. The response shows `"integrity": {"source": "verification_records#<id>"}`.

`verification_records` has no columns for reproducible build or timestamp results, so those two show as `NOT_PROVIDED` in that path.

## 7. Alerts, email and triage (additional features)

### Alert generation

For each analysis:

1. The result is always stored in `anomaly_detections`.
2. An alert is created when severity ≥ `SSCA_ALERT_MIN_SEVERITY` (default **Medium**).
3. **Duplicate protection:** a fingerprint is built from ecosystem, package, version and the *kinds* of findings. If an alert with the same fingerprint is still **New**, **Under Review** or was marked **False Positive**, no new alert and no email are created; only `occurrence_count` and `last_seen_at` are updated. If the earlier alert was **Resolved**, the problem has come back, so a new alert is created.

### Email

An email is sent when severity ≥ `SSCA_EMAIL_MIN_SEVERITY` (default **High**). It contains:

- alert ID, package, version, ecosystem, severity, risk score and detection time
- every finding with its evidence
- the recommended actions
- how to triage the alert

The outcome is stored on the alert as `email_status`:

| Status | Meaning |
|---|---|
| `SENT` | The SMTP server accepted the email. |
| `NOT_REQUIRED` | The severity is below the email threshold. |
| `DISABLED` | Email is switched off or settings are missing. The reason is stored. |
| `FAILED` | Sending was attempted and failed. The error is stored; the alert is still created. |

This is an **alert notification channel only**, not an email security gateway or phishing detector.

| Environment variable | Meaning | Default |
|---|---|---|
| `SSCA_EMAIL_ENABLED` | `true` to send emails | `false` |
| `SSCA_SMTP_HOST` / `SSCA_SMTP_PORT` | SMTP server | – / `587` |
| `SSCA_SMTP_USERNAME` / `SSCA_SMTP_PASSWORD` | Login. For Gmail, use an **App Password**. | empty |
| `SSCA_SMTP_STARTTLS` | Upgrade to TLS | `true` |
| `SSCA_SMTP_SSL` | Use SSL (port 465) instead | `false` |
| `SSCA_EMAIL_FROM` / `SSCA_EMAIL_TO` | Sender; comma-separated recipients | – |
| `SSCA_EMAIL_MIN_SEVERITY` | Lowest severity that is emailed | `High` |
| `SSCA_ALERT_MIN_SEVERITY` | Lowest severity that creates an alert | `Medium` |

### Triage

```text
NEW ──► UNDER_REVIEW ──► RESOLVED
 │            │
 │            └────────► FALSE_POSITIVE
 └──► RESOLVED / FALSE_POSITIVE (directly)

RESOLVED / FALSE_POSITIVE ──► UNDER_REVIEW   (re-open)
```

- Closing an alert (Resolved or False Positive) **requires `action_taken`**.
- Every change is saved in `alert_triage_history` with the analyst, notes and time.
- "Needs attention" means status **New** or **Under Review**.
- A status change only succeeds if nobody else changed the alert in the meantime.

### Checking the configuration (no changes, no emails)

```powershell
python -m database.check_connection     # READ-ONLY: connection, tables, row counts
python -m alerts.email_check            # shows email settings (passwords hidden), logs in to SMTP, sends NOTHING
python -m alerts.email_check --send-test  # sends ONE [TEST] alert email built from synthetic sample data
```

`--send-test` uses the real pipeline (detector → alert service → email) but keeps the alert in memory, so nothing is written to PostgreSQL.

## 8. API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/anomaly/analyze` | Analyse one observation. Returns `detection` and `response` (alert action, alert, email result). |
| GET | `/anomaly/model` | Model information and the latest evaluation report. |
| GET | `/alerts` | List alerts. Filters: `status`, `severity`, `needs_attention=true/false`, `limit`. Most severe first. |
| GET | `/alerts/summary` | Counts per status, open alerts per severity, number needing attention. |
| GET | `/alerts/<id>` | One alert with reasons, recommendations and triage history. |
| PATCH | `/alerts/<id>/status` | Body: `{"status": "Under Review", "action_taken": "...", "analyst": "...", "notes": "..."}` |

When PostgreSQL is unavailable, the endpoints return **503**. `/anomaly/analyze` still includes the detection result, with `"stored": false`.

## 9. Testing that was performed

| Test file | What it checks |
|---|---|
| `tests/test_stage1_features.py` | Statistics, obfuscation analysis, behaviour analysis, input validation, feature extraction |
| `tests/test_stage2_detection.py` | Model training, save and load; normal vs suspicious data; every attack scenario flagged for the right reasons; integrity integration, including running the **real** `verify_package()` |
| `tests/test_stage3_alerts.py` | Alert creation, duplicate suppression, thresholds, recommendations, triage rules, and email against a **real local SMTP server** (aiosmtpd): sent, disabled, failed, header-injection protection |
| `tests/test_stage4_api.py` | All new endpoints through the real `api.py` app; existing `/` and `/verify` still work; 503 behaviour without a database |
| `tests/test_postgres_repository.py` | Real PostgreSQL: table creation, JSONB storage, duplicates, triage history, check constraints, `verification_records` lookup, the existing `save_audit_record()`, and the full `/verify` → `/anomaly/analyze` → triage flow through the API. It runs inside a temporary schema that is dropped afterwards, and is **skipped** unless `SSCA_DB_PASSWORD` is set. |

## 10. Limitations: please read

**The sample data is synthetic.** Everything in `anomaly/sample_data.py` and `data/samples/` was written by hand or generated by rules I chose. The attack scenarios are simplified imitations *inspired by* public incidents (event-stream, credential-stealing typosquats, colors/faker, download inflation, tampered artifacts). They are **not** real malware samples or real registry data.

**The evaluation numbers do not show real-world accuracy.** On held-out synthetic data the detector flagged all 120 simulated attacks, with a 1% false-positive rate on 300 simulated normal packages. Because the same person designed both the normal data and the attacks, these numbers only show that the code behaves as designed. Real attacks are more varied and more subtle.

Other limitations:

- **Behaviour data is not collected yet.** Network, file and API-call data must be supplied in the input. In the full architecture it would come from the Runtime Protection Layer or a CI sandbox (eBPF, strace, Procmon, proxy logs). This project does not include those collectors yet.
- Download counts, release history and authors must also be supplied. There is no live connection to npm or PyPI yet; that belongs to the Dependency Intelligence Engine.
- Code analysis uses patterns on raw text. Skilled attackers can avoid these patterns.
- Escalation is limited. A repeated detection of the same problem at a *higher* severity only increases `occurrence_count` and does not send a new email.
- The default model file is trained on synthetic data. Its metadata says so (`data_source: "synthetic"`), and every API result includes `model.training_data_source`.

### What real-world detection needs

1. **Real normal data.** Collect observations for packages you trust (registry metadata from the npm and PyPI APIs, plus sandboxed install behaviour). Save them as a JSON list and retrain:

   ```powershell
   python -m anomaly.train_model --data path\to\normal_packages.json
   ```

2. **Real labelled malicious data** for evaluation, and later for supervised models (Random Forest / XGBoost). Public research datasets of malicious npm and PyPI packages exist, such as the Backstabber's Knife Collection (available to researchers on request) and the OpenSSF `malicious-packages` repository. Check their licences and handle the samples only inside an isolated environment.
3. A **sandbox or eBPF collector** that records network, file and API behaviour during `npm install` / `pip install`.
4. Measure precision and recall on that real data, then tune the thresholds in `anomaly/detector.py`.

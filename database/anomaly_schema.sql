-- SSCA-Defender: tables for the Anomaly Detection System, alerts and triage.
-- These tables live in the SAME database as verification_records
-- (ssca_defender_db). Safe to run more than once.
--
-- Run with:  python -m database.init_anomaly_tables

-- 1. Every anomaly analysis that was run (normal or suspicious).
CREATE TABLE IF NOT EXISTS anomaly_detections (
    id                  SERIAL PRIMARY KEY,
    package_name        TEXT NOT NULL,
    package_version     TEXT NOT NULL,
    ecosystem           TEXT,
    verdict             TEXT NOT NULL,           -- NORMAL / REVIEW / SUSPICIOUS
    severity            TEXT,                    -- NULL when nothing was found
    risk_score          INTEGER NOT NULL,
    anomaly_percentile  DOUBLE PRECISION,
    ml_raw_score        DOUBLE PRECISION,
    findings            JSONB NOT NULL,
    features            JSONB NOT NULL,
    integrity_statuses  JSONB,
    input_is_synthetic  BOOLEAN NOT NULL DEFAULT FALSE,
    model_trained_at    TEXT,
    analyzed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomaly_detections_package
    ON anomaly_detections (package_name, package_version);

-- 2. Security alerts that need human attention (triage).
CREATE TABLE IF NOT EXISTS security_alerts (
    id                  SERIAL PRIMARY KEY,
    fingerprint         TEXT NOT NULL,           -- used to avoid duplicate alerts
    detection_id        INTEGER REFERENCES anomaly_detections (id),
    package_name        TEXT NOT NULL,
    package_version     TEXT NOT NULL,
    ecosystem           TEXT,
    severity            TEXT NOT NULL
        CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    risk_score          INTEGER NOT NULL,
    summary             TEXT NOT NULL,
    reasons             JSONB NOT NULL,          -- findings that caused the alert
    recommendations     JSONB NOT NULL,
    status              TEXT NOT NULL DEFAULT 'NEW'
        CHECK (status IN ('NEW', 'UNDER_REVIEW', 'RESOLVED', 'FALSE_POSITIVE')),
    action_taken        TEXT,
    assigned_to         TEXT,
    occurrence_count    INTEGER NOT NULL DEFAULT 1,
    email_status        TEXT NOT NULL DEFAULT 'PENDING',
    email_error         TEXT,
    email_sent_at       TIMESTAMPTZ,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at           TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_security_alerts_fingerprint
    ON security_alerts (fingerprint);
CREATE INDEX IF NOT EXISTS idx_security_alerts_status
    ON security_alerts (status);

-- 3. History of every triage status change (who did what, and when).
CREATE TABLE IF NOT EXISTS alert_triage_history (
    id              SERIAL PRIMARY KEY,
    alert_id        INTEGER NOT NULL REFERENCES security_alerts (id) ON DELETE CASCADE,
    old_status      TEXT NOT NULL,
    new_status      TEXT NOT NULL,
    action_taken    TEXT,
    analyst         TEXT,
    notes           TEXT,
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_triage_history_alert
    ON alert_triage_history (alert_id);

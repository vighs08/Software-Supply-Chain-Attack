"""
Shared test fixtures.

A small model is trained ONCE per test run on SYNTHETIC normal data
(fast, and independent of models/anomaly_model.joblib on disk).
"""

import pytest

from anomaly.detector import AnomalyDetector
from anomaly.model import AnomalyModel
from anomaly.sample_data import generate_normal_dataset


@pytest.fixture(autouse=True)
def isolate_email_settings(monkeypatch):
    """
    Remove any real email/alert settings (e.g. a Gmail App Password set
    in the current PowerShell window) before EVERY test, so tests can
    never use or depend on real credentials. SSCA_DB_PASSWORD is kept
    because the PostgreSQL tests need it.
    """

    import os

    for name in list(os.environ):
        if name.startswith(("SSCA_EMAIL_", "SSCA_SMTP_", "SSCA_ALERT_")):
            monkeypatch.delenv(name)


@pytest.fixture(scope="session")
def trained_model():
    return AnomalyModel(n_estimators=100).fit(
        generate_normal_dataset(600, seed=1), data_source="synthetic-test"
    )


@pytest.fixture(scope="session")
def detector(trained_model):
    return AnomalyDetector(trained_model)

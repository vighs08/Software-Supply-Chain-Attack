
"""
Offline demo of the Anomaly Detection System.

Analyses the sample files in data/samples/ (SYNTHETIC data) and shows
the alert/triage flow. Uses the in-memory repository, so PostgreSQL is
NOT needed and no emails are sent.

    python demo_anomaly.py
    python demo_anomaly.py path\\to\\my_observation.json
"""

import json
import sys
from pathlib import Path

from alerts.alert_service import AlertService
from alerts.email_notifier import EmailSettings
from alerts.triage import change_status
from anomaly.detector import AnomalyDetector
from anomaly.model import ModelNotTrainedError
from database.alert_repository import InMemoryAlertRepository


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SAMPLES = sorted((PROJECT_ROOT / "data" / "samples").glob("*.json"))


def print_result(result):
    print("-" * 70)
    print(f"Package:   {result['package_name']} {result['version']} ({result['ecosystem']})")
    print(f"Verdict:   {result['verdict']}   Severity: {result['severity'] or '-'}   "
          f"Risk score: {result['risk_score']}/100")
    print(f"ML:        anomaly percentile {result['ml']['anomaly_percentile']:.3f} "
          f"(1.0 = more unusual than every normal training package)")
    print(f"Summary:   {result['summary']}")

    for finding in result["findings"]:
        print(f"  [{finding['severity']:8s}] {finding['title']}")
        print(f"             {finding['evidence']}")

    for note in result["notes"]:
        print(f"  [note    ] {note}")

    if result["ml"]["top_unusual_features"]:
        print("  Most unusual features (value vs typical normal value):")
        for item in result["ml"]["top_unusual_features"]:
            print(f"    - {item['feature']}: {item['value']} vs {item['typical_value']}")

    missing = [name for name, present in result["data_coverage"].items() if not present]
    if missing:
        print(f"  Not analysed (no data supplied): {', '.join(missing)}")
    if result["input_is_synthetic"]:
        print("  (input is SYNTHETIC sample data)")


def main():
    files = [Path(arg) for arg in sys.argv[1:]] or DEFAULT_SAMPLES

    try:
        detector = AnomalyDetector.load()
    except ModelNotTrainedError as exc:
        print(exc)
        sys.exit(1)

    print(f"Model trained at {detector.model.metadata['trained_at']} on "
          f"{detector.model.metadata['training_samples']} "
          f"{detector.model.metadata['data_source']} observations.")

    repository = InMemoryAlertRepository()
    service = AlertService(repository, EmailSettings(enabled=False))

    for path in files:
        result = detector.analyze(json.loads(path.read_text(encoding="utf-8")))
        print_result(result)
        outcome = service.process_detection(result)
        print(f"  Alert:   {outcome['alert_action']}"
              + (f" (alert #{outcome['alert']['id']})" if outcome["alert"] else ""))

    print("=" * 70)
    print("Alerts that need attention:")
    for alert in repository.list_alerts(needs_attention=True):
        print(f"  #{alert['id']} [{alert['severity']}] {alert['package_name']} "
              f"{alert['package_version']} - {alert['status']}")

    if repository.alerts:
        alert_id = repository.alerts[0]["id"]
        print(f"\nTriage demo on alert #{alert_id}:")
        change_status(repository, alert_id, "Under Review", analyst="demo-user")
        alert = change_status(repository, alert_id, "Resolved",
                              action_taken="Demo: removed package and rotated credentials")
        for entry in alert["history"]:
            print(f"  {entry['old_status']} -> {entry['new_status']} "
                  f"({entry['action_taken'] or 'no action text'})")


if __name__ == "__main__":
    main()


"""
Train and evaluate the anomaly detection model.

Usage (from the project folder):

    # Train on SYNTHETIC normal data (default)
    python -m anomaly.train_model

    # Train on your own NORMAL observations (JSON list, same format as
    # data/samples/*.json) - recommended once real data is collected
    python -m anomaly.train_model --data path\\to\\normal_packages.json

The script:
  1. loads (or generates) normal training observations
  2. trains the Isolation Forest
  3. evaluates it on a separate, held-out SYNTHETIC test set
  4. saves the model to models/anomaly_model.joblib and a report to
     models/training_report.json
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from .detector import AnomalyDetector
from .model import DEFAULT_MODEL_PATH, AnomalyModel
from .sample_data import generate_normal_dataset, generate_suspicious_dataset


def evaluate(detector, normal_test, suspicious_test):
    """
    Measure how the detector behaves on held-out synthetic data.

    "Flagged" means verdict == SUSPICIOUS (severity Medium or higher),
    which is the level that creates an alert by default.
    """

    normal_verdicts = Counter(detector.analyze(item)["verdict"] for item in normal_test)

    per_scenario = defaultdict(Counter)
    for item in suspicious_test:
        result = detector.analyze(item)
        per_scenario[item["scenario"]][result["verdict"]] += 1

    flagged_normal = normal_verdicts["SUSPICIOUS"]
    flagged_attacks = sum(c["SUSPICIOUS"] for c in per_scenario.values())
    total_attacks = len(suspicious_test)

    precision = flagged_attacks / max(flagged_attacks + flagged_normal, 1)
    recall = flagged_attacks / max(total_attacks, 1)

    return {
        "warning": "Measured on SYNTHETIC data only. Not an estimate of real-world accuracy.",
        "normal_test_samples": len(normal_test),
        "normal_verdicts": dict(normal_verdicts),
        "false_positive_rate": round(flagged_normal / max(len(normal_test), 1), 4),
        "suspicious_test_samples": total_attacks,
        "detection_rate_per_scenario": {
            name: round(counts["SUSPICIOUS"] / sum(counts.values()), 3)
            for name, counts in per_scenario.items()
        },
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(2 * precision * recall / max(precision + recall, 1e-9), 4),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Train the SSCA-Defender anomaly model")
    parser.add_argument("--data", help="JSON file containing a list of NORMAL observations")
    parser.add_argument("--samples", type=int, default=1500, help="number of synthetic training samples")
    parser.add_argument("--output", default=str(DEFAULT_MODEL_PATH), help="where to save the model")
    args = parser.parse_args(argv)

    if args.data:
        training = json.loads(Path(args.data).read_text(encoding="utf-8"))
        source = f"file:{Path(args.data).name}"
    else:
        training = generate_normal_dataset(args.samples, seed=42)
        source = "synthetic"

    print(f"Training Isolation Forest on {len(training)} observations ({source})...")
    model = AnomalyModel().fit(training, data_source=source)
    path = model.save(args.output)
    print(f"Model saved to {path}")

    # Different seeds, so test data was never seen during training.
    print("Evaluating on held-out SYNTHETIC test data...")
    report = evaluate(
        AnomalyDetector(model),
        generate_normal_dataset(300, seed=2024),
        generate_suspicious_dataset(20, seed=99),
    )
    report["model"] = model.metadata

    report_path = Path(args.output).with_name("training_report.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps({k: v for k, v in report.items() if k != "model"}, indent=2))
    print(f"Report saved to {report_path}")


if __name__ == "__main__":
    main()

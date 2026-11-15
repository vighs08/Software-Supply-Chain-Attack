
"""
The Machine Learning model: Isolation Forest.

WHY ISOLATION FOREST?
---------------------
We have plenty of examples of NORMAL packages (or can collect them),
but almost no reliable, labelled examples of real supply chain attacks.
Supervised models such as Random Forest or XGBoost need many labelled
attack examples to learn from. Isolation Forest is UNSUPERVISED: it
only needs normal data and learns what "normal" looks like.

HOW IT WORKS (in plain words)
-----------------------------
The model builds many random decision trees. Each tree keeps splitting
the data with random questions such as
    "is sensitive_file_reads > 0.7?"
until every package sits alone in its own leaf.

  * A NORMAL package looks like many others, so it takes MANY splits
    to isolate it (it ends deep in the tree).
  * An UNUSUAL package is different from the rest, so it is isolated
    after only a FEW splits (it ends near the top of the tree).

The average depth over all trees becomes the anomaly score.
Isolation Forest does not need feature scaling, which keeps it simple.

WHAT THIS FILE ADDS ON TOP
--------------------------
  * Calibration: the raw score is converted into an easy number,
    the "anomaly percentile" (0.0 - 1.0): the share of normal training
    packages that look MORE normal than the analysed package.
    0.50 = average, 0.99 = more unusual than 99% of normal packages.
  * Explanation: for every feature we remember the typical training
    value, so we can say WHICH features made a package unusual.
"""

from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .data_preparation import prepare_observation
from .features import FEATURE_DESCRIPTIONS, FEATURE_NAMES, collect_known_bigrams, extract_features


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "anomaly_model.joblib"

MODEL_FORMAT_VERSION = 1


class ModelNotTrainedError(RuntimeError):
    """Raised when no trained model file is available."""


class AnomalyModel:
    def __init__(self, n_estimators=200, random_state=42):
        self.forest = IsolationForest(
            n_estimators=n_estimators,
            contamination="auto",
            random_state=random_state,
        )
        self.feature_names = list(FEATURE_NAMES)
        self.known_bigrams = set()
        self.training_scores = None     # sorted raw scores of training data
        self.feature_median = None
        self.feature_scale = None
        self.feature_p95 = None
        self.metadata = {}

    # --------------------------------------------------
    # Training
    # --------------------------------------------------

    def fit(self, raw_observations, data_source):
        """
        Train on observations that are believed to be NORMAL.

        data_source: short text saying where the data came from,
        e.g. "synthetic" - stored with the model so results can always
        be traced back to the kind of data used for training.
        """

        prepared = [prepare_observation(raw) for raw in raw_observations]

        if len(prepared) < 50:
            raise ValueError("At least 50 normal observations are needed for training")

        # Learn which API call transitions are normal BEFORE extracting
        # the sequence-novelty feature.
        self.known_bigrams = collect_known_bigrams(prepared)

        matrix = np.array([
            list(extract_features(item, self.known_bigrams)[0].values())
            for item in prepared
        ])

        self.forest.fit(matrix)

        # score_samples: higher = more normal, lower = more unusual.
        self.training_scores = np.sort(self.forest.score_samples(matrix))

        # Typical values per feature, used for explanations.
        self.feature_median = np.median(matrix, axis=0)
        mad = np.median(np.abs(matrix - self.feature_median), axis=0) * 1.4826
        std = matrix.std(axis=0)
        # Avoid dividing by zero for features that are almost always 0.
        self.feature_scale = np.maximum(np.maximum(mad, std), 0.05)
        self.feature_p95 = np.percentile(matrix, 95, axis=0)

        self.metadata = {
            "algorithm": "IsolationForest",
            "n_estimators": self.forest.n_estimators,
            "training_samples": len(prepared),
            "data_source": data_source,
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "feature_names": self.feature_names,
            "format_version": MODEL_FORMAT_VERSION,
        }

        return self

    # --------------------------------------------------
    # Scoring
    # --------------------------------------------------

    def _require_trained(self):
        if self.training_scores is None:
            raise ModelNotTrainedError("The anomaly model has not been trained yet")

    def vectorize(self, features):
        return np.array([[features[name] for name in self.feature_names]])

    def score(self, features):
        """
        Score one feature dictionary.

        Returns:
          raw_score:          Isolation Forest score (lower = more unusual)
          anomaly_percentile: 0..1, share of normal training packages
                              that look more normal than this one
          is_outlier:         the model's own yes/no decision
        """

        self._require_trained()
        vector = self.vectorize(features)

        raw_score = float(self.forest.score_samples(vector)[0])

        # Number of training scores strictly greater (= more normal).
        more_normal = len(self.training_scores) - np.searchsorted(
            self.training_scores, raw_score, side="right"
        )
        percentile = more_normal / len(self.training_scores)

        return {
            "raw_score": round(raw_score, 4),
            "anomaly_percentile": round(float(percentile), 4),
            "is_outlier": bool(self.forest.predict(vector)[0] == -1),
        }

    def explain(self, features, top=5, threshold=3.0):
        """
        List the features that are far from the typical (median) value
        seen during training, most unusual first.
        """

        self._require_trained()
        values = self.vectorize(features)[0]
        deviations = (values - self.feature_median) / self.feature_scale

        reasons = []
        for index in np.argsort(-np.abs(deviations)):
            if abs(deviations[index]) < threshold:
                break

            name = self.feature_names[index]
            reasons.append({
                "feature": name,
                "description": FEATURE_DESCRIPTIONS[name],
                "value": round(float(values[index]), 3),
                "typical_value": round(float(self.feature_median[index]), 3),
                "normal_95th_percentile": round(float(self.feature_p95[index]), 3),
                "deviation": round(float(min(deviations[index], 99.0)), 1),
            })

            if len(reasons) == top:
                break

        return reasons

    # --------------------------------------------------
    # Saving and loading
    # --------------------------------------------------

    def save(self, path=DEFAULT_MODEL_PATH):
        self._require_trained()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(cls, path=DEFAULT_MODEL_PATH):
        """
        Load a model saved by save().

        Security note: joblib files can run code when loaded. Only load
        model files that you created yourself.
        """

        path = Path(path)

        if not path.is_file():
            raise ModelNotTrainedError(
                f"No trained model found at {path}. "
                "Train one with:  python -m anomaly.train_model"
            )

        model = joblib.load(path)

        if not isinstance(model, cls) or model.feature_names != FEATURE_NAMES:
            raise ModelNotTrainedError(
                "The saved model does not match the current feature list. "
                "Re-train it with:  python -m anomaly.train_model"
            )

        return model

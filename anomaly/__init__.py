"""
SSCA-Defender Anomaly Detection System (ML).

This package implements Component 2 of the project guide:
behavioural profiling of packages and ML-based detection of unusual
package activity, combined with statistical tests and the results of
the Integrity Verification Module.

Main entry point:

    from anomaly.detector import AnomalyDetector
    detector = AnomalyDetector.load()
    result = detector.analyze(observation_dict)
"""

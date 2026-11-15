
"""
Statistical anomaly detection helpers (z-score, IQR and MAD).

These are the "Statistical anomaly detection (z-score, IQR, MAD)"
methods listed in the project guide. They compare ONE new value with
a package's OWN history, for example:

    "This week the package was downloaded 900,000 times.
     Normally it is downloaded about 10,000 times. How unusual is that?"
"""

import statistics


# MAD has to be multiplied by this constant so that, for normally
# distributed data, the robust z-score is on the same scale as a
# normal z-score.
MAD_SCALE = 1.4826


def z_score(value, history):
    """
    Classic z-score: how many standard deviations `value` is from the
    mean of `history`.

    Returns 0.0 when there is not enough history to decide.
    """

    if len(history) < 3:
        return 0.0

    mean = statistics.fmean(history)
    stdev = statistics.pstdev(history)

    if stdev == 0:
        # Every historical value was identical. Any difference is
        # unusual, but we cap the result to avoid infinity.
        return 0.0 if value == mean else 10.0

    return (value - mean) / stdev


def robust_z_score(value, history):
    """
    Robust z-score based on the median and MAD
    (Median Absolute Deviation).

    Unlike the classic z-score, one huge value in the history does not
    distort the result, which makes it better for spiky data such as
    download counts.
    """

    if len(history) < 3:
        return 0.0

    median = statistics.median(history)
    mad = statistics.median(abs(x - median) for x in history)

    if mad == 0:
        # More than half of the history is identical. Fall back to
        # a small scale based on the median so a tiny change is not
        # reported as infinitely unusual.
        mad = max(abs(median) * 0.05, 1e-9)

    return (value - median) / (MAD_SCALE * mad)


def iqr_bounds(history, factor=1.5):
    """
    Return (lower, upper) bounds using the IQR (Interquartile Range)
    rule. Values outside these bounds are outliers.

    Returns None when there is not enough history.
    """

    if len(history) < 4:
        return None

    q1, _, q3 = statistics.quantiles(history, n=4, method="inclusive")
    iqr = q3 - q1

    return q1 - factor * iqr, q3 + factor * iqr


def is_iqr_outlier(value, history, factor=1.5):
    """True when `value` falls outside the IQR bounds of `history`."""

    bounds = iqr_bounds(history, factor)

    if bounds is None:
        return False

    lower, upper = bounds
    return value < lower or value > upper

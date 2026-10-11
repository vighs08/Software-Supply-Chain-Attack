def verify_version(
    expected_version,
    actual_version
):

    if expected_version == actual_version:

        return {
            "expected": expected_version,
            "actual": actual_version,
            "status": "PASS"
        }

    return {
        "expected": expected_version,
        "actual": actual_version,
        "status": "FAIL"
    }
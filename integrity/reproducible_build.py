from .hash_verifier import calculate_hash


def verify_reproducible_build(build_a, build_b):

    hash_a = calculate_hash(
        build_a,
        "sha256"
    )

    hash_b = calculate_hash(
        build_b,
        "sha256"
    )

    if hash_a == hash_b:

        status = "PASS"

    else:

        status = "FAIL"

    return {
        "build_a": build_a,
        "build_b": build_b,
        "hash_a": hash_a,
        "hash_b": hash_b,
        "status": status
    }
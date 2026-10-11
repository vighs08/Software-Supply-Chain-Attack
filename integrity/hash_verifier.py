import hashlib


def calculate_hash(file_path, algorithm="sha256"):

    if algorithm == "sha256":
        hash_object = hashlib.sha256()

    elif algorithm == "sha512":
        hash_object = hashlib.sha512()

    else:
        raise ValueError(
            "Unsupported hashing algorithm"
        )

    with open(file_path, "rb") as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            hash_object.update(data)

    return hash_object.hexdigest()


def verify_hash(
    file_path,
    expected_hash,
    algorithm="sha256"
):

    actual_hash = calculate_hash(
        file_path,
        algorithm
    )

    is_valid = (
        actual_hash.lower()
        == expected_hash.lower()
    )

    return {
        "algorithm": algorithm,
        "expected_hash": expected_hash,
        "actual_hash": actual_hash,
        "status": "PASS" if is_valid else "FAIL"
    }
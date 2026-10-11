import json

from .hash_verifier import calculate_hash


def verify_attestation(attestation_path):

    # Read the attestation file
    with open(attestation_path, "r") as file:
        attestation = json.load(file)

    # Get artifact information
    artifact_path = attestation["artifact"]["path"]
    expected_hash = attestation["artifact"]["sha256"]

    # Calculate actual hash of the artifact
    actual_hash = calculate_hash(
        artifact_path,
        "sha256"
    )

    # Compare the hashes
    if actual_hash.lower() == expected_hash.lower():

        hash_status = "PASS"

    else:

        hash_status = "FAIL"

    return {
        "package": attestation["package"]["name"],
        "version": attestation["package"]["version"],
        "builder": attestation["builder"]["id"],
        "source_repository": attestation["source"]["repository"],
        "build_type": attestation["build"]["build_type"],
        "artifact": artifact_path,
        "expected_hash": expected_hash,
        "actual_hash": actual_hash,
        "status": hash_status
    }
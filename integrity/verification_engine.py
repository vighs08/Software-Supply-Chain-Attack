
from .hash_verifier import verify_hash
from .version_verifier import verify_version
from .source_verifier import verify_source
from .attestation_verifier import verify_attestation
from .reproducible_build import verify_reproducible_build
from .signature_verifier import verify_signature
from .timestamp_verifier import verify_timestamp


def verify_package(package):

    # 1. Verify the package hash.
    hash_result = verify_hash(
        package.file_path,
        package.expected_hash,
        "sha256"
    )

    # 2. Verify the package version.
    version_result = verify_version(
        package.expected_version,
        package.actual_version
    )

    # 3. Verify the package source.
    source_result = verify_source(
        package.source
    )

    # 4. Verify the package attestation.
    attestation_result = verify_attestation(
        "attestations/test_attestation.json"
    )

    # 5. Compare reproducible build outputs.
    reproducible_result = verify_reproducible_build(
        "reproducible/build_a/package.txt",
        "reproducible/build_b/package.txt"
    )

    # 6. Verify the signature when verification data is provided.
    if (
        getattr(package, "signed_data", None) is not None
        and getattr(package, "signature", None) is not None
        and getattr(package, "public_key_bytes", None) is not None
    ):
        signature_result = verify_signature(
            package.signed_data,
            package.signature,
            package.public_key_bytes
        )
    else:
        signature_result = {
            "status": "NOT_CHECKED",
            "message": "Signature verification data was not provided."
        }

    # 7. Verify the RFC 3161 timestamp.
    timestamp_result = verify_timestamp(
        "attestations/test_package.tsr",
        package.file_path,
        "attestations/freetsa_official_root.pem"
    )

    # Collect the results from all verification checks.
    result = {
        "package": package.name,
        "version": package.version,

        "hash_verification": {
            "algorithm": "SHA-256",
            "status": hash_result["status"],
            "details": hash_result
        },

        "signature_verification": signature_result,

        "source_verification": {
            "status": source_result["status"],
            "details": source_result
        },

        "version_verification": {
            "status": version_result["status"],
            "details": version_result
        },

        "attestation_verification": {
            "status": attestation_result["status"],
            "details": attestation_result
        },

        "reproducible_build_verification": {
            "status": reproducible_result["status"],
            "hash_a": reproducible_result["hash_a"],
            "hash_b": reproducible_result["hash_b"],
            "details": reproducible_result
        },

        "timestamp_verification": timestamp_result,

        # Keep the existing overall status until all checks have
        # a clearly defined policy for determining overall trust.
        "overall_status": "PARTIALLY_VERIFIED"
    }

    return result

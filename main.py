
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from integrity.hash_verifier import calculate_hash, verify_hash
from integrity.package_info import PackageInfo
from integrity.version_verifier import verify_version
from integrity.source_verifier import verify_source
from integrity.verification_engine import verify_package
from integrity.attestation_verifier import verify_attestation
from database.audit_logger import save_audit_record


# --------------------------------------------------
# 1. Set project and package file paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent

file_path = PROJECT_ROOT / "samples" / "test_package.txt"

if not file_path.is_file():
    raise FileNotFoundError(f"Package file not found: {file_path}")


# --------------------------------------------------
# 2. Calculate SHA-256 and SHA-512 hashes
# --------------------------------------------------

sha256 = calculate_hash(str(file_path), "sha256")
sha512 = calculate_hash(str(file_path), "sha512")

print("=" * 60)
print("SSCA-DEFENDER INTEGRITY VERIFICATION")
print("=" * 60)

print("\nSHA-256:")
print(sha256)

print("\nSHA-512:")
print(sha512)


# --------------------------------------------------
# 3. Verify the package hash against the expected hash
# --------------------------------------------------

# DEMO ONLY:
# This hash is for the current sample file.
# In a real deployment, obtain the expected hash from
# an independently trusted source.

trusted_hash = (
    "a1bfdd904c055dfefe3f46804f992a65e2977b0203bc653ea2900640e1557b5b"
)

result = verify_hash(
    str(file_path),
    trusted_hash,
    "sha256",
)

print("\nHash Verification Result:")
print(result)


# --------------------------------------------------
# 4. Load persistent test keys and create package info
# --------------------------------------------------

private_key_path = (
    PROJECT_ROOT
    / "integrity"
    / "test_keys"
    / "test_private_key.pem"
)

public_key_path = (
    PROJECT_ROOT
    / "integrity"
    / "test_keys"
    / "test_public_key.bin"
)

if not private_key_path.is_file():
    raise FileNotFoundError(
        "Test private key not found. Run python generate_test_keys.py first."
    )

if not public_key_path.is_file():
    raise FileNotFoundError(
        "Test public key not found. Run python generate_test_keys.py first."
    )

private_key = serialization.load_pem_private_key(
    private_key_path.read_bytes(),
    password=None,
)

public_key_bytes = public_key_path.read_bytes()

# Read the exact package bytes and sign them for this local demonstration.
signed_data = file_path.read_bytes()
signature = private_key.sign(signed_data)

package = PackageInfo(
    name="test-package",
    version="1.0.0",
    ecosystem="python",
    file_path=str(file_path),
    expected_hash=trusted_hash,
    expected_version="1.0.0",
    actual_version="1.0.0",
    source="pypi.org",
    signed_data=signed_data,
    signature=signature,
    public_key_bytes=public_key_bytes,
)

print("\nPackage Information:")
print("Package Name:", package.name)
print("Package Version:", package.version)
print("Package Ecosystem:", package.ecosystem)
print("Package File:", package.file_path)
print("Package Expected Hash:", package.expected_hash)
print("Package Expected Version:", package.expected_version)
print("Package Actual Version:", package.actual_version)
print("Package Source:", package.source)


# --------------------------------------------------
# 5. Test version verification
# --------------------------------------------------

version_result = verify_version("1.0.0", "1.0.0")

print("\nVersion Verification:")
print(version_result)


# --------------------------------------------------
# 6. Test version mismatch detection
# --------------------------------------------------

version_mismatch_result = verify_version("1.0.0", "1.1.0")

print("\nVersion Mismatch Test:")
print(version_mismatch_result)


# --------------------------------------------------
# 7. Verify the package source
# --------------------------------------------------

source_result = verify_source("pypi.org")

print("\nSource Verification:")
print(source_result)


# --------------------------------------------------
# 8. Run the complete verification engine
# --------------------------------------------------

verification_result = verify_package(package)

print("\nComplete Package Verification:")
print(verification_result)


# --------------------------------------------------
# 9. Verify the attestation
# --------------------------------------------------

attestation_path = (
    PROJECT_ROOT / "attestations" / "test_attestation.json"
)

attestation_result = verify_attestation(str(attestation_path))

print("\nSLSA Attestation Verification:")
print(attestation_result)


# --------------------------------------------------
# 10. Prepare the audit record
# --------------------------------------------------

audit_record = {
    "package_name": package.name,
    "package_version": package.version,
    "ecosystem": package.ecosystem,
    "file_name": package.file_path,
    "sha256": sha256,
    "sha512": sha512,
    "hash_status": verification_result["hash_verification"]["status"],
    "signature_status": verification_result["signature_verification"]["status"],
    "source_status": verification_result["source_verification"]["status"],
    "version_status": verification_result["version_verification"]["status"],
    "attestation_status": verification_result["attestation_verification"]["status"],
    "overall_status": verification_result["overall_status"],
}


# --------------------------------------------------
# 11. Save the audit record in PostgreSQL
# --------------------------------------------------

print("\nSaving verification results to PostgreSQL...")

audit_id = save_audit_record(audit_record)

print("Audit record saved successfully!")
print("Audit record ID:", audit_id)

print("\n" + "=" * 60)
print("SSCA-DEFENDER RUN COMPLETED")
print("=" * 60)

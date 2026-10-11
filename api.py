
from pathlib import Path

from flask import Flask, jsonify, request

from integrity.hash_verifier import calculate_hash
from integrity.package_info import PackageInfo
from integrity.verification_engine import verify_package
from database.audit_logger import save_audit_record


app = Flask(__name__)

# --------------------------------------------------
# 1. Configure the project and allowed package folder
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = (PROJECT_ROOT / "samples").resolve()

# Trusted hash configured for Test 2.
# This matches the current test_package.txt file.
# Use an independently trusted hash in a real system.
TRUSTED_HASHES = {
    ("test-package", "test_package.txt"):
        "a1bfdd904c055dfefe3f46804f992a65"
        "e2977b0203bc653ea2900640e1557b5b"
}


# --------------------------------------------------
# 2. Home endpoint
# --------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "SSCA-Defender API is running"
    }), 200


# --------------------------------------------------
# 3. Package verification endpoint
# --------------------------------------------------

@app.route("/verify", methods=["POST"])
def verify():

    # Read JSON from the request.
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Request body must be a JSON object"
        }), 400

    package_name = data.get("package")
    version = data.get("version")
    file_name = data.get("file")

    # Validate required fields.
    if not all(
        isinstance(value, str) and value.strip()
        for value in (package_name, version, file_name)
    ):
        return jsonify({
            "error": "package, version, and file are required"
        }), 400

    # Accept filenames only, not arbitrary paths.
    if Path(file_name).name != file_name or file_name in (".", ".."):
        return jsonify({
            "error": "Only filenames inside the samples folder are allowed"
        }), 400

    file_path = (SAMPLES_DIR / file_name).resolve()

    # Ensure the resolved file remains inside samples.
    if not file_path.is_relative_to(SAMPLES_DIR):
        return jsonify({
            "error": "Invalid file path"
        }), 400

    if not file_path.is_file():
        return jsonify({
            "error": "Package file not found"
        }), 404

    # Only verify packages with a configured trusted hash.
    expected_hash = TRUSTED_HASHES.get((package_name, file_name))

    if expected_hash is None:
        return jsonify({
            "error": "No trusted hash is configured for this package"
        }), 400

    try:
        # --------------------------------------------------
        # 4. Calculate the actual file hashes
        # --------------------------------------------------

        sha256 = calculate_hash(str(file_path), "sha256")
        sha512 = calculate_hash(str(file_path), "sha512")

        # --------------------------------------------------
        # 5. Create package metadata
        # --------------------------------------------------

        package = PackageInfo(
            name=package_name,
            version=version,
            ecosystem="python",
            file_path=str(file_path),
            expected_hash=expected_hash,
            expected_version=version,
            actual_version=version,
            source="pypi.org"
        )

        # --------------------------------------------------
        # 6. Run the existing verification engine
        # --------------------------------------------------

        result = verify_package(package)

        checks = {
            "hash": result["hash_verification"]["status"],
            "signature": result["signature_verification"]["status"],
            "version": result["version_verification"]["status"],
            "source": result["source_verification"]["status"],
            "attestation": result["attestation_verification"]["status"],
            "reproducible_build": (
                result["reproducible_build_verification"]["status"]
            )
        }

        # --------------------------------------------------
        # 7. Calculate the overall status
        # --------------------------------------------------

        # NOT_CHECKED does not count as a successful check.
        all_checks_passed = all(
            status in ("PASS", "TRUSTED")
            for status in checks.values()
        )

        overall_status = (
            "VERIFIED" if all_checks_passed else "NOT_VERIFIED"
        )

        # --------------------------------------------------
        # 8. Prepare the PostgreSQL audit record
        # --------------------------------------------------

        audit_record = {
            "package_name": package.name,
            "package_version": package.version,
            "ecosystem": package.ecosystem,
            "file_name": file_path.name,
            "sha256": sha256,
            "sha512": sha512,
            "hash_status": checks["hash"],
            "signature_status": checks["signature"],
            "source_status": checks["source"],
            "version_status": checks["version"],
            "attestation_status": checks["attestation"],
            "overall_status": overall_status
        }

        # --------------------------------------------------
        # 9. Save the audit record to PostgreSQL
        # --------------------------------------------------

        audit_id = save_audit_record(audit_record)

        # --------------------------------------------------
        # 10. Return the JSON response
        # --------------------------------------------------

        return jsonify({
            "package": package_name,
            "version": version,
            "status": overall_status,
            "sha256": sha256,
            "sha512": sha512,
            "checks": checks,
            "audit_record_id": audit_id
        }), 200

    except Exception:
        app.logger.exception(
            "Package verification or audit logging failed"
        )

        return jsonify({
            "error": "Verification or audit logging could not be completed"
        }), 500


# --------------------------------------------------
# 11. Start the development server
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)

# SSCA-Defender

SSCA-Defender is a final-year Software Supply Chain Attack Detection and Defense project. The long-term project goal is to combine dependency intelligence, anomaly detection, integrity verification, CI/CD security checks, audit logging, and response workflows for software supply chain security.

This repository currently contains a prototype of the **Integrity Verification Module**. It is one component of the larger SSCA-Defender architecture, not a complete production-ready supply chain security platform. Several checks use local sample files and simplified demonstration data so the module can be tested while the broader system is still being developed.

## Current Module Scope

The Integrity Verification Module checks whether a package artifact still matches trusted integrity and provenance expectations.

Implemented prototype checks include:

- SHA-256 and SHA-512 hash calculation for package files.
- SHA-256 hash verification against a trusted expected hash.
- Version consistency checking by comparing expected and actual version strings.
- Trusted-source checking against a small allowlist: `pypi.org`, `github.com`, and `registry.npmjs.org`.
- Ed25519 digital signature verification when signed data, a signature, and a trusted public key are provided.
- SLSA-style attestation hash comparison using `attestations/test_attestation.json`.
- Reproducible-file comparison by hashing two local build outputs.
- RFC 3161 timestamp verification for the included FreeTSA timestamp response and trusted root certificate.
- Flask API integration with `GET /` and `POST /verify`.
- PostgreSQL audit logging of verification results through `database/audit_logger.py`.

The current implementation does not yet provide the full SSCA-Defender vision described in the project guide, such as complete dependency intelligence, ML-based anomaly detection, runtime protection, CI/CD gateway enforcement, incident response orchestration, or a dashboard.

## Project Structure

```text
SSCA-Defender/
|-- api.py
|-- main.py
|-- generate_test_keys.py
|-- test_signature.py
|-- test_signature_integration.py
|-- integrity/
|   |-- attestation_verifier.py
|   |-- hash_verifier.py
|   |-- package_info.py
|   |-- reproducible_build.py
|   |-- signature_verifier.py
|   |-- source_verifier.py
|   |-- timestamp_verifier.py
|   |-- verification_engine.py
|   |-- version_verifier.py
|   `-- test_keys/
|-- database/
|   |-- audit_logger.py
|   `-- __init__.py
|-- attestations/
|   |-- test_attestation.json
|   |-- test_package.tsr
|   |-- freetsa_embedded_root.pem
|   `-- freetsa_official_root.pem
|-- reproducible/
|   |-- build_a/package.txt
|   |-- build_b/package.txt
|   `-- source/package.txt
|-- samples/
|   |-- test_package.txt
|   |-- test_package.txt.gpg
|   `-- test_package.txt.sig
|-- timestamps/
|   |-- ca.crt
|   |-- timestamp_request.tsq
|   |-- timestamp_response.tsr
|   |-- timestamp_token.tst
|   `-- tsa_chain.pem
`-- correlation/
    `-- __init__.py
```

Generated folders such as `venv/` and `__pycache__/` should not be committed.

## Setup on Windows PowerShell

Create and activate a Python virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

Install the Python packages used by the current prototype:

```powershell
pip install flask cryptography psycopg pyasn1 rfc3161ng
```

If PowerShell blocks script activation, allow scripts for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Environment Variables

The audit logger reads the PostgreSQL password from an environment variable. Do not hard-code real credentials in source files, README examples, screenshots, or commits.

For the current PowerShell session:

```powershell
$env:SSCA_DB_PASSWORD = "replace-with-your-local-password"
```

For a persistent user-level variable:

```powershell
setx SSCA_DB_PASSWORD "replace-with-your-local-password"
```

After using `setx`, open a new PowerShell window so the variable is available.

The current database connection settings in `database/audit_logger.py` are:

- Host: `localhost`
- Port: `5432`
- Database: `ssca_defender_db`
- User: `postgres`
- Password: `SSCA_DB_PASSWORD`

The `verification_records` table must contain the columns inserted by `save_audit_record`: `package_name`, `package_version`, `ecosystem`, `file_name`, `sha256`, `sha512`, `hash_status`, `signature_status`, `source_status`, `version_status`, `attestation_status`, and `overall_status`.

## Running the Prototype

Run the command-line verification flow:

```powershell
python main.py
```

`main.py` calculates hashes for `samples/test_package.txt`, runs the verification engine, verifies the test attestation, and writes an audit record to PostgreSQL. It requires the sample files, test keys, timestamp assets, and database connection to be available.

Start the Flask API:

```powershell
python api.py
```

By default Flask starts at:

```text
http://127.0.0.1:5000
```

Test the health endpoint:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/ -Method GET
```

Representative response:

```json
{
  "message": "SSCA-Defender API is running"
}
```

Test the verification endpoint:

```powershell
$body = @{
    package = "test-package"
    version = "1.0.0"
    file = "test_package.txt"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri http://127.0.0.1:5000/verify `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

Representative response shape:

```json
{
  "package": "test-package",
  "version": "1.0.0",
  "status": "NOT_VERIFIED",
  "sha256": "a1bfdd904c055dfefe3f46804f992a65e2977b0203bc653ea2900640e1557b5b",
  "sha512": "example-sha512-value",
  "checks": {
    "hash": "PASS",
    "signature": "NOT_CHECKED",
    "version": "PASS",
    "source": "TRUSTED",
    "attestation": "PASS",
    "reproducible_build": "PASS"
  },
  "audit_record_id": 1
}
```

The API returns `NOT_VERIFIED` when all required checks do not pass. In the current `/verify` API flow, signature data is not supplied to the verification engine, so the signature check is normally `NOT_CHECKED`.

## API Error Examples

Missing JSON body or wrong body type:

```json
{
  "error": "Request body must be a JSON object"
}
```

Missing required fields:

```json
{
  "error": "package, version, and file are required"
}
```

Unknown package/file trusted hash:

```json
{
  "error": "No trusted hash is configured for this package"
}
```

Missing sample file:

```json
{
  "error": "Package file not found"
}
```

Database or verification failure:

```json
{
  "error": "Verification or audit logging could not be completed"
}
```

## Test and Demo Scripts

Run the standalone digital signature test:

```powershell
python test_signature.py
```

Run the integration-style signature verification demo:

```powershell
python test_signature_integration.py
```

Create local test keys if they are missing:

```powershell
python generate_test_keys.py
```

The generated private key is for local demonstration only and should not be committed or treated as a production signing key.

## Current Limitations

- This is a prototype module, not a full SSCA-Defender production deployment.
- Trusted hashes are hard-coded for the local sample package.
- Source trust is a simple allowlist, not live registry or repository verification.
- Version checks compare strings directly and do not implement semantic-version policy.
- Attestation verification currently checks a local JSON file and artifact hash; it does not fully validate SLSA provenance signatures or transparency logs.
- Reproducible build verification compares two local files by hash rather than rebuilding from source in an isolated environment.
- API signature verification is normally `NOT_CHECKED` because `/verify` does not accept signature material.
- PostgreSQL audit logging is required for successful `main.py` and `/verify` execution.
- No complete dependency intelligence, anomaly detection, runtime protection, CI/CD gateway, response orchestration, or dashboard implementation is present yet.

## Future Improvements

- Move trusted package metadata to a signed configuration store or trusted registry source.
- Add a migration or setup script for the PostgreSQL audit table.
- Add a `requirements.txt` or `pyproject.toml` for reproducible dependency installation.
- Extend the API to accept or resolve trusted signatures and public keys securely.
- Add full SLSA/in-toto provenance validation and Sigstore/cosign verification.
- Add semantic-version policy checks and package ecosystem metadata lookup.
- Add automated unit tests for each verifier and API tests for success and failure cases.
- Integrate this module with the planned dependency intelligence, anomaly detection, CI/CD, dashboard, and incident response components.

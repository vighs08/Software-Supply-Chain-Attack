
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from integrity.package_info import PackageInfo
from integrity.verification_engine import verify_package
from integrity.hash_verifier import calculate_hash


project_root = Path(__file__).resolve().parent

package_file = project_root / "samples" / "test_package.txt"
private_key_path = (
    project_root / "integrity" / "test_keys" / "test_private_key.pem"
)
public_key_path = (
    project_root / "integrity" / "test_keys" / "test_public_key.bin"
)

if not package_file.is_file():
    raise FileNotFoundError(f"Sample package not found: {package_file}")

if not private_key_path.is_file() or not public_key_path.is_file():
    raise FileNotFoundError(
        "Test keys not found. Run python generate_test_keys.py first."
    )

# Read the exact package bytes.
signed_data = package_file.read_bytes()

# Load the persistent test private key.
private_key = serialization.load_pem_private_key(
    private_key_path.read_bytes(),
    password=None,
)

# Load the persistent public key.
public_key_bytes = public_key_path.read_bytes()

# Sign the package using the saved private key.
signature = private_key.sign(signed_data)

expected_hash = calculate_hash(str(package_file), "sha256")

package = PackageInfo(
    name="test-package",
    version="1.0.0",
    ecosystem="python",
    file_path=str(package_file),
    expected_hash=expected_hash,
    expected_version="1.0.0",
    actual_version="1.0.0",
    source="pypi.org",
    signed_data=signed_data,
    signature=signature,
    public_key_bytes=public_key_bytes,
)

result = verify_package(package)

print("Signature result:", result["signature_verification"])
print("Hash result:", result["hash_verification"])
print("Version result:", result["version_verification"])

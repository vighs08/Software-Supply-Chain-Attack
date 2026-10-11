
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

project_root = Path(__file__).resolve().parent
key_dir = project_root / "integrity" / "test_keys"
key_dir.mkdir(parents=True, exist_ok=True)

private_key_path = key_dir / "test_private_key.pem"
public_key_path = key_dir / "test_public_key.bin"

if private_key_path.exists() or public_key_path.exists():
    print("A test key already exists.")
    print("Keeping the existing key files unchanged.")
else:
    private_key = Ed25519PrivateKey.generate()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_key_path.write_bytes(private_bytes)
    public_key_path.write_bytes(public_bytes)

    print("Test key pair created successfully.")

print("Private key:", private_key_path)
print("Public key:", public_key_path)

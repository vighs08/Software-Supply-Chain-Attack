
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from integrity.signature_verifier import verify_signature


# Generate a temporary key pair for testing.
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Convert the public key to raw bytes.
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

# Create the original message.
message = b"SSCA-Defender package verification test"

# Sign the original message using the private key.
signature = private_key.sign(message)


# TEST 1: Verify the original message.
result1 = verify_signature(
    message,
    signature,
    public_key_bytes,
)
print("TEST 1 - Valid signature:", result1)


# TEST 2: Verify a changed message.
tampered_message = b"SSCA-Defender package has been modified"

result2 = verify_signature(
    tampered_message,
    signature,
    public_key_bytes,
)
print("TEST 2 - Tampered message:", result2)


# TEST 3: Verify a changed signature.
tampered_signature = bytearray(signature)
tampered_signature[0] ^= 1

result3 = verify_signature(
    message,
    bytes(tampered_signature),
    public_key_bytes,
)
print("TEST 3 - Tampered signature:", result3)

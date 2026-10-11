
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


def verify_signature(data, signature, public_key_bytes):
    """
    Verify an Ed25519 digital signature.

    data: bytes that were originally signed
    signature: signature bytes
    public_key_bytes: trusted signer's public key in raw format
    """

    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        public_key.verify(signature, data)

        return {
            "status": "PASS",
            "message": "Digital signature is valid."
        }

    except InvalidSignature:
        return {
            "status": "FAIL",
            "message": "Digital signature is invalid."
        }

    except ValueError:
        return {
            "status": "FAIL",
            "message": "Invalid public key."
        }

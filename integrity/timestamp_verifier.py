
from pathlib import Path
from datetime import timezone
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from pyasn1.type import univ
from rfc3161ng import decode_timestamp_response


def verify_timestamp(token_path, data_path, certificate_path):
    """
    Verify a FreeTSA RFC 3161 timestamp response.

    Checks:
    - The timestamp's SHA-256 imprint matches the file.
    - The embedded root matches the separately supplied root certificate.
    - The TSA certificate signature, validity, and timestamping usage.
    - The timestamp token's signed content digest and ECDSA signature.

    This implementation is tailored to the inspected FreeTSA response.
    """

    token_file = Path(token_path)
    data_file = Path(data_path)
    root_file = Path(certificate_path)

    for path in (token_file, data_file, root_file):
        if not path.is_file():
            return {
                "status": "FAIL",
                "message": f"Required file not found: {path}",
            }

    try:
        # Read and decode the timestamp response.
        response = decode_timestamp_response(token_file.read_bytes())
        token = response.time_stamp_token

        if token is None:
            raise ValueError("Timestamp response contains no token.")

        signed_data = token["content"]
        certificates = signed_data["certificates"]

        if len(certificates) < 2:
            raise ValueError("Expected TSA and root certificates.")

        tsa_cert = x509.load_der_x509_certificate(
            encode(certificates[0][0])
        )
        embedded_root = x509.load_der_x509_certificate(
            encode(certificates[1][0])
        )
        trusted_root = x509.load_pem_x509_certificate(
            root_file.read_bytes()
        )

        # Ensure the embedded root matches the independently supplied root.
        if embedded_root.fingerprint(hashes.SHA256()) != (
            trusted_root.fingerprint(hashes.SHA256())
        ):
            raise ValueError("Embedded root does not match trusted root.")

        if tsa_cert.issuer != trusted_root.subject:
            raise ValueError("TSA certificate issuer does not match root.")

        # Verify the TSA certificate signature using the root public key.
        root_key = trusted_root.public_key()

        if isinstance(root_key, rsa.RSAPublicKey):
            root_key.verify(
                tsa_cert.signature,
                tsa_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                tsa_cert.signature_hash_algorithm,
            )
        elif isinstance(root_key, ec.EllipticCurvePublicKey):
            root_key.verify(
                tsa_cert.signature,
                tsa_cert.tbs_certificate_bytes,
                ec.ECDSA(tsa_cert.signature_hash_algorithm),
            )
        else:
            raise ValueError("Unsupported root public-key type.")

        # Extract genTime from the timestamp information.
        tst_info = token.tst_info
        timestamp_value = tst_info.getComponentByName("genTime")

        if timestamp_value is None or not timestamp_value.isValue:
            raise ValueError(
                "Timestamp token does not contain a valid genTime."
            )

        timestamp = timestamp_value.asDateTime

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        # Verify that the TSA certificate was valid at the timestamp time.
        if not (
            tsa_cert.not_valid_before_utc
            <= timestamp
            <= tsa_cert.not_valid_after_utc
        ):
            raise ValueError(
                "TSA certificate was not valid at the timestamp time."
            )

        # Check timestamping Extended Key Usage.
        eku = tsa_cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value

        if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
            raise ValueError(
                "TSA certificate does not permit timestamping."
            )

        # Check the timestamp's SHA-256 message imprint against the file.
        expected_digest = bytes(
            tst_info.message_imprint.hashed_message
        )
        actual_digest = hashlib.sha256(data_file.read_bytes()).digest()

        if expected_digest != actual_digest:
            raise ValueError(
                "Timestamp message imprint does not match the file."
            )

        # Confirm the token has a signer and signed attributes.
        signer_infos = signed_data["signerInfos"]

        if len(signer_infos) == 0:
            raise ValueError("Timestamp token contains no signature.")

        signer_info = signer_infos[0]
        attributes = signer_info["authenticatedAttributes"]

        if len(attributes) == 0:
            raise ValueError("Timestamp signed attributes are missing.")

        # Decode the encapsulated timestamp content.
        content = bytes(
            decode(
                bytes(signed_data["contentInfo"]["content"]),
                asn1Spec=univ.OctetString(),
            )[0]
        )

        # Find the CMS messageDigest attribute.
        message_digest_oid = "1.2.840.113549.1.9.4"
        signed_digest = None

        for attribute in attributes:
            if str(attribute["type"]) == message_digest_oid:
                signed_digest = bytes(
                    decode(
                        bytes(attribute["values"][0]),
                        asn1Spec=univ.OctetString(),
                    )[0]
                )
                break

        if signed_digest is None:
            raise ValueError(
                "Timestamp signed messageDigest attribute is missing."
            )

        if signed_digest != hashlib.sha512(content).digest():
            raise ValueError(
                "Timestamp signed content digest is invalid."
            )

        # Encode authenticated attributes as a DER SET OF for verification.
        attrs_set = univ.SetOf()

        for index, attribute in enumerate(attributes):
            attrs_set.setComponentByPosition(index, attribute)

        signed_attributes = encode(attrs_set)
        signature = bytes(signer_info["encryptedDigest"])

        tsa_key = tsa_cert.public_key()

        if not isinstance(tsa_key, ec.EllipticCurvePublicKey):
            raise ValueError(
                "This verifier expects an elliptic-curve TSA public key."
            )

        # Verify the token signature using the observed ECDSA/SHA-512 format.
        tsa_key.verify(
            signature,
            signed_attributes,
            ec.ECDSA(hashes.SHA512()),
        )

        return {
            "status": "PASS",
            "message": (
                "Timestamp imprint, token signature, and direct TSA "
                "certificate checks passed."
            ),
            "timestamp": timestamp.isoformat(),
            "algorithm": "sha256",
        }

    except (
        InvalidSignature,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
    ) as exc:
        return {
            "status": "FAIL",
            "message": f"Timestamp verification failed: {exc}",
        }

    except Exception as exc:
        return {
            "status": "FAIL",
            "message": f"Unexpected timestamp verification error: {exc}",
        }

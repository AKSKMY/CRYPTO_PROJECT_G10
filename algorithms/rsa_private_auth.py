0# /algorithms/rsa_private_auth.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def is_private_key_correct(private_key_pem, public_key_pem, challenge):
    """
    Verifies if the loaded private key is correct by signing a challenge
    and verifying the signature with the corresponding public key.

    Parameters:
    - private_key_pem: Private key in PEM format (string)
    - public_key_pem: Public key in PEM format (string)
    - challenge: Challenge string to be signed and verified

    Returns:
    - True if the private key is correct, False otherwise
    """
    try:
        # Convert the private key PEM string to an RSA key object
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),  # Ensure it's in bytes
            password=None  # Assuming no password protection
        )

        # Convert the public key PEM to an RSA key object
        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        # Sign the challenge with the loaded private key
        signed_challenge = private_key.sign(
            challenge.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # Verify the signature using the public key
        public_key.verify(
            signed_challenge,
            challenge.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # If verification passes, the private key is correct
        return True

    except InvalidSignature:
        print("Signature verification failed. The private key is incorrect.")
        return False
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

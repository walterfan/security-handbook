"""Asymmetric encryption / signature demos.

- RSA-OAEP encryption (public key encrypts, private key decrypts)
- RSA-PSS signatures
- ECDSA signatures
- ECDH key agreement (shared secret between two EC key pairs)
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------- #
# RSA-OAEP encryption
# --------------------------------------------------------------------------- #
def rsa_encrypt(public_pem: str, plaintext: str) -> str:
    pub = serialization.load_pem_public_key(public_pem.encode())
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("Provided public key is not an RSA key.")
    ct = pub.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ct).decode()


def rsa_decrypt(private_pem: str, ciphertext_b64: str, passphrase: str | None = None) -> str:
    pw = passphrase.encode() if passphrase else None
    key = serialization.load_pem_private_key(private_pem.encode(), password=pw)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Provided private key is not an RSA key.")
    pt = key.decrypt(
        base64.b64decode(ciphertext_b64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return pt.decode()


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #
def sign(private_pem: str, message: str, passphrase: str | None = None) -> str:
    pw = passphrase.encode() if passphrase else None
    key = serialization.load_pem_private_key(private_pem.encode(), password=pw)
    data = message.encode()

    if isinstance(key, rsa.RSAPrivateKey):
        sig = key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("Unsupported key type for signing.")
    return base64.b64encode(sig).decode()


def verify(public_pem: str, message: str, signature_b64: str) -> bool:
    pub = serialization.load_pem_public_key(public_pem.encode())
    data = message.encode()
    sig = base64.b64decode(signature_b64)
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                sig,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError("Unsupported key type for verification.")
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- #
# ECDH key agreement demo
# --------------------------------------------------------------------------- #
def ecdh_demo(curve_name: str = "SECP256R1") -> dict:
    from .keys import EC_CURVES

    curve = EC_CURVES.get(f"{curve_name} (P-256)", ec.SECP256R1)()
    # Alice and Bob each generate an EC key pair.
    alice = ec.generate_private_key(curve)
    bob = ec.generate_private_key(curve)

    alice_shared = alice.exchange(ec.ECDH(), bob.public_key())
    bob_shared = bob.exchange(ec.ECDH(), alice.public_key())

    def kdf(raw: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecdh demo").derive(raw)

    alice_key = kdf(alice_shared)
    bob_key = kdf(bob_shared)

    return {
        "curve": curve.name,
        "alice_raw_secret": alice_shared.hex(),
        "bob_raw_secret": bob_shared.hex(),
        "alice_derived_key": alice_key.hex(),
        "bob_derived_key": bob_key.hex(),
        "match": alice_key == bob_key,
    }

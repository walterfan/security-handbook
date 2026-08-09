"""Key and certificate generation / inspection helpers.

All functions return PEM strings (``str``) so they can be shown, downloaded and
re-parsed easily inside the Streamlit UI.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


# --------------------------------------------------------------------------- #
# Key pair generation
# --------------------------------------------------------------------------- #
RSA_SIZES = [2048, 3072, 4096]
EC_CURVES = {
    "SECP256R1 (P-256)": ec.SECP256R1,
    "SECP384R1 (P-384)": ec.SECP384R1,
    "SECP521R1 (P-521)": ec.SECP521R1,
}


@dataclass
class KeyPair:
    private_pem: str
    public_pem: str
    kind: str  # "RSA" or "EC"
    detail: str


def generate_rsa_keypair(key_size: int = 2048, passphrase: str | None = None) -> KeyPair:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return _serialize_keypair(key, "RSA", f"{key_size}-bit", passphrase)


def generate_ec_keypair(curve_name: str = "SECP256R1 (P-256)", passphrase: str | None = None) -> KeyPair:
    curve = EC_CURVES[curve_name]()
    key = ec.generate_private_key(curve)
    return _serialize_keypair(key, "EC", curve_name, passphrase)


def _serialize_keypair(key, kind: str, detail: str, passphrase: str | None) -> KeyPair:
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        enc = serialization.NoEncryption()

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    ).decode()

    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return KeyPair(private_pem=private_pem, public_pem=public_pem, kind=kind, detail=detail)


# --------------------------------------------------------------------------- #
# X.509 certificate generation (self-signed)
# --------------------------------------------------------------------------- #
@dataclass
class CertResult:
    private_pem: str
    cert_pem: str


def _build_name(cn: str, org: str, country: str) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if country:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()))
    return x509.Name(attrs)


def generate_self_signed_cert(
    common_name: str,
    organization: str = "",
    country: str = "",
    sans: list[str] | None = None,
    valid_days: int = 365,
    key_type: str = "RSA",
    rsa_size: int = 2048,
    ec_curve: str = "SECP256R1 (P-256)",
) -> CertResult:
    if key_type == "EC":
        key = ec.generate_private_key(EC_CURVES[ec_curve]())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_size)

    subject = issuer = _build_name(common_name, organization, country)
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    san_list = [s.strip() for s in (sans or []) if s.strip()]
    if not san_list:
        san_list = [common_name]
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(s) for s in san_list]),
        critical=False,
    )

    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return CertResult(private_pem=private_pem, cert_pem=cert_pem)


# --------------------------------------------------------------------------- #
# Inspection
# --------------------------------------------------------------------------- #
def inspect_certificate(cert_pem: str) -> dict:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    pub = cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        pub_info = f"RSA {pub.key_size}-bit"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub_info = f"EC {pub.curve.name}"
    else:
        pub_info = type(pub).__name__

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    return {
        "Subject": cert.subject.rfc4514_string(),
        "Issuer": cert.issuer.rfc4514_string(),
        "Serial Number": hex(cert.serial_number),
        "Version": cert.version.name,
        "Signature Algorithm": cert.signature_algorithm_oid._name,
        "Public Key": pub_info,
        "Not Valid Before": not_before.isoformat(),
        "Not Valid After": not_after.isoformat(),
        "Status": "VALID" if not_before <= now <= not_after else "EXPIRED / NOT YET VALID",
        "Days Remaining": (not_after - now).days,
        "SHA-256 Fingerprint": cert.fingerprint(hashes.SHA256()).hex(":"),
        "Subject Alt Names": ", ".join(san) if san else "(none)",
        "Self-Signed": cert.subject == cert.issuer,
    }


def inspect_private_key(key_pem: str, passphrase: str | None = None) -> dict:
    pw = passphrase.encode() if passphrase else None
    key = serialization.load_pem_private_key(key_pem.encode(), password=pw)

    if isinstance(key, rsa.RSAPrivateKey):
        return {
            "Type": "RSA",
            "Key Size": f"{key.key_size} bits",
            "Public Exponent": key.public_key().public_numbers().e,
        }
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {
            "Type": "EC (Elliptic Curve)",
            "Curve": key.curve.name,
            "Key Size": f"{key.key_size} bits",
        }
    return {"Type": type(key).__name__}


def inspect_public_key(key_pem: str) -> dict:
    key = serialization.load_pem_public_key(key_pem.encode())
    if isinstance(key, rsa.RSAPublicKey):
        return {
            "Type": "RSA",
            "Key Size": f"{key.key_size} bits",
            "Public Exponent": key.public_numbers().e,
        }
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {
            "Type": "EC (Elliptic Curve)",
            "Curve": key.curve.name,
            "Key Size": f"{key.key_size} bits",
        }
    return {"Type": type(key).__name__}

from datetime import datetime, timedelta
from typing import Tuple, List
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from ib1.directory.extensions import encode_roles, encode_application


def _ca_extensions_cert(
    subject: x509.Name,
    issuer_name: x509.Name,
    issuer_key: ec.EllipticCurvePrivateKey,
    signing_key: ec.EllipticCurvePrivateKey,
    ca_path_length: int | None = 0,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                signing_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=ca_path_length), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
                key_encipherment=False,
                data_encipherment=False,
            ),
            critical=True,
        )
        .sign(signing_key, hashes.SHA256(), default_backend())
    )


def load_certificate(cert_pem: bytes) -> x509.Certificate:
    """
    Load a certificate from a PEM-encoded byte string.

    Args:
        cert_pem (bytes): PEM-encoded certificate.

    Returns:
        x509.Certificate: The loaded certificate.
    """
    return x509.load_pem_x509_certificate(cert_pem, default_backend())


def load_key(key_pem: bytes) -> PrivateKeyTypes:
    """
    Load a private key from a PEM-encoded byte string.

    Args:
        key_pem (bytes): PEM-encoded private key.

    Returns:
        PrivateKeyTypes: The loaded private key.
    """
    return serialization.load_pem_private_key(
        key_pem, password=None, backend=default_backend()
    )


def build_subject(
    country: str,
    state: str,
    organization_name: str,
    common_name: str,
) -> x509.Name:
    """
    Build an X.509 subject name.

    Args:
        country (str): Country name.
        state (str): State or province name.
        organization_name (str): Organization name.
        common_name (str): Common name.

    Returns:
        x509.Name: The constructed X.509 subject name.
    """
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def generate_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def create_signing_pair(
    country: str = "GB",
    state: str = "London",
    framework: str = "Core",
    use: str = "Client",
    kind: str = "CA",
    ca_cert: x509.Certificate | None = None,
    ca_key: ec.EllipticCurvePrivateKey | None = None,
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Create a signing key certificate pair.

    Args:
        country (str): Country name.
        state (str): State or province name.
        framework (str): Framework name.
        use (str): Use case (e.g., Client, Server).
        kind (str): Kind of certificate (e.g., CA).
        ca_cert (x509.Certificate, optional): CA certificate.
        ca_key (ec.EllipticCurvePrivateKey, optional): CA private key.

    Returns:
        Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]: The generated private key and certificate.
    """
    key = generate_key()
    description = f"{framework} Trust Framework"
    subject_name = build_subject(
        country, state, description, f"{description} {use} {kind}"
    )
    if ca_cert is None or ca_key is None:
        issuer = subject_name
        ca_key = key
        path_length = None
    else:
        issuer = ca_cert.subject
        path_length = 0

    # Build the certificate
    if ca_key:
        cert = _ca_extensions_cert(
            subject=subject_name,
            issuer_name=issuer,
            issuer_key=key,
            signing_key=ca_key,
            ca_path_length=path_length,
        )
    return key, cert


def get_bundle(certificate_pem: bytes, issuer_cert_pem: bytes) -> bytes:

    # Concatenate certificates in memory
    bundle = BytesIO()
    bundle.write(certificate_pem)
    bundle.write(issuer_cert_pem)

    # Get the concatenated bundle as bytes
    bundle_pem = bundle.getvalue()

    # Close the BytesIO object
    bundle.close()
    return bundle_pem


def sign_csr(
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    csr_pem: bytes,
    subject: x509.Name,
    roles: List[str] | None = None,
    application: str | None = None,
    server: bool = False,
    days_valid: int = 365,
) -> x509.Certificate:
    """
    Sign a user-provided CSR.

    Args:
        issuer_cert (x509.Certificate): Issuer certificate.
        issuer_key (ec.EllipticCurvePrivateKey): Issuer private key.
        csr_pem (bytes): CSR in PEM format.
        days_valid (int): Number of days the certificate is valid for.
        subject (x509.Name): Subject name for the certificate.
        roles (List[str], optional): Roles to encode in the certificate.
        application (str, optional): Application to encode in the certificate.
        server (bool, optional): Whether the certificate is for a server.

    Returns:
        x509.Certificate: The signed certificate.
    """
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    # Build the application certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
        .serial_number(x509.random_serial_number())
    )

    if server:
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
                key_encipherment=True,
                data_encipherment=False,
            ),
            critical=True,
        )
    else:
        common_name = str(subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        print(common_name)
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(common_name)]),
            critical=False,
        )

    if roles:
        cert_builder = encode_roles(cert_builder, roles)
    if application:
        cert_builder = encode_application(cert_builder, application)

    cert = cert_builder.sign(issuer_key, hashes.SHA256(), default_backend())
    return cert

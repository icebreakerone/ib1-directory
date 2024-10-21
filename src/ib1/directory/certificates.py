from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from typing import Tuple, List

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


def create_signing_ca(
    country="GB", framework="Core Trust Framework"
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Create the CA key and certificate"""
    # Generate CA key
    ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, framework),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{framework} Signing CA"),
        ]
    )

    # Build the CA certificate
    ca_cert = _ca_extensions_cert(
        subject=subject,
        issuer_name=subject,
        issuer_key=ca_key,
        signing_key=ca_key,
        ca_path_length=None,
    )
    return ca_key, ca_cert


def create_signing_issuer(
    ca_cert: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Create an issuer certificate signed by the CA"""
    # Generate issuer key
    issuer_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Build issuer subject
    issuer_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "London"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "Energy Sector Trust Framework"
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, "Energy Sector Trust Framework Signing Issuer"
            ),
        ]
    )
    # Build the issuer certificate
    issuer_cert = _ca_extensions_cert(
        subject=issuer_subject,
        issuer_name=ca_cert.subject,
        issuer_key=issuer_key,
        signing_key=ca_key,
    )

    return issuer_key, issuer_cert


def sign_application_csr(
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    csr_pem: bytes,
    roles: List[str],
    application: str,
    san_uri: str,
    serial_number: int,
    days_valid: int,
) -> x509.Certificate:
    """Sign a user-provided CSR"""
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    # Build the application certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]),
            critical=False,
        )
    )
    if roles:
        cert_builder = encode_roles(cert_builder, roles)
    if application:
        cert_builder = encode_application(cert_builder, application)

    cert = cert_builder.sign(issuer_key, hashes.SHA256(), default_backend())
    return cert

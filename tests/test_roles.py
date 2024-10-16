import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from ib1.directory.exceptions import CertificateRoleError, CertificateExtensionError

from ib1.directory.roles import (
    encode_roles,
    encode_application,
    decode_roles,
    decode_application,
    require_role,
)


@pytest.fixture
def certificate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mycompany.com"),
        ]
    )
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
    )
    return cert_builder, private_key


def test_encode_roles(certificate):
    cert_builder, private_key = certificate
    roles = ["admin", "user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    decoded_roles = decode_roles(cert)
    assert decoded_roles == roles


def test_encode_application(certificate):
    cert_builder, private_key = certificate
    application = "my_app"
    cert_builder = encode_application(cert_builder, application)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    decoded_application = decode_application(cert)
    assert decoded_application == application


def test_decode_roles_missing_extension(certificate):
    cert_builder, private_key = certificate
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateExtensionError):
        decode_roles(cert)


def test_decode_application_missing_extension(certificate):
    cert_builder, private_key = certificate
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateExtensionError):
        decode_application(cert)


def test_require_role(certificate):
    cert_builder, private_key = certificate
    roles = ["admin", "user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    assert require_role("admin", cert) is True


def test_require_role_missing(certificate):
    cert_builder, private_key = certificate
    roles = ["user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateRoleError):
        require_role("admin", cert)

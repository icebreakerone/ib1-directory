import pytest
from cryptography.hazmat.primitives import hashes
from ib1.directory.exceptions import CertificateRoleError, CertificateExtensionError

from ib1.directory.roles import (
    encode_roles,
    encode_application,
    decode_roles,
    decode_application,
    require_role,
)

from tests import certificate_builder


def test_encode_roles(certificate_builder):
    cert_builder, private_key = certificate_builder
    roles = ["admin", "user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    decoded_roles = decode_roles(cert)
    assert decoded_roles == roles


def test_encode_application(certificate_builder):
    cert_builder, private_key = certificate_builder
    application = "https://directory.ib1.org/application/123456"
    cert_builder = encode_application(cert_builder, application)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    decoded_application = decode_application(cert)
    assert decoded_application == application


def test_decode_roles_missing_extension(certificate_builder):
    cert_builder, private_key = certificate_builder
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateExtensionError):
        decode_roles(cert)


def test_decode_application_missing_extension(certificate_builder):
    cert_builder, private_key = certificate_builder
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateExtensionError):
        decode_application(cert)


def test_require_role(certificate_builder):
    cert_builder, private_key = certificate_builder
    roles = ["admin", "user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    assert require_role("admin", cert) is True


def test_require_role_missing(certificate_builder):
    cert_builder, private_key = certificate_builder
    roles = ["user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateRoleError):
        require_role("admin", cert)

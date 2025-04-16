import pytest
from cryptography.hazmat.primitives import hashes
from ib1.directory import CertificateRoleError, CertificateExtensionError

from ib1.directory import (
    require_role,
)
from ib1.directory.extensions import (
    encode_roles,
    encode_member,
    decode_roles,
    decode_member,
)

from tests import certificate_builder  # noqa: F401


def test_encode_roles(certificate_builder):  # noqa: F811
    cert_builder, private_key = certificate_builder
    roles = ["admin", "user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    decoded_roles = decode_roles(cert)
    assert decoded_roles == roles


def test_encode_member(certificate_builder):  # noqa: F811
    cert_builder, private_key = certificate_builder
    application = "https://directory.core.trust.ib1.org/member/71212388"
    cert_builder = encode_member(cert_builder, application)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    decoded_application = decode_member(cert)
    assert decoded_application == application


def test_decode_roles_missing_extension(certificate_builder):  # noqa: F811
    cert_builder, private_key = certificate_builder
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateExtensionError):
        decode_roles(cert)


def test_decode_application_missing_extension(certificate_builder):  # noqa: F811
    cert_builder, private_key = certificate_builder
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateExtensionError):
        decode_member(cert)


def test_require_role(certificate_builder):  # noqa: F811
    cert_builder, private_key = certificate_builder
    roles = ["admin", "user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    assert require_role("admin", cert) is True


def test_require_role_missing(certificate_builder):  # noqa: F811
    cert_builder, private_key = certificate_builder
    roles = ["user"]
    cert_builder = encode_roles(cert_builder, roles)
    cert = cert_builder.sign(private_key, hashes.SHA256())
    with pytest.raises(CertificateRoleError):
        require_role("admin", cert)

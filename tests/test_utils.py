import pytest
from urllib.parse import quote
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from ib1.directory.utils import parse_cert
from ib1.directory import CertificateError

from tests import certificate_builder  # noqa: F401


@pytest.fixture
def pem_certificate(certificate_builder):  # noqa: F811
    cert_builder, private_key = certificate_builder
    cert = cert_builder.sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_parse_cert_with_pem_string(pem_certificate):
    cert = parse_cert(pem_certificate)
    assert isinstance(cert, x509.Certificate)


def test_parse_cert_with_quoted_pem_string(pem_certificate):
    quoted_pem_cert = quote(pem_certificate)
    cert = parse_cert(quoted_pem_cert)
    assert isinstance(cert, x509.Certificate)


def test_parse_cert_with_invalid_string():
    with pytest.raises(CertificateError):
        parse_cert("invalid_certificate_string")

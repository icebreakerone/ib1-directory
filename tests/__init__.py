import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import pytest


@pytest.fixture
def certificate_builder():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "London"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Member"),
            x509.NameAttribute(
                NameOID.COMMON_NAME, "https://directory.ib1.org/member/123456"
            ),
        ]
    )
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
    )
    return cert_builder, private_key

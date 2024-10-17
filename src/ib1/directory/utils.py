from urllib.parse import unquote
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .exceptions import CertificateInvalidError


def parse_cert(client_certificate: str) -> x509.Certificate:
    """
    Given a certificate as a quoted or unquoted string, return a x509.Certificate object.

    Parameters:
        client_certificate (str): The client certificate as a string, which can be either quoted or unquoted.

    Returns:
        x509.Certificate: The parsed x509.Certificate object.

    Raises:
        CertificateInvalidError: If the certificate string is invalid and cannot be parsed.
    """
    try:
        return x509.load_pem_x509_certificate(
            bytes(unquote(client_certificate), "utf-8"), default_backend()
        )
    except ValueError:
        raise CertificateInvalidError("Invalid certificate string")

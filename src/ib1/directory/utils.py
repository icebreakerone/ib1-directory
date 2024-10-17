from urllib.parse import unquote
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .exceptions import CertificateMissingError


def parse_cert(client_certificate: str) -> x509.Certificate:
    """
    Given a certificate as a quoted string, parse it into a x509.Certificate object.

    If a certificate is present, on our deployment it will be in request.headers['X-Amzn-Mtls-Clientcert']
    nb. the method and naming of passing the client certificate may vary depending on the deployment
    """
    try:
        return x509.load_pem_x509_certificate(
            bytes(unquote(client_certificate), "utf-8"), default_backend()
        )
    except TypeError:
        raise CertificateMissingError("No client certificate presented")

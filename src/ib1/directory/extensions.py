from cryptography import x509

from ib1.directory.exceptions import CertificateRoleError, CertificateExtensionError
from ib1.directory import der

ROLE_IDENTIFIER = "1.3.6.1.4.1.62329.1.1"
MEMBER_IDENTIFIER = "1.3.6.1.4.1.62329.1.3"


def _add_extension(
    cert_builder: x509.CertificateBuilder, oid: str, value: bytes
) -> x509.CertificateBuilder:
    """
    Add an extension to the certificate builder.

    Args:
        cert_builder (x509.CertificateBuilder): The certificate builder.
        oid (str): The object identifier for the extension.
        value (bytes): The value of the extension.

    Returns:
        x509.CertificateBuilder: The updated certificate builder with the new extension.
    """
    return cert_builder.add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier(oid),
            value,
        ),
        critical=False,
    )


def _extension_value(cert: x509.Certificate, oid: str) -> bytes:
    """
    Retrieve the value of an extension from a certificate.

    Args:
        cert (x509.Certificate): The certificate.
        oid (str): The object identifier for the extension.

    Returns:
        bytes: The value of the extension.
    """
    try:
        extension = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(oid)
        ).value.value  # type: ignore [attr-defined]
    except AttributeError:
        raise CertificateExtensionError("Certificate is invalid or missing extensions")
    return extension


def encode_roles(cert_builder: x509.CertificateBuilder, roles: list[str]):
    """
    Encode roles into the certificate builder as an extension.

    Args:
        cert_builder (x509.CertificateBuilder): The certificate builder.
        roles (list[str]): The roles to encode.

    Returns:
        x509.CertificateBuilder: The updated certificate builder with the roles extension.
    """
    return _add_extension(cert_builder, ROLE_IDENTIFIER, der.encode_sequence(roles))


def encode_member(cert_builder: x509.CertificateBuilder, member: str):
    """
    Encode member information into the certificate builder as an extension.

    Args:
        cert_builder (x509.CertificateBuilder): The certificate builder.
        member (str): The member information to encode.

    Returns:
        x509.CertificateBuilder: The updated certificate builder with the member extension.
    """
    return _add_extension(cert_builder, MEMBER_IDENTIFIER, der.encode_string(member))


def decode_roles(cert: x509.Certificate) -> list[str]:
    """
    Decode roles from a certificate.

    Args:
        cert (x509.Certificate): The certificate.

    Returns:
        list[str]: The decoded roles.

    Raises:
        CertificateExtensionError: If the certificate does not include role information.
    """
    try:
        role_der = _extension_value(cert, ROLE_IDENTIFIER)
    except x509.ExtensionNotFound:
        raise CertificateExtensionError(
            "Client certificate does not include role information"
        )
    return der.decode_sequence(role_der)


def decode_member(cert: x509.Certificate) -> str:
    """
    Decode member information from a certificate.

    Args:
        cert (x509.Certificate): The certificate.

    Returns:
        str: The decoded member information.

    Raises:
        CertificateExtensionError: If the certificate does not include member information.
    """
    try:
        member_der = _extension_value(cert, MEMBER_IDENTIFIER)
    except x509.ExtensionNotFound:
        raise CertificateExtensionError(
            "Client certificate does not include member information"
        )
    return der.decode_string(member_der)


def require_role(role_name: str, cert: x509.Certificate) -> bool:
    """
    Check that the certificate includes the given role, raising an exception if not.

    Args:
        role_name (str): The role name to check for.
        cert (x509.Certificate): The certificate.

    Returns:
        bool: True if the role is present in the certificate.

    Raises:
        CertificateRoleError: If the certificate does not include the role or the role information.
    """
    roles = decode_roles(cert)
    if role_name not in roles:
        raise CertificateRoleError(
            "Client certificate does not include role " + role_name
        )
    return True

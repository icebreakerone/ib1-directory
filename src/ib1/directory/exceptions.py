class Ib1DirectoryError(Exception):
    """Base class for exceptions in this module."""


class CertificateError(Ib1DirectoryError):
    """
    Base class for errors related to the client certificate
    """


class CertificateMissingError(CertificateError):
    """
    Raised when the client certificate is missing
    """


class CertificateInvalidError(CertificateError):
    pass


class CertificateExtensionError(CertificateError):
    pass


class CertificateRoleError(CertificateError):
    pass

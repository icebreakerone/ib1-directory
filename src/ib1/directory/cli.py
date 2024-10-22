import click
from cryptography.hazmat.primitives import serialization

from ib1.directory.certificates import (
    create_signing_pair,
)


# def create_client_signing_ca(
#     country="GB", state="London", framework="Core"
# ) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
#     """Create the CA key and certificate"""
#     # Generate CA key
#     return create_signing_pair(
#         country=country, state=state, framework=framework, use="Client", kind="CA"
#     )


# def create_client_signing_issuer(
#     ca_cert: x509.Certificate,
#     ca_key: ec.EllipticCurvePrivateKey,
#     country="GB",
#     state="London",
#     framework="Core",
#     use="Client",
# ) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
#     """Create an issuer certificate signed by the CA"""
#     return create_signing_pair(
#         ca_cert=ca_cert,
#         ca_key=ca_key,
#         country=country,
#         state=state,
#         framework=framework,
#         use="Client",
#         kind="Issuer",
#     )


# def create_server_signing_ca(
#     country="GB", state="London", framework="Core"
# ) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
#     """Create the CA key and certificate"""
#     # Generate CA key
#     return create_signing_pair(
#         country=country, state=state, framework=framework, use="Server", kind="CA"
#     )


# def create_server_signing_issuer(
#     ca_cert: x509.Certificate,
#     ca_key: ec.EllipticCurvePrivateKey,
#     country="GB",
#     state="London",
#     framework="Core",
#     use="Client",
# ) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
#     """Create an issuer certificate signed by the CA"""
#     return create_signing_pair(
#         ca_cert=ca_cert,
#         ca_key=ca_key,
#         country=country,
#         state=state,
#         framework=framework,
#         use="Server",
#         kind="Issuer",
#     )


@click.group()
def cli():
    """A CLI for generating and signing certificates."""
    pass


@cli.command()
@click.option(
    "-u",
    "--usage",
    type=click.Choice(["client", "server"]),
    help="Choose server or client CA",
    default="client",
)
@click.option(
    "-c", "--country", default="GB", help="Country to use for certificate generation"
)  # , state: str, framework: str
@click.option(
    "-s", "--state", default="London", help="State to use for certificate generation"
)
@click.option(
    "-f", "--framework", default="Core", help="Framework this certificate is for"
)
def create_ca(usage: str, country: str, state: str, framework: str):
    """Generate a server signing CA key and certificate and an issuer key and certificate pair signed by the CA then saves all files to disk"""
    print(f"Creating {usage} CA")
    ca_key, ca_certificate = create_signing_pair(
        country=country,
        state=state,
        framework=framework,
        use=usage.capitalize(),
        kind="CA",
    )
    issuer_key, issuer_certificate = create_signing_pair(
        country=country,
        state=state,
        framework=framework,
        use=usage.capitalize(),
        kind="Issuer",
        ca_cert=ca_certificate,
        ca_key=ca_key,
    )
    with open(f"{usage.lower()}-signing-ca-cert.pem", "wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
    print(f"CA cert: {usage.lower()}-signing-ca-cert.pem")
    with open(f"{usage.lower()}-signing-ca-key.pem", "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"CA key: {usage.lower()}-signing-ca-key.pem")
    with open(f"{usage.lower()}-signing-issuer-cert.pem", "wb") as f:
        f.write(issuer_certificate.public_bytes(serialization.Encoding.PEM))
    print(f"Issuer cert: {usage.lower()}-signing-issuer-cert.pem")
    with open(f"{usage.lower()}-signing-issuer-key.pem", "wb") as f:
        f.write(
            issuer_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"Issuer key: {usage.lower()}-signing-issuer-key.pem")


if __name__ == "__main__":
    cli()

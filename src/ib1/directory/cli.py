import click
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

from ib1.directory.certificates import (
    create_signing_pair,
    load_certificate,
    load_key,
    build_subject,
    sign_csr,
    generate_key,
    get_bundle,
)


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


@cli.command()
@click.option(
    "--issuer-key-file",
    type=click.File("rb"),
    help="Issuer key file",
    default="client-signing-issuer-key.pem",
)
@click.option(
    "--issuer-cert-file",
    type=click.File("rb"),
    help="Issuer certificate file",
    default="client-signing-issuer-cert.pem",
)
@click.option(
    "--member_uri",
    type=str,
    help="Member uri",
    default="https://directory.estf.ib1.org/member/2876152",
)
@click.option(
    "--organization_name",
    type=str,
    help="Organization name",
    default="Demo Carbon Accounting Platform",
)
@click.option("--country", type=str, help="Country", default="GB")
@click.option("--state", type=str, help="State", default="London")
@click.option(
    "--role",
    "-r",
    help="Client roles",
    multiple=True,
    default=[
        "https://registry.estf.ib1.org/scheme/electricty/role/supply-voltage-reader"
    ],
)
@click.option(
    "--application_uri",
    type=str,
    help="Application uri",
    default="https://directory.estf.ib1.org/scheme/electricty/application/26241",
)
def create_client_certificates(
    issuer_key_file: click.Path,
    issuer_cert_file: click.Path,
    member_uri: str,
    organization_name: str,
    country: str,
    state: str,
    role: list[str],
    application_uri: str,
):
    """
    Create a private key and use it generate a CSR, then sign the CSR with a CA key and certificate.

    Saves the private key, CSR, certificate and bundle to disk.
    """

    with open(issuer_cert_file.name, "rb") as f:
        issuer_cert_pem = f.read()
    with open(issuer_key_file.name, "rb") as f:
        issuer_key_pem = f.read()
    issuer_cert = load_certificate(issuer_cert_pem)
    issuer_key = load_key(issuer_key_pem)
    client_key = generate_key()
    subject = build_subject(
        country=country,
        state=state,
        organization_name=organization_name,
        common_name=member_uri,
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(client_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    # Create a CSR using the arguments given
    client_certificate = sign_csr(
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        csr_pem=csr_pem,
        subject=subject,
        roles=role,
        application=application_uri,
    )
    client_certificate_pem = client_certificate.public_bytes(serialization.Encoding.PEM)
    bundle = get_bundle(client_certificate_pem, issuer_cert_pem)
    file_prefix = organization_name.lower().replace(" ", "-")
    # Write private key to disk as application-key.pem
    with open(f"{file_prefix}-key.pem", "wb") as f:
        f.write(
            issuer_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    # Write certifivate PEM to disk as application-cert.pem
    with open(f"{file_prefix}-cert.pem", "wb") as f:
        f.write(client_certificate_pem)
    # Write bundle to disk as application-bundle.pem
    with open(f"{file_prefix}-bundle.pem", "wb") as f:
        f.write(bundle)


# Write a command create server certificates with similar functionality except we must accept a domain name rather than application name, and we don't need to encode rules or applicaiton_uri
@cli.command()
@click.option(
    "--issuer-key-file",
    type=click.File("rb"),
    help="Issuer key file",
    default="server-signing-issuer-key.pem",
)
@click.option(
    "--issuer-cert-file",
    type=click.File("rb"),
    help="Issuer certificate file",
    default="server-signing-issuer-cert.pem",
)
@click.option(
    "--domain",
    type=str,
    help="Domain name",
    default="http://tf-member.org",
)
@click.option(
    "--trust_framework",
    type=str,
    help="Trust framework",
    default="Core Trust Framework",
)
@click.option("--country", type=str, help="Country", default="GB")
@click.option("--state", type=str, help="State", default="London")
def create_server_certificates(
    issuer_key_file: click.Path,
    issuer_cert_file: click.Path,
    domain: str,
    trust_framework: str,
    country: str,
    state: str,
):
    """
    Create a private key and use it generate a CSR, then sign the CSR with a CA key and certificate.

    Saves the private key, CSR, certificate and bundle to disk.
    """

    with open(issuer_cert_file.name, "rb") as f:
        issuer_cert_pem = f.read()
    with open(issuer_key_file.name, "rb") as f:
        issuer_key_pem = f.read()
    issuer_cert = load_certificate(issuer_cert_pem)
    issuer_key = load_key(issuer_key_pem)
    server_key = generate_key()
    subject = build_subject(
        country=country,
        state=state,
        organization_name=trust_framework,
        common_name=domain,
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(server_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    # Create a CSR using the arguments given
    server_certificate = sign_csr(
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        csr_pem=csr_pem,
        subject=subject,
        server=True,
    )
    server_certificate_pem = server_certificate.public_bytes(serialization.Encoding.PEM)
    bundle = get_bundle(server_certificate_pem, issuer_cert_pem)
    file_prefix = domain.replace("/", "").replace(":", "")
    # Write private key to disk as application-key.pem
    with open(f"{file_prefix}-key.pem", "wb") as f:
        f.write(
            issuer_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    # Write certifivate PEM to disk as application-cert.pem
    with open(f"{file_prefix}-cert.pem", "wb") as f:
        f.write(server_certificate_pem)
    # Write bundle to disk as application-bundle.pem
    with open(f"{file_prefix}-bundle.pem", "wb") as f:
        f.write(bundle)


if __name__ == "__main__":
    cli()

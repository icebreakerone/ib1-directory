# IB1 Directory

A library to simplify working with the IB1 Trust Framework directory

## Development

### Setup

```bash
poetry install
```

### Run tests

```bash
poetry run pytest
```

### Package and publish

```bash
poetry build
poetry publish
```

## Usage

### Encoding and decoding

```python
from ib1.directory.extensions import encode_roles, decode_roles
...

cert_builder = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
)

cert_builder = encode_roles(cert_builder, roles)

cert = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

roles = decode_roles(cert)
```

### Require a role

```python
from ib1 import directory
...
    cert = directory.parse_cert(quoted_certificate_from_header)
    try:
        directory.require_role(
            "https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting",
            cert,
        )
    except directory.CertificateRoleError as e:
        raise HTTPException(
            status_code=401,
            detail=str(e),
        )
...
```

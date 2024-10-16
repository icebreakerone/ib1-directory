from asn1crypto.core import SequenceOf, UTF8String  # type: ignore


class UTF8Sequence(SequenceOf):
    _child_spec = UTF8String


def decode_der_sequence(der_bytes: bytes) -> list[str]:
    values = UTF8Sequence.load(der_bytes)
    decoded = []
    for i in range(0, len(values)):
        decoded.append(values[i].native)
    return decoded


def encode_der_sequence(urls: list[str]) -> bytes:
    extension_sequence = UTF8Sequence(urls)
    return extension_sequence.dump()

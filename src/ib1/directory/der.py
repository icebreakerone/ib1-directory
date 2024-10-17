from asn1crypto.core import SequenceOf, UTF8String  # type: ignore


class UTF8Sequence(SequenceOf):
    _child_spec = UTF8String


def decode_sequence(der_bytes: bytes) -> list[str]:
    values = UTF8Sequence.load(der_bytes)
    decoded = []
    for i in range(0, len(values)):
        decoded.append(values[i].native)
    return decoded


def encode_sequence(urls: list[str]) -> bytes:
    extension_sequence = UTF8Sequence(urls)
    return extension_sequence.dump()


def encode_string(string: str) -> bytes:
    return UTF8String(string).dump()


def decode_string(der_bytes: bytes) -> str:
    return str(UTF8String.load(der_bytes))

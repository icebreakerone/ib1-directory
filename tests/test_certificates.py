from cryptography.x509.oid import NameOID

from ib1.directory.certificates import build_subject


def test_build_subject():
    subject = build_subject("GB", "London", "Test Organization", "Test CN")

    # Verify the subject fields
    assert subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "GB"
    assert (
        subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
        == "London"
    )
    assert (
        subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        == "Test Organization"
    )
    assert subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test CN"

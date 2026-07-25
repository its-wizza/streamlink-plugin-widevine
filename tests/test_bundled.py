import base64
import shutil
from pathlib import Path
from uuid import UUID

import pytest
import pywidevine as upstream
import pywidevine.license_protocol_pb2 as upstream_protocol
import pywidevine.utils as upstream_utils
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Util import Padding
from pywidevine.device import _Structures as UpstreamStructures

import pywidevine_bundled as bundled


ENC_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff",
)

IV = bytes.fromhex(
    "ffeeddccbbaa99887766554433221100",
)

KID = bytes.fromhex(
    "0123456789abcdeffedcba9876543210",
)


def _encrypt_key(key):
    return AES.new(
        ENC_KEY,
        AES.MODE_CBC,
        iv=IV,
    ).encrypt(Padding.pad(key, 16))


def _make_bundled_widevine_data():
    return bundled.WidevinePsshData(
        key_ids=[
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        ],
        provider="test-provider",
        content_id=b"test-content",
        protection_scheme=0x63656E63,
    )


def _make_upstream_widevine_data():
    return upstream_protocol.WidevinePsshData(
        key_ids=[
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        ],
        provider="test-provider",
        content_id=b"test-content",
        protection_scheme=0x63656E63,
    )


def _make_device_material():
    private_key = RSA.generate(2048)

    drm_certificate = upstream_protocol.DrmCertificate(
        type="DEVICE",
        serial_number=b"test-serial",
        creation_time_seconds=123456789,
        public_key=private_key.public_key().export_key("DER"),
        system_id=12345,
    )

    signed_drm_certificate = upstream_protocol.SignedDrmCertificate(
        drm_certificate=drm_certificate.SerializeToString(),
        signature=b"test-signature",
    )

    file_hashes = upstream_protocol.FileHashes(
        signer=b"test-signer",
        signatures=[
            {
                "filename": "test.bin",
                "test_signing": True,
                "SHA512Hash": b"test-hash",
                "main_exe": True,
                "signature": b"test-file-signature",
            },
        ],
    )

    client_id = upstream_protocol.ClientIdentification(
        token=signed_drm_certificate.SerializeToString(),
        client_info=[
            {
                "name": "company_name",
                "value": "Test Company",
            },
            {
                "name": "model_name",
                "value": "Test Device",
            },
        ],
        vmp_data=file_hashes.SerializeToString(),
    )

    return private_key, client_id


def _make_upstream_device(material=None):
    private_key, client_id = material or _make_device_material()

    return upstream.Device(
        type_=upstream.DeviceTypes.ANDROID,
        security_level=3,
        flags={},
        private_key=private_key.export_key("DER"),
        client_id=client_id.SerializeToString(),
    )


def _make_bundled_device(material=None):
    private_key, client_id = material or _make_device_material()

    return bundled.Device(
        type_=bundled.DeviceTypes.ANDROID,
        security_level=3,
        flags={},
        private_key=private_key.export_key("DER"),
        client_id=client_id.SerializeToString(),
    )


def _make_v1_device_data(*, with_vmp=False):
    private_key, client_id = _make_device_material()

    vmp = client_id.vmp_data if with_vmp else b""
    client_id.vmp_data = b""

    private_key_data = private_key.export_key("DER")
    client_id_data = client_id.SerializeToString()

    return UpstreamStructures.v1.build({
        "type_": "ANDROID",
        "security_level": 3,
        "flags": {},
        "private_key_len": len(private_key_data),
        "private_key": private_key_data,
        "client_id_len": len(client_id_data),
        "client_id": client_id_data,
        "vmp_len": len(vmp),
        "vmp": vmp,
    })


def _make_cdms():
    material = _make_device_material()

    bundled_cdm = bundled.Cdm.from_device(
        _make_bundled_device(material),
    )
    upstream_cdm = upstream.Cdm.from_device(
        _make_upstream_device(material),
    )

    return bundled_cdm, upstream_cdm


def _parse_bundled_license_request(challenge):
    signed = bundled.SignedMessage()
    signed.ParseFromString(challenge)

    request = bundled.LicenseRequest()
    request.ParseFromString(signed.msg)

    return signed, request


def _parse_upstream_license_request(challenge):
    signed = upstream_protocol.SignedMessage()
    signed.ParseFromString(challenge)

    request = upstream_protocol.LicenseRequest()
    request.ParseFromString(signed.msg)

    return signed, request


def _make_bundled_pssh():
    return bundled.PSSH(
        _make_bundled_widevine_data().SerializeToString(),
    )


def _make_upstream_pssh():
    return upstream.PSSH(
        _make_upstream_widevine_data().SerializeToString(),
    )


def _make_license_response(
    impl,
    protocol,
    device,
    challenge,
    *,
    content_keys=None,
    oemcrypto_core_message=b"",
):
    if content_keys is None:
        content_keys = [
            (
                bytes.fromhex(
                    "00112233445566778899aabbccddeeff",
                ),
                bytes.fromhex(
                    "11223344556677889900aabbccddeeff",
                ),
            ),
        ]

    signed_request = protocol.SignedMessage()
    signed_request.ParseFromString(challenge)

    request = protocol.LicenseRequest()
    request.ParseFromString(signed_request.msg)

    request_id = request.content_id.widevine_pssh_data.request_id

    # This is the AES session key the "license server"
    # gives to the CDM, RSA-OAEP wrapped for the device.
    session_key = bytes.fromhex(
        "0123456789abcdeffedcba9876543210",
    )

    enc_context, mac_context = impl.Cdm.derive_context(
        signed_request.msg,
    )
    enc_key, mac_key_server, _ = impl.Cdm.derive_keys(
        enc_context,
        mac_context,
        session_key,
    )

    license_message = protocol.License()
    license_message.id.request_id = request_id

    for kid, plaintext_key in content_keys:
        iv = bytes.fromhex(
            "ffeeddccbbaa99887766554433221100",
        )

        encrypted_key = AES.new(
            enc_key,
            AES.MODE_CBC,
            iv=iv,
        ).encrypt(
            Padding.pad(plaintext_key, 16),
        )

        key = protocol.License.KeyContainer(
            id=kid,
            iv=iv,
            key=encrypted_key,
            type="CONTENT",
        )

        license_message.key.append(key)

    license_bytes = license_message.SerializeToString()

    encrypted_session_key = PKCS1_OAEP.new(
        device.private_key.public_key(),
    ).encrypt(session_key)

    signature = (
        HMAC
        .new(
            mac_key_server,
            digestmod=SHA256,
        )
        .update(oemcrypto_core_message)
        .update(license_bytes)
        .digest()
    )

    return protocol.SignedMessage(
        type=protocol.SignedMessage.MessageType.Value(
            "LICENSE",
        ),
        msg=license_bytes,
        signature=signature,
        session_key=encrypted_session_key,
        oemcrypto_core_message=oemcrypto_core_message,
    )


def test_key_from_content_key_container_matches_upstream():
    plaintext_key = bytes.fromhex(
        "11223344556677889900aabbccddeeff",
    )
    encrypted_key = _encrypt_key(plaintext_key)

    bundled_container = bundled.License.KeyContainer(
        id=KID,
        iv=IV,
        key=encrypted_key,
        type="CONTENT",
    )

    upstream_container = upstream_protocol.License.KeyContainer(
        id=KID,
        iv=IV,
        key=encrypted_key,
        type="CONTENT",
    )

    bundled_key = bundled.Key.from_key_container(
        bundled_container,
        ENC_KEY,
    )

    upstream_key = upstream.Key.from_key_container(
        upstream_container,
        ENC_KEY,
    )

    assert bundled_key.type == upstream_key.type
    assert bundled_key.kid == upstream_key.kid
    assert bundled_key.key == upstream_key.key
    assert bundled_key.permissions == upstream_key.permissions


def test_key_from_operator_session_key_container_matches_upstream():
    plaintext_key = bytes.fromhex(
        "aabbccddeeff00112233445566778899",
    )
    encrypted_key = _encrypt_key(plaintext_key)

    bundled_container = bundled.License.KeyContainer(
        id=KID,
        iv=IV,
        key=encrypted_key,
        type="OPERATOR_SESSION",
        operator_session_key_permissions=(
            bundled.License.KeyContainer.OperatorSessionKeyPermissions(
                allow_encrypt=True,
                allow_decrypt=False,
                allow_sign=True,
                allow_signature_verify=True,
            )
        ),
    )

    upstream_container = upstream_protocol.License.KeyContainer(
        id=KID,
        iv=IV,
        key=encrypted_key,
        type="OPERATOR_SESSION",
        operator_session_key_permissions={
            "allow_encrypt": True,
            "allow_decrypt": False,
            "allow_sign": True,
            "allow_signature_verify": True,
        },
    )

    bundled_key = bundled.Key.from_key_container(
        bundled_container,
        ENC_KEY,
    )

    upstream_key = upstream.Key.from_key_container(
        upstream_container,
        ENC_KEY,
    )

    assert bundled_key.type == upstream_key.type
    assert bundled_key.kid == upstream_key.kid
    assert bundled_key.key == upstream_key.key
    assert bundled_key.permissions == upstream_key.permissions


@pytest.mark.parametrize(
    "kid",
    [
        b"",
        b"\x00",
        b"\x01",
        b"\x01\x02\x03\x04",
        b"12345",
        b"0011223344556677",
        bytes.fromhex(
            "00112233445566778899aabbccddeeff",
        ),
        b"a-longer-than-sixteen-byte-key-id",
        base64.b64encode(
            bytes.fromhex(
                "00112233445566778899aabbccddeeff",
            ),
        ).decode(),
    ],
)
def test_key_kid_to_uuid_matches_upstream(kid):
    try:
        upstream_result = upstream.Key.kid_to_uuid(kid)
    except Exception as upstream_error:
        with pytest.raises(type(upstream_error)) as bundled_error:
            bundled.Key.kid_to_uuid(kid)

        assert str(bundled_error.value) == str(upstream_error)
    else:
        bundled_result = bundled.Key.kid_to_uuid(kid)

        assert bundled_result == upstream_result
        assert type(bundled_result) is type(upstream_result)


def test_pssh_widevine_data_matches_upstream():
    bundled_widevine_data = _make_bundled_widevine_data()
    upstream_widevine_data = _make_upstream_widevine_data()

    assert bundled_widevine_data.SerializeToString() == upstream_widevine_data.SerializeToString()


def test_pssh_from_widevine_data_matches_upstream():
    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    assert bundled_pssh.system_id == upstream_pssh.system_id
    assert bundled_pssh.version == upstream_pssh.version
    assert bundled_pssh.flags == upstream_pssh.flags
    assert bundled_pssh.key_ids == upstream_pssh.key_ids
    assert bundled_pssh.init_data == upstream_pssh.init_data

    assert bundled_pssh.dumps() == upstream_pssh.dumps()


def test_pssh_parse_matches_upstream():
    source = upstream.PSSH(
        _make_upstream_widevine_data().SerializeToString(),
    ).dumps()

    bundled_pssh = bundled.PSSH(source)
    upstream_pssh = upstream.PSSH(source)

    assert bundled_pssh.system_id == upstream_pssh.system_id
    assert bundled_pssh.version == upstream_pssh.version
    assert bundled_pssh.flags == upstream_pssh.flags
    assert bundled_pssh.key_ids == upstream_pssh.key_ids
    assert bundled_pssh.init_data == upstream_pssh.init_data

    assert bundled_pssh.dumps() == upstream_pssh.dumps()


def test_pssh_parsed_widevine_data_matches_upstream():
    source = upstream.PSSH(
        _make_upstream_widevine_data().SerializeToString(),
    ).dumps()

    bundled_pssh = bundled.PSSH(source)
    upstream_pssh = upstream.PSSH(source)

    bundled_widevine_data = bundled.WidevinePsshData()
    bundled_widevine_data.ParseFromString(bundled_pssh.init_data)

    upstream_widevine_data = upstream_protocol.WidevinePsshData()
    upstream_widevine_data.ParseFromString(upstream_pssh.init_data)

    assert list(bundled_widevine_data.key_ids) == list(upstream_widevine_data.key_ids)
    assert bundled_widevine_data.provider == upstream_widevine_data.provider
    assert bundled_widevine_data.content_id == upstream_widevine_data.content_id
    assert bundled_widevine_data.protection_scheme == upstream_widevine_data.protection_scheme

    assert bundled_widevine_data.SerializeToString() == upstream_widevine_data.SerializeToString()


def test_device_properties_match_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    assert bundled_device.type.value == upstream_device.type.value
    assert bundled_device.security_level == upstream_device.security_level
    assert bundled_device.flags == upstream_device.flags
    assert bundled_device.system_id == upstream_device.system_id

    assert bundled_device.private_key.export_key("DER") == upstream_device.private_key.export_key("DER")

    assert bundled_device.client_id.SerializeToString() == upstream_device.client_id.SerializeToString()

    assert bundled_device.vmp.SerializeToString() == upstream_device.vmp.SerializeToString()


def test_device_dumps_matches_upstream():
    private_key, client_id = _make_device_material()

    bundled_device = bundled.Device(
        type_=bundled.DeviceTypes.ANDROID,
        security_level=3,
        flags={},
        private_key=private_key.export_key("DER"),
        client_id=client_id.SerializeToString(),
    )

    upstream_device = upstream.Device(
        type_=upstream.DeviceTypes.ANDROID,
        security_level=3,
        flags={},
        private_key=private_key.export_key("DER"),
        client_id=client_id.SerializeToString(),
    )

    assert bundled_device.dumps() == upstream_device.dumps()


def test_device_loads_upstream_dump():
    upstream_device = _make_upstream_device()

    bundled_device = bundled.Device.loads(upstream_device.dumps())

    assert bundled_device.type.value == upstream_device.type.value
    assert bundled_device.security_level == upstream_device.security_level
    assert bundled_device.flags == upstream_device.flags
    assert bundled_device.system_id == upstream_device.system_id

    assert bundled_device.private_key.export_key("DER") == upstream_device.private_key.export_key("DER")

    assert bundled_device.client_id.SerializeToString() == upstream_device.client_id.SerializeToString()


def test_upstream_device_loads_bundled_dump():
    bundled_device = _make_bundled_device()

    upstream_device = upstream.Device.loads(bundled_device.dumps())

    assert upstream_device.type.value == bundled_device.type.value
    assert upstream_device.security_level == bundled_device.security_level
    assert upstream_device.flags == bundled_device.flags
    assert upstream_device.system_id == bundled_device.system_id

    assert upstream_device.private_key.export_key("DER") == bundled_device.private_key.export_key("DER")

    assert upstream_device.client_id.SerializeToString() == bundled_device.client_id.SerializeToString()


def test_device_loads_base64_matches_upstream():
    private_key, client_id = _make_device_material()

    upstream_device = upstream.Device(
        type_=upstream.DeviceTypes.ANDROID,
        security_level=3,
        flags={},
        private_key=private_key.export_key("DER"),
        client_id=client_id.SerializeToString(),
    )

    data = base64.b64encode(upstream_device.dumps()).decode()

    bundled_device = bundled.Device.loads(data)
    upstream_device = upstream.Device.loads(data)

    assert bundled_device.type.value == upstream_device.type.value
    assert bundled_device.security_level == upstream_device.security_level
    assert bundled_device.system_id == upstream_device.system_id
    assert bundled_device.dumps() == upstream_device.dumps()


def test_device_dump_and_load_match_upstream(tmp_path):
    private_key, client_id = _make_device_material()

    bundled_device = bundled.Device(
        type_=bundled.DeviceTypes.ANDROID,
        security_level=3,
        flags={},
        private_key=private_key.export_key("DER"),
        client_id=client_id.SerializeToString(),
    )

    upstream_device = upstream.Device(
        type_=upstream.DeviceTypes.ANDROID,
        security_level=3,
        flags={},
        private_key=private_key.export_key("DER"),
        client_id=client_id.SerializeToString(),
    )

    bundled_path = tmp_path / "bundled.wvd"
    upstream_path = tmp_path / "upstream.wvd"

    bundled_device.dump(bundled_path)
    upstream_device.dump(upstream_path)

    assert bundled_path.read_bytes() == upstream_path.read_bytes()

    bundled_loaded = bundled.Device.load(upstream_path)
    upstream_loaded = upstream.Device.load(bundled_path)

    assert bundled_loaded.dumps() == upstream_loaded.dumps()


@pytest.mark.parametrize(
    ("private_key", "client_id"),
    [
        (None, b"client-id"),
        (b"private-key", None),
        (None, None),
    ],
)
def test_device_missing_data_matches_upstream(private_key, client_id):
    def make_bundled():
        return bundled.Device(
            type_=bundled.DeviceTypes.ANDROID,
            security_level=3,
            flags={},
            private_key=private_key,
            client_id=client_id,
        )

    def make_upstream():
        return upstream.Device(
            type_=upstream.DeviceTypes.ANDROID,
            security_level=3,
            flags={},
            private_key=private_key,
            client_id=client_id,
        )

    try:
        make_upstream()
    except Exception as upstream_error:
        with pytest.raises(type(upstream_error)) as bundled_error:
            make_bundled()

        assert str(bundled_error.value) == str(upstream_error)
    else:
        pytest.fail("Upstream unexpectedly accepted invalid device data")


def test_device_migrate_v1_matches_upstream():
    source = _make_v1_device_data()

    bundled_device = bundled.Device.migrate(source)
    upstream_device = upstream.Device.migrate(source)

    assert bundled_device.type.value == upstream_device.type.value
    assert bundled_device.security_level == upstream_device.security_level
    assert bundled_device.flags == upstream_device.flags
    assert bundled_device.system_id == upstream_device.system_id

    assert bundled_device.private_key.export_key("DER") == upstream_device.private_key.export_key("DER")
    assert bundled_device.client_id.SerializeToString() == upstream_device.client_id.SerializeToString()
    assert bundled_device.vmp.SerializeToString() == upstream_device.vmp.SerializeToString()

    assert bundled_device.dumps() == upstream_device.dumps()


def test_device_migrate_v1_with_vmp_upstream_behavior():
    source = _make_v1_device_data(with_vmp=True)

    with pytest.raises(
        ValueError,
        match=r"Migration failed, could not write bytes",
    ):
        upstream.Device.migrate(source)


def test_bundled_device_migrate_v1_with_vmp():
    source = _make_v1_device_data(with_vmp=True)

    device = bundled.Device.migrate(source)

    assert device.client_id.vmp_data
    assert device.vmp.SerializeToString() == device.client_id.vmp_data


def test_device_migrate_v2_matches_upstream():
    material = _make_device_material()

    device = _make_upstream_device(material)
    source = device.dumps()

    with pytest.raises(ValueError) as upstream_error:
        upstream.Device.migrate(source)

    with pytest.raises(ValueError) as bundled_error:
        bundled.Device.migrate(source)

    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_from_device_matches_upstream():
    material = _make_device_material()

    bundled_cdm = bundled.Cdm.from_device(
        _make_bundled_device(material),
    )
    upstream_cdm = upstream.Cdm.from_device(
        _make_upstream_device(material),
    )

    assert bundled_cdm.device_type.value == upstream_cdm.device_type.value
    assert bundled_cdm.system_id == upstream_cdm.system_id
    assert bundled_cdm.security_level == upstream_cdm.security_level


def test_cdm_open_matches_upstream():
    material = _make_device_material()

    bundled_cdm = bundled.Cdm.from_device(
        _make_bundled_device(material),
    )
    upstream_cdm = upstream.Cdm.from_device(
        _make_upstream_device(material),
    )

    bundled_first = bundled_cdm.open()
    upstream_first = upstream_cdm.open()

    assert type(bundled_first) is type(upstream_first)
    assert len(bundled_first) == len(upstream_first)

    bundled_second = bundled_cdm.open()
    upstream_second = upstream_cdm.open()

    assert type(bundled_second) is type(upstream_second)
    assert len(bundled_second) == len(upstream_second)

    assert bundled_first != bundled_second
    assert upstream_first != upstream_second


def test_cdm_close_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_result = bundled_cdm.close(bundled_session)
    upstream_result = upstream_cdm.close(upstream_session)

    assert bundled_result == upstream_result

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_keys(bundled_session)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_keys(upstream_session)

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__ == "InvalidSession"

    # The session IDs are randomly generated independently,
    # so normalise them before comparing the messages.
    bundled_message = str(bundled_error.value).replace(
        repr(bundled_session),
        "<session_id>",
    )
    upstream_message = str(upstream_error.value).replace(
        repr(upstream_session),
        "<session_id>",
    )

    assert bundled_message == upstream_message


@pytest.mark.parametrize(
    "session_id",
    [
        b"invalid-session",
        bytes.fromhex(
            "00112233445566778899aabbccddeeff",
        ),
    ],
)
def test_cdm_close_invalid_session_matches_upstream(session_id):
    bundled_cdm, upstream_cdm = _make_cdms()

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.close(session_id)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.close(session_id)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_derive_context_matches_upstream():
    messages = [
        b"",
        b"test",
        b"\x00",
        b"\x00\x01\x02\x03",
        bytes(range(256)),
    ]

    for message in messages:
        bundled_result = bundled.Cdm.derive_context(message)
        upstream_result = upstream.Cdm.derive_context(message)

        assert bundled_result == upstream_result


def test_cdm_derive_keys_from_derived_context_matches_upstream():
    messages = [
        b"",
        b"test-license-request",
        bytes(range(256)),
    ]

    keys = [
        bytes.fromhex(
            "00112233445566778899aabbccddeeff",
        ),
        bytes.fromhex(
            "ffeeddccbbaa99887766554433221100",
        ),
    ]

    for message in messages:
        bundled_context = bundled.Cdm.derive_context(message)
        upstream_context = upstream.Cdm.derive_context(message)

        for key in keys:
            bundled_cdm = bundled.Cdm.derive_keys(
                *bundled_context,
                key=key,
            )

            upstream_cdm = upstream.Cdm.derive_keys(
                *upstream_context,
                key=key,
            )

            assert bundled_cdm == upstream_cdm


def test_cdm_encrypt_client_id_matches_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_certificate = bundled.Cdm.root_cert
    upstream_certificate = upstream.Cdm.root_cert

    key = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )
    iv = bytes.fromhex(
        "ffeeddccbbaa99887766554433221100",
    )

    bundled_encrypted_id = bundled.Cdm.encrypt_client_id(
        bundled_device.client_id,
        bundled_certificate,
        key=key,
        iv=iv,
    )

    upstream_encrypted_id = upstream.Cdm.encrypt_client_id(
        upstream_device.client_id,
        upstream_certificate,
        key=key,
        iv=iv,
    )

    assert bundled_encrypted_id.provider_id == upstream_encrypted_id.provider_id
    assert bundled_encrypted_id.service_certificate_serial_number == upstream_encrypted_id.service_certificate_serial_number
    assert bundled_encrypted_id.encrypted_client_id == upstream_encrypted_id.encrypted_client_id
    assert bundled_encrypted_id.encrypted_client_id_iv == upstream_encrypted_id.encrypted_client_id_iv

    # RSA-OAEP encryption is probabilistic, so the ciphertext itself
    # cannot be compared between independent calls.
    assert len(bundled_encrypted_id.encrypted_privacy_key) == len(
        upstream_encrypted_id.encrypted_privacy_key,
    )


def test_cdm_session_limit_matches_upstream():
    material = _make_device_material()

    bundled_cdm = bundled.Cdm.from_device(
        _make_bundled_device(material),
    )
    upstream_cdm = upstream.Cdm.from_device(
        _make_upstream_device(material),
    )

    for _ in range(
        upstream.Cdm.MAX_NUM_OF_SESSIONS + 2,
    ):
        try:
            bundled_session = bundled_cdm.open()
            bundled_result = (
                "return",
                type(bundled_session).__name__,
                len(bundled_session),
            )
        except Exception as exc:
            bundled_result = (
                "raise",
                type(exc).__name__,
                str(exc),
            )

        try:
            upstream_session = upstream_cdm.open()
            upstream_result = (
                "return",
                type(upstream_session).__name__,
                len(upstream_session),
            )
        except Exception as exc:
            upstream_result = (
                "raise",
                type(exc).__name__,
                str(exc),
            )

        assert bundled_result == upstream_result


def test_cdm_get_service_certificate_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_certificate = bundled_cdm.get_service_certificate(
        bundled_session,
    )
    upstream_certificate = upstream_cdm.get_service_certificate(
        upstream_session,
    )

    assert bundled_certificate == upstream_certificate
    assert bundled_certificate is None


def test_cdm_get_service_certificate_invalid_session_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = b"invalid-session"

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_service_certificate(session_id)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_service_certificate(session_id)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_set_service_certificate_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_provider_id = bundled_cdm.set_service_certificate(
        bundled_session,
        bundled.Cdm.common_privacy_cert,
    )
    upstream_provider_id = upstream_cdm.set_service_certificate(
        upstream_session,
        upstream.Cdm.common_privacy_cert,
    )

    assert bundled_provider_id == upstream_provider_id

    bundled_certificate = bundled_cdm.get_service_certificate(
        bundled_session,
    )
    upstream_certificate = upstream_cdm.get_service_certificate(
        upstream_session,
    )

    assert bundled_certificate.SerializeToString() == upstream_certificate.SerializeToString()


def test_cdm_remove_service_certificate_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_cdm.set_service_certificate(
        bundled_session,
        bundled.Cdm.common_privacy_cert,
    )
    upstream_cdm.set_service_certificate(
        upstream_session,
        upstream.Cdm.common_privacy_cert,
    )

    bundled_result = bundled_cdm.set_service_certificate(
        bundled_session,
        None,
    )
    upstream_result = upstream_cdm.set_service_certificate(
        upstream_session,
        None,
    )

    assert bundled_result == upstream_result

    assert bundled_cdm.get_service_certificate(bundled_session) is None
    assert upstream_cdm.get_service_certificate(upstream_session) is None


@pytest.mark.parametrize(
    "certificate",
    [
        b"",
        b"invalid",
        b"\x00",
        b"\x08\x01",
    ],
)
def test_cdm_invalid_service_certificate_matches_upstream(
    certificate,
):
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.set_service_certificate(
            bundled_session,
            certificate,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.set_service_certificate(
            upstream_session,
            certificate,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__

    if type(upstream_error.value).__name__ == "DecodeError":
        prefix = "Could not parse certificate as a SignedDrmCertificate, "

        assert str(bundled_error.value).startswith(prefix)
        assert str(upstream_error.value).startswith(prefix)
    else:
        assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_set_service_certificate_invalid_session_with_certificate_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = b"invalid-session"

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.set_service_certificate(
            session_id,
            bundled.Cdm.common_privacy_cert,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.set_service_certificate(
            session_id,
            upstream.Cdm.common_privacy_cert,
        )

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_set_service_certificate_base64_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    assert isinstance(
        bundled.Cdm.common_privacy_cert,
        str,
    )
    assert isinstance(
        upstream.Cdm.common_privacy_cert,
        str,
    )

    bundled_provider_id = bundled_cdm.set_service_certificate(
        bundled_session,
        bundled.Cdm.common_privacy_cert,
    )
    upstream_provider_id = upstream_cdm.set_service_certificate(
        upstream_session,
        upstream.Cdm.common_privacy_cert,
    )

    assert bundled_provider_id == upstream_provider_id

    assert (
        bundled_cdm.get_service_certificate(
            bundled_session,
        ).SerializeToString()
        == upstream_cdm.get_service_certificate(
            upstream_session,
        ).SerializeToString()
    )


def test_cdm_set_service_certificate_bytes_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_certificate = base64.b64decode(
        bundled.Cdm.common_privacy_cert,
    )
    upstream_certificate = base64.b64decode(
        upstream.Cdm.common_privacy_cert,
    )

    bundled_provider_id = bundled_cdm.set_service_certificate(
        bundled_session,
        bundled_certificate,
    )
    upstream_provider_id = upstream_cdm.set_service_certificate(
        upstream_session,
        upstream_certificate,
    )

    assert bundled_provider_id == upstream_provider_id

    assert (
        bundled_cdm.get_service_certificate(
            bundled_session,
        ).SerializeToString()
        == upstream_cdm.get_service_certificate(
            upstream_session,
        ).SerializeToString()
    )


@pytest.mark.parametrize(
    "license_type",
    [
        "STREAMING",
        "OFFLINE",
        "AUTOMATIC",
    ],
)
def test_cdm_license_challenge_matches_upstream(
    license_type,
):
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type=license_type,
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type=license_type,
        privacy_mode=False,
    )

    bundled_signed, bundled_request = _parse_bundled_license_request(bundled_challenge)
    upstream_signed, upstream_request = _parse_upstream_license_request(upstream_challenge)

    # SignedMessage envelope.
    assert bundled_signed.type == upstream_signed.type

    # LicenseRequest metadata.
    assert bundled_request.type == upstream_request.type
    assert bundled_request.protocol_version == upstream_request.protocol_version

    # Same device identity.
    assert bundled_request.client_id.SerializeToString() == upstream_request.client_id.SerializeToString()

    # Same PSSH/license-type information.
    bundled_content = bundled_request.content_id.widevine_pssh_data
    upstream_content = upstream_request.content_id.widevine_pssh_data

    assert list(bundled_content.pssh_data) == list(upstream_content.pssh_data)
    assert bundled_content.license_type == upstream_content.license_type

    # These are intentionally generated independently.
    assert len(bundled_content.request_id) == len(
        upstream_content.request_id,
    )

    # request_time is inherently time-dependent.
    assert isinstance(bundled_request.request_time, int)
    assert isinstance(upstream_request.request_time, int)

    assert bundled_request.key_control_nonce >= 0
    assert upstream_request.key_control_nonce >= 0


def test_cdm_license_challenge_signature_matches_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_cdm = bundled.Cdm.from_device(bundled_device)
    upstream_cdm = upstream.Cdm.from_device(upstream_device)

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    bundled_signed, _ = _parse_bundled_license_request(
        bundled_challenge,
    )
    upstream_signed, _ = _parse_upstream_license_request(
        upstream_challenge,
    )

    assert len(bundled_signed.signature) == len(
        upstream_signed.signature,
    )

    public_key = bundled_device.private_key.public_key()

    pss.new(public_key).verify(
        SHA1.new(bundled_signed.msg),
        bundled_signed.signature,
    )

    pss.new(public_key).verify(
        SHA1.new(upstream_signed.msg),
        upstream_signed.signature,
    )


def test_cdm_privacy_license_challenge_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_cdm.set_service_certificate(
        bundled_session,
        bundled.Cdm.common_privacy_cert,
    )
    upstream_cdm.set_service_certificate(
        upstream_session,
        upstream.Cdm.common_privacy_cert,
    )

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=True,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=True,
    )

    _, bundled_request = _parse_bundled_license_request(
        bundled_challenge,
    )
    _, upstream_request = _parse_upstream_license_request(
        upstream_challenge,
    )

    # Privacy mode must omit the plaintext ClientIdentification.
    assert not bundled_request.HasField("client_id")
    assert not upstream_request.HasField("client_id")

    assert bundled_request.HasField("encrypted_client_id")
    assert upstream_request.HasField("encrypted_client_id")

    bundled_encrypted = bundled_request.encrypted_client_id
    upstream_encrypted = upstream_request.encrypted_client_id

    assert bundled_encrypted.provider_id == upstream_encrypted.provider_id
    assert bundled_encrypted.service_certificate_serial_number == upstream_encrypted.service_certificate_serial_number

    # RSA encryption is randomized, so encrypted_privacy_key
    # cannot be byte-for-byte compared.
    assert len(bundled_encrypted.encrypted_privacy_key) == len(
        upstream_encrypted.encrypted_privacy_key,
    )

    # AES encryption also uses independently generated key/IV
    # material in this path.
    assert len(bundled_encrypted.encrypted_client_id) == len(
        upstream_encrypted.encrypted_client_id,
    )
    assert len(bundled_encrypted.encrypted_client_id_iv) == len(
        upstream_encrypted.encrypted_client_id_iv,
    )


def test_cdm_parse_license_and_get_keys_matches_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_cdm = bundled.Cdm.from_device(bundled_device)
    upstream_cdm = upstream.Cdm.from_device(upstream_device)

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    bundled_response = _make_license_response(
        bundled,
        bundled,
        bundled_device,
        bundled_challenge,
    )
    upstream_response = _make_license_response(
        upstream,
        upstream_protocol,
        upstream_device,
        upstream_challenge,
    )

    assert (
        bundled_cdm.parse_license(
            bundled_session,
            bundled_response,
        )
        is None
    )
    assert (
        upstream_cdm.parse_license(
            upstream_session,
            upstream_response,
        )
        is None
    )

    bundled_keys = bundled_cdm.get_keys(bundled_session)
    upstream_keys = upstream_cdm.get_keys(
        upstream_session,
    )

    assert len(bundled_keys) == len(upstream_keys)

    for bundled_key, upstream_key in zip(
        bundled_keys,
        upstream_keys,
        strict=True,
    ):
        assert bundled_key.type == upstream_key.type
        assert bundled_key.kid == upstream_key.kid
        assert bundled_key.key == upstream_key.key
        assert bundled_key.permissions == upstream_key.permissions


def test_cdm_parse_license_decrypts_content_key():
    material = _make_device_material()

    device = _make_bundled_device(material)
    cdm = bundled.Cdm.from_device(device)

    session_id = cdm.open()

    challenge = cdm.get_license_challenge(
        session_id,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    kid = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )
    plaintext_key = bytes.fromhex(
        "11223344556677889900aabbccddeeff",
    )

    response = _make_license_response(
        bundled,
        bundled,
        device,
        challenge,
        content_keys=[
            (kid, plaintext_key),
        ],
    )

    cdm.parse_license(
        session_id,
        response,
    )

    keys = cdm.get_keys(session_id)

    assert len(keys) == 1
    assert keys[0].kid.bytes == kid
    assert keys[0].key == plaintext_key
    assert keys[0].type == "CONTENT"


def test_cdm_parse_multiple_keys_matches_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_cdm = bundled.Cdm.from_device(bundled_device)
    upstream_cdm = upstream.Cdm.from_device(upstream_device)

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    content_keys = [
        (
            bytes.fromhex(
                "00112233445566778899aabbccddeeff",
            ),
            bytes.fromhex(
                "11111111111111111111111111111111",
            ),
        ),
        (
            bytes.fromhex(
                "ffeeddccbbaa99887766554433221100",
            ),
            bytes.fromhex(
                "22222222222222222222222222222222",
            ),
        ),
    ]

    bundled_response = _make_license_response(
        bundled,
        bundled,
        bundled_device,
        bundled_challenge,
        content_keys=content_keys,
    )
    upstream_response = _make_license_response(
        upstream,
        upstream_protocol,
        upstream_device,
        upstream_challenge,
        content_keys=content_keys,
    )

    bundled_cdm.parse_license(
        bundled_session,
        bundled_response,
    )
    upstream_cdm.parse_license(
        upstream_session,
        upstream_response,
    )

    bundled_keys = bundled_cdm.get_keys(bundled_session)
    upstream_keys = upstream_cdm.get_keys(
        upstream_session,
    )

    assert len(bundled_keys) == len(upstream_keys) == 2

    for bundled_key, upstream_key in zip(
        bundled_keys,
        upstream_keys,
        strict=True,
    ):
        assert bundled_key.type == upstream_key.type
        assert bundled_key.kid == upstream_key.kid
        assert bundled_key.key == upstream_key.key
        assert bundled_key.permissions == upstream_key.permissions


def test_cdm_parse_license_oemcrypto_message_matches_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_cdm = bundled.Cdm.from_device(bundled_device)
    upstream_cdm = upstream.Cdm.from_device(upstream_device)

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    core_message = b"test-oemcrypto-core-message"

    bundled_response = _make_license_response(
        bundled,
        bundled,
        bundled_device,
        bundled_challenge,
        oemcrypto_core_message=core_message,
    )
    upstream_response = _make_license_response(
        upstream,
        upstream_protocol,
        upstream_device,
        upstream_challenge,
        oemcrypto_core_message=core_message,
    )

    bundled_cdm.parse_license(
        bundled_session,
        bundled_response,
    )
    upstream_cdm.parse_license(
        upstream_session,
        upstream_response,
    )

    bundled_keys = bundled_cdm.get_keys(bundled_session)
    upstream_keys = upstream_cdm.get_keys(
        upstream_session,
    )

    assert len(bundled_keys) == len(upstream_keys)

    for bundled_key, upstream_key in zip(
        bundled_keys,
        upstream_keys,
        strict=True,
    ):
        assert bundled_key.type == upstream_key.type
        assert bundled_key.kid == upstream_key.kid
        assert bundled_key.key == upstream_key.key
        assert bundled_key.permissions == upstream_key.permissions


def test_cdm_parse_license_twice_matches_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_cdm = bundled.Cdm.from_device(bundled_device)
    upstream_cdm = upstream.Cdm.from_device(upstream_device)

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    bundled_response = _make_license_response(
        bundled,
        bundled,
        bundled_device,
        bundled_challenge,
    )
    upstream_response = _make_license_response(
        upstream,
        upstream_protocol,
        upstream_device,
        upstream_challenge,
    )

    bundled_cdm.parse_license(bundled_session, bundled_response)
    upstream_cdm.parse_license(
        upstream_session,
        upstream_response,
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.parse_license(bundled_session, bundled_response)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.parse_license(
            upstream_session,
            upstream_response,
        )

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(upstream_error.value)


@pytest.mark.parametrize(
    "license_message",
    [
        b"",
        b"invalid",
        b"\x00",
        b"\x08\x01",
    ],
)
def test_cdm_invalid_license_message_matches_upstream(
    license_message,
):
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.parse_license(
            bundled_session,
            license_message,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.parse_license(
            upstream_session,
            license_message,
        )

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )


def test_cdm_parse_license_without_context_matches_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    #
    # Generate valid license responses using CDMs which DO have
    # request context.
    #
    bundled_source = bundled.Cdm.from_device(bundled_device)
    upstream_source = upstream.Cdm.from_device(
        upstream_device,
    )

    bundled_source_session = bundled_source.open()
    upstream_source_session = upstream_source.open()

    bundled_challenge = bundled_source.get_license_challenge(
        bundled_source_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )
    upstream_challenge = upstream_source.get_license_challenge(
        upstream_source_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    bundled_response = _make_license_response(
        bundled,
        bundled,
        bundled_device,
        bundled_challenge,
    )
    upstream_response = _make_license_response(
        upstream,
        upstream_protocol,
        upstream_device,
        upstream_challenge,
    )

    #
    # Parse them in fresh CDMs. These sessions did not create
    # the corresponding requests and therefore have no context.
    #
    bundled_cdm = bundled.Cdm.from_device(bundled_device)
    upstream_cdm = upstream.Cdm.from_device(upstream_device)

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.parse_license(
            bundled_session,
            bundled_response,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.parse_license(
            upstream_session,
            upstream_response,
        )

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_get_keys_before_license_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_keys = bundled_cdm.get_keys(bundled_session)
    upstream_keys = upstream_cdm.get_keys(upstream_session)

    assert bundled_keys == upstream_keys


def test_cdm_get_keys_filter_matches_upstream():
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_cdm = bundled.Cdm.from_device(bundled_device)
    upstream_cdm = upstream.Cdm.from_device(upstream_device)

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    content_keys = [
        (
            bytes.fromhex(
                "00112233445566778899aabbccddeeff",
            ),
            bytes.fromhex(
                "11223344556677889900aabbccddeeff",
            ),
        ),
        (
            bytes.fromhex(
                "102132435465768798a9bacbdcedfe0f",
            ),
            bytes.fromhex(
                "ffeeddccbbaa00998877665544332211",
            ),
        ),
    ]

    bundled_response = _make_license_response(
        bundled,
        bundled,
        bundled_device,
        bundled_challenge,
        content_keys=content_keys,
    )
    upstream_response = _make_license_response(
        upstream,
        upstream_protocol,
        upstream_device,
        upstream_challenge,
        content_keys=content_keys,
    )

    bundled_cdm.parse_license(bundled_session, bundled_response)
    upstream_cdm.parse_license(
        upstream_session,
        upstream_response,
    )

    bundled_keys = bundled_cdm.get_keys(
        bundled_session,
        "CONTENT",
    )
    upstream_keys = upstream_cdm.get_keys(
        upstream_session,
        "CONTENT",
    )

    assert len(bundled_keys) == len(upstream_keys)

    for bundled_key, upstream_key in zip(
        bundled_keys,
        upstream_keys,
        strict=True,
    ):
        assert bundled_key.type == upstream_key.type
        assert bundled_key.kid == upstream_key.kid
        assert bundled_key.key == upstream_key.key
        assert bundled_key.permissions == upstream_key.permissions


@pytest.mark.parametrize(
    "key_type",
    [
        "CONTENT",
        "SIGNING",
        "KEY_CONTROL",
        "OPERATOR_SESSION",
    ],
)
def test_cdm_get_keys_empty_filter_matches_upstream(
    key_type,
):
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    assert bundled_cdm.get_keys(bundled_session, key_type) == upstream_cdm.get_keys(upstream_session, key_type)


def test_cdm_get_keys_invalid_session_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_keys(session_id)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_keys(session_id)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_derive_keys_with_explicit_context_matches_upstream():
    contexts = [
        b"",
        b"test-context",
        bytes(range(64)),
    ]

    keys = [
        bytes.fromhex(
            "00112233445566778899aabbccddeeff",
        ),
        bytes.fromhex(
            "ffeeddccbbaa99887766554433221100",
        ),
    ]

    for context in contexts:
        for key in keys:
            bundled_result = bundled.Cdm.derive_keys(
                context,
                context,
                key,
            )
            upstream_result = upstream.Cdm.derive_keys(
                context,
                context,
                key,
            )

            assert bundled_result == upstream_result


@pytest.mark.parametrize(
    "license_type",
    [
        "STREAMING",
        "OFFLINE",
        "AUTOMATIC",
    ],
)
def test_cdm_license_types_match_upstream(license_type):
    material = _make_device_material()

    bundled_cdm = bundled.Cdm.from_device(
        _make_bundled_device(material),
    )
    upstream_cdm = upstream.Cdm.from_device(
        _make_upstream_device(material),
    )

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type=license_type,
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type=license_type,
        privacy_mode=False,
    )

    bundled_signed = bundled.SignedMessage()
    bundled_signed.ParseFromString(bundled_challenge)

    upstream_signed = upstream_protocol.SignedMessage()
    upstream_signed.ParseFromString(upstream_challenge)

    bundled_request = bundled.LicenseRequest()
    bundled_request.ParseFromString(bundled_signed.msg)

    upstream_request = upstream_protocol.LicenseRequest()
    upstream_request.ParseFromString(upstream_signed.msg)

    assert bundled_request.type == upstream_request.type


@pytest.mark.parametrize(
    "license_type",
    [
        "",
        "INVALID",
        "streaming",
        None,
        123,
    ],
)
def test_cdm_invalid_license_type_matches_upstream(
    license_type,
):
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_license_challenge(
            bundled_session,
            _make_bundled_pssh(),
            license_type=license_type,
            privacy_mode=False,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_license_challenge(
            upstream_session,
            _make_upstream_pssh(),
            license_type=license_type,
            privacy_mode=False,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__


def test_cdm_get_license_challenge_invalid_session_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_license_challenge(
            session_id,
            _make_bundled_pssh(),
            privacy_mode=False,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_license_challenge(
            session_id,
            _make_upstream_pssh(),
            privacy_mode=False,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_parse_license_invalid_session_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    license_message = b"invalid"

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.parse_license(
            session_id,
            license_message,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.parse_license(
            session_id,
            license_message,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_set_service_certificate_invalid_session_with_none_matches_upstream():
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.set_service_certificate(
            session_id,
            None,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.set_service_certificate(
            session_id,
            None,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_constants_match_upstream():
    assert bundled.Cdm.uuid == upstream.Cdm.uuid
    assert bundled.Cdm.urn == upstream.Cdm.urn
    assert bundled.Cdm.key_format == upstream.Cdm.key_format
    assert bundled.Cdm.service_certificate_challenge == upstream.Cdm.service_certificate_challenge
    assert bundled.Cdm.MAX_NUM_OF_SESSIONS == upstream.Cdm.MAX_NUM_OF_SESSIONS


def test_cdm_privacy_certificates_match_upstream():
    assert bundled.Cdm.common_privacy_cert == upstream.Cdm.common_privacy_cert
    assert bundled.Cdm.staging_privacy_cert == upstream.Cdm.staging_privacy_cert


def test_cdm_root_certificate_matches_upstream():
    assert bundled.Cdm.root_cert.SerializeToString() == upstream.Cdm.root_cert.SerializeToString()

    assert bundled.Cdm.root_signed_cert.SerializeToString() == upstream.Cdm.root_signed_cert.SerializeToString()


@pytest.mark.parametrize(
    ("input_file", "output_file", "temp_dir"),
    [
        (None, "output.mp4", None),
        ("", "output.mp4", None),
        ("input.mp4", None, None),
        ("input.mp4", "", None),
        (123, "output.mp4", None),
        ("input.mp4", 123, None),
        ("input.mp4", "output.mp4", 123),
    ],
)
def test_cdm_decrypt_invalid_paths_match_upstream(
    input_file,
    output_file,
    temp_dir,
):
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.decrypt(
            session_id,
            input_file,
            output_file,
            temp_dir,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.decrypt(
            session_id,
            input_file,
            output_file,
            temp_dir,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_decrypt_missing_input_matches_upstream(tmp_path):
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    input_file = tmp_path / "missing.mp4"
    output_file = tmp_path / "output.mp4"

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.decrypt(
            session_id,
            input_file,
            output_file,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.decrypt(
            session_id,
            input_file,
            output_file,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_decrypt_existing_output_matches_upstream(tmp_path):
    bundled_cdm, upstream_cdm = _make_cdms()

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    input_file = tmp_path / "input.mp4"
    output_file = tmp_path / "output.mp4"

    input_file.write_bytes(b"input")
    output_file.write_bytes(b"output")

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.decrypt(
            session_id,
            input_file,
            output_file,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.decrypt(
            session_id,
            input_file,
            output_file,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_decrypt_invalid_session_matches_upstream(tmp_path):
    bundled_cdm, upstream_cdm = _make_cdms()

    input_file = tmp_path / "input.mp4"
    output_file = tmp_path / "output.mp4"
    input_file.write_bytes(b"input")

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.decrypt(
            session_id,
            input_file,
            output_file,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.decrypt(
            session_id,
            input_file,
            output_file,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_decrypt_no_keys_matches_upstream(tmp_path):
    bundled_cdm, upstream_cdm = _make_cdms()

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    input_file = tmp_path / "input.mp4"
    output_file = tmp_path / "output.mp4"
    input_file.write_bytes(b"input")

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.decrypt(
            bundled_session,
            input_file,
            output_file,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.decrypt(
            upstream_session,
            input_file,
            output_file,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__ == "NoKeysLoaded"

    assert str(bundled_error.value) == str(upstream_error.value)


def test_cdm_decrypt_command_matches_upstream(
    tmp_path,
    monkeypatch,
):
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_cdm = bundled.Cdm.from_device(bundled_device)
    upstream_cdm = upstream.Cdm.from_device(upstream_device)

    bundled_session = bundled_cdm.open()
    upstream_session = upstream_cdm.open()

    bundled_challenge = bundled_cdm.get_license_challenge(
        bundled_session,
        _make_bundled_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )
    upstream_challenge = upstream_cdm.get_license_challenge(
        upstream_session,
        _make_upstream_pssh(),
        license_type="STREAMING",
        privacy_mode=False,
    )

    bundled_response = _make_license_response(
        bundled,
        bundled,
        bundled_device,
        bundled_challenge,
    )
    upstream_response = _make_license_response(
        upstream,
        upstream_protocol,
        upstream_device,
        upstream_challenge,
    )

    bundled_cdm.parse_license(
        bundled_session,
        bundled_response,
    )
    upstream_cdm.parse_license(
        upstream_session,
        upstream_response,
    )

    input_file = tmp_path / "input.mp4"
    input_file.write_bytes(b"input")

    bundled_output = tmp_path / "bundled.mp4"
    upstream_output = tmp_path / "upstream.mp4"

    bundled_calls = []
    upstream_calls = []

    bundled_globals = bundled.Cdm.decrypt.__globals__
    upstream_globals = upstream.Cdm.decrypt.__globals__

    monkeypatch.setitem(
        bundled_globals,
        "get_binary_path",
        lambda *args: "packager",
    )
    monkeypatch.setitem(
        upstream_globals,
        "get_binary_path",
        lambda *args: "packager",
    )

    class BundledSubprocess:
        @staticmethod
        def check_call(args):
            bundled_calls.append(args)
            return 0

    class UpstreamSubprocess:
        @staticmethod
        def check_call(args):
            upstream_calls.append(args)
            return 0

    monkeypatch.setitem(
        bundled_globals,
        "subprocess",
        BundledSubprocess,
    )
    monkeypatch.setitem(
        upstream_globals,
        "subprocess",
        UpstreamSubprocess,
    )

    bundled_result = bundled_cdm.decrypt(
        bundled_session,
        input_file,
        bundled_output,
    )
    upstream_result = upstream_cdm.decrypt(
        upstream_session,
        input_file,
        upstream_output,
    )

    assert bundled_result == upstream_result == 0

    # Output filenames intentionally differ, so normalise that
    # argument before comparing the commands.
    bundled_command = bundled_calls[0]
    upstream_command = upstream_calls[0]

    assert bundled_command[0] == upstream_command[0]
    assert bundled_command[2:] == upstream_command[2:]

    assert bundled_command[1] == (f"input={input_file},stream=0,output={bundled_output}")
    assert upstream_command[1] == (f"input={input_file},stream=0,output={upstream_output}")


def test_pssh_system_ids_match_upstream():
    assert bundled.PSSH.SystemId.Widevine == upstream.PSSH.SystemId.Widevine
    assert bundled.PSSH.SystemId.PlayReady == upstream.PSSH.SystemId.PlayReady


def test_pssh_dump_matches_upstream():
    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    assert bundled_pssh.dump() == upstream_pssh.dump()
    assert bundled_pssh.dumps() == upstream_pssh.dumps()


def test_pssh_key_ids_match_upstream():
    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    assert bundled_pssh.key_ids == upstream_pssh.key_ids


@pytest.mark.parametrize(
    "key_ids",
    [
        [],
        [
            "00112233445566778899aabbccddeeff",
        ],
        [
            bytes.fromhex(
                "00112233445566778899aabbccddeeff",
            ),
        ],
        [
            UUID(
                "00112233-4455-6677-8899-aabbccddeeff",
            ),
        ],
        [
            "00112233445566778899aabbccddeeff",
            "ffeeddccbbaa99887766554433221100",
        ],
    ],
)
def test_pssh_parse_key_ids_matches_upstream(key_ids):
    bundled_result = bundled.PSSH.parse_key_ids(key_ids)
    upstream_result = upstream.PSSH.parse_key_ids(key_ids)

    assert bundled_result == upstream_result


@pytest.mark.parametrize(
    "key_ids",
    [
        [],
        [
            "00112233445566778899aabbccddeeff",
        ],
        [
            bytes.fromhex(
                "00112233445566778899aabbccddeeff",
            ),
        ],
        [
            UUID(
                "00112233-4455-6677-8899-aabbccddeeff",
            ),
        ],
        [
            "00112233445566778899aabbccddeeff",
            "ffeeddccbbaa99887766554433221100",
        ],
    ],
)
def test_pssh_set_key_ids_matches_upstream(key_ids):
    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    bundled_result = bundled_pssh.set_key_ids(key_ids)
    upstream_result = upstream_pssh.set_key_ids(key_ids)

    assert bundled_result == upstream_result
    assert bundled_pssh.key_ids == upstream_pssh.key_ids
    assert bundled_pssh.dump() == upstream_pssh.dump()


@pytest.mark.parametrize(
    "key_ids",
    [
        None,
        "00112233445566778899aabbccddeeff",
        b"\x00" * 16,
        123,
        [None],
        [123],
        [object()],
    ],
)
def test_pssh_parse_invalid_key_ids_matches_upstream(key_ids):
    with pytest.raises(Exception) as bundled_error:
        bundled.PSSH.parse_key_ids(key_ids)

    with pytest.raises(Exception) as upstream_error:
        upstream.PSSH.parse_key_ids(key_ids)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )

    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


def test_pssh_to_widevine_matches_upstream():
    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    bundled_pssh.to_playready()
    upstream_pssh.to_playready()

    bundled_result = bundled_pssh.to_widevine()
    upstream_result = upstream_pssh.to_widevine()

    assert bundled_result == upstream_result
    assert bundled_pssh.system_id == upstream_pssh.system_id
    assert bundled_pssh.version == upstream_pssh.version
    assert bundled_pssh.key_ids == upstream_pssh.key_ids
    assert bundled_pssh.init_data == upstream_pssh.init_data
    assert bundled_pssh.dump() == upstream_pssh.dump()


def test_pssh_to_playready_matches_upstream():
    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    bundled_result = bundled_pssh.to_playready()
    upstream_result = upstream_pssh.to_playready()

    assert bundled_result == upstream_result
    assert bundled_pssh.system_id == upstream_pssh.system_id
    assert bundled_pssh.version == upstream_pssh.version
    assert bundled_pssh.key_ids == upstream_pssh.key_ids
    assert bundled_pssh.init_data == upstream_pssh.init_data
    assert bundled_pssh.dump() == upstream_pssh.dump()


def test_pssh_to_playready_options_match_upstream():
    kwargs = {
        "la_url": "https://example.com/license",
        "lui_url": "https://example.com/ui",
        "ds_id": b"test-domain-service-id",
        "decryptor_setup": "ONDEMAND",
        "custom_data": "<TEST>hello</TEST>",
    }

    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    bundled_result = bundled_pssh.to_playready(**kwargs)
    upstream_result = upstream_pssh.to_playready(**kwargs)

    assert bundled_result == upstream_result
    assert bundled_pssh.system_id == upstream_pssh.system_id
    assert bundled_pssh.version == upstream_pssh.version
    assert bundled_pssh.key_ids == upstream_pssh.key_ids
    assert bundled_pssh.init_data == upstream_pssh.init_data
    assert bundled_pssh.dump() == upstream_pssh.dump()


def test_pssh_to_playready_when_already_playready_matches_upstream():
    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    bundled_pssh.to_playready()
    upstream_pssh.to_playready()

    with pytest.raises(Exception) as bundled_error:
        bundled_pssh.to_playready()

    with pytest.raises(Exception) as upstream_error:
        upstream_pssh.to_playready()

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


def test_pssh_to_widevine_when_already_widevine_matches_upstream():
    bundled_pssh = _make_bundled_pssh()
    upstream_pssh = _make_upstream_pssh()

    with pytest.raises(Exception) as bundled_error:
        bundled_pssh.to_widevine()

    with pytest.raises(Exception) as upstream_error:
        upstream_pssh.to_widevine()

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


def test_pssh_v1_playready_to_widevine_matches_upstream():
    kid = UUID("00112233-4455-6677-8899-aabbccddeeff")

    bundled_pssh = bundled.PSSH.new(
        bundled.PSSH.SystemId.Widevine,
        key_ids=[kid],
        version=1,
    )
    upstream_pssh = upstream.PSSH.new(
        upstream.PSSH.SystemId.Widevine,
        key_ids=[kid],
        version=1,
    )

    bundled_pssh.to_playready()
    upstream_pssh.to_playready()

    bundled_pssh.to_widevine()
    upstream_pssh.to_widevine()

    assert bundled_pssh.version == upstream_pssh.version == 1
    assert bundled_pssh.system_id == upstream_pssh.system_id
    assert bundled_pssh.key_ids == upstream_pssh.key_ids
    assert bundled_pssh.init_data == upstream_pssh.init_data
    assert bundled_pssh.dump() == upstream_pssh.dump()


@pytest.mark.parametrize(
    "key_ids",
    [
        ["00112233-4455-6677-8899-aabbccddeeff"],
        ["not-a-key-id"],
        [b""],
        [b"\x00"],
        [123],
        None,
        "00112233445566778899aabbccddeeff",
    ],
)
def test_pssh_parse_key_ids_errors_match_upstream(key_ids):
    with pytest.raises(Exception) as bundled_error:
        bundled.PSSH.parse_key_ids(key_ids)

    with pytest.raises(Exception) as upstream_error:
        upstream.PSSH.parse_key_ids(key_ids)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


def test_key_init_matches_upstream():
    kid = UUID("00112233-4455-6677-8899-aabbccddeeff")
    key = bytes.fromhex(
        "11223344556677889900aabbccddeeff",
    )

    bundled_result = bundled.Key(
        "CONTENT",
        kid,
        key,
    )
    upstream_result = upstream.Key(
        "CONTENT",
        kid,
        key,
    )

    assert bundled_result.__dict__ == upstream_result.__dict__
    assert repr(bundled_result) == repr(upstream_result)


def test_key_permissions_default_matches_upstream():
    kid = UUID("00112233-4455-6677-8899-aabbccddeeff")
    key = b"\x00" * 16

    bundled_result = bundled.Key("CONTENT", kid, key)
    upstream_result = upstream.Key("CONTENT", kid, key)

    assert bundled_result.permissions == upstream_result.permissions
    assert bundled_result.permissions == []


@pytest.mark.parametrize(
    "key_type",
    [
        "CONTENT",
        "SIGNING",
        "KEY_CONTROL",
    ],
)
def test_key_from_key_container_matches_upstream(key_type):
    enc_key = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )
    plaintext_key = bytes.fromhex(
        "11223344556677889900aabbccddeeff",
    )
    iv = bytes.fromhex(
        "ffeeddccbbaa99887766554433221100",
    )
    kid = bytes.fromhex(
        "0123456789abcdeffedcba9876543210",
    )

    encrypted_key = AES.new(
        enc_key,
        AES.MODE_CBC,
        iv=iv,
    ).encrypt(
        Padding.pad(plaintext_key, 16),
    )

    bundled_container = bundled.License.KeyContainer()
    bundled_container.type = bundled.License.KeyContainer.KeyType.Value(key_type)
    bundled_container.id = kid
    bundled_container.iv = iv
    bundled_container.key = encrypted_key

    upstream_container = upstream_protocol.License.KeyContainer()
    upstream_container.type = upstream_protocol.License.KeyContainer.KeyType.Value(
        key_type,
    )
    upstream_container.id = kid
    upstream_container.iv = iv
    upstream_container.key = encrypted_key

    bundled_result = bundled.Key.from_key_container(
        bundled_container,
        enc_key,
    )
    upstream_result = upstream.Key.from_key_container(
        upstream_container,
        enc_key,
    )

    assert bundled_result.type == upstream_result.type
    assert bundled_result.kid == upstream_result.kid
    assert bundled_result.key == upstream_result.key
    assert bundled_result.permissions == upstream_result.permissions


def test_key_from_operator_session_container_matches_upstream():
    enc_key = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )
    plaintext_key = bytes.fromhex(
        "11223344556677889900aabbccddeeff",
    )
    iv = bytes.fromhex(
        "ffeeddccbbaa99887766554433221100",
    )
    kid = bytes.fromhex(
        "0123456789abcdeffedcba9876543210",
    )

    encrypted_key = AES.new(
        enc_key,
        AES.MODE_CBC,
        iv=iv,
    ).encrypt(
        Padding.pad(plaintext_key, 16),
    )

    # Build the permissions with the real protobuf implementation,
    # then feed the same wire representation to the bundled one.
    upstream_permissions = upstream_protocol.License.KeyContainer().operator_session_key_permissions
    upstream_permissions.allow_encrypt = 1
    upstream_permissions.allow_decrypt = 0
    upstream_permissions.allow_sign = 1
    upstream_permissions.allow_signature_verify = 0

    permission_bytes = upstream_permissions.SerializeToString()

    bundled_container = bundled.License.KeyContainer()
    bundled_container.type = bundled.License.KeyContainer.KeyType.Value(
        "OPERATOR_SESSION",
    )
    bundled_container.id = kid
    bundled_container.iv = iv
    bundled_container.key = encrypted_key
    bundled_container.operator_session_key_permissions.ParseFromString(
        permission_bytes,
    )

    upstream_container = upstream_protocol.License.KeyContainer()
    upstream_container.type = upstream_protocol.License.KeyContainer.KeyType.Value(
        "OPERATOR_SESSION",
    )
    upstream_container.id = kid
    upstream_container.iv = iv
    upstream_container.key = encrypted_key
    upstream_container.operator_session_key_permissions.ParseFromString(
        permission_bytes,
    )

    bundled_result = bundled.Key.from_key_container(
        bundled_container,
        enc_key,
    )
    upstream_result = upstream.Key.from_key_container(
        upstream_container,
        enc_key,
    )

    assert bundled_result.type == upstream_result.type
    assert bundled_result.kid == upstream_result.kid
    assert bundled_result.key == upstream_result.key
    assert bundled_result.permissions == upstream_result.permissions

    # Make sure this actually exercised permission extraction.
    assert bundled_result.permissions == [
        "allow_encrypt",
        "allow_sign",
    ]


def test_device_loads_matches_upstream():
    material = _make_device_material()

    upstream_device = _make_upstream_device(material)
    data = upstream_device.dumps()

    bundled_result = bundled.Device.loads(data)
    upstream_result = upstream.Device.loads(data)

    assert bundled_result.type.value == upstream_result.type.value
    assert bundled_result.security_level == upstream_result.security_level
    assert bundled_result.flags == upstream_result.flags
    assert bundled_result.private_key.export_key("DER") == upstream_result.private_key.export_key("DER")
    assert bundled_result.client_id.SerializeToString() == upstream_result.client_id.SerializeToString()
    assert bundled_result.vmp.SerializeToString() == upstream_result.vmp.SerializeToString()
    assert bundled_result.system_id == upstream_result.system_id


def test_device_dump_matches_upstream(tmp_path):
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    bundled_path = tmp_path / "bundled" / "device.wvd"
    upstream_path = tmp_path / "upstream" / "device.wvd"

    bundled_result = bundled_device.dump(bundled_path)
    upstream_result = upstream_device.dump(upstream_path)

    assert bundled_result == upstream_result
    assert bundled_path.read_bytes() == upstream_path.read_bytes()


def test_device_load_matches_upstream(tmp_path):
    material = _make_device_material()
    data = _make_upstream_device(material).dumps()

    path = tmp_path / "device.wvd"
    path.write_bytes(data)

    bundled_result = bundled.Device.load(path)
    upstream_result = upstream.Device.load(path)

    assert bundled_result.dumps() == upstream_result.dumps()


@pytest.mark.parametrize(
    "data",
    [
        None,
        123,
        [],
        {},
    ],
)
def test_device_loads_invalid_type_matches_upstream(data):
    with pytest.raises(Exception) as bundled_error:
        bundled.Device.loads(data)

    with pytest.raises(Exception) as upstream_error:
        upstream.Device.loads(data)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


@pytest.mark.parametrize(
    "path",
    [
        None,
        123,
        [],
        {},
    ],
)
def test_device_load_invalid_path_type_matches_upstream(path):
    with pytest.raises(Exception) as bundled_error:
        bundled.Device.load(path)

    with pytest.raises(Exception) as upstream_error:
        upstream.Device.load(path)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


@pytest.mark.parametrize(
    "path",
    [
        None,
        123,
        [],
        {},
    ],
)
def test_device_dump_invalid_path_type_matches_upstream(
    path,
):
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    with pytest.raises(Exception) as bundled_error:
        bundled_device.dump(path)

    with pytest.raises(Exception) as upstream_error:
        upstream_device.dump(path)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


@pytest.mark.parametrize(
    "path",
    [
        None,
        123,
        b"device.wvd",
    ],
)
def test_device_dump_invalid_path_matches_upstream(path):
    material = _make_device_material()

    bundled_device = _make_bundled_device(material)
    upstream_device = _make_upstream_device(material)

    with pytest.raises(Exception) as bundled_error:
        bundled_device.dump(path)

    with pytest.raises(Exception) as upstream_error:
        upstream_device.dump(path)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


@pytest.mark.parametrize(
    "data",
    [
        None,
        123,
        [],
    ],
)
def test_device_migrate_invalid_input_matches_upstream(data):
    with pytest.raises(Exception) as bundled_error:
        bundled.Device.migrate(data)

    with pytest.raises(Exception) as upstream_error:
        upstream.Device.migrate(data)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


def test_session_init_matches_upstream():
    bundled_session = bundled.Session(7)
    upstream_session = upstream.Session(7)

    assert bundled_session.number == upstream_session.number == 7

    assert type(bundled_session.id) is type(upstream_session.id)
    assert len(bundled_session.id) == len(upstream_session.id) == 16

    assert bundled_session.service_certificate is None
    assert upstream_session.service_certificate is None

    assert bundled_session.context == upstream_session.context == {}
    assert bundled_session.keys == upstream_session.keys == []


@pytest.mark.parametrize(
    "kid",
    [
        b"\x00" * 17,
        123,
    ],
)
def test_key_kid_to_uuid_invalid_matches_upstream(kid):
    with pytest.raises(Exception) as bundled_error:
        bundled.Key.kid_to_uuid(kid)

    with pytest.raises(Exception) as upstream_error:
        upstream.Key.kid_to_uuid(kid)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(
        upstream_error.value,
    )


def test_exception_hierarchy_matches_upstream():
    exception_names = [
        "PyWidevineException",
        "TooManySessions",
        "InvalidSession",
        "InvalidInitData",
        "InvalidLicenseType",
        "InvalidLicenseMessage",
        "InvalidContext",
        "SignatureMismatch",
        "NoKeysLoaded",
        "DeviceMismatch",
    ]

    for name in exception_names:
        bundled_exception = getattr(bundled, name)
        upstream_exception = getattr(upstream.exceptions, name)

        assert bundled_exception.__name__ == upstream_exception.__name__

        assert [base.__name__ for base in bundled_exception.__bases__] == [
            base.__name__ for base in upstream_exception.__bases__
        ]


def test_get_binary_path_first_match_matches_upstream(
    monkeypatch,
):
    first = r"C:\test\first.exe"
    second = r"C:\test\second.exe"

    def fake_which(name):
        return {
            "first": first,
            "second": second,
        }.get(name)

    monkeypatch.setattr(shutil, "which", fake_which)

    bundled_result = bundled.get_binary_path(
        "first",
        "second",
    )
    upstream_result = upstream_utils.get_binary_path(
        "first",
        "second",
    )

    assert bundled_result == upstream_result
    assert isinstance(bundled_result, Path)


def test_get_binary_path_fallback_matches_upstream(
    monkeypatch,
):
    found = r"C:\test\found.exe"

    def fake_which(name):
        if name == "found":
            return found
        return None

    monkeypatch.setattr(shutil, "which", fake_which)

    bundled_result = bundled.get_binary_path(
        "missing",
        "found",
    )
    upstream_result = upstream_utils.get_binary_path(
        "missing",
        "found",
    )

    assert bundled_result == upstream_result


def test_get_binary_path_missing_matches_upstream(
    monkeypatch,
):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: None,
    )

    bundled_result = bundled.get_binary_path(
        "missing-one",
        "missing-two",
    )
    upstream_result = upstream_utils.get_binary_path(
        "missing-one",
        "missing-two",
    )

    assert bundled_result == upstream_result
    assert bundled_result is None


def test_pymp4_box_parse_returns_bundled_container():
    data = bundled.Box.build(
        {
            "type": b"pssh",
            "version": 0,
            "flags": 0,
            "system_ID": bundled.PSSH.SystemId.Widevine,
            "init_data": b"test-data",
        },
    )

    result = bundled.Box.parse(data)

    assert isinstance(result, bundled.Container)


def test_remotecdm_init_matches_upstream(requests_mock):
    host = "https://remote.example"

    requests_mock.head(
        host,
        status_code=200,
        headers={
            "Server": "pywidevine serve v1.9.0",
        },
    )

    bundled_cdm = bundled.RemoteCdm(
        device_type=bundled.DeviceTypes.ANDROID,
        system_id=1234,
        security_level=3,
        host=host,
        secret="test-secret",
        device_name="test-device",
    )

    upstream_cdm = upstream.RemoteCdm(
        device_type=upstream.DeviceTypes.ANDROID,
        system_id=1234,
        security_level=3,
        host=host,
        secret="test-secret",
        device_name="test-device",
    )

    assert bundled_cdm.device_type.value == upstream_cdm.device_type.value
    assert bundled_cdm.system_id == upstream_cdm.system_id
    assert bundled_cdm.security_level == upstream_cdm.security_level
    assert bundled_cdm.host == upstream_cdm.host
    assert bundled_cdm.device_name == upstream_cdm.device_name


@pytest.mark.parametrize(
    ("argument", "value"),
    [
        ("device_type", None),
        ("system_id", None),
        ("security_level", None),
        ("host", None),
        ("secret", None),
        ("device_name", None),
    ],
)
def test_remotecdm_init_invalid_arguments_match_upstream(
    argument,
    value,
):
    kwargs = {
        "device_type": "ANDROID",
        "system_id": 1234,
        "security_level": 3,
        "host": "https://remote.example",
        "secret": "test-secret",
        "device_name": "test-device",
    }
    kwargs[argument] = value

    with pytest.raises(Exception) as bundled_error:
        bundled.RemoteCdm(**kwargs)

    with pytest.raises(Exception) as upstream_error:
        upstream.RemoteCdm(**kwargs)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(upstream_error.value)


@pytest.mark.parametrize(
    ("status_code", "server"),
    [
        (500, "pywidevine serve v1.9.0"),
        (200, None),
        (200, "something else"),
        (200, "pywidevine serve"),
        (200, "pywidevine serve v1.4.2"),
    ],
)
def test_remotecdm_server_validation_matches_upstream(
    requests_mock,
    status_code,
    server,
):
    headers = {}
    if server is not None:
        headers["Server"] = server

    requests_mock.head(
        "https://remote.example",
        status_code=status_code,
        headers=headers,
    )

    kwargs = {
        "device_type": "ANDROID",
        "system_id": 1234,
        "security_level": 3,
        "host": "https://remote.example",
        "secret": "test-secret",
        "device_name": "test-device",
    }

    with pytest.raises(Exception) as bundled_error:
        bundled.RemoteCdm(**kwargs)

    with pytest.raises(Exception) as upstream_error:
        upstream.RemoteCdm(**kwargs)

    assert (
        type(bundled_error.value).__name__
        == type(
            upstream_error.value,
        ).__name__
    )
    assert str(bundled_error.value) == str(upstream_error.value)


def _make_remote_cdms(requests_mock):
    host = "https://remote.example"

    requests_mock.head(
        host,
        status_code=200,
        headers={
            "Server": "pywidevine serve v1.9.0",
        },
    )

    bundled_cdm = bundled.RemoteCdm(
        device_type=bundled.DeviceTypes.ANDROID,
        system_id=1234,
        security_level=3,
        host=host,
        secret="test-secret",
        device_name="test-device",
    )

    upstream_cdm = upstream.RemoteCdm(
        device_type=upstream.DeviceTypes.ANDROID,
        system_id=1234,
        security_level=3,
        host=host,
        secret="test-secret",
        device_name="test-device",
    )

    return bundled_cdm, upstream_cdm


def test_remotecdm_from_device_matches_upstream():
    with pytest.raises(Exception) as bundled_error:
        bundled.RemoteCdm.from_device(None)

    with pytest.raises(Exception) as upstream_error:
        upstream.RemoteCdm.from_device(None)

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_open_matches_upstream(requests_mock):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.get(
        "https://remote.example/test-device/open",
        json={
            "status": 200,
            "message": "OK",
            "data": {
                "session_id": session_id.hex(),
                "device": {
                    "system_id": 1234,
                    "security_level": 3,
                },
            },
        },
    )

    bundled_result = bundled_cdm.open()
    upstream_result = upstream_cdm.open()

    assert bundled_result == upstream_result == session_id


@pytest.mark.parametrize(
    ("system_id", "security_level"),
    [
        (9999, 3),
        (1234, 1),
    ],
)
def test_remotecdm_open_device_mismatch_matches_upstream(
    requests_mock,
    system_id,
    security_level,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    requests_mock.get(
        "https://remote.example/test-device/open",
        json={
            "status": 200,
            "message": "OK",
            "data": {
                "session_id": ("00112233445566778899aabbccddeeff"),
                "device": {
                    "system_id": system_id,
                    "security_level": security_level,
                },
            },
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.open()

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.open()

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_open_api_error_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    requests_mock.get(
        "https://remote.example/test-device/open",
        json={
            "status": 403,
            "message": "Access denied",
            "data": {},
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.open()

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.open()

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_close_matches_upstream(requests_mock):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.get(
        (f"https://remote.example/test-device/close/{session_id.hex()}"),
        json={
            "status": 200,
            "message": "OK",
            "data": {},
        },
    )

    bundled_result = bundled_cdm.close(session_id)
    upstream_result = upstream_cdm.close(session_id)

    assert bundled_result == upstream_result


@pytest.mark.parametrize(
    "certificate",
    [
        None,
        "dGVzdC1jZXJ0aWZpY2F0ZQ==",
        b"test-certificate",
    ],
)
def test_remotecdm_set_service_certificate_matches_upstream(
    requests_mock,
    certificate,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.post(
        ("https://remote.example/test-device/set_service_certificate"),
        json={
            "status": 200,
            "message": "OK",
            "data": {
                "provider_id": "test-provider",
            },
        },
    )

    bundled_result = bundled_cdm.set_service_certificate(
        session_id,
        certificate,
    )
    upstream_result = upstream_cdm.set_service_certificate(
        session_id,
        certificate,
    )

    assert bundled_result == upstream_result == "test-provider"


def test_remotecdm_set_service_certificate_invalid_type_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.set_service_certificate(
            session_id,
            123,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.set_service_certificate(
            session_id,
            123,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_get_service_certificate_none_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.post(
        ("https://remote.example/test-device/get_service_certificate"),
        json={
            "status": 200,
            "message": "OK",
            "data": {
                "service_certificate": None,
            },
        },
    )

    bundled_result = bundled_cdm.get_service_certificate(
        session_id,
    )
    upstream_result = upstream_cdm.get_service_certificate(
        session_id,
    )

    assert bundled_result == upstream_result is None


def test_remotecdm_get_license_challenge_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    pssh_data = (
        "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsI"
        "ARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVz"
        "dCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
    )

    bundled_pssh = bundled.PSSH(pssh_data)
    upstream_pssh = upstream.PSSH(pssh_data)

    message = bundled.SignedMessage()
    message.type = bundled.SignedMessage.MessageType.Value(
        "LICENSE_REQUEST",
    )
    challenge = message.SerializeToString()

    requests_mock.post(
        ("https://remote.example/test-device/get_license_challenge/STREAMING"),
        json={
            "status": 200,
            "message": "OK",
            "data": {
                "challenge_b64": base64.b64encode(
                    challenge,
                ).decode(),
            },
        },
    )

    bundled_result = bundled_cdm.get_license_challenge(
        session_id,
        bundled_pssh,
    )
    upstream_result = upstream_cdm.get_license_challenge(
        session_id,
        upstream_pssh,
    )

    assert bundled_result == upstream_result == challenge


@pytest.mark.parametrize(
    "license_type",
    [
        None,
        123,
        "NOT_A_LICENSE_TYPE",
    ],
)
def test_remotecdm_get_license_challenge_invalid_type_matches_upstream(
    requests_mock,
    license_type,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    pssh_data = (
        "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsI"
        "ARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVz"
        "dCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
    )

    bundled_pssh = bundled.PSSH(pssh_data)
    upstream_pssh = upstream.PSSH(pssh_data)

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_license_challenge(
            session_id,
            bundled_pssh,
            license_type,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_license_challenge(
            session_id,
            upstream_pssh,
            license_type,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_parse_license_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    bundled_message = bundled.SignedMessage()
    bundled_message.type = bundled.SignedMessage.MessageType.Value("LICENSE")
    bundled_data = bundled_message.SerializeToString()

    upstream_message = upstream_protocol.SignedMessage()
    upstream_message.type = upstream_protocol.SignedMessage.MessageType.Value(
        "LICENSE",
    )
    upstream_data = upstream_message.SerializeToString()

    assert bundled_data == upstream_data

    requests_mock.post(
        ("https://remote.example/test-device/parse_license"),
        json={
            "status": 200,
            "message": "OK",
            "data": {},
        },
    )

    bundled_result = bundled_cdm.parse_license(
        session_id,
        bundled_data,
    )
    upstream_result = upstream_cdm.parse_license(
        session_id,
        upstream_data,
    )

    assert bundled_result == upstream_result


@pytest.mark.parametrize(
    "license_message",
    [
        None,
        b"",
        "",
        123,
    ],
)
def test_remotecdm_parse_license_invalid_message_matches_upstream(
    requests_mock,
    license_message,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.parse_license(
            session_id,
            license_message,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.parse_license(
            session_id,
            license_message,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


@pytest.mark.parametrize(
    "key_type",
    [
        None,
        "CONTENT",
        2,
    ],
)
def test_remotecdm_get_keys_matches_upstream(
    requests_mock,
    key_type,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    kid = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )
    key = bytes.fromhex(
        "ffeeddccbbaa99887766554433221100",
    )

    response = {
        "status": 200,
        "message": "OK",
        "data": {
            "keys": [
                {
                    "type": "CONTENT",
                    "key_id": kid.hex(),
                    "key": key.hex(),
                    "permissions": [],
                },
            ],
        },
    }

    # Register every endpoint which this parametrisation
    # can request.
    for name in (
        "ALL",
        "CONTENT",
        "SIGNING",
    ):
        requests_mock.post(
            (f"https://remote.example/test-device/get_keys/{name}"),
            json=response,
        )

    bundled_keys = bundled_cdm.get_keys(
        session_id,
        key_type,
    )
    upstream_keys = upstream_cdm.get_keys(
        session_id,
        key_type,
    )

    assert len(bundled_keys) == len(upstream_keys) == 1

    bundled_key = bundled_keys[0]
    upstream_key = upstream_keys[0]

    assert bundled_key.type == upstream_key.type
    assert bundled_key.kid == upstream_key.kid
    assert bundled_key.key == upstream_key.key
    assert bundled_key.permissions == upstream_key.permissions


def test_remotecdm_get_license_challenge_invalid_pssh_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    for value in (None, b"not-a-pssh", "not-a-pssh"):
        with pytest.raises(Exception) as bundled_error:
            bundled_cdm.get_license_challenge(
                session_id,
                value,
            )

        with pytest.raises(Exception) as upstream_error:
            upstream_cdm.get_license_challenge(
                session_id,
                value,
            )

        assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__

        if value is None:
            assert str(bundled_error.value) == str(upstream_error.value)
        else:
            assert "Expected pssh to be a" in str(
                bundled_error.value,
            )
            assert "Expected pssh to be a" in str(
                upstream_error.value,
            )
            assert repr(value) in str(bundled_error.value)
            assert repr(value) in str(upstream_error.value)


def test_remotecdm_get_license_challenge_api_error_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    pssh_data = (
        "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsI"
        "ARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVz"
        "dCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
    )

    bundled_pssh = bundled.PSSH(pssh_data)
    upstream_pssh = upstream.PSSH(pssh_data)

    requests_mock.post(
        ("https://remote.example/test-device/get_license_challenge/STREAMING"),
        json={
            "status": 403,
            "message": "Access denied",
            "data": {},
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_license_challenge(
            session_id,
            bundled_pssh,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_license_challenge(
            session_id,
            upstream_pssh,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_parse_license_wrong_type_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    bundled_message = bundled.SignedMessage()
    bundled_message.type = bundled.SignedMessage.MessageType.Value(
        "LICENSE_REQUEST",
    )

    upstream_message = upstream_protocol.SignedMessage()
    upstream_message.type = upstream_protocol.SignedMessage.MessageType.Value(
        "LICENSE_REQUEST",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.parse_license(
            session_id,
            bundled_message,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.parse_license(
            session_id,
            upstream_message,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_get_keys_invalid_name_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_keys(
            session_id,
            "INVALID",
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_keys(
            session_id,
            "INVALID",
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__ == "ValueError"

    expected = "Enum KeyType has no value defined for name 'INVALID'"

    assert expected in str(bundled_error.value)
    assert expected in str(upstream_error.value)


def test_remotecdm_get_keys_invalid_type_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    value = object()

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_keys(
            session_id,
            value,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_keys(
            session_id,
            value,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__ == "TypeError"

    assert "Expected type_ to be a" in str(
        bundled_error.value,
    )
    assert "Expected type_ to be a" in str(
        upstream_error.value,
    )

    assert repr(value) in str(bundled_error.value)
    assert repr(value) in str(upstream_error.value)


def test_remotecdm_close_api_error_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.get(
        (f"https://remote.example/test-device/close/{session_id.hex()}"),
        json={
            "status": 404,
            "message": "Session not found",
            "data": {},
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.close(session_id)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.close(session_id)

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_set_service_certificate_api_error_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.post(
        ("https://remote.example/test-device/set_service_certificate"),
        json={
            "status": 400,
            "message": "Invalid certificate",
            "data": {},
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.set_service_certificate(
            session_id,
            b"certificate",
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.set_service_certificate(
            session_id,
            b"certificate",
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_get_service_certificate_api_error_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.post(
        ("https://remote.example/test-device/get_service_certificate"),
        json={
            "status": 404,
            "message": "Session not found",
            "data": {},
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_service_certificate(session_id)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_service_certificate(session_id)

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_parse_license_api_error_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    bundled_message = bundled.SignedMessage()
    bundled_message.type = bundled.SignedMessage.MessageType.Value("LICENSE")

    upstream_message = upstream_protocol.SignedMessage()
    upstream_message.type = upstream_protocol.SignedMessage.MessageType.Value(
        "LICENSE",
    )

    requests_mock.post(
        ("https://remote.example/test-device/parse_license"),
        json={
            "status": 400,
            "message": "Invalid license",
            "data": {},
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.parse_license(
            session_id,
            bundled_message,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.parse_license(
            session_id,
            upstream_message,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_get_keys_api_error_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.post(
        ("https://remote.example/test-device/get_keys/ALL"),
        json={
            "status": 404,
            "message": "Session not found",
            "data": {},
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_keys(session_id)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_keys(session_id)

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__
    assert str(bundled_error.value) == str(upstream_error.value)


def test_remotecdm_get_license_challenge_malformed_response_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    pssh_data = (
        "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsI"
        "ARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVz"
        "dCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
    )

    bundled_pssh = bundled.PSSH(pssh_data)
    upstream_pssh = upstream.PSSH(pssh_data)

    requests_mock.post(
        ("https://remote.example/test-device/get_license_challenge/STREAMING"),
        json={
            "status": 200,
            "message": "OK",
            "data": {
                "challenge_b64": base64.b64encode(
                    b"\xff\xff\xff\xff",
                ).decode(),
            },
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_license_challenge(
            session_id,
            bundled_pssh,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_license_challenge(
            session_id,
            upstream_pssh,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__


def test_remotecdm_get_service_certificate_malformed_matches_upstream(
    requests_mock,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    requests_mock.post(
        ("https://remote.example/test-device/get_service_certificate"),
        json={
            "status": 200,
            "message": "OK",
            "data": {
                "service_certificate": base64.b64encode(
                    b"\xff\xff\xff\xff",
                ).decode(),
            },
        },
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.get_service_certificate(session_id)

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.get_service_certificate(session_id)

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__ == "DecodeError"


@pytest.mark.parametrize(
    "license_message",
    [
        b"\xff\xff\xff\xff",
        base64.b64encode(b"\xff\xff\xff\xff").decode(),
    ],
)
def test_remotecdm_parse_license_malformed_matches_upstream(
    requests_mock,
    license_message,
):
    bundled_cdm, upstream_cdm = _make_remote_cdms(
        requests_mock,
    )

    session_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff",
    )

    with pytest.raises(Exception) as bundled_error:
        bundled_cdm.parse_license(
            session_id,
            license_message,
        )

    with pytest.raises(Exception) as upstream_error:
        upstream_cdm.parse_license(
            session_id,
            license_message,
        )

    assert type(bundled_error.value).__name__ == type(upstream_error.value).__name__ == "InvalidLicenseMessage"

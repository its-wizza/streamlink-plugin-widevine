import base64

import pywidevine.license_protocol_pb2 as upstream

from compat import license_protocol as compat


ROOT_SIGNED_CERT = base64.b64decode(
    "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZy"
    "f7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfM"
    "qIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx"
    "+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg1"
    "7B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSC"
    "UNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0a"
    "y5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZV"
    "dA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2F"
    "RXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7"
    "evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA==",
)

COMMON_PRIVACY_CERT = base64.b64decode(
    "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8yzdQPgZFuBTYdrjfQFEE"
    "Qa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHleB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3r"
    "M3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/THhv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ"
    "7c4kcHCCaA1vZ8bYLErF8xNEkKdO7DevSy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmlu"
    "ZS5jb20SgAOuNHMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M4PxL/C"
    "CpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9qm9Nta/gr52u/DLpP3lnSq8x2"
    "/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeF"
    "Hd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkPj89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98"
    "X/8z8QSQ+spbJTYLdgFenFoGq47gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ=",
)


def test_license_identification():
    custom = compat.LicenseIdentification(
        request_id=b"request",
        session_id=b"session",
        purchase_id=b"purchase",
        type="STREAMING",
        version=42,
        provider_session_token=b"token",
    )

    google = upstream.LicenseIdentification(
        request_id=b"request",
        session_id=b"session",
        purchase_id=b"purchase",
        type="STREAMING",
        version=42,
        provider_session_token=b"token",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_policy():
    custom = compat.License.Policy(
        can_play=True,
        can_persist=True,
        rental_duration_seconds=123,
        renewal_server_url="https://example.com/",
        soft_enforce_rental_duration=False,
    )

    google = upstream.License.Policy(
        can_play=True,
        can_persist=True,
        rental_duration_seconds=123,
        renewal_server_url="https://example.com/",
        soft_enforce_rental_duration=False,
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_policy_defaults():
    custom = compat.License.Policy()
    google = upstream.License.Policy()

    assert custom.can_play == google.can_play
    assert custom.can_play is False
    assert custom.can_persist == google.can_persist
    assert custom.can_persist is False
    assert custom.can_renew == google.can_renew
    assert custom.can_renew is False

    assert custom.soft_enforce_rental_duration == google.soft_enforce_rental_duration
    assert custom.soft_enforce_rental_duration is True

    assert custom.SerializeToString() == google.SerializeToString() == b""


def test_license_key_container():
    custom = compat.License.KeyContainer(
        id=b"id",
        iv=b"iv",
        key=b"key",
        type="CONTENT",
        level="HW_SECURE_ALL",
        required_protection=compat.License.KeyContainer.OutputProtection(
            hdcp="HDCP_V2_2",
            cgms_flags="COPY_NEVER",
            disable_analog_output=True,
        ),
        operator_session_key_permissions=(
            compat.License.KeyContainer.OperatorSessionKeyPermissions(
                allow_encrypt=True,
                allow_decrypt=True,
            )
        ),
        video_resolution_constraints=[
            compat.License.KeyContainer.VideoResolutionConstraint(
                min_resolution_pixels=0,
                max_resolution_pixels=1920 * 1080,
            ),
        ],
        anti_rollback_usage_table=True,
        track_label="HD",
    )

    google = upstream.License.KeyContainer(
        id=b"id",
        iv=b"iv",
        key=b"key",
        type="CONTENT",
        level="HW_SECURE_ALL",
        required_protection={
            "hdcp": "HDCP_V2_2",
            "cgms_flags": "COPY_NEVER",
            "disable_analog_output": True,
        },
        operator_session_key_permissions={
            "allow_encrypt": True,
            "allow_decrypt": True,
        },
        video_resolution_constraints=[
            {
                "min_resolution_pixels": 0,
                "max_resolution_pixels": 1920 * 1080,
            },
        ],
        anti_rollback_usage_table=True,
        track_label="HD",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license():
    custom = compat.License(
        id=compat.LicenseIdentification(
            request_id=b"request",
            session_id=b"session",
            type="STREAMING",
            version=1,
        ),
        policy=compat.License.Policy(
            can_play=True,
            can_persist=True,
            license_duration_seconds=3600,
        ),
        key=[
            compat.License.KeyContainer(
                id=b"kid",
                iv=b"iv",
                key=b"content-key",
                type="CONTENT",
                level="SW_SECURE_CRYPTO",
            ),
        ],
        license_start_time=123456789,
        remote_attestation_verified=True,
        provider_client_token=b"provider-token",
        protection_scheme=0x63656E63,
        srm_requirement=b"requirement",
        srm_update=b"update",
        platform_verification_status="PLATFORM_HARDWARE_VERIFIED",
        group_ids=[
            b"group-1",
            b"group-2",
        ],
    )

    google = upstream.License(
        id={
            "request_id": b"request",
            "session_id": b"session",
            "type": "STREAMING",
            "version": 1,
        },
        policy={
            "can_play": True,
            "can_persist": True,
            "license_duration_seconds": 3600,
        },
        key=[
            {
                "id": b"kid",
                "iv": b"iv",
                "key": b"content-key",
                "type": "CONTENT",
                "level": "SW_SECURE_CRYPTO",
            },
        ],
        license_start_time=123456789,
        remote_attestation_verified=True,
        provider_client_token=b"provider-token",
        protection_scheme=0x63656E63,
        srm_requirement=b"requirement",
        srm_update=b"update",
        platform_verification_status="PLATFORM_HARDWARE_VERIFIED",
        group_ids=[
            b"group-1",
            b"group-2",
        ],
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_defaults():
    custom = compat.License()
    google = upstream.License()

    assert custom.remote_attestation_verified == google.remote_attestation_verified
    assert custom.remote_attestation_verified is False

    assert custom.platform_verification_status == google.platform_verification_status == 4

    assert custom.SerializeToString() == google.SerializeToString() == b""


def test_client_identification():
    custom = compat.ClientIdentification(
        type="DRM_DEVICE_CERTIFICATE",
        token=b"device-token",
        client_info=[
            compat.ClientIdentification.NameValue(
                name="company_name",
                value="Example",
            ),
            compat.ClientIdentification.NameValue(
                name="model_name",
                value="Example Device",
            ),
        ],
        provider_client_token=b"provider-token",
        license_counter=123,
        client_capabilities=compat.ClientIdentification.ClientCapabilities(
            client_token=True,
            session_token=True,
            video_resolution_constraints=True,
            max_hdcp_version="HDCP_V2_2",
            oem_crypto_api_version=16,
            anti_rollback_usage_table=True,
            srm_version=12,
            can_update_srm=True,
            supported_certificate_key_type=[
                "RSA_2048",
                "ECC_SECP256R1",
            ],
            analog_output_capabilities="ANALOG_OUTPUT_SUPPORTED",
            can_disable_analog_output=True,
            resource_rating_tier=3,
        ),
        vmp_data=b"vmp",
        device_credentials=[
            compat.ClientIdentification.ClientCredentials(
                type="KEYBOX",
                token=b"credential",
            ),
        ],
    )

    google = upstream.ClientIdentification(
        type="DRM_DEVICE_CERTIFICATE",
        token=b"device-token",
        client_info=[
            {
                "name": "company_name",
                "value": "Example",
            },
            {
                "name": "model_name",
                "value": "Example Device",
            },
        ],
        provider_client_token=b"provider-token",
        license_counter=123,
        client_capabilities={
            "client_token": True,
            "session_token": True,
            "video_resolution_constraints": True,
            "max_hdcp_version": "HDCP_V2_2",
            "oem_crypto_api_version": 16,
            "anti_rollback_usage_table": True,
            "srm_version": 12,
            "can_update_srm": True,
            "supported_certificate_key_type": [
                "RSA_2048",
                "ECC_SECP256R1",
            ],
            "analog_output_capabilities": "ANALOG_OUTPUT_SUPPORTED",
            "can_disable_analog_output": True,
            "resource_rating_tier": 3,
        },
        vmp_data=b"vmp",
        device_credentials=[
            {
                "type": "KEYBOX",
                "token": b"credential",
            },
        ],
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_client_identification_parse():
    google = upstream.ClientIdentification(
        type="DRM_DEVICE_CERTIFICATE",
        token=b"device-token",
        client_info=[
            {
                "name": "company_name",
                "value": "Example",
            },
        ],
        client_capabilities={
            "max_hdcp_version": "HDCP_V2_2",
            "oem_crypto_api_version": 16,
        },
        vmp_data=b"vmp-data",
    )

    data = google.SerializeToString()

    custom = compat.ClientIdentification()
    custom.ParseFromString(data)

    assert custom.type == google.type
    assert custom.token == google.token
    assert custom.client_info[0].name == google.client_info[0].name
    assert custom.client_info[0].value == google.client_info[0].value
    assert custom.client_capabilities.max_hdcp_version == google.client_capabilities.max_hdcp_version
    assert custom.client_capabilities.oem_crypto_api_version == google.client_capabilities.oem_crypto_api_version
    assert custom.vmp_data == google.vmp_data

    assert custom.SerializeToString() == data


def test_encrypted_client_identification():
    custom = compat.EncryptedClientIdentification(
        provider_id="example-provider",
        service_certificate_serial_number=b"serial-number",
        encrypted_client_id=b"encrypted-client-id",
        encrypted_client_id_iv=b"0123456789abcdef",
        encrypted_privacy_key=b"encrypted-privacy-key",
    )

    google = upstream.EncryptedClientIdentification(
        provider_id="example-provider",
        service_certificate_serial_number=b"serial-number",
        encrypted_client_id=b"encrypted-client-id",
        encrypted_client_id_iv=b"0123456789abcdef",
        encrypted_privacy_key=b"encrypted-privacy-key",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_encrypted_client_identification_parse():
    google = upstream.EncryptedClientIdentification(
        provider_id="example-provider",
        service_certificate_serial_number=b"serial-number",
        encrypted_client_id=b"encrypted-client-id",
        encrypted_client_id_iv=b"0123456789abcdef",
        encrypted_privacy_key=b"encrypted-privacy-key",
    )

    data = google.SerializeToString()

    custom = compat.EncryptedClientIdentification()
    custom.ParseFromString(data)

    assert custom.provider_id == google.provider_id
    assert custom.service_certificate_serial_number == google.service_certificate_serial_number
    assert custom.encrypted_client_id == google.encrypted_client_id
    assert custom.encrypted_client_id_iv == google.encrypted_client_id_iv
    assert custom.encrypted_privacy_key == google.encrypted_privacy_key

    assert custom.SerializeToString() == data


def test_license_request():
    client_id = compat.ClientIdentification(
        type="DRM_DEVICE_CERTIFICATE",
        token=b"device-token",
    )

    google_client_id = upstream.ClientIdentification(
        type="DRM_DEVICE_CERTIFICATE",
        token=b"device-token",
    )

    custom = compat.LicenseRequest(
        client_id=client_id,
        content_id=compat.LicenseRequest.ContentIdentification(
            widevine_pssh_data=(
                compat.LicenseRequest.ContentIdentification.WidevinePsshData(
                    pssh_data=[b"pssh-data"],
                    license_type="STREAMING",
                    request_id=b"request-id",
                )
            ),
        ),
        type="NEW",
        request_time=123456789,
        protocol_version="VERSION_2_1",
        key_control_nonce=123456,
    )

    google = upstream.LicenseRequest(
        client_id=google_client_id,
        content_id={
            "widevine_pssh_data": {
                "pssh_data": [b"pssh-data"],
                "license_type": "STREAMING",
                "request_id": b"request-id",
            },
        },
        type="NEW",
        request_time=123456789,
        protocol_version="VERSION_2_1",
        key_control_nonce=123456,
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_request_encrypted_client_id():
    encrypted = compat.EncryptedClientIdentification(
        provider_id="provider",
        service_certificate_serial_number=b"serial",
        encrypted_client_id=b"encrypted-client",
        encrypted_client_id_iv=b"0123456789abcdef",
        encrypted_privacy_key=b"encrypted-key",
    )

    google_encrypted = upstream.EncryptedClientIdentification(
        provider_id="provider",
        service_certificate_serial_number=b"serial",
        encrypted_client_id=b"encrypted-client",
        encrypted_client_id_iv=b"0123456789abcdef",
        encrypted_privacy_key=b"encrypted-key",
    )

    custom = compat.LicenseRequest(
        client_id=None,
        encrypted_client_id=encrypted,
        content_id=compat.LicenseRequest.ContentIdentification(
            widevine_pssh_data=(
                compat.LicenseRequest.ContentIdentification.WidevinePsshData(
                    pssh_data=[b"pssh-data"],
                    license_type="STREAMING",
                    request_id=b"request-id",
                )
            ),
        ),
        type="NEW",
        request_time=123456789,
        protocol_version="VERSION_2_1",
        key_control_nonce=123456,
    )

    google = upstream.LicenseRequest(
        encrypted_client_id=google_encrypted,
        content_id={
            "widevine_pssh_data": {
                "pssh_data": [b"pssh-data"],
                "license_type": "STREAMING",
                "request_id": b"request-id",
            },
        },
        type="NEW",
        request_time=123456789,
        protocol_version="VERSION_2_1",
        key_control_nonce=123456,
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_signed_message_license_request():
    custom = compat.SignedMessage(
        type="LICENSE_REQUEST",
        msg=b"serialized-license-request",
        signature=b"rsa-signature",
    )

    google = upstream.SignedMessage(
        type="LICENSE_REQUEST",
        msg=b"serialized-license-request",
        signature=b"rsa-signature",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_signed_message_license_response():
    custom = compat.SignedMessage(
        type="LICENSE",
        msg=b"serialized-license",
        signature=b"hmac-signature",
        session_key=b"wrapped-session-key",
        session_key_type="WRAPPED_AES_KEY",
        oemcrypto_core_message=b"oemcrypto-core",
        service_version_info=compat.VersionInfo(
            license_sdk_version="1.2.3",
            license_service_version="4.5.6",
        ),
        metric_data=[
            compat.MetricData(
                stage_name="license",
                metric_data=[
                    compat.MetricData.TypeValue(
                        type="LATENCY",
                        value=12345,
                    ),
                ],
            ),
        ],
    )

    google = upstream.SignedMessage(
        type="LICENSE",
        msg=b"serialized-license",
        signature=b"hmac-signature",
        session_key=b"wrapped-session-key",
        session_key_type="WRAPPED_AES_KEY",
        oemcrypto_core_message=b"oemcrypto-core",
        service_version_info={
            "license_sdk_version": "1.2.3",
            "license_service_version": "4.5.6",
        },
        metric_data=[
            {
                "stage_name": "license",
                "metric_data": [
                    {
                        "type": "LATENCY",
                        "value": 12345,
                    },
                ],
            },
        ],
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_signed_message_parse_license_response():
    google = upstream.SignedMessage(
        type="LICENSE",
        msg=b"serialized-license",
        signature=b"hmac-signature",
        session_key=b"wrapped-session-key",
        oemcrypto_core_message=b"oemcrypto-core",
    )

    data = google.SerializeToString()

    custom = compat.SignedMessage()
    custom.ParseFromString(data)

    assert custom.type == upstream.SignedMessage.MessageType.Value("LICENSE")
    assert custom.msg == b"serialized-license"
    assert custom.signature == b"hmac-signature"
    assert custom.session_key == b"wrapped-session-key"
    assert custom.oemcrypto_core_message == b"oemcrypto-core"

    assert custom.SerializeToString() == data


def test_signed_message_message_type():
    assert compat.SignedMessage.MessageType.Value("LICENSE") == upstream.SignedMessage.MessageType.Value("LICENSE") == 2

    assert compat.SignedMessage.MessageType.Name(2) == "LICENSE"


def test_drm_certificate():
    custom = compat.DrmCertificate(
        type="SERVICE",
        serial_number=b"serial",
        creation_time_seconds=123456789,
        expiration_time_seconds=987654321,
        public_key=b"public-key",
        system_id=1234,
        test_device_deprecated=False,
        provider_id="example-provider",
        service_types=[
            "LICENSE_SERVER_SDK",
            "LICENSE_SERVER_PROXY_SDK",
        ],
        algorithm="RSA",
        rot_id=b"rot-id",
        encryption_key=compat.DrmCertificate.EncryptionKey(
            public_key=b"encryption-public-key",
            algorithm="ECC_SECP256R1",
        ),
    )

    google = upstream.DrmCertificate(
        type="SERVICE",
        serial_number=b"serial",
        creation_time_seconds=123456789,
        expiration_time_seconds=987654321,
        public_key=b"public-key",
        system_id=1234,
        test_device_deprecated=False,
        provider_id="example-provider",
        service_types=[
            "LICENSE_SERVER_SDK",
            "LICENSE_SERVER_PROXY_SDK",
        ],
        algorithm="RSA",
        rot_id=b"rot-id",
        encryption_key={
            "public_key": b"encryption-public-key",
            "algorithm": "ECC_SECP256R1",
        },
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_signed_drm_certificate():
    signer = compat.SignedDrmCertificate(
        drm_certificate=b"signer-certificate",
        signature=b"signer-signature",
        hash_algorithm="HASH_ALGORITHM_SHA_256",
    )

    custom = compat.SignedDrmCertificate(
        drm_certificate=b"certificate",
        signature=b"signature",
        signer=signer,
        hash_algorithm="HASH_ALGORITHM_SHA_256",
    )

    google = upstream.SignedDrmCertificate(
        drm_certificate=b"certificate",
        signature=b"signature",
        signer={
            "drm_certificate": b"signer-certificate",
            "signature": b"signer-signature",
            "hash_algorithm": "HASH_ALGORITHM_SHA_256",
        },
        hash_algorithm="HASH_ALGORITHM_SHA_256",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_signed_drm_certificate_parse():
    google = upstream.SignedDrmCertificate(
        drm_certificate=b"certificate",
        signature=b"signature",
        signer={
            "drm_certificate": b"signer-certificate",
            "signature": b"signer-signature",
        },
        hash_algorithm="HASH_ALGORITHM_SHA_1",
    )

    data = google.SerializeToString()

    custom = compat.SignedDrmCertificate()
    custom.ParseFromString(data)

    assert custom.drm_certificate == b"certificate"
    assert custom.signature == b"signature"
    assert custom.signer.drm_certificate == b"signer-certificate"
    assert custom.signer.signature == b"signer-signature"
    assert (
        custom.hash_algorithm
        == upstream.SignedDrmCertificate.DESCRIPTOR
        .fields_by_name["hash_algorithm"]
        .enum_type.values_by_name["HASH_ALGORITHM_SHA_1"]
        .number
        == 1
    )

    assert custom.SerializeToString() == data


def test_drm_certificate_algorithm_defaults():
    custom = compat.DrmCertificate()
    google = upstream.DrmCertificate()

    assert custom.algorithm == google.algorithm == 1

    custom_key = compat.DrmCertificate.EncryptionKey()
    google_key = upstream.DrmCertificate.EncryptionKey()

    assert custom_key.algorithm == google_key.algorithm == 1


def test_real_root_signed_drm_certificate():
    signed = compat.SignedDrmCertificate()
    signed.ParseFromString(ROOT_SIGNED_CERT)

    assert signed.SerializeToString() == ROOT_SIGNED_CERT

    assert signed.drm_certificate
    assert signed.signature

    certificate = compat.DrmCertificate()
    certificate.ParseFromString(signed.drm_certificate)

    assert certificate.SerializeToString() == signed.drm_certificate

    assert certificate.type == compat.DrmCertificate.Type.Value("ROOT")
    assert certificate.public_key


def test_real_root_certificate_matches_google():
    custom_signed = compat.SignedDrmCertificate()
    custom_signed.ParseFromString(ROOT_SIGNED_CERT)

    google_signed = upstream.SignedDrmCertificate()
    google_signed.ParseFromString(ROOT_SIGNED_CERT)

    assert custom_signed.SerializeToString() == google_signed.SerializeToString()

    custom = compat.DrmCertificate()
    custom.ParseFromString(custom_signed.drm_certificate)

    google = upstream.DrmCertificate()
    google.ParseFromString(google_signed.drm_certificate)

    assert custom.type == google.type
    assert custom.serial_number == google.serial_number
    assert custom.creation_time_seconds == google.creation_time_seconds
    assert custom.expiration_time_seconds == google.expiration_time_seconds
    assert custom.public_key == google.public_key
    assert custom.system_id == google.system_id
    assert custom.provider_id == google.provider_id
    assert list(custom.service_types) == list(google.service_types)
    assert custom.algorithm == google.algorithm
    assert custom.rot_id == google.rot_id

    assert custom.SerializeToString() == google.SerializeToString()


def test_real_common_privacy_certificate():
    message = compat.SignedMessage()
    message.ParseFromString(COMMON_PRIVACY_CERT)

    assert message.SerializeToString() == COMMON_PRIVACY_CERT
    assert message.type == compat.SignedMessage.MessageType.Value(
        "SERVICE_CERTIFICATE",
    )
    assert message.msg

    signed = compat.SignedDrmCertificate()
    signed.ParseFromString(message.msg)

    assert signed.SerializeToString() == message.msg
    assert signed.drm_certificate
    assert signed.signature

    certificate = compat.DrmCertificate()
    certificate.ParseFromString(signed.drm_certificate)

    assert certificate.SerializeToString() == signed.drm_certificate
    assert certificate.type == compat.DrmCertificate.Type.Value("SERVICE")
    assert certificate.provider_id
    assert certificate.serial_number
    assert certificate.public_key


def test_real_common_privacy_certificate_matches_google():
    custom_message = compat.SignedMessage()
    custom_message.ParseFromString(COMMON_PRIVACY_CERT)

    google_message = upstream.SignedMessage()
    google_message.ParseFromString(COMMON_PRIVACY_CERT)

    assert custom_message.SerializeToString() == google_message.SerializeToString() == COMMON_PRIVACY_CERT

    assert custom_message.type == google_message.type
    assert custom_message.msg == google_message.msg

    custom_signed = compat.SignedDrmCertificate()
    custom_signed.ParseFromString(custom_message.msg)

    google_signed = upstream.SignedDrmCertificate()
    google_signed.ParseFromString(google_message.msg)

    assert custom_signed.SerializeToString() == google_signed.SerializeToString()

    custom = compat.DrmCertificate()
    custom.ParseFromString(custom_signed.drm_certificate)

    google = upstream.DrmCertificate()
    google.ParseFromString(google_signed.drm_certificate)

    assert custom.type == google.type
    assert custom.serial_number == google.serial_number
    assert custom.creation_time_seconds == google.creation_time_seconds
    assert custom.expiration_time_seconds == google.expiration_time_seconds
    assert custom.public_key == google.public_key
    assert custom.system_id == google.system_id
    assert custom.provider_id == google.provider_id
    assert list(custom.service_types) == list(google.service_types)
    assert custom.algorithm == google.algorithm
    assert custom.rot_id == google.rot_id

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_content_key_matches_google():
    custom = compat.License.KeyContainer(
        id=b"content-key-id",
        iv=b"0123456789abcdef",
        key=b"encrypted-content-key",
        type="CONTENT",
        level="HW_SECURE_CRYPTO",
        anti_rollback_usage_table=True,
        track_label="HD",
    )

    google = upstream.License.KeyContainer(
        id=b"content-key-id",
        iv=b"0123456789abcdef",
        key=b"encrypted-content-key",
        type="CONTENT",
        level="HW_SECURE_CRYPTO",
        anti_rollback_usage_table=True,
        track_label="HD",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_operator_session_key_matches_google():
    custom = compat.License.KeyContainer(
        id=b"operator-key-id",
        iv=b"0123456789abcdef",
        key=b"encrypted-operator-key",
        type="OPERATOR_SESSION",
        operator_session_key_permissions=(
            compat.License.KeyContainer.OperatorSessionKeyPermissions(
                allow_encrypt=True,
                allow_decrypt=True,
                allow_sign=False,
                allow_signature_verify=True,
            )
        ),
    )

    google = upstream.License.KeyContainer(
        id=b"operator-key-id",
        iv=b"0123456789abcdef",
        key=b"encrypted-operator-key",
        type="OPERATOR_SESSION",
        operator_session_key_permissions={
            "allow_encrypt": True,
            "allow_decrypt": True,
            "allow_sign": False,
            "allow_signature_verify": True,
        },
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_output_protection_matches_google():
    custom = compat.License.KeyContainer.OutputProtection(
        hdcp="HDCP_V2_2",
        cgms_flags="COPY_NEVER",
        hdcp_srm_rule="CURRENT_SRM",
        disable_analog_output=True,
        disable_digital_output=False,
    )

    google = upstream.License.KeyContainer.OutputProtection(
        hdcp="HDCP_V2_2",
        cgms_flags="COPY_NEVER",
        hdcp_srm_rule="CURRENT_SRM",
        disable_analog_output=True,
        disable_digital_output=False,
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_video_resolution_constraint_matches_google():
    custom = compat.License.KeyContainer.VideoResolutionConstraint(
        min_resolution_pixels=0,
        max_resolution_pixels=1920 * 1080,
        required_protection=compat.License.KeyContainer.OutputProtection(
            hdcp="HDCP_V2_2",
        ),
    )

    google = upstream.License.KeyContainer.VideoResolutionConstraint(
        min_resolution_pixels=0,
        max_resolution_pixels=1920 * 1080,
        required_protection={
            "hdcp": "HDCP_V2_2",
        },
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_policy_matches_google():
    custom = compat.License.Policy(
        can_play=True,
        can_persist=True,
        can_renew=True,
        rental_duration_seconds=86400,
        playback_duration_seconds=7200,
        license_duration_seconds=172800,
        renewal_recovery_duration_seconds=300,
        renewal_server_url="https://example.invalid/renew",
        renewal_delay_seconds=60,
        renewal_retry_interval_seconds=30,
        renew_with_usage=True,
        always_include_client_id=True,
        play_start_grace_period_seconds=10,
        soft_enforce_playback_duration=True,
        soft_enforce_rental_duration=False,
    )

    google = upstream.License.Policy(
        can_play=True,
        can_persist=True,
        can_renew=True,
        rental_duration_seconds=86400,
        playback_duration_seconds=7200,
        license_duration_seconds=172800,
        renewal_recovery_duration_seconds=300,
        renewal_server_url="https://example.invalid/renew",
        renewal_delay_seconds=60,
        renewal_retry_interval_seconds=30,
        renew_with_usage=True,
        always_include_client_id=True,
        play_start_grace_period_seconds=10,
        soft_enforce_playback_duration=True,
        soft_enforce_rental_duration=False,
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_defaults_match_google():
    custom = compat.License()
    google = upstream.License()

    assert custom.platform_verification_status == google.platform_verification_status

    assert custom.policy.can_play == google.policy.can_play
    assert custom.policy.soft_enforce_rental_duration == google.policy.soft_enforce_rental_duration


def test_license_matches_google():
    custom = compat.License(
        id=compat.LicenseIdentification(
            request_id=b"request-id",
            session_id=b"session-id",
            type="STREAMING",
            version=1,
        ),
        policy=compat.License.Policy(
            can_play=True,
            can_persist=False,
            license_duration_seconds=3600,
        ),
        key=[
            compat.License.KeyContainer(
                id=b"content-id",
                iv=b"content-iv",
                key=b"encrypted-content-key",
                type="CONTENT",
                level="HW_SECURE_CRYPTO",
            ),
            compat.License.KeyContainer(
                id=b"operator-id",
                iv=b"operator-iv",
                key=b"encrypted-operator-key",
                type="OPERATOR_SESSION",
                operator_session_key_permissions=(
                    compat.License.KeyContainer.OperatorSessionKeyPermissions(
                        allow_encrypt=True,
                        allow_decrypt=True,
                        allow_signature_verify=True,
                    )
                ),
            ),
        ],
        license_start_time=123456789,
        remote_attestation_verified=True,
        provider_client_token=b"provider-token",
        protection_scheme=0x63656E63,
        srm_requirement=b"srm-requirement",
        srm_update=b"srm-update",
        platform_verification_status="PLATFORM_HARDWARE_VERIFIED",
        group_ids=[
            b"group-one",
            b"group-two",
        ],
    )

    google = upstream.License(
        id={
            "request_id": b"request-id",
            "session_id": b"session-id",
            "type": "STREAMING",
            "version": 1,
        },
        policy={
            "can_play": True,
            "can_persist": False,
            "license_duration_seconds": 3600,
        },
        key=[
            {
                "id": b"content-id",
                "iv": b"content-iv",
                "key": b"encrypted-content-key",
                "type": "CONTENT",
                "level": "HW_SECURE_CRYPTO",
            },
            {
                "id": b"operator-id",
                "iv": b"operator-iv",
                "key": b"encrypted-operator-key",
                "type": "OPERATOR_SESSION",
                "operator_session_key_permissions": {
                    "allow_encrypt": True,
                    "allow_decrypt": True,
                    "allow_signature_verify": True,
                },
            },
        ],
        license_start_time=123456789,
        remote_attestation_verified=True,
        provider_client_token=b"provider-token",
        protection_scheme=0x63656E63,
        srm_requirement=b"srm-requirement",
        srm_update=b"srm-update",
        platform_verification_status="PLATFORM_HARDWARE_VERIFIED",
        group_ids=[
            b"group-one",
            b"group-two",
        ],
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_license_parse_from_google():
    google = upstream.License(
        id={
            "request_id": b"request-id",
            "type": "STREAMING",
        },
        key=[
            {
                "id": b"content-id",
                "iv": b"content-iv",
                "key": b"encrypted-content-key",
                "type": "CONTENT",
                "level": "HW_SECURE_CRYPTO",
            },
            {
                "id": b"operator-id",
                "iv": b"operator-iv",
                "key": b"encrypted-operator-key",
                "type": "OPERATOR_SESSION",
                "operator_session_key_permissions": {
                    "allow_encrypt": True,
                    "allow_sign": True,
                },
            },
        ],
    )

    data = google.SerializeToString()

    custom = compat.License()
    custom.ParseFromString(data)

    assert custom.id.request_id == b"request-id"
    assert custom.id.type == compat.LicenseType.Value("STREAMING")

    assert len(custom.key) == 2

    assert custom.key[0].id == b"content-id"
    assert custom.key[0].type == compat.License.KeyContainer.KeyType.Value("CONTENT")
    assert custom.key[0].level == compat.License.KeyContainer.SecurityLevel.Value("HW_SECURE_CRYPTO")

    assert custom.key[1].type == (compat.License.KeyContainer.KeyType.Value("OPERATOR_SESSION"))
    assert custom.key[1].operator_session_key_permissions.allow_encrypt is True
    assert custom.key[1].operator_session_key_permissions.allow_sign is True
    assert custom.key[1].operator_session_key_permissions.allow_decrypt is False

    assert custom.SerializeToString() == data


def test_operator_permissions_list_fields_empty():
    custom = compat.License.KeyContainer.OperatorSessionKeyPermissions()
    google = upstream.License.KeyContainer.OperatorSessionKeyPermissions()

    assert (
        [(descriptor.name, value) for descriptor, value in custom.ListFields()]
        == [(descriptor.name, value) for descriptor, value in google.ListFields()]
        == []
    )


def test_operator_permissions_list_fields():
    custom = compat.License.KeyContainer.OperatorSessionKeyPermissions(
        allow_encrypt=True,
    )

    google = upstream.License.KeyContainer.OperatorSessionKeyPermissions(
        allow_encrypt=True,
    )

    assert [(descriptor.name, value) for descriptor, value in custom.ListFields()] == [
        (descriptor.name, value) for descriptor, value in google.ListFields()
    ]


def test_operator_permissions_list_fields_false():
    custom = compat.License.KeyContainer.OperatorSessionKeyPermissions(
        allow_encrypt=True,
        allow_decrypt=False,
        allow_sign=True,
    )

    google = upstream.License.KeyContainer.OperatorSessionKeyPermissions(
        allow_encrypt=True,
        allow_decrypt=False,
        allow_sign=True,
    )

    custom_fields = [(descriptor.name, value) for descriptor, value in custom.ListFields()]

    google_fields = [(descriptor.name, value) for descriptor, value in google.ListFields()]

    assert custom_fields == google_fields


def test_operator_permissions_list_fields_after_parse():
    google = upstream.License.KeyContainer.OperatorSessionKeyPermissions(
        allow_encrypt=True,
        allow_decrypt=False,
        allow_signature_verify=True,
    )

    data = google.SerializeToString()

    custom = compat.License.KeyContainer.OperatorSessionKeyPermissions()
    custom.ParseFromString(data)

    custom_fields = [(descriptor.name, value) for descriptor, value in custom.ListFields()]

    google_fields = [(descriptor.name, value) for descriptor, value in google.ListFields()]

    assert custom_fields == google_fields


def test_file_hashes_matches_google():
    custom = compat.FileHashes(
        signer=b"signer-data",
        signatures=[
            compat.FileHashes.Signature(
                filename="widevinecdm.dll",
                test_signing=False,
                SHA512Hash=b"hash-one",
                main_exe=False,
                signature=b"signature-one",
            ),
            compat.FileHashes.Signature(
                filename="widevine.exe",
                test_signing=True,
                SHA512Hash=b"hash-two",
                main_exe=True,
                signature=b"signature-two",
            ),
        ],
    )

    google = upstream.FileHashes(
        signer=b"signer-data",
        signatures=[
            {
                "filename": "widevinecdm.dll",
                "test_signing": False,
                "SHA512Hash": b"hash-one",
                "main_exe": False,
                "signature": b"signature-one",
            },
            {
                "filename": "widevine.exe",
                "test_signing": True,
                "SHA512Hash": b"hash-two",
                "main_exe": True,
                "signature": b"signature-two",
            },
        ],
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_file_hashes_parse_from_google():
    google = upstream.FileHashes(
        signer=b"signer-data",
        signatures=[
            {
                "filename": "widevinecdm.dll",
                "test_signing": False,
                "SHA512Hash": b"sha512-data",
                "main_exe": True,
                "signature": b"signature-data",
            },
        ],
    )

    data = google.SerializeToString()

    custom = compat.FileHashes()
    custom.ParseFromString(data)

    assert custom.signer == b"signer-data"
    assert len(custom.signatures) == 1

    signature = custom.signatures[0]
    assert signature.filename == "widevinecdm.dll"
    assert signature.test_signing is False
    assert signature.SHA512Hash == b"sha512-data"
    assert signature.main_exe is True
    assert signature.signature == b"signature-data"

    assert custom.SerializeToString() == data


def test_widevine_pssh_data_matches_google():
    custom = compat.WidevinePsshData(
        algorithm="AESCTR",
        key_ids=[
            b"key-one",
            b"key-two",
        ],
        provider="example",
        content_id=b"content-id",
        track_type="HD",
        policy="policy",
        crypto_period_index=123,
        grouped_license=b"grouped-license",
        protection_scheme=0x63656E63,
        crypto_period_seconds=10,
        type="ENTITLED_KEY",
        key_sequence=456,
        group_ids=[
            b"group-one",
            b"group-two",
        ],
        entitled_keys=[
            compat.WidevinePsshData.EntitledKey(
                entitlement_key_id=b"entitlement-id",
                key_id=b"key-id",
                key=b"wrapped-key",
                iv=b"0123456789abcdef",
                entitlement_key_size_bytes=32,
            ),
        ],
        video_feature="HDR",
    )

    google = upstream.WidevinePsshData(
        algorithm="AESCTR",
        key_ids=[
            b"key-one",
            b"key-two",
        ],
        provider="example",
        content_id=b"content-id",
        track_type="HD",
        policy="policy",
        crypto_period_index=123,
        grouped_license=b"grouped-license",
        protection_scheme=0x63656E63,
        crypto_period_seconds=10,
        type="ENTITLED_KEY",
        key_sequence=456,
        group_ids=[
            b"group-one",
            b"group-two",
        ],
        entitled_keys=[
            {
                "entitlement_key_id": b"entitlement-id",
                "key_id": b"key-id",
                "key": b"wrapped-key",
                "iv": b"0123456789abcdef",
                "entitlement_key_size_bytes": 32,
            },
        ],
        video_feature="HDR",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_widevine_pssh_data_parse_from_google():
    google = upstream.WidevinePsshData(
        key_ids=[
            b"key-one",
            b"key-two",
        ],
        provider="example",
        content_id=b"content-id",
        protection_scheme=0x63656E63,
        crypto_period_seconds=10,
        type="ENTITLEMENT",
        group_ids=[
            b"group-one",
            b"group-two",
        ],
        video_feature="HDR",
    )

    data = google.SerializeToString()

    custom = compat.WidevinePsshData()
    custom.ParseFromString(data)

    assert list(custom.key_ids) == [
        b"key-one",
        b"key-two",
    ]
    assert custom.provider == "example"
    assert custom.content_id == b"content-id"
    assert custom.protection_scheme == 0x63656E63
    assert custom.crypto_period_seconds == 10
    assert custom.type == compat.WidevinePsshData.Type.Value("ENTITLEMENT")
    assert list(custom.group_ids) == [
        b"group-one",
        b"group-two",
    ]
    assert custom.video_feature == "HDR"

    assert custom.SerializeToString() == data


def test_widevine_pssh_data_defaults_match_google():
    custom = compat.WidevinePsshData()
    google = upstream.WidevinePsshData()

    assert custom.type == google.type == 0

    custom_key = compat.WidevinePsshData.EntitledKey()
    google_key = upstream.WidevinePsshData.EntitledKey()

    assert custom_key.entitlement_key_size_bytes == google_key.entitlement_key_size_bytes == 32


def test_enum_constructor_string_is_normalized():
    custom = compat.License.KeyContainer(
        type="CONTENT",
    )

    google = upstream.License.KeyContainer(
        type="CONTENT",
    )

    assert custom.type == google.type == 2
    assert isinstance(custom.type, int)


def test_enum_constructor_strings_are_normalized():
    custom = compat.License.KeyContainer(
        type="OPERATOR_SESSION",
        level="HW_SECURE_CRYPTO",
    )

    google = upstream.License.KeyContainer(
        type="OPERATOR_SESSION",
        level="HW_SECURE_CRYPTO",
    )

    assert custom.type == google.type == 4
    assert custom.level == google.level == 3
